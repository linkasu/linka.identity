package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/linka-cloud/linka.identity/internal/accountbroker"
	"github.com/linka-cloud/linka.identity/internal/accountmail"
	"github.com/linka-cloud/linka.identity/internal/authz"
	"github.com/linka-cloud/linka.identity/internal/config"
	"github.com/linka-cloud/linka.identity/internal/cryptokit"
	"github.com/linka-cloud/linka.identity/internal/httpapi"
	"github.com/linka-cloud/linka.identity/internal/installationbroker"
	"github.com/linka-cloud/linka.identity/internal/outbox"
	"github.com/linka-cloud/linka.identity/internal/pairwise"
	"github.com/linka-cloud/linka.identity/internal/privacyworker"
	"github.com/linka-cloud/linka.identity/internal/productdirectory"
	"github.com/linka-cloud/linka.identity/internal/service"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/linka-cloud/linka.identity/internal/token"
	"github.com/linka-cloud/linka.identity/internal/verificationworker"
	"github.com/linka-cloud/linka.identity/internal/workertick"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("identity service stopped", "error", err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	listener, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return fmt.Errorf("listen HTTP: %w", err)
	}
	defer listener.Close()
	logger.Info("identity service listening", "address", cfg.HTTPAddr)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if cfg.MaintenanceMode {
		return runMaintenance(ctx, listener, logger)
	}

	database, err := store.Open(ctx, cfg.YDBEndpoint, cfg.YDBDatabase)
	if err != nil {
		return err
	}
	defer database.Close()
	pingCtx, cancelPing := context.WithTimeout(ctx, 5*time.Second)
	err = database.Ready(pingCtx)
	cancelPing()
	if err != nil {
		return fmt.Errorf("database readiness failed (%T)", err)
	}

	var keyProvider cryptokit.KeyProvider
	switch cfg.EmailKeyProvider {
	case "local":
		keyProvider, err = cryptokit.NewLocalAESKeyring(cfg.EmailKeyActiveID, cfg.EmailLocalKEKs)
	case "yandex-kms":
		var kmsKeyring *cryptokit.YandexKMSKeyring
		kmsKeyring, err = cryptokit.NewYandexKMSKeyring(cfg.EmailKeyActiveID, cfg.EmailYandexKMSKeys, cryptokit.NewMetadataIAMTokenSource())
		if err == nil {
			defer kmsKeyring.Close()
			keyProvider = kmsKeyring
		}
	default:
		err = errors.New("unsupported email key provider")
	}
	if err != nil {
		return fmt.Errorf("key provider: %w", err)
	}
	configuredEnvelopeKeys := make(map[string]struct{})
	for keyID := range cfg.EmailLocalKEKs {
		configuredEnvelopeKeys[keyID] = struct{}{}
	}
	for keyID := range cfg.EmailYandexKMSKeys {
		configuredEnvelopeKeys[keyID] = struct{}{}
	}
	if err := database.ValidateEnvelopeKeyIDs(ctx, configuredEnvelopeKeys); err != nil {
		return fmt.Errorf("envelope-key rotation guard: %w", err)
	}
	envelope := cryptokit.NewEnvelope(keyProvider)
	indexer, err := cryptokit.NewBlindIndexer(cfg.BlindIndexCurrentVersion, cfg.BlindIndexKeys)
	if err != nil {
		return fmt.Errorf("blind indexer: %w", err)
	}
	if err := database.ValidateBlindIndexVersions(ctx, cfg.BlindIndexKeys); err != nil {
		return fmt.Errorf("blind-index rotation guard: %w", err)
	}
	tokenSigner, err := token.NewKeyring(cfg.TokenSigningSeeds, cfg.TokenActiveKeyID, cfg.TokenIssuer, cfg.TokenTTL, cfg.TokenMaxTTL)
	if err != nil {
		return fmt.Errorf("token signer: %w", err)
	}
	authenticator, err := authz.New(cfg.Workloads)
	if err != nil {
		return fmt.Errorf("workload authentication: %w", err)
	}
	pairwiseIDs, err := pairwise.New(cfg.PairwiseIDKey)
	if err != nil {
		return fmt.Errorf("pairwise IDs: %w", err)
	}
	products := make(map[string]string, len(cfg.Products))
	for productID, product := range cfg.Products {
		products[productID] = product.TelemetryAudience
	}
	var publicBroker *installationbroker.Broker
	publicProducts := make(map[string]installationbroker.Product, len(products))
	for productID := range products {
		publicProducts[productID] = installationbroker.Product{Audience: products[productID], AdditionalPolicies: cfg.PublicAdditionalPolicies[productID]}
	}
	if len(cfg.PublicInstallationProducts) > 0 {
		publicBroker, err = installationbroker.New(database, tokenSigner, pairwiseIDs, installationbroker.Config{
			Products: publicProducts, RegistrationProducts: cfg.PublicInstallationProducts,
			PolicyVersion: cfg.PublicPolicyVersion, RefreshTTL: cfg.PublicRefreshTTL,
		})
		if err != nil {
			return fmt.Errorf("public installation broker: %w", err)
		}
	}
	identityService := service.NewIdentityServiceWithVerification(database, envelope, indexer, cfg.MinorCrossProductLinking, cfg.EmailVerificationTTL)
	var publicAccounts *accountbroker.Broker
	var deliveryWorker *accountbroker.DeliveryWorker
	if cfg.PublicAccounts.Enabled {
		if err := database.ValidatePublicOTPKeyID(ctx, cfg.PublicAccounts.OTPKeyID, time.Now().UTC()); err != nil {
			return fmt.Errorf("public OTP-key rotation guard: %w", err)
		}
		publicAccounts, err = accountbroker.New(accountbroker.Dependencies{
			Repository: database, Installations: publicBroker, Identity: identityService, Envelope: envelope, Signer: tokenSigner, Pairwise: pairwiseIDs,
		}, accountbroker.Config{Logger: logger, Products: publicProducts, RegistrationProducts: cfg.PublicAccounts.Products,
			RegistrationPolicyVersion: cfg.PublicAccounts.PolicyVersion, OTPKeyID: cfg.PublicAccounts.OTPKeyID, OTPKey: cfg.PublicAccounts.OTPKey, DailyLimit: uint64(cfg.PublicAccounts.DailyLimit)})
		if err != nil {
			return fmt.Errorf("public product account broker: %w", err)
		}
		deliveryWorker, err = accountbroker.NewDeliveryWorker(publicAccounts, accountmail.SMTP{Addr: cfg.PublicAccounts.SMTPAddr,
			User: cfg.PublicAccounts.SMTPUser, Password: cfg.PublicAccounts.SMTPPassword, From: cfg.PublicAccounts.SMTPFrom, Timeout: 10 * time.Second}, logger)
		if err != nil {
			return err
		}
	}
	outboxWorker := outbox.New(database, cfg.OutboxURL, tokenSigner, products, cfg.OutboxPollInterval, cfg.OutboxMaxAttempts, logger)
	privacyWorker := privacyworker.New(database, cfg.OutboxPollInterval, cfg.OutboxMaxAttempts, logger)
	verificationWorker := verificationworker.New(database, cfg.EmailCleanupInterval, logger)
	var accountRoutes httpapi.PublicAccountBroker
	if publicAccounts != nil {
		accountRoutes = publicAccounts
	}
	directory, err := productdirectory.New(database, envelope, pairwiseIDs, products)
	if err != nil {
		return fmt.Errorf("product directory: %w", err)
	}
	apiHandler := httpapi.New(database, identityService, tokenSigner, authenticator, pairwiseIDs, products, publicBroker, accountRoutes, directory, cfg.PublicAllowedOrigins,
		cfg.RequireOutboxDelivery, cfg.OutboxReadinessMaxAge, logger)
	handler := http.NewServeMux()
	var registrationProcessor workertick.Processor
	if deliveryWorker != nil {
		registrationProcessor = deliveryWorker
	}
	handler.Handle(workertick.Path, workertick.New(outboxWorker, privacyWorker, verificationWorker, registrationProcessor))
	handler.Handle("/", apiHandler)
	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	workerCtx, cancelWorker := context.WithCancel(context.Background())
	defer cancelWorker()
	go outboxWorker.Run(workerCtx)
	go privacyWorker.Run(workerCtx)
	go verificationWorker.Run(workerCtx)
	if deliveryWorker != nil {
		go deliveryWorker.Run(workerCtx)
	}

	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- httpServer.Serve(listener)
	}()

	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve HTTP: %w", err)
		}
		return nil
	case <-ctx.Done():
		cancelWorker()
		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancelShutdown()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown HTTP server: %w", err)
		}
		return nil
	}
}
