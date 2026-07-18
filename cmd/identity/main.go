package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/linka-cloud/linka.identity/internal/authz"
	"github.com/linka-cloud/linka.identity/internal/config"
	"github.com/linka-cloud/linka.identity/internal/cryptokit"
	"github.com/linka-cloud/linka.identity/internal/httpapi"
	"github.com/linka-cloud/linka.identity/internal/outbox"
	"github.com/linka-cloud/linka.identity/internal/pairwise"
	"github.com/linka-cloud/linka.identity/internal/privacyworker"
	"github.com/linka-cloud/linka.identity/internal/service"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/linka-cloud/linka.identity/internal/token"
	"github.com/linka-cloud/linka.identity/internal/verificationworker"
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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	database, err := store.Open(ctx, cfg.DatabaseURL, cfg.DatabaseMaxConnections)
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
		keyProvider, err = cryptokit.NewYandexKMSKeyring(cfg.EmailKeyActiveID, cfg.EmailYandexKMSKeys, cryptokit.NewMetadataIAMTokenSource())
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
	identityService := service.NewIdentityServiceWithVerification(database, envelope, indexer, cfg.MinorCrossProductLinking, cfg.EmailVerificationTTL)
	handler := httpapi.New(database, identityService, tokenSigner, authenticator, pairwiseIDs, products,
		cfg.RequireOutboxDelivery, cfg.OutboxReadinessMaxAge, logger)
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
	go outbox.New(database, cfg.OutboxURL, tokenSigner, products, cfg.OutboxPollInterval, cfg.OutboxMaxAttempts, logger).Run(workerCtx)
	go privacyworker.New(database, cfg.OutboxPollInterval, cfg.OutboxMaxAttempts, logger).Run(workerCtx)
	go verificationworker.New(database, cfg.EmailCleanupInterval, logger).Run(workerCtx)

	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("identity service listening", "address", cfg.HTTPAddr)
		serverErrors <- httpServer.ListenAndServe()
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
