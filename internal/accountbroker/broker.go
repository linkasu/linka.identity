package accountbroker

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/linka-cloud/linka.identity/internal/cryptokit"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/installationbroker"
	"github.com/linka-cloud/linka.identity/internal/pairwise"
	"github.com/linka-cloud/linka.identity/internal/service"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/linka-cloud/linka.identity/internal/token"
)

type Repository interface {
	PublicEmailChallenge(context.Context, string) (store.PublicEmailChallenge, error)
	CreatePublicEmailChallenge(context.Context, store.PublicEmailChallenge, store.EmailVerification, uint64) (store.PublicEmailChallenge, bool, error)
	EmailVerification(context.Context, string) (store.EmailVerification, error)
	CompletePublicEmailChallenge(context.Context, store.PublicEmailCompletion) (store.PublicEmailRegistration, error)
	AuthorizedPublicAccountSession(context.Context, string, string) (store.AccountSession, store.ProductAccount, error)
	RotatePublicAccountRefresh(context.Context, []byte, []byte) (store.AccountSession, store.ProductAccount, error)
	RevokePublicAccountSession(context.Context, string, string) error
	UpdatePublicAccountProfile(context.Context, string, string, uint64, string, string, string) (store.ProductAccount, error)
	ClaimPublicEmailDelivery(context.Context, string, []string, uint64) (store.PublicEmailChallenge, store.EmailVerification, error)
	FinishPublicEmailDelivery(context.Context, string, string, domain.PublicChallengeState) error
	DeferPublicEmailDelivery(context.Context, string, string, time.Time) error
}

type InstallationAuthenticator interface {
	AuthenticateInstallation(context.Context, string) (installationbroker.InstallationContext, error)
}

type Dependencies struct {
	Repository    Repository
	Installations InstallationAuthenticator
	Identity      *service.IdentityService
	Envelope      *cryptokit.Envelope
	Signer        *token.Signer
	Pairwise      *pairwise.Generator
}

type Config struct {
	Products                  map[string]installationbroker.Product
	RegistrationProducts      map[string]struct{}
	RegistrationPolicyVersion string
	OTPKeyID                  string
	OTPKey                    []byte
	DailyLimit                uint64
}

type Broker struct {
	repository    Repository
	installations InstallationAuthenticator
	identity      *service.IdentityService
	envelope      *cryptokit.Envelope
	signer        *token.Signer
	pairwise      *pairwise.Generator
	products      map[string]string
	allowed       map[string]struct{}
	policy        string
	otpKeyID      string
	otpKey        []byte
	dailyLimit    uint64
	now           func() time.Time
}

func New(deps Dependencies, config Config) (*Broker, error) {
	validLabel := func(value string) bool {
		return len(value) >= 1 && len(value) <= 100 && strings.TrimSpace(value) == value && utf8.ValidString(value) &&
			!strings.Contains(value, "@") && strings.IndexFunc(value, unicode.IsControl) == -1
	}
	if deps.Repository == nil || deps.Installations == nil || deps.Identity == nil || deps.Envelope == nil || deps.Signer == nil || deps.Pairwise == nil ||
		len(config.Products) == 0 || !validLabel(config.RegistrationPolicyVersion) || !validLabel(config.OTPKeyID) || len(config.OTPKey) < 32 || len(config.OTPKey) > 128 || config.DailyLimit > 10000 {
		return nil, errors.New("invalid public account broker configuration")
	}
	if config.DailyLimit == 0 {
		config.DailyLimit = 200
	}
	products, allowed := make(map[string]string, len(config.Products)), make(map[string]struct{}, len(config.RegistrationProducts))
	for id, product := range config.Products {
		if !domain.ValidProductID(id) || product.Audience == "" {
			return nil, errors.New("invalid public account product registry")
		}
		products[id] = product.Audience
	}
	for id := range config.RegistrationProducts {
		if _, ok := products[id]; !ok {
			return nil, errors.New("public account registration references an unknown product")
		}
		allowed[id] = struct{}{}
	}
	return &Broker{repository: deps.Repository, installations: deps.Installations, identity: deps.Identity, envelope: deps.Envelope,
		signer: deps.Signer, pairwise: deps.Pairwise, products: products, allowed: allowed, policy: config.RegistrationPolicyVersion,
		otpKeyID: config.OTPKeyID, otpKey: append([]byte(nil), config.OTPKey...), dailyLimit: config.DailyLimit, now: time.Now}, nil
}

// Begin returns the same generic shape for new and existing email identities.
// The durable challenge is also the encrypted sender job; no mail is sent here.
func (b *Broker) Begin(ctx context.Context, credential string, input ChallengeInput) (ChallengeResponse, error) {
	input, err := input.normalized()
	if err != nil {
		return ChallengeResponse{}, err
	}
	installation, err := b.authenticateInstallation(ctx, credential, input.ProductID)
	if err != nil {
		return ChallengeResponse{}, err
	}
	fingerprint := b.digest("request", input.RequestID, input.ProductID, installation.InstallationID, input.Purpose, input.ClientNonce, input.Email, input.HolderRole)
	existing, err := b.repository.PublicEmailChallenge(ctx, input.RequestID)
	if err == nil {
		if existing.ProductID != input.ProductID || existing.InstallationID != installation.InstallationID || !bytes.Equal(existing.RequestFingerprint, fingerprint) {
			return ChallengeResponse{}, domain.ErrConflict
		}
		return challengeResponse(existing), nil
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return ChallengeResponse{}, err
	}
	now := b.now().UTC().Truncate(time.Microsecond)
	verification, err := b.identity.PreparePublicVerification(ctx, service.PublicVerificationInput{ID: input.RequestID,
		ProductID: input.ProductID, Email: input.Email, InstallationID: installation.InstallationID, ExpiresAt: now.Add(domain.PublicEmailQueueTTL)})
	if err != nil {
		return ChallengeResponse{}, err
	}
	number, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return ChallengeResponse{}, errors.New("verification code unavailable")
	}
	code := fmt.Sprintf("%06d", number.Int64())
	cipher, err := b.envelope.Encrypt(ctx, []byte(code), otpAAD(input.RequestID, input.ProductID))
	if err != nil {
		return ChallengeResponse{}, err
	}
	nonceHash := b.digest("nonce", input.ProductID, installation.InstallationID, input.ClientNonce)
	challenge := store.PublicEmailChallenge{ID: input.RequestID, ProductID: input.ProductID, InstallationID: installation.InstallationID,
		Purpose: RegistrationPurpose, HolderRole: input.HolderRole, RequestFingerprint: fingerprint, NonceHash: nonceHash,
		CodeHash: b.digest("code", input.ProductID, installation.InstallationID, input.RequestID, RegistrationPurpose, hex.EncodeToString(nonceHash), hex.EncodeToString(verification.BlindIndex), code),
		OTPKeyID: b.otpKeyID, Code: cipher, EmailBlindIndexVersion: verification.BlindIndexVersion, EmailBlindIndex: verification.BlindIndex,
		State: domain.PublicChallengeRequested, MailAvailableAt: now, CreatedAt: now, UpdatedAt: now, ExpiresAt: verification.ExpiresAt, Version: 1}
	saved, _, err := b.repository.CreatePublicEmailChallenge(ctx, challenge, verification, b.dailyLimit)
	if err != nil {
		return ChallengeResponse{}, err
	}
	return challengeResponse(saved), nil
}

func (b *Broker) authenticateInstallation(ctx context.Context, credential, product string) (installationbroker.InstallationContext, error) {
	if _, ok := b.allowed[product]; !ok {
		return installationbroker.InstallationContext{}, domain.ErrInvalid
	}
	installation, err := b.installations.AuthenticateInstallation(ctx, credential)
	if err != nil {
		return installationbroker.InstallationContext{}, err
	}
	if installation.ProductID != product || !domain.ValidUUID(installation.InstallationID) || !pairwise.Valid(installation.InstallationKey) || installation.TelemetryAudience != b.products[product] {
		return installationbroker.InstallationContext{}, installationbroker.ErrInvalidCredential
	}
	return installation, nil
}

func (b *Broker) digest(purpose string, values ...string) []byte {
	mac := hmac.New(sha256.New, b.otpKey)
	_, _ = io.WriteString(mac, "linka-public-product-account-v1\x00"+purpose+"\x00"+strings.Join(values, "\x00"))
	return mac.Sum(nil)
}

func otpAAD(id, product string) []byte {
	return []byte(strings.Join([]string{"public-email-otp-v1", product, id}, "\x00"))
}

func challengeResponse(c store.PublicEmailChallenge) ChallengeResponse {
	status := string(c.State)
	switch c.State {
	case domain.PublicChallengeRequested:
		status = "queued"
	case domain.PublicChallengeDelivering, domain.PublicChallengeDelivered, domain.PublicChallengeDeliveryUncertain:
		status = "pending"
	case domain.PublicChallengeConsumed:
		status = "verified"
	}
	return ChallengeResponse{ContractVersion: ContractVersion, ChallengeID: c.ID, Status: status, ExpiresAt: c.ExpiresAt, ResendAfter: c.CreatedAt.Add(time.Minute)}
}
