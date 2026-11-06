package service

import (
	"context"
	"strings"
	"time"

	"github.com/linka-cloud/linka.identity/internal/cryptokit"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/ids"
	"github.com/linka-cloud/linka.identity/internal/store"
)

type PublicVerificationInput struct {
	ID, ProductID, Email, InstallationID string
	ExpiresAt                            time.Time
}

// PreparePublicVerification prepares ciphertext outside transaction retries.
// It neither verifies ownership nor persists a challenge; Broker owns those steps.
func (s *IdentityService) PreparePublicVerification(ctx context.Context, input PublicVerificationInput) (store.EmailVerification, error) {
	now := s.now().UTC()
	if !domain.ValidUUID(input.ID) || !domain.ValidUUID(input.InstallationID) || !input.ExpiresAt.After(now) || input.ExpiresAt.After(now.Add(10*time.Minute)) {
		return store.EmailVerification{}, domain.ErrInvalid
	}
	return s.prepareEmailVerification(ctx, BeginEmailVerificationInput{
		ProductID: input.ProductID, Email: input.Email, Namespace: "account", AgeCategory: "unknown", InstallationID: &input.InstallationID,
	}, input.ID, input.ExpiresAt)
}

// PreparePublicIdentity creates encrypted registration inputs, never authority.
// OTP, latest-flow, expiry and linkage must be rechecked in the final transaction.
func (s *IdentityService) PreparePublicIdentity(ctx context.Context, verification store.EmailVerification, verifiedAt time.Time) (store.NewEmailIdentity, []cryptokit.BlindIndex, error) {
	if verification.Namespace != "account" || verification.AgeCategory != "unknown" || verification.LinkAcrossProducts || verification.InstallationID == nil || verifiedAt.IsZero() || verifiedAt.After(s.now().UTC()) {
		return store.NewEmailIdentity{}, nil, domain.ErrInvalid
	}
	email, err := s.OpenVerificationEmail(ctx, verification)
	if err != nil {
		return store.NewEmailIdentity{}, nil, err
	}
	return s.prepareEmailIdentity(ctx, RegisterEmailIdentityInput{
		ProductID: verification.ProductID, Email: email, Namespace: "account", AgeCategory: "unknown",
		CreateAccount: true, InstallationID: verification.InstallationID, VerifiedAt: verifiedAt,
	})
}

// OpenVerificationEmail is server-side preparation, not a public read operation.
func (s *IdentityService) OpenVerificationEmail(ctx context.Context, verification store.EmailVerification) (string, error) {
	aad := []byte(strings.Join([]string{"email-verification-v1", verification.ID, verification.ProductID}, "\x00"))
	plain, err := s.envelope.Decrypt(ctx, verification.EncryptedEmail, aad)
	if err != nil {
		return "", err
	}
	defer clear(plain)
	return domain.NormalizeEmail(string(plain))
}

func (s *IdentityService) prepareEmailVerification(ctx context.Context, input BeginEmailVerificationInput, id string, expiresAt time.Time) (store.EmailVerification, error) {
	normalized, err := domain.NormalizeEmail(input.Email)
	if err != nil {
		return store.EmailVerification{}, domain.ErrInvalid
	}
	registration := RegisterEmailIdentityInput{
		ProductID: input.ProductID, Email: normalized, Namespace: input.Namespace, AgeCategory: input.AgeCategory,
		GuardianRelationship: input.GuardianRelationship, LinkAcrossProducts: input.LinkAcrossProducts,
		InstallationID: input.InstallationID, VerifiedAt: s.now().UTC(),
	}
	if err := s.validateRegistration(registration); err != nil {
		return store.EmailVerification{}, err
	}
	scope, scopeKey, err := s.linkageScope(registration)
	if err != nil {
		return store.EmailVerification{}, err
	}
	if id == "" {
		id, err = ids.NewUUID()
		if err != nil {
			return store.EmailVerification{}, err
		}
	}
	index := s.indexer.Current([]byte(strings.Join([]string{input.Namespace, scope, scopeKey, normalized}, "\x00")))
	aad := []byte(strings.Join([]string{"email-verification-v1", id, input.ProductID}, "\x00"))
	cipher, err := s.envelope.Encrypt(ctx, []byte(normalized), aad)
	if err != nil {
		return store.EmailVerification{}, err
	}
	return store.EmailVerification{
		ID: id, ProductID: input.ProductID, InstallationID: input.InstallationID,
		Namespace: input.Namespace, AgeCategory: input.AgeCategory, GuardianRelationship: input.GuardianRelationship,
		LinkAcrossProducts: input.LinkAcrossProducts, BlindIndexVersion: index.Version, BlindIndex: index.Value,
		EncryptedEmail: cipher, ExpiresAt: expiresAt,
	}, nil
}
