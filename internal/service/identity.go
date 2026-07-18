package service

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/linka-cloud/linka.identity/internal/cryptokit"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/ids"
	"github.com/linka-cloud/linka.identity/internal/store"
)

type IdentityService struct {
	store                    IdentityStore
	envelope                 *cryptokit.Envelope
	indexer                  *cryptokit.BlindIndexer
	minorCrossProductLinking bool
	emailVerificationTTL     time.Duration
	now                      func() time.Time
}

type IdentityStore interface {
	CreateEmailVerification(context.Context, store.EmailVerification) error
	ClaimVerifiedEmail(context.Context, string, string, string, time.Time, time.Duration) (store.EmailVerification, error)
	ReleaseEmailVerification(context.Context, string, string) error
	ConsumeEmailVerification(context.Context, string, string, string, time.Time) error
	RegisterEmailIdentity(context.Context, store.NewEmailIdentity, []cryptokit.BlindIndex) (store.EmailIdentity, bool, error)
}

type RegisterEmailIdentityInput struct {
	ProductID            string
	Email                string
	Namespace            string
	AgeCategory          string
	GuardianRelationship *string
	LinkAcrossProducts   bool
	CreateAccount        bool
	InstallationID       *string
	VerifiedAt           time.Time
}

type RegisterEmailIdentityResult struct {
	PersonID  string
	AccountID string
	Created   bool
}

func NewIdentityService(database IdentityStore, envelope *cryptokit.Envelope, indexer *cryptokit.BlindIndexer, minorCrossProductLinking bool) *IdentityService {
	return NewIdentityServiceWithVerification(database, envelope, indexer, minorCrossProductLinking, 15*time.Minute)
}

func NewIdentityServiceWithVerification(database IdentityStore, envelope *cryptokit.Envelope, indexer *cryptokit.BlindIndexer, minorCrossProductLinking bool, verificationTTL time.Duration) *IdentityService {
	return &IdentityService{
		store:                    database,
		envelope:                 envelope,
		indexer:                  indexer,
		minorCrossProductLinking: minorCrossProductLinking,
		emailVerificationTTL:     verificationTTL,
		now:                      time.Now,
	}
}

type BeginEmailVerificationInput struct {
	ProductID            string
	Email                string
	Namespace            string
	AgeCategory          string
	GuardianRelationship *string
	LinkAcrossProducts   bool
	InstallationID       *string
}

func (s *IdentityService) BeginEmailVerification(ctx context.Context, input BeginEmailVerificationInput) (string, time.Time, error) {
	normalizedEmail, err := normalizeEmail(input.Email)
	if err != nil {
		return "", time.Time{}, domain.ErrInvalid
	}
	registration := RegisterEmailIdentityInput{
		ProductID: input.ProductID, Email: normalizedEmail, Namespace: input.Namespace, AgeCategory: input.AgeCategory,
		GuardianRelationship: input.GuardianRelationship, LinkAcrossProducts: input.LinkAcrossProducts, InstallationID: input.InstallationID,
		VerifiedAt: s.now().UTC(),
	}
	if err := s.validateRegistration(registration); err != nil {
		return "", time.Time{}, err
	}
	linkageScope, scopeKey, err := s.linkageScope(registration)
	if err != nil {
		return "", time.Time{}, err
	}
	verificationID, err := ids.NewUUID()
	if err != nil {
		return "", time.Time{}, err
	}
	indexMessage := []byte(strings.Join([]string{input.Namespace, linkageScope, scopeKey, normalizedEmail}, "\x00"))
	index := s.indexer.Current(indexMessage)
	aad := []byte(strings.Join([]string{"email-verification-v1", verificationID, input.ProductID}, "\x00"))
	encrypted, err := s.envelope.Encrypt(ctx, []byte(normalizedEmail), aad)
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := s.now().UTC().Add(s.emailVerificationTTL)
	if err := s.store.CreateEmailVerification(ctx, store.EmailVerification{
		ID: verificationID, ProductID: input.ProductID, InstallationID: input.InstallationID,
		Namespace: input.Namespace, AgeCategory: input.AgeCategory, GuardianRelationship: input.GuardianRelationship,
		LinkAcrossProducts: input.LinkAcrossProducts, BlindIndexVersion: index.Version, BlindIndex: index.Value,
		EncryptedEmail: encrypted, ExpiresAt: expiresAt,
	}); err != nil {
		return "", time.Time{}, err
	}
	return verificationID, expiresAt, nil
}

func (s *IdentityService) CompleteEmailVerification(ctx context.Context, verificationID, productID string, createAccount bool) (RegisterEmailIdentityResult, error) {
	now := s.now().UTC()
	claimToken, err := ids.NewUUID()
	if err != nil {
		return RegisterEmailIdentityResult{}, err
	}
	verification, err := s.store.ClaimVerifiedEmail(ctx, verificationID, productID, claimToken, now, 5*time.Minute)
	if err != nil {
		return RegisterEmailIdentityResult{}, err
	}
	claimed := true
	defer func() {
		if claimed {
			releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			defer cancel()
			_ = s.store.ReleaseEmailVerification(releaseCtx, verificationID, claimToken)
		}
	}()
	aad := []byte(strings.Join([]string{"email-verification-v1", verification.ID, verification.ProductID}, "\x00"))
	plaintext, err := s.envelope.Decrypt(ctx, verification.EncryptedEmail, aad)
	if err != nil {
		return RegisterEmailIdentityResult{}, err
	}
	defer clear(plaintext)
	result, err := s.RegisterEmailIdentity(ctx, RegisterEmailIdentityInput{
		ProductID: verification.ProductID, Email: string(plaintext), Namespace: verification.Namespace,
		AgeCategory: verification.AgeCategory, GuardianRelationship: verification.GuardianRelationship,
		LinkAcrossProducts: verification.LinkAcrossProducts, CreateAccount: createAccount,
		InstallationID: verification.InstallationID, VerifiedAt: *verification.VerifiedAt,
	})
	if err != nil {
		return RegisterEmailIdentityResult{}, err
	}
	if err := s.store.ConsumeEmailVerification(ctx, verificationID, claimToken, result.PersonID, now); err != nil {
		return RegisterEmailIdentityResult{}, err
	}
	claimed = false
	return result, nil
}

func (s *IdentityService) RegisterEmailIdentity(ctx context.Context, input RegisterEmailIdentityInput) (RegisterEmailIdentityResult, error) {
	normalizedEmail, err := normalizeEmail(input.Email)
	if err != nil {
		return RegisterEmailIdentityResult{}, domain.ErrInvalid
	}
	input.Email = normalizedEmail
	if err := s.validateRegistration(input); err != nil {
		return RegisterEmailIdentityResult{}, err
	}

	linkageScope, scopeKey, err := s.linkageScope(input)
	if err != nil {
		return RegisterEmailIdentityResult{}, err
	}
	indexMessage := []byte(strings.Join([]string{input.Namespace, linkageScope, scopeKey, normalizedEmail}, "\x00"))
	currentIndex := s.indexer.Current(indexMessage)
	allIndexes := s.indexer.All(indexMessage)

	personID, err := ids.NewUUID()
	if err != nil {
		return RegisterEmailIdentityResult{}, err
	}
	identityID, err := ids.NewUUID()
	if err != nil {
		return RegisterEmailIdentityResult{}, err
	}
	aad := []byte(strings.Join([]string{"email-v1", identityID, input.Namespace, linkageScope, scopeKey}, "\x00"))
	encrypted, err := s.envelope.Encrypt(ctx, []byte(normalizedEmail), aad)
	if err != nil {
		return RegisterEmailIdentityResult{}, err
	}
	accountID, err := ids.NewUUID()
	if err != nil {
		return RegisterEmailIdentityResult{}, err
	}
	if input.CreateAccount {
		// Keep the generated ID; the store uses it only when an account must be created.
	} else {
		accountID = ""
	}
	existing, created, err := s.store.RegisterEmailIdentity(ctx, store.NewEmailIdentity{
		ID: identityID, PersonID: personID, AccountID: accountID, ProductID: input.ProductID,
		Namespace: input.Namespace, LinkageScope: linkageScope, ScopeKey: scopeKey,
		BlindIndexVersion: currentIndex.Version, BlindIndex: currentIndex.Value,
		EncryptedEmail: encrypted, AgeCategory: input.AgeCategory,
		GuardianRelationship: input.GuardianRelationship, VerifiedAt: input.VerifiedAt,
		CreateAccount: input.CreateAccount, InstallationID: input.InstallationID,
	}, allIndexes)
	if err != nil {
		return RegisterEmailIdentityResult{}, fmt.Errorf("register identity transaction: %w", err)
	}
	return RegisterEmailIdentityResult{PersonID: existing.PersonID, AccountID: existing.AccountID, Created: created}, nil
}

func (s *IdentityService) validateRegistration(input RegisterEmailIdentityInput) error {
	if !domain.ValidProductID(input.ProductID) || input.VerifiedAt.IsZero() {
		return domain.ErrInvalid
	}
	if input.Namespace != "account" && input.Namespace != "donation" {
		return domain.ErrInvalid
	}
	if input.AgeCategory != "unknown" && input.AgeCategory != "adult" && input.AgeCategory != "minor" {
		return domain.ErrInvalid
	}
	if input.GuardianRelationship != nil {
		trimmed, ok := domain.TrimmedWithin(*input.GuardianRelationship, 1, 120)
		if !ok || input.AgeCategory != "minor" {
			return domain.ErrInvalid
		}
		input.GuardianRelationship = &trimmed
	}
	if input.CreateAccount && input.Namespace != "account" {
		return domain.ErrInvalid
	}
	if input.InstallationID != nil && !domain.ValidUUID(*input.InstallationID) {
		return domain.ErrInvalid
	}
	return nil
}

func (s *IdentityService) linkageScope(input RegisterEmailIdentityInput) (string, string, error) {
	if input.Namespace == "donation" || !input.LinkAcrossProducts {
		return "product", input.ProductID, nil
	}
	if input.AgeCategory == "minor" && !s.minorCrossProductLinking {
		return "", "", domain.ErrForbidden
	}
	if input.AgeCategory == "unknown" {
		return "", "", domain.ErrForbidden
	}
	return "global", "global", nil
}

func normalizeEmail(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) < 3 || len(trimmed) > 320 || !strings.Contains(trimmed, "@") {
		return "", errors.New("invalid email")
	}
	parsed, err := mail.ParseAddress(trimmed)
	if err != nil || parsed.Address != trimmed || strings.ContainsAny(trimmed, "\r\n\x00") {
		return "", errors.New("invalid email")
	}
	return strings.ToLower(parsed.Address), nil
}
