package installationbroker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/ids"
	"github.com/linka-cloud/linka.identity/internal/pairwise"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/linka-cloud/linka.identity/internal/token"
)

var ErrInvalidCredential = errors.New("invalid installation credential")

type Repository interface {
	RegisterPublicInstallation(context.Context, store.PublicInstallationRegistration) (store.Installation, error)
	DenyPublicInstallation(context.Context, store.PublicTelemetryDenial) (time.Time, error)
	ResolveSubjectAlias(context.Context, string, string, string) (store.ResolvedAlias, error)
	ResolveTokenSubject(context.Context, string, string, string) error
	GetTelemetryPreference(context.Context, store.Subject, string) (store.TelemetryPreference, error)
}

type Product struct {
	Audience string
}

type Config struct {
	Products             map[string]Product
	RegistrationProducts map[string]struct{}
	PolicyVersion        string
	RefreshTTL           time.Duration
}

type RegisterInput struct {
	RequestID     string    `json:"request_id"`
	ProductID     string    `json:"product_id"`
	Platform      string    `json:"platform"`
	Preference    string    `json:"preference"`
	PolicyVersion string    `json:"policy_version"`
	RecordedAt    time.Time `json:"recorded_at"`
}

type PreferenceInput struct {
	Preference    string    `json:"preference"`
	PolicyVersion string    `json:"policy_version"`
	RecordedAt    time.Time `json:"recorded_at"`
}

type AccessToken struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type Registration struct {
	InstallationKey string       `json:"installation_key"`
	Product         string       `json:"product"`
	Platform        string       `json:"platform"`
	Preference      string       `json:"preference"`
	PolicyVersion   string       `json:"policy_version"`
	RecordedAt      time.Time    `json:"recorded_at"`
	RefreshToken    string       `json:"refresh_token"`
	RefreshExpires  time.Time    `json:"refresh_expires_at"`
	MetricsToken    *AccessToken `json:"metrics_token"`
}

type TokenResponse struct {
	InstallationKey string      `json:"installation_key"`
	Product         string      `json:"product"`
	MetricsToken    AccessToken `json:"metrics_token"`
}

type PreferenceResponse struct {
	InstallationKey string    `json:"installation_key"`
	Product         string    `json:"product"`
	Preference      string    `json:"preference"`
	PolicyVersion   string    `json:"policy_version"`
	RecordedAt      time.Time `json:"recorded_at"`
}

type Broker struct {
	repository Repository
	signer     *token.Signer
	pairwise   *pairwise.Generator
	config     Config
	now        func() time.Time
}

func New(repository Repository, signer *token.Signer, pairwiseIDs *pairwise.Generator, config Config) (*Broker, error) {
	if repository == nil || signer == nil || pairwiseIDs == nil || len(config.Products) == 0 || len(config.RegistrationProducts) == 0 ||
		config.PolicyVersion == "" || config.RefreshTTL < 24*time.Hour || config.RefreshTTL > 365*24*time.Hour {
		return nil, errors.New("invalid public installation broker configuration")
	}
	for productID, product := range config.Products {
		if !domain.ValidProductID(productID) || product.Audience == "" {
			return nil, errors.New("invalid public installation product")
		}
	}
	for productID := range config.RegistrationProducts {
		if _, ok := config.Products[productID]; !ok {
			return nil, errors.New("public registration references an unknown product")
		}
	}
	return &Broker{repository: repository, signer: signer, pairwise: pairwiseIDs, config: config, now: time.Now}, nil
}

func (b *Broker) Register(ctx context.Context, input RegisterInput) (Registration, error) {
	product, ok := b.config.Products[input.ProductID]
	_, registrationEnabled := b.config.RegistrationProducts[input.ProductID]
	if !ok || !registrationEnabled || !domain.ValidUUID(input.RequestID) || !validPlatform(input.Platform) || !b.validRegistration(input.Preference, input.PolicyVersion, input.RecordedAt) {
		return Registration{}, domain.ErrInvalid
	}
	input.RecordedAt = input.RecordedAt.UTC().Truncate(time.Microsecond)
	rootID := b.registrationID(input, product.Audience)
	consentID, err := ids.NewUUID()
	if err != nil {
		return Registration{}, err
	}
	suppressionID, err := ids.NewUUID()
	if err != nil {
		return Registration{}, err
	}
	installationKey := b.pairwise.Subject(input.ProductID, product.Audience, "installation", rootID)
	consentStatus := "granted"
	if input.Preference == "denied" {
		consentStatus = "withdrawn"
	}
	installation, err := b.repository.RegisterPublicInstallation(ctx, store.PublicInstallationRegistration{
		Installation: store.Installation{ID: rootID, ProductID: input.ProductID, Platform: input.Platform},
		OpaqueKey:    installationKey, Audience: product.Audience, Preference: input.Preference,
		PreferenceAt: input.RecordedAt.UTC(), SuppressionID: suppressionID,
		Consent: store.Consent{
			ID: consentID, Subject: store.Subject{Kind: "installation", ID: rootID}, ProductID: input.ProductID,
			ConsentType: "telemetry", PolicyVersion: input.PolicyVersion, Status: consentStatus, RecordedAt: input.RecordedAt.UTC(),
		},
	})
	if err != nil {
		return Registration{}, err
	}
	refreshToken, refreshExpires, err := b.signer.SignRefresh(input.ProductID, installationKey, input.PolicyVersion, b.config.RefreshTTL)
	if err != nil {
		return Registration{}, err
	}
	result := Registration{
		InstallationKey: installationKey, Product: input.ProductID, Platform: installation.Platform,
		Preference: input.Preference, PolicyVersion: input.PolicyVersion, RecordedAt: input.RecordedAt.UTC(),
		RefreshToken: refreshToken, RefreshExpires: refreshExpires,
	}
	if input.Preference == "allowed" {
		access, err := b.issueAccess(input.ProductID, product.Audience, installationKey)
		if err != nil {
			return Registration{}, err
		}
		result.MetricsToken = &access
	}
	return result, nil
}

func (b *Broker) Refresh(ctx context.Context, refreshToken string) (TokenResponse, error) {
	authenticated, err := b.authenticate(ctx, refreshToken)
	if err != nil {
		return TokenResponse{}, err
	}
	preference, err := b.repository.GetTelemetryPreference(ctx, store.Subject{Kind: "installation", ID: authenticated.alias.SubjectID}, authenticated.productID)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && preference.Preference != "allowed") {
		return TokenResponse{}, domain.ErrForbidden
	}
	if err != nil {
		return TokenResponse{}, err
	}
	access, err := b.issueAccess(authenticated.productID, authenticated.audience, authenticated.alias.OpaqueKey)
	if err != nil {
		return TokenResponse{}, err
	}
	return TokenResponse{InstallationKey: authenticated.alias.OpaqueKey, Product: authenticated.productID, MetricsToken: access}, nil
}

func (b *Broker) SetPreference(ctx context.Context, refreshToken string, input PreferenceInput) (PreferenceResponse, error) {
	if input.Preference != "denied" || !b.validDenial(input.PolicyVersion, input.RecordedAt) {
		return PreferenceResponse{}, domain.ErrInvalid
	}
	input.RecordedAt = input.RecordedAt.UTC().Truncate(time.Microsecond)
	authenticated, err := b.authenticate(ctx, refreshToken)
	if err != nil {
		return PreferenceResponse{}, err
	}
	if input.PolicyVersion != authenticated.policyVersion {
		return PreferenceResponse{}, domain.ErrConflict
	}
	consentID, err := ids.NewUUID()
	if err != nil {
		return PreferenceResponse{}, err
	}
	suppressionID, err := ids.NewUUID()
	if err != nil {
		return PreferenceResponse{}, err
	}
	effectiveAt, err := b.repository.DenyPublicInstallation(ctx, store.PublicTelemetryDenial{
		Subject: store.Subject{Kind: "installation", ID: authenticated.alias.SubjectID}, SubjectKey: authenticated.alias.OpaqueKey,
		ProductID: authenticated.productID, RecordedAt: input.RecordedAt.UTC(), SuppressionID: suppressionID,
		Consent: store.Consent{
			ID: consentID, Subject: store.Subject{Kind: "installation", ID: authenticated.alias.SubjectID},
			ProductID: authenticated.productID, ConsentType: "telemetry", PolicyVersion: input.PolicyVersion,
			Status: "withdrawn", RecordedAt: input.RecordedAt.UTC(),
		},
	})
	if err != nil {
		return PreferenceResponse{}, err
	}
	return PreferenceResponse{
		InstallationKey: authenticated.alias.OpaqueKey, Product: authenticated.productID,
		Preference: input.Preference, PolicyVersion: authenticated.policyVersion, RecordedAt: effectiveAt,
	}, nil
}

type authenticatedInstallation struct {
	productID     string
	audience      string
	alias         store.ResolvedAlias
	policyVersion string
}

func (b *Broker) authenticate(ctx context.Context, encoded string) (authenticatedInstallation, error) {
	claims, err := b.signer.VerifyRefresh(encoded)
	if err != nil {
		return authenticatedInstallation{}, ErrInvalidCredential
	}
	product, ok := b.config.Products[claims.Product]
	if !ok || !pairwise.Valid(claims.Subject) {
		return authenticatedInstallation{}, ErrInvalidCredential
	}
	alias, err := b.repository.ResolveSubjectAlias(ctx, claims.Subject, claims.Product, product.Audience)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && alias.SubjectType != "installation") {
		return authenticatedInstallation{}, ErrInvalidCredential
	}
	if err != nil {
		return authenticatedInstallation{}, err
	}
	if err := b.repository.ResolveTokenSubject(ctx, claims.Product, alias.SubjectType, alias.SubjectID); errors.Is(err, domain.ErrNotFound) {
		return authenticatedInstallation{}, ErrInvalidCredential
	} else if err != nil {
		return authenticatedInstallation{}, err
	}
	return authenticatedInstallation{productID: claims.Product, audience: product.Audience, alias: alias, policyVersion: claims.PolicyVersion}, nil
}

func (b *Broker) issueAccess(productID, audience, installationKey string) (AccessToken, error) {
	encoded, expiresAt, err := b.signer.SignClaims(token.SignInput{
		Audience: audience, Product: productID, Subject: installationKey,
		SubjectType: "installation", Scopes: []string{"telemetry:write"},
	})
	if err != nil {
		return AccessToken{}, err
	}
	return AccessToken{AccessToken: encoded, TokenType: "Bearer", ExpiresAt: expiresAt}, nil
}

func (b *Broker) validRegistration(preference, policyVersion string, recordedAt time.Time) bool {
	now := b.now().UTC()
	return (preference == "allowed" || preference == "denied") && policyVersion == b.config.PolicyVersion &&
		!recordedAt.IsZero() && !recordedAt.Before(now.Add(-24*time.Hour)) && !recordedAt.After(now.Add(5*time.Minute))
}

func (b *Broker) validDenial(policyVersion string, recordedAt time.Time) bool {
	now := b.now().UTC()
	return len(policyVersion) >= 1 && len(policyVersion) <= 100 && !recordedAt.IsZero() &&
		!recordedAt.Before(now.Add(-24*time.Hour)) && !recordedAt.After(now.Add(5*time.Minute))
}

func (b *Broker) registrationID(input RegisterInput, audience string) string {
	fingerprint := strings.Join([]string{
		strings.ToLower(input.RequestID), input.ProductID, input.Platform, input.Preference, input.PolicyVersion,
		input.RecordedAt.UTC().Format(time.RFC3339Nano),
	}, "\x00")
	digest := []byte(b.pairwise.Subject(input.ProductID, audience, "public-registration", fingerprint)[:32])
	digest[12] = '4'
	digest[16] = '8'
	return fmt.Sprintf("%s-%s-%s-%s-%s", digest[0:8], digest[8:12], digest[12:16], digest[16:20], digest[20:32])
}

func validPlatform(platform string) bool {
	switch platform {
	case "windows", "macos", "linux", "web", "android", "ios":
		return true
	default:
		return false
	}
}
