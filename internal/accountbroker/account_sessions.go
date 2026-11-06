package accountbroker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/ids"
	"github.com/linka-cloud/linka.identity/internal/installationbroker"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/linka-cloud/linka.identity/internal/token"
)

var ErrAccountCredential = errors.New("invalid public account credential")

func (b *Broker) Verify(ctx context.Context, credential, id string, input VerifyInput) (Registration, error) {
	id = strings.ToLower(id)
	if !domain.ValidUUID(id) || input.valid() != nil {
		return Registration{}, domain.ErrInvalid
	}
	installation, err := b.authenticateInstallation(ctx, credential, input.ProductID)
	if err != nil {
		return Registration{}, err
	}
	c, err := b.repository.PublicEmailChallenge(ctx, id)
	if err != nil {
		return Registration{}, err
	}
	nonce := b.digest("nonce", input.ProductID, installation.InstallationID, input.ClientNonce)
	if c.ProductID != input.ProductID || c.InstallationID != installation.InstallationID || c.Purpose != RegistrationPurpose || c.OTPKeyID != b.otpKeyID || subtle.ConstantTimeCompare(c.NonceHash, nonce) != 1 {
		return Registration{}, domain.ErrNotFound
	}
	proof := b.digest("code", input.ProductID, installation.InstallationID, id, RegistrationPurpose, hex.EncodeToString(nonce), hex.EncodeToString(c.EmailBlindIndex), input.Code)
	completion := store.PublicEmailCompletion{ChallengeID: id, ProductID: input.ProductID, InstallationID: installation.InstallationID, OTPKeyID: b.otpKeyID, NonceHash: nonce, CodeHash: proof}
	if subtle.ConstantTimeCompare(c.CodeHash, proof) != 1 || !b.now().UTC().Before(c.ExpiresAt) || (c.State != domain.PublicChallengeDelivering && c.State != domain.PublicChallengeDelivered && c.State != domain.PublicChallengeDeliveryUncertain) {
		_, err := b.repository.CompletePublicEmailChallenge(ctx, completion)
		if err == nil {
			err = domain.ErrNotFound
		}
		return Registration{}, err
	}
	verification, err := b.repository.EmailVerification(ctx, id)
	if err != nil {
		return Registration{}, err
	}
	now := b.now().UTC().Truncate(time.Microsecond)
	completion.Identity, completion.Indexes, err = b.identity.PreparePublicIdentity(ctx, verification, now)
	if err != nil {
		return Registration{}, err
	}
	completion.SessionID, err = ids.NewUUID()
	if err != nil {
		return Registration{}, errors.New("account session unavailable")
	}
	refresh, refreshHash, err := newRefreshCapability()
	if err != nil {
		return Registration{}, err
	}
	completion.RefreshHash, completion.RefreshExpiresAt = refreshHash, now.Add(90*24*time.Hour)
	registered, err := b.repository.CompletePublicEmailChallenge(ctx, completion)
	if err != nil {
		return Registration{}, err
	}
	if registered.Session.ProductID != input.ProductID || registered.Session.InstallationID != installation.InstallationID {
		return Registration{}, errors.New("invalid committed registration context")
	}
	return b.registration(registered.Session, registered.Account, refresh)
}

func (b *Broker) Refresh(ctx context.Context, credential string) (Registration, error) {
	oldHash, err := refreshCapabilityHash(credential)
	if err != nil {
		return Registration{}, err
	}
	fresh, freshHash, err := newRefreshCapability()
	if err != nil {
		return Registration{}, err
	}
	session, profile, err := b.repository.RotatePublicAccountRefresh(ctx, oldHash, freshHash)
	if errors.Is(err, domain.ErrNotFound) {
		return Registration{}, ErrAccountCredential
	}
	if err != nil {
		return Registration{}, err
	}
	return b.registration(session, profile, fresh)
}

func (b *Broker) Revoke(ctx context.Context, credential string) error {
	claims, err := b.signer.VerifyAccountAccess(credential)
	if err != nil || b.products[claims.Product] == "" {
		return ErrAccountCredential
	}
	// The signed SID selects only its own device family, never a body-supplied ID.
	return b.repository.RevokePublicAccountSession(ctx, claims.SessionID, claims.Product)
}

func (b *Broker) UpdateProfile(ctx context.Context, credential string, input ProfileInput) (Profile, error) {
	input, err := input.normalized()
	if err != nil {
		return Profile{}, err
	}
	claims, err := b.signer.VerifyAccountAccess(credential)
	if err != nil || b.products[claims.Product] == "" {
		return Profile{}, ErrAccountCredential
	}
	session, _, err := b.repository.AuthorizedPublicAccountSession(ctx, claims.SessionID, claims.Product)
	if errors.Is(err, domain.ErrNotFound) {
		return Profile{}, ErrAccountCredential
	}
	if err != nil {
		return Profile{}, err
	}
	expectedKey := b.pairwise.Subject(claims.Product, token.AccountAudience, "account", session.AccountID)
	if subtle.ConstantTimeCompare([]byte(expectedKey), []byte(claims.Subject)) != 1 {
		return Profile{}, ErrAccountCredential
	}
	profile, err := b.repository.UpdatePublicAccountProfile(ctx, session.ID, session.ProductID, input.Version, input.HolderRole, input.Country, input.Region)
	if err != nil {
		return Profile{}, err
	}
	return publicProfile(profile, expectedKey), nil
}

func (b *Broker) registration(session store.AccountSession, profile store.ProductAccount, refresh string) (Registration, error) {
	if b.products[session.ProductID] == "" || !domain.ValidUUID(session.AccountID) || !domain.ValidUUID(session.InstallationID) || profile.AccountID != session.AccountID || profile.ProductID != session.ProductID || profile.Status != "active" || !domain.ValidHolderRole(profile.HolderRole) {
		return Registration{}, errors.New("invalid committed account session")
	}
	accountKey := b.pairwise.Subject(session.ProductID, token.AccountAudience, "account", session.AccountID)
	installationKey := b.pairwise.Subject(session.ProductID, b.products[session.ProductID], "installation", session.InstallationID)
	access, expires, err := b.signer.SignAccountAccess(token.AccountAccessInput{Product: session.ProductID, Subject: accountKey, SessionID: session.ID, TTL: 5 * time.Minute})
	if err != nil {
		return Registration{}, err
	}
	receipt, err := b.signer.SignRegistrationReceipt(token.RegistrationReceiptInput{Product: session.ProductID, AccountKey: accountKey, InstallationKey: installationKey, HolderRole: profile.HolderRole, PolicyVersion: b.policy, VerifiedAt: profile.VerifiedAt})
	if err != nil {
		return Registration{}, err
	}
	return Registration{ContractVersion: ContractVersion, Product: session.ProductID, AccountKey: accountKey, InstallationKey: installationKey,
		AccountProfile: publicProfile(profile, accountKey), AccountToken: installationbroker.AccessToken{AccessToken: access, TokenType: "Bearer", ExpiresAt: expires},
		RefreshToken: refresh, RefreshExpiresAt: session.ExpiresAt, RegistrationReceipt: receipt, MetricsToken: nil}, nil
}

func publicProfile(profile store.ProductAccount, key string) Profile {
	return Profile{Product: profile.ProductID, AccountKey: key, Version: profile.Version, HolderRole: profile.HolderRole, Country: profile.Country, Region: profile.Region, UpdatedAt: profile.UpdatedAt}
}

func newRefreshCapability() (string, []byte, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", nil, errors.New("account refresh capability unavailable")
	}
	raw := base64.RawURLEncoding.EncodeToString(value)
	hash, err := refreshCapabilityHash(raw)
	return raw, hash, err
}

func refreshCapabilityHash(raw string) ([]byte, error) {
	if !validClientNonce(raw) {
		return nil, ErrAccountCredential
	}
	digest := sha256.Sum256([]byte("linka-account-refresh-v1\x00" + raw))
	return digest[:], nil
}
