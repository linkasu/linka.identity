package token

import (
	"errors"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/ids"
	"github.com/linka-cloud/linka.identity/internal/pairwise"
)

const (
	AccountAudience = "linka-identity-public-account"
	AccountScope    = "account:access"
	maxAccountTTL   = 15 * time.Minute
)

type AccountAccessInput struct {
	Product   string
	Subject   string
	SessionID string
	TTL       time.Duration
}

type AccountAccessClaims struct {
	Issuer      string   `json:"iss"`
	Subject     string   `json:"sub"`
	Audience    string   `json:"aud"`
	Product     string   `json:"product"`
	SubjectType string   `json:"subject_type"`
	Scopes      []string `json:"scope"`
	SessionID   string   `json:"sid"`
	IssuedAt    int64    `json:"iat"`
	ExpiresAt   int64    `json:"exp"`
	TokenID     string   `json:"jti"`
}

func (s *Signer) SignAccountAccess(input AccountAccessInput) (string, time.Time, error) {
	if input.TTL == 0 {
		input.TTL = s.defaultTTL
	}
	if !domain.ValidProductID(input.Product) || !pairwise.Valid(input.Subject) || !domain.ValidUUID(input.SessionID) || input.TTL <= 0 || input.TTL > s.maxTTL || input.TTL > maxAccountTTL {
		return "", time.Time{}, errors.New("invalid account access input")
	}
	now := s.now().UTC()
	expires := now.Add(input.TTL)
	id, err := ids.NewUUID()
	if err != nil {
		return "", time.Time{}, err
	}
	claims := AccountAccessClaims{Issuer: s.issuer, Subject: input.Subject, Audience: AccountAudience, Product: input.Product, SubjectType: "account", Scopes: []string{AccountScope}, SessionID: input.SessionID, IssuedAt: now.Unix(), ExpiresAt: expires.Unix(), TokenID: id}
	if !s.validAccountAccess(claims) {
		return "", time.Time{}, errors.New("invalid account access claims")
	}
	encoded, err := s.signPayload(claims)
	return encoded, expires, err
}

// VerifyAccountAccess checks the signed credential, not authoritative active-session
// or account state. Every online operation must also check those records.
func (s *Signer) VerifyAccountAccess(encoded string) (AccountAccessClaims, error) {
	var claims AccountAccessClaims
	if err := s.verifyPayload(encoded, &claims); err != nil {
		return AccountAccessClaims{}, err
	}
	if !s.validAccountAccess(claims) {
		return AccountAccessClaims{}, errors.New("invalid account access claims")
	}
	return claims, nil
}

func (s *Signer) validAccountAccess(c AccountAccessClaims) bool {
	now := s.now().UTC()
	return c.Issuer == s.issuer && c.Audience == AccountAudience && c.SubjectType == "account" &&
		domain.ValidProductID(c.Product) && pairwise.Valid(c.Subject) && domain.ValidUUID(c.SessionID) && domain.ValidUUID(c.TokenID) &&
		len(c.Scopes) == 1 && c.Scopes[0] == AccountScope && c.IssuedAt > 0 && c.IssuedAt <= now.Add(5*time.Minute).Unix() &&
		c.ExpiresAt > now.Unix() && c.ExpiresAt > c.IssuedAt &&
		c.ExpiresAt-c.IssuedAt <= int64(maxAccountTTL/time.Second) && c.ExpiresAt-c.IssuedAt <= int64(s.maxTTL/time.Second)
}
