package token

import (
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/ids"
	"github.com/linka-cloud/linka.identity/internal/pairwise"
)

const ReceiptAudience = "linka-product-registration"

type RegistrationReceiptInput struct {
	Product         string
	AccountKey      string
	InstallationKey string
	HolderRole      string
	PolicyVersion   string
	VerifiedAt      time.Time
}

type RegistrationReceiptClaims struct {
	ContractVersion int    `json:"contract_version"`
	Issuer          string `json:"iss"`
	Subject         string `json:"sub"`
	Audience        string `json:"aud"`
	Product         string `json:"product"`
	SubjectType     string `json:"subject_type"`
	InstallationKey string `json:"installation_key"`
	HolderRole      string `json:"holder_role"`
	PolicyVersion   string `json:"policy_version"`
	VerifiedAt      int64  `json:"verified_at"`
	IssuedAt        int64  `json:"iat"`
	TokenID         string `json:"jti"`
}

func (s *Signer) SignRegistrationReceipt(input RegistrationReceiptInput) (string, error) {
	now := s.now().UTC()
	if input.VerifiedAt.IsZero() || input.VerifiedAt.After(now) {
		return "", errors.New("invalid registration receipt input")
	}
	id, err := ids.NewUUID()
	if err != nil {
		return "", err
	}
	claims := RegistrationReceiptClaims{ContractVersion: 1, Issuer: s.issuer, Subject: input.AccountKey, Audience: ReceiptAudience, Product: input.Product, SubjectType: "registration_receipt", InstallationKey: input.InstallationKey, HolderRole: input.HolderRole, PolicyVersion: strings.TrimSpace(input.PolicyVersion), VerifiedAt: input.VerifiedAt.Unix(), IssuedAt: now.Unix(), TokenID: id}
	if !s.validRegistrationReceipt(claims) {
		return "", errors.New("invalid registration receipt input")
	}
	return s.signPayload(claims)
}

// VerifyRegistrationReceipt validates nonexpiring local evidence, never online
// authorization. Clients must cache the trusted public key with the receipt and
// match Product and InstallationKey to their configured context. No local-clock
// or remote-expiry check applies; payloads cannot supply verification keys.
func (s *Signer) VerifyRegistrationReceipt(encoded string) (RegistrationReceiptClaims, error) {
	var claims RegistrationReceiptClaims
	if err := s.verifyPayload(encoded, &claims); err != nil {
		return RegistrationReceiptClaims{}, err
	}
	if !s.validRegistrationReceipt(claims) {
		return RegistrationReceiptClaims{}, errors.New("invalid registration receipt claims")
	}
	return claims, nil
}

func (s *Signer) validRegistrationReceipt(c RegistrationReceiptClaims) bool {
	return c.ContractVersion == 1 && c.Issuer == s.issuer && c.Audience == ReceiptAudience && c.SubjectType == "registration_receipt" &&
		domain.ValidProductID(c.Product) && pairwise.Valid(c.Subject) && pairwise.Valid(c.InstallationKey) && domain.ValidUUID(c.TokenID) &&
		(c.HolderRole == "self" || c.HolderRole == "representative") && validReceiptPolicy(c.PolicyVersion) &&
		c.VerifiedAt > 0 && c.IssuedAt > 0 && c.VerifiedAt <= c.IssuedAt
}

func validReceiptPolicy(value string) bool {
	return value == strings.TrimSpace(value) && len(value) >= 1 && len(value) <= 100 && utf8.ValidString(value) &&
		!strings.Contains(value, "@") && strings.IndexFunc(value, unicode.IsControl) == -1
}
