package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/linka-cloud/linka.identity/internal/ids"
)

const (
	RefreshAudience = "linka-identity-public-installation"
	RefreshScope    = "installation:refresh"
	maxRefreshTTL   = 365 * 24 * time.Hour
)

type Signer struct {
	privateKey ed25519.PrivateKey
	publicKeys map[string]ed25519.PublicKey
	keyID      string
	issuer     string
	defaultTTL time.Duration
	maxTTL     time.Duration
	now        func() time.Time
}

type Claims struct {
	Issuer        string   `json:"iss"`
	Subject       string   `json:"sub"`
	Audience      string   `json:"aud"`
	Product       string   `json:"product"`
	SubjectType   string   `json:"subject_type"`
	Scopes        []string `json:"scope"`
	PersonKey     *string  `json:"person_key,omitempty"`
	OrgKey        *string  `json:"org_key,omitempty"`
	PolicyVersion string   `json:"policy_version,omitempty"`
	IssuedAt      int64    `json:"iat"`
	ExpiresAt     int64    `json:"exp"`
	TokenID       string   `json:"jti"`
}

type SignInput struct {
	Audience      string
	Product       string
	Subject       string
	SubjectType   string
	Scopes        []string
	PersonKey     *string
	OrgKey        *string
	PolicyVersion string
	TTL           time.Duration
}

func NewSigner(seed []byte, keyID, issuer string, defaultTTL, maxTTL time.Duration) (*Signer, error) {
	return NewKeyring(map[string][]byte{keyID: seed}, keyID, issuer, defaultTTL, maxTTL)
}

func NewKeyring(seeds map[string][]byte, activeKeyID, issuer string, defaultTTL, maxTTL time.Duration) (*Signer, error) {
	if len(seeds) == 0 || activeKeyID == "" || issuer == "" {
		return nil, errors.New("invalid signing configuration")
	}
	if defaultTTL <= 0 || maxTTL <= 0 || defaultTTL > maxTTL {
		return nil, errors.New("invalid signing TTL configuration")
	}
	publicKeys := make(map[string]ed25519.PublicKey, len(seeds))
	var privateKey ed25519.PrivateKey
	for keyID, seed := range seeds {
		if keyID == "" || len(seed) != ed25519.SeedSize {
			return nil, errors.New("invalid signing keyring")
		}
		candidate := ed25519.NewKeyFromSeed(seed)
		publicKeys[keyID] = candidate.Public().(ed25519.PublicKey)
		if keyID == activeKeyID {
			privateKey = candidate
		}
	}
	if privateKey == nil {
		return nil, errors.New("active signing key is absent from keyring")
	}
	return &Signer{
		privateKey: privateKey,
		publicKeys: publicKeys,
		keyID:      activeKeyID,
		issuer:     issuer,
		defaultTTL: defaultTTL,
		maxTTL:     maxTTL,
		now:        time.Now,
	}, nil
}

func (s *Signer) Sign(productID, subjectType, subjectID string, ttl time.Duration) (string, time.Time, error) {
	return s.SignClaims(SignInput{
		Audience: productID, Product: productID, Subject: subjectID, SubjectType: subjectType, Scopes: []string{"product:access"}, TTL: ttl,
	})
}

func (s *Signer) SignClaims(input SignInput) (string, time.Time, error) {
	if input.Audience == "" || input.Product == "" || input.Subject == "" || len(input.Scopes) == 0 ||
		(input.SubjectType != "account" && input.SubjectType != "installation" && input.SubjectType != "service") {
		return "", time.Time{}, errors.New("invalid token subject")
	}
	if input.TTL == 0 {
		input.TTL = s.defaultTTL
	}
	if input.TTL <= 0 || input.TTL > s.maxTTL {
		return "", time.Time{}, errors.New("requested token TTL is outside configured bounds")
	}
	return s.signClaims(input)
}

func (s *Signer) SignRefresh(productID, subjectKey, policyVersion string, ttl time.Duration) (string, time.Time, error) {
	if policyVersion == "" || ttl <= 0 || ttl > maxRefreshTTL {
		return "", time.Time{}, errors.New("refresh token TTL is outside configured bounds")
	}
	return s.signClaims(SignInput{
		Audience: RefreshAudience, Product: productID, Subject: subjectKey,
		SubjectType: "installation", Scopes: []string{RefreshScope}, PolicyVersion: policyVersion, TTL: ttl,
	})
}

func (s *Signer) signClaims(input SignInput) (string, time.Time, error) {
	now := s.now().UTC()
	expiresAt := now.Add(input.TTL)
	tokenID, err := ids.NewUUID()
	if err != nil {
		return "", time.Time{}, err
	}
	header := map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": s.keyID}
	claims := Claims{
		Issuer:        s.issuer,
		Subject:       input.Subject,
		Audience:      input.Audience,
		Product:       input.Product,
		SubjectType:   input.SubjectType,
		Scopes:        append([]string(nil), input.Scopes...),
		PersonKey:     input.PersonKey,
		OrgKey:        input.OrgKey,
		PolicyVersion: input.PolicyVersion,
		IssuedAt:      now.Unix(),
		ExpiresAt:     expiresAt.Unix(),
		TokenID:       tokenID,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("encode token header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("encode token claims: %w", err)
	}
	unsigned := rawBase64(headerJSON) + "." + rawBase64(claimsJSON)
	signature := ed25519.Sign(s.privateKey, []byte(unsigned))
	return unsigned + "." + rawBase64(signature), expiresAt, nil
}

func (s *Signer) JWKS() map[string]any {
	keys := make([]map[string]string, 0, len(s.publicKeys))
	for keyID, publicKey := range s.publicKeys {
		state := "retiring"
		if keyID == s.keyID {
			state = "active"
		}
		keys = append(keys, map[string]string{
			"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": keyID, "x": rawBase64(publicKey), "x-linka-state": state,
		})
	}
	return map[string]any{"keys": keys}
}

func (s *Signer) VerifyForTest(encoded string) (Claims, error) {
	return s.verify(encoded)
}

func (s *Signer) VerifyRefresh(encoded string) (Claims, error) {
	claims, err := s.verify(encoded)
	if err != nil {
		return Claims{}, err
	}
	now := s.now().UTC()
	if claims.Issuer != s.issuer || claims.Audience != RefreshAudience || claims.SubjectType != "installation" ||
		claims.Product == "" || claims.Subject == "" || len(claims.Scopes) != 1 || claims.Scopes[0] != RefreshScope ||
		claims.PolicyVersion == "" || len(claims.PolicyVersion) > 100 ||
		claims.IssuedAt > now.Add(5*time.Minute).Unix() || claims.ExpiresAt <= now.Unix() ||
		claims.ExpiresAt <= claims.IssuedAt || time.Duration(claims.ExpiresAt-claims.IssuedAt)*time.Second > maxRefreshTTL {
		return Claims{}, errors.New("invalid refresh token claims")
	}
	return claims, nil
}

func (s *Signer) verify(encoded string) (Claims, error) {
	parts := strings.Split(encoded, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("invalid token structure")
	}
	headerPayload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, errors.New("invalid token header")
	}
	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
		KeyID     string `json:"kid"`
	}
	headerDecoder := json.NewDecoder(strings.NewReader(string(headerPayload)))
	headerDecoder.DisallowUnknownFields()
	if err := headerDecoder.Decode(&header); err != nil || header.Algorithm != "EdDSA" || header.Type != "JWT" {
		return Claims{}, errors.New("invalid token header")
	}
	publicKey, ok := s.publicKeys[header.KeyID]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ok || !ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return Claims{}, errors.New("invalid token signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, errors.New("invalid token payload")
	}
	var claims Claims
	claimsDecoder := json.NewDecoder(strings.NewReader(string(payload)))
	claimsDecoder.DisallowUnknownFields()
	if err := claimsDecoder.Decode(&claims); err != nil {
		return Claims{}, errors.New("invalid token claims")
	}
	return claims, nil
}

func rawBase64(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}
