package token

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

func accountTestSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := NewSigner(bytes.Repeat([]byte{7}, 32), "test", "identity.test", time.Minute, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Unix(1800000000, 0) }
	return s
}

func accountTestInput() AccountAccessInput {
	return AccountAccessInput{Product: "linka-plays", Subject: strings.Repeat("a", 64), SessionID: "11111111-1111-4111-8111-111111111111"}
}

func TestAccountAccessRoundTrip(t *testing.T) {
	s := accountTestSigner(t)
	encoded, expires, err := s.SignAccountAccess(accountTestInput())
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.VerifyAccountAccess(encoded)
	if err != nil || c.Audience != AccountAudience || c.SessionID != accountTestInput().SessionID || c.ExpiresAt != expires.Unix() {
		t.Fatalf("claims=%#v err=%v", c, err)
	}
	if _, err := s.VerifyRefresh(encoded); err == nil {
		t.Fatal("account accepted as refresh")
	}
}

func TestAccountRejectsOtherPurposes(t *testing.T) {
	s := accountTestSigner(t)
	metrics, _, _ := s.SignClaims(SignInput{Audience: "metrics", Product: "linka-plays", Subject: strings.Repeat("a", 64), SubjectType: "installation", Scopes: []string{"telemetry:write"}})
	refresh, _, _ := s.SignRefresh("linka-plays", strings.Repeat("a", 64), "v1", time.Hour)
	for _, encoded := range []string{metrics, refresh} {
		if _, err := s.VerifyAccountAccess(encoded); err == nil {
			t.Fatal("other purpose accepted as account")
		}
		if _, err := s.VerifyRegistrationReceipt(encoded); err == nil {
			t.Fatal("other purpose accepted as receipt")
		}
	}
}

func TestAccountAccessInputValidation(t *testing.T) {
	for name, mutate := range map[string]func(*AccountAccessInput){
		"product":           func(i *AccountAccessInput) { i.Product = "BAD" },
		"subject uuid":      func(i *AccountAccessInput) { i.Subject = i.SessionID },
		"subject uppercase": func(i *AccountAccessInput) { i.Subject = strings.Repeat("A", 64) },
		"session":           func(i *AccountAccessInput) { i.SessionID = "session" },
		"negative ttl":      func(i *AccountAccessInput) { i.TTL = -time.Second },
		"overlong ttl":      func(i *AccountAccessInput) { i.TTL = 15*time.Minute + time.Nanosecond },
		"subsecond ttl":     func(i *AccountAccessInput) { i.TTL = time.Nanosecond },
	} {
		t.Run(name, func(t *testing.T) {
			i := accountTestInput()
			mutate(&i)
			if _, _, err := accountTestSigner(t).SignAccountAccess(i); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
	s := accountTestSigner(t)
	i := accountTestInput()
	i.TTL = 15 * time.Minute
	if _, _, err := s.SignAccountAccess(i); err != nil {
		t.Fatal(err)
	}
	s.maxTTL = time.Minute
	if _, _, err := s.SignAccountAccess(i); err == nil {
		t.Fatal("configured limit ignored")
	}
	s.defaultTTL = 16 * time.Minute
	s.maxTTL = time.Hour
	i.TTL = 0
	if _, _, err := s.SignAccountAccess(i); err == nil {
		t.Fatal("invalid default TTL accepted")
	}
}

func TestAccountAccessClaimValidation(t *testing.T) {
	s := accountTestSigner(t)
	encoded, _, _ := s.SignAccountAccess(accountTestInput())
	valid, err := s.VerifyAccountAccess(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*AccountAccessClaims){
		"issuer":        func(c *AccountAccessClaims) { c.Issuer = "other" },
		"audience":      func(c *AccountAccessClaims) { c.Audience = RefreshAudience },
		"type":          func(c *AccountAccessClaims) { c.SubjectType = "installation" },
		"product":       func(c *AccountAccessClaims) { c.Product = "bad product" },
		"subject":       func(c *AccountAccessClaims) { c.Subject = c.SessionID },
		"session":       func(c *AccountAccessClaims) { c.SessionID = "" },
		"jti":           func(c *AccountAccessClaims) { c.TokenID = "invalid" },
		"scope":         func(c *AccountAccessClaims) { c.Scopes = []string{RefreshScope} },
		"extra scope":   func(c *AccountAccessClaims) { c.Scopes = []string{AccountScope, "telemetry:write"} },
		"missing scope": func(c *AccountAccessClaims) { c.Scopes = nil },
		"expired":       func(c *AccountAccessClaims) { c.ExpiresAt = s.now().Unix() },
		"future": func(c *AccountAccessClaims) {
			c.IssuedAt = s.now().Add(5*time.Minute + time.Second).Unix()
			c.ExpiresAt = c.IssuedAt + 60
		},
		"zero iat":          func(c *AccountAccessClaims) { c.IssuedAt = 0 },
		"negative iat":      func(c *AccountAccessClaims) { c.IssuedAt = math.MinInt64 },
		"overflow":          func(c *AccountAccessClaims) { c.ExpiresAt = math.MaxInt64 },
		"duration overflow": func(c *AccountAccessClaims) { c.ExpiresAt = c.IssuedAt + (1<<63-1)/int64(time.Second) + 1 },
		"negative exp":      func(c *AccountAccessClaims) { c.ExpiresAt = math.MinInt64 },
		"equal timestamps":  func(c *AccountAccessClaims) { c.ExpiresAt = c.IssuedAt },
		"long ttl":          func(c *AccountAccessClaims) { c.ExpiresAt = c.IssuedAt + 901 },
	} {
		t.Run(name, func(t *testing.T) {
			c := valid
			mutate(&c)
			encoded, err := s.signPayload(c)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.VerifyAccountAccess(encoded); err == nil {
				t.Fatal("invalid claims accepted")
			}
		})
	}
	c := valid
	c.IssuedAt = s.now().Add(5 * time.Minute).Unix()
	c.ExpiresAt = c.IssuedAt + 60
	encoded, _ = s.signPayload(c)
	if _, err := s.VerifyAccountAccess(encoded); err != nil {
		t.Fatal("allowed clock skew rejected", err)
	}
	s.maxTTL = 30 * time.Second
	encoded, _ = s.signPayload(valid)
	if _, err := s.VerifyAccountAccess(encoded); err == nil {
		t.Fatal("configured TTL limit ignored")
	}
}

func signRawToken(s *Signer, header, payload string) string {
	unsigned := rawBase64([]byte(header)) + "." + rawBase64([]byte(payload))
	return unsigned + "." + rawBase64(ed25519.Sign(s.privateKey, []byte(unsigned)))
}

func TestStrictTokenCodec(t *testing.T) {
	s := accountTestSigner(t)
	account, _, _ := s.SignAccountAccess(accountTestInput())
	receipt, _ := s.SignRegistrationReceipt(receiptTestInput(s))
	for name, verify := range map[string]func(string) error{
		"account": func(token string) error { _, err := s.VerifyAccountAccess(token); return err },
		"receipt": func(token string) error { _, err := s.VerifyRegistrationReceipt(token); return err },
	} {
		t.Run(name, func(t *testing.T) {
			encoded := account
			if name == "receipt" {
				encoded = receipt
			}
			parts := strings.Split(encoded, ".")
			headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
			header := string(headerBytes)
			payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
			payload := string(payloadBytes)
			for attack, h := range map[string]string{
				"alg none":    strings.Replace(header, "EdDSA", "none", 1),
				"alg other":   strings.Replace(header, "EdDSA", "HS256", 1),
				"typ":         strings.Replace(header, "JWT", "JWS", 1),
				"unknown kid": strings.Replace(header, "test", "unknown", 1),
				"jwk":         strings.TrimSuffix(header, "}") + `,"jwk":{}}`,
				"jku":         strings.TrimSuffix(header, "}") + `,"jku":"https://attacker.invalid/keys"}`,
				"duplicate":   strings.TrimSuffix(header, "}") + `,"alg":"EdDSA"}`,
				"case alias":  strings.Replace(header, "alg", "ALG", 1),
				"trailing":    header + ` {}`,
				"malformed":   `{`,
			} {
				t.Run(attack, func(t *testing.T) {
					if verify(signRawToken(s, h, payload)) == nil {
						t.Fatal("bad header accepted")
					}
				})
			}
			for attack, p := range map[string]string{
				"email":        strings.TrimSuffix(payload, "}") + `,"email":"private@example.org"}`,
				"person":       strings.TrimSuffix(payload, "}") + `,"person_key":"private"}`,
				"organization": strings.TrimSuffix(payload, "}") + `,"org_key":"private"}`,
				"duplicate":    strings.TrimSuffix(payload, "}") + `,"iss":"identity.test"}`,
				"case alias":   strings.Replace(payload, `"iss"`, `"ISS"`, 1),
				"trailing":     payload + ` {}`,
				"null":         `null`,
				"malformed":    `{`,
			} {
				t.Run(attack, func(t *testing.T) {
					if verify(signRawToken(s, header, p)) == nil {
						t.Fatal("bad payload accepted")
					}
				})
			}
			for _, bad := range []string{"", "a.b", "a.b.c.d", strings.Repeat("x", 8193), "!." + parts[1] + "." + parts[2], parts[0] + ".!." + parts[2], parts[0] + "." + parts[1] + ".!", signRawToken(s, header, payload) + "x", signRawToken(s, header, strings.Repeat("x", 8193))} {
				if verify(bad) == nil {
					t.Fatal("malformed token accepted")
				}
			}
			tampered := strings.Replace(payload, "linka-plays", "linka-other", 1)
			if verify(parts[0]+"."+rawBase64([]byte(tampered))+"."+parts[2]) == nil {
				t.Fatal("tampered payload accepted")
			}
		})
	}
}

func TestTokenKeyRotationAndLegacyWireFormat(t *testing.T) {
	seeds := map[string][]byte{"old": bytes.Repeat([]byte{1}, 32), "new": bytes.Repeat([]byte{2}, 32)}
	old, _ := NewKeyring(seeds, "old", "identity.test", time.Minute, 15*time.Minute)
	current, _ := NewKeyring(seeds, "new", "identity.test", time.Minute, 15*time.Minute)
	for _, issuer := range []*Signer{old, current} {
		issuer.now = accountTestSigner(t).now
		account, _, err := issuer.SignAccountAccess(accountTestInput())
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := issuer.SignRegistrationReceipt(receiptTestInput(issuer))
		if err != nil {
			t.Fatal(err)
		}
		refresh, _, err := issuer.SignRefresh("linka-plays", strings.Repeat("a", 64), "v1", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		for _, verifier := range []*Signer{old, current} {
			verifier.now = issuer.now
			if _, err := verifier.VerifyAccountAccess(account); err != nil {
				t.Fatal(err)
			}
			if _, err := verifier.VerifyRegistrationReceipt(receipt); err != nil {
				t.Fatal(err)
			}
			if _, err := verifier.VerifyRefresh(refresh); err != nil {
				t.Fatal(err)
			}
		}
		for _, encoded := range []string{refresh} {
			parts := strings.Split(encoded, ".")
			payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
			var c Claims
			if err := json.Unmarshal(payload, &c); err != nil {
				t.Fatal(err)
			}
			header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": issuer.keyID})
			claims, _ := json.Marshal(c)
			if expected := signRawToken(issuer, string(header), string(claims)); expected != encoded {
				t.Fatal("legacy wire format changed")
			}
			if bytes.Contains(payload, []byte(`"sid"`)) || bytes.Contains(payload, []byte(`"contract_version"`)) {
				t.Fatal("new claims leaked into legacy token")
			}
		}
	}
}
