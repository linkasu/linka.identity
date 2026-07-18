package token

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestTokenIsProductScopedAndContainsNoEmail(t *testing.T) {
	signer, err := NewSigner(bytes.Repeat([]byte{7}, 32), "test-key", "identity.test", time.Minute, 5*time.Minute)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	encoded, expiresAt, err := signer.Sign("plays", "installation", "11111111-1111-4111-8111-111111111111", 2*time.Minute)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if strings.Contains(encoded, "email") || expiresAt.IsZero() {
		t.Fatal("token must contain no email and must expire")
	}
	claims, err := signer.VerifyForTest(encoded)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Audience != "plays" || claims.Product != "plays" || claims.SubjectType != "installation" {
		t.Fatalf("unexpected claims: %#v", claims)
	}
}

func TestJWKSContainsActiveAndRetiringKeys(t *testing.T) {
	signer, err := NewKeyring(map[string][]byte{
		"old": bytes.Repeat([]byte{1}, 32), "new": bytes.Repeat([]byte{2}, 32),
	}, "new", "identity.test", time.Minute, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	keys := signer.JWKS()["keys"].([]map[string]string)
	if len(keys) != 2 {
		t.Fatalf("JWKS keys = %d", len(keys))
	}
}

func TestTokenRejectsLongTTL(t *testing.T) {
	signer, _ := NewSigner(bytes.Repeat([]byte{7}, 32), "test-key", "identity.test", time.Minute, 5*time.Minute)
	if _, _, err := signer.Sign("plays", "account", "subject", 6*time.Minute); err == nil {
		t.Fatal("expected TTL rejection")
	}
}
