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

func TestRefreshTokenUsesSeparateAudienceAndExpires(t *testing.T) {
	signer, _ := NewSigner(bytes.Repeat([]byte{7}, 32), "test-key", "identity.test", time.Minute, 5*time.Minute)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	signer.now = func() time.Time { return now }
	encoded, expiresAt, err := signer.SignRefresh("linka-plays", strings.Repeat("a", 64), "v3", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := signer.VerifyRefresh(encoded)
	if err != nil || claims.Audience != RefreshAudience || claims.Scopes[0] != RefreshScope || claims.PolicyVersion != "v3" || !expiresAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("claims=%#v expires=%v err=%v", claims, expiresAt, err)
	}
	signer.now = func() time.Time { return now.Add(25 * time.Hour) }
	if _, err := signer.VerifyRefresh(encoded); err == nil {
		t.Fatal("expired refresh token was accepted")
	}
	if _, _, err := signer.SignRefresh("linka-plays", strings.Repeat("a", 64), "v3", 366*24*time.Hour); err == nil {
		t.Fatal("overlong refresh token was accepted")
	}
}

func TestRefreshTokenRejectsWrongScopeAndTampering(t *testing.T) {
	signer, _ := NewSigner(bytes.Repeat([]byte{7}, 32), "test-key", "identity.test", time.Minute, 5*time.Minute)
	wrongScope, _, err := signer.signClaims(SignInput{
		Audience: RefreshAudience, Product: "linka-plays", Subject: strings.Repeat("a", 64),
		SubjectType: "installation", Scopes: []string{"telemetry:write"}, PolicyVersion: "v3", TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.VerifyRefresh(wrongScope); err == nil {
		t.Fatal("wrong refresh scope was accepted")
	}
	valid, _, _ := signer.SignRefresh("linka-plays", strings.Repeat("a", 64), "v3", 24*time.Hour)
	parts := strings.Split(valid, ".")
	replacement := "A"
	if parts[1][0] == 'A' {
		replacement = "B"
	}
	parts[1] = replacement + parts[1][1:]
	if _, err := signer.VerifyRefresh(strings.Join(parts, ".")); err == nil {
		t.Fatal("tampered refresh token was accepted")
	}
}
