package token

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func receiptTestInput(s *Signer) RegistrationReceiptInput {
	return RegistrationReceiptInput{Product: "linka-plays", AccountKey: strings.Repeat("a", 64), InstallationKey: strings.Repeat("b", 64), HolderRole: "self", PolicyVersion: "v1", VerifiedAt: s.now().Add(-time.Minute)}
}

func TestReceiptIsNonexpiringEvidence(t *testing.T) {
	s := accountTestSigner(t)
	encoded, err := s.SignRegistrationReceipt(receiptTestInput(s))
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Unix(1, 0) }
	if _, err := s.VerifyRegistrationReceipt(encoded); err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Unix(4000000000, 0) }
	c, err := s.VerifyRegistrationReceipt(encoded)
	if err != nil || c.ContractVersion != 1 || c.Audience != ReceiptAudience {
		t.Fatalf("claims=%#v err=%v", c, err)
	}
	if _, err := s.VerifyAccountAccess(encoded); err == nil {
		t.Fatal("receipt accepted as account")
	}
	if _, err := s.VerifyRefresh(encoded); err == nil {
		t.Fatal("receipt accepted as refresh")
	}
	account, _, err := s.SignAccountAccess(accountTestInput())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyRegistrationReceipt(account); err == nil {
		t.Fatal("account accepted as receipt")
	}
}

func TestRegistrationReceiptInputValidation(t *testing.T) {
	s := accountTestSigner(t)
	for name, mutate := range map[string]func(*RegistrationReceiptInput){
		"product":                func(i *RegistrationReceiptInput) { i.Product = "wrong product" },
		"account uuid":           func(i *RegistrationReceiptInput) { i.AccountKey = accountTestInput().SessionID },
		"installation uuid":      func(i *RegistrationReceiptInput) { i.InstallationKey = accountTestInput().SessionID },
		"role":                   func(i *RegistrationReceiptInput) { i.HolderRole = "owner" },
		"zero verified":          func(i *RegistrationReceiptInput) { i.VerifiedAt = time.Time{} },
		"negative verified":      func(i *RegistrationReceiptInput) { i.VerifiedAt = time.Unix(-1, 0) },
		"future verified":        func(i *RegistrationReceiptInput) { i.VerifiedAt = s.now().Add(time.Nanosecond) },
		"policy empty":           func(i *RegistrationReceiptInput) { i.PolicyVersion = " " },
		"policy long":            func(i *RegistrationReceiptInput) { i.PolicyVersion = strings.Repeat("v", 101) },
		"policy email":           func(i *RegistrationReceiptInput) { i.PolicyVersion = "person@example.org" },
		"policy control":         func(i *RegistrationReceiptInput) { i.PolicyVersion = "v\x00x" },
		"policy unicode control": func(i *RegistrationReceiptInput) { i.PolicyVersion = "v\u0085x" },
		"policy invalid utf8":    func(i *RegistrationReceiptInput) { i.PolicyVersion = "v\xff" },
	} {
		t.Run(name, func(t *testing.T) {
			i := receiptTestInput(s)
			mutate(&i)
			if _, err := s.SignRegistrationReceipt(i); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
	i := receiptTestInput(s)
	i.HolderRole = "representative"
	i.PolicyVersion = "  v1  "
	encoded, err := s.SignRegistrationReceipt(i)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.VerifyRegistrationReceipt(encoded)
	if err != nil || c.PolicyVersion != "v1" || c.HolderRole != "representative" {
		t.Fatalf("claims=%#v err=%v", c, err)
	}
}

func TestRegistrationReceiptClaimsValidation(t *testing.T) {
	s := accountTestSigner(t)
	encoded, _ := s.SignRegistrationReceipt(receiptTestInput(s))
	valid, err := s.VerifyRegistrationReceipt(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*RegistrationReceiptClaims){
		"contract":              func(c *RegistrationReceiptClaims) { c.ContractVersion = 2 },
		"issuer":                func(c *RegistrationReceiptClaims) { c.Issuer = "other" },
		"audience":              func(c *RegistrationReceiptClaims) { c.Audience = AccountAudience },
		"subject type":          func(c *RegistrationReceiptClaims) { c.SubjectType = "account" },
		"product":               func(c *RegistrationReceiptClaims) { c.Product = "wrong product" },
		"account":               func(c *RegistrationReceiptClaims) { c.Subject = "not-pairwise" },
		"installation":          func(c *RegistrationReceiptClaims) { c.InstallationKey = "not-pairwise" },
		"role":                  func(c *RegistrationReceiptClaims) { c.HolderRole = "admin" },
		"policy":                func(c *RegistrationReceiptClaims) { c.PolicyVersion = "v1@example.org" },
		"policy untrimmed":      func(c *RegistrationReceiptClaims) { c.PolicyVersion = " v1 " },
		"jti":                   func(c *RegistrationReceiptClaims) { c.TokenID = "not-uuid" },
		"zero issued":           func(c *RegistrationReceiptClaims) { c.IssuedAt = 0 },
		"zero verified":         func(c *RegistrationReceiptClaims) { c.VerifiedAt = 0 },
		"negative verified":     func(c *RegistrationReceiptClaims) { c.VerifiedAt = -1 },
		"verified after issued": func(c *RegistrationReceiptClaims) { c.VerifiedAt = c.IssuedAt + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			c := valid
			mutate(&c)
			encoded, err := s.signPayload(c)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.VerifyRegistrationReceipt(encoded); err == nil {
				t.Fatal("invalid claims accepted")
			}
		})
	}
	// Valid but foreign contexts are deliberately returned for the caller to match.
	c := valid
	c.Product = "linka-other"
	c.InstallationKey = strings.Repeat("c", 64)
	encoded, _ = s.signPayload(c)
	foreign, err := s.VerifyRegistrationReceipt(encoded)
	if err != nil || foreign.Product == valid.Product || foreign.InstallationKey == valid.InstallationKey {
		t.Fatalf("context binding lost: %#v %v", foreign, err)
	}
}

func TestReceiptRejectsCredentialFields(t *testing.T) {
	s := accountTestSigner(t)
	encoded, _ := s.SignRegistrationReceipt(receiptTestInput(s))
	parts := strings.Split(encoded, ".")
	header, _ := base64.RawURLEncoding.DecodeString(parts[0])
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	for _, field := range []string{`"exp":1800000100`, `"scope":["account:access"]`, `"sid":"11111111-1111-4111-8111-111111111111"`, `"session_credential":"secret"`} {
		bad := strings.TrimSuffix(string(payload), "}") + "," + field + "}"
		if _, err := s.VerifyRegistrationReceipt(signRawToken(s, string(header), bad)); err == nil {
			t.Fatal("credential field accepted", field)
		}
	}
	invalidUTF8 := strings.Replace(string(payload), `"v1"`, "\"v\xff\"", 1)
	if _, err := s.VerifyRegistrationReceipt(signRawToken(s, string(header), invalidUTF8)); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}
