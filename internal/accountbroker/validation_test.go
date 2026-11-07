package accountbroker

import (
	"encoding/base64"
	"math"
	"strings"
	"testing"

	"github.com/linka-cloud/linka.identity/internal/domain"
)

func validChallengeInput() ChallengeInput {
	return ChallengeInput{
		RequestID: "12345678-1234-4234-8234-123456789abc", ProductID: "unknown-product",
		Email: "User.Name+Tag@Example.com", Purpose: RegistrationPurpose,
		ClientNonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), HolderRole: "self",
	}
}

func TestChallengeInputNormalized(t *testing.T) {
	input := validChallengeInput()
	input.RequestID = strings.ToUpper(input.RequestID)
	input.Email = " \tUser.Name+Tag@Example.com \n"
	got, err := input.normalized()
	if err != nil {
		t.Fatal(err)
	}
	want := validChallengeInput()
	want.Email = "user.name+tag@example.com"
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	// A syntactically valid unknown product passes: only the broker checks its registry.
	if got.ProductID != "unknown-product" {
		t.Fatal("syntax validation changed product")
	}
}

func TestChallengeInputInvalid(t *testing.T) {
	tests := []struct {
		name   string
		change func(*ChallengeInput)
	}{
		{"empty request", func(i *ChallengeInput) { i.RequestID = "" }},
		{"short request", func(i *ChallengeInput) { i.RequestID = "a" }},
		{"uuid v1", func(i *ChallengeInput) { i.RequestID = "12345678-1234-1234-8234-123456789abc" }},
		{"uuid variant", func(i *ChallengeInput) { i.RequestID = "12345678-1234-4234-7234-123456789abc" }},
		{"uuid path", func(i *ChallengeInput) { i.RequestID += "/verify" }},
		{"uuid whitespace", func(i *ChallengeInput) { i.RequestID += " " }},
		{"uuid unicode", func(i *ChallengeInput) { i.RequestID = "１２３４５６７８-1234-4234-8234-123456789abc" }},
		{"empty product", func(i *ChallengeInput) { i.ProductID = "" }},
		{"short product", func(i *ChallengeInput) { i.ProductID = "a" }},
		{"product uppercase", func(i *ChallengeInput) { i.ProductID = "Product" }},
		{"product path", func(i *ChallengeInput) { i.ProductID = "../product" }},
		{"product unicode", func(i *ChallengeInput) { i.ProductID = "prоduct" }},
		{"product long", func(i *ChallengeInput) { i.ProductID = strings.Repeat("a", 65) }},
		{"purpose", func(i *ChallengeInput) { i.Purpose = "login" }},
		{"purpose whitespace", func(i *ChallengeInput) { i.Purpose += " " }},
		{"holder", func(i *ChallengeInput) { i.HolderRole = "guardian" }},
		{"holder whitespace", func(i *ChallengeInput) { i.HolderRole = "self " }},
		{"email malformed", func(i *ChallengeInput) { i.Email = "not-an-email" }},
		{"email display name", func(i *ChallengeInput) { i.Email = "User <user@example.com>" }},
		{"email injection", func(i *ChallengeInput) { i.Email = "a@example.com\r\nBcc: b@example.com" }},
		{"email nul", func(i *ChallengeInput) { i.Email = "a\x00@example.com" }},
		{"email 321 bytes", func(i *ChallengeInput) { i.Email = strings.Repeat("a", 309) + "@example.com" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := validChallengeInput()
			tt.change(&input)
			got, err := input.normalized()
			if err != domain.ErrInvalid || got != (ChallengeInput{}) {
				t.Fatalf("got %+v, %v; want empty input and ErrInvalid", got, err)
			}
		})
	}
}

func TestChallengeInputEmailByteBoundary(t *testing.T) {
	for _, email := range []string{strings.Repeat("a", 308) + "@example.com", strings.Repeat("é", 154) + "@example.com"} {
		input := validChallengeInput()
		input.Email = email
		if len(email) != 320 {
			t.Fatal("test boundary must be 320 bytes")
		}
		if _, err := input.normalized(); err != nil {
			t.Fatalf("320-byte address rejected: %v", err)
		}
		input.Email = "a" + email
		if _, err := input.normalized(); err != domain.ErrInvalid {
			t.Fatalf("321-byte address: %v", err)
		}
	}
}

func TestClientNonceValidation(t *testing.T) {
	canonical := validChallengeInput().ClientNonce
	tests := []struct {
		name, nonce string
		valid       bool
	}{
		{"canonical", canonical, true},
		{"empty", "", false},
		{"31 bytes", base64.RawURLEncoding.EncodeToString(make([]byte, 31)), false},
		{"33 bytes", base64.RawURLEncoding.EncodeToString(make([]byte, 33)), false},
		{"padding", canonical + "=", false},
		{"nonzero trailing bits", canonical[:42] + "B", false},
		{"standard alphabet slash", "/" + canonical[1:], false},
		{"standard alphabet plus", "+" + canonical[1:], false},
		{"newline", canonical[:20] + "\n" + canonical[20:], false},
		{"space", " " + canonical[1:], false},
		{"unicode", "Ａ" + canonical[3:], false},
		{"path", "../" + canonical[3:], false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challenge := validChallengeInput()
			challenge.ClientNonce = tt.nonce
			_, challengeErr := challenge.normalized()
			verifyErr := (VerifyInput{ProductID: challenge.ProductID, ClientNonce: tt.nonce, Code: "012345"}).valid()
			if tt.valid {
				if challengeErr != nil || verifyErr != nil {
					t.Fatalf("canonical nonce rejected: %v, %v", challengeErr, verifyErr)
				}
			} else if challengeErr != domain.ErrInvalid || verifyErr != domain.ErrInvalid {
				t.Fatalf("invalid nonce errors = %v, %v", challengeErr, verifyErr)
			}
		})
	}
}

func TestVerifyInputValid(t *testing.T) {
	for _, code := range []string{"000000", "012345", "999999", "", "12345", "1234567", "１２３４５６", "١٢٣٤٥٦", "12345a", "12345\n", " 12345", "12\x00345", "../123"} {
		input := VerifyInput{ProductID: "unknown-product", ClientNonce: validChallengeInput().ClientNonce, Code: code}
		err := input.valid()
		wantValid := code == "000000" || code == "012345" || code == "999999"
		if (wantValid && err != nil) || (!wantValid && err != domain.ErrInvalid) {
			t.Errorf("code %q: %v", code, err)
		}
	}
	for _, product := range []string{"", "a", "Product", "../product", "prоduct", strings.Repeat("a", 65)} {
		input := VerifyInput{ProductID: product, ClientNonce: validChallengeInput().ClientNonce, Code: "012345"}
		if err := input.valid(); err != domain.ErrInvalid {
			t.Errorf("product %q: %v", product, err)
		}
	}
}

func TestProfileInputNormalized(t *testing.T) {
	tests := []struct {
		name string
		in   ProfileInput
		want ProfileInput
	}{
		{"optional geography", ProfileInput{HolderRole: "self"}, ProfileInput{HolderRole: "self"}},
		{"country only", ProfileInput{HolderRole: "representative", Country: " ru "}, ProfileInput{HolderRole: "representative", Country: "RU"}},
		{"region normalized", ProfileInput{Version: 7, HolderRole: "self", Country: " us\t", Region: " us-ca "}, ProfileInput{Version: 7, HolderRole: "self", Country: "US", Region: "US-CA"}},
		{"numeric region", ProfileInput{Version: math.MaxUint64 - 1, HolderRole: "self", Country: "ru", Region: "ru-123"}, ProfileInput{Version: math.MaxUint64 - 1, HolderRole: "self", Country: "RU", Region: "RU-123"}},
		{"one character region", ProfileInput{HolderRole: "self", Country: "zz", Region: "zz-a"}, ProfileInput{HolderRole: "self", Country: "ZZ", Region: "ZZ-A"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.in.normalized()
			if err != nil || got != tt.want {
				t.Fatalf("got %+v, %v; want %+v", got, err, tt.want)
			}
		})
	}
}

func TestProfileInputInvalid(t *testing.T) {
	tests := []ProfileInput{
		{Version: math.MaxUint64, HolderRole: "self"},
		{HolderRole: ""}, {HolderRole: "Self"}, {HolderRole: "self "}, {HolderRole: "guardian"},
		{HolderRole: "self", Country: "USA"}, {HolderRole: "self", Country: "U"},
		{HolderRole: "self", Country: "12"}, {HolderRole: "self", Country: "ſu"},
		{HolderRole: "self", Country: "ＲＵ"}, {HolderRole: "self", Country: "R\x00"},
		{HolderRole: "self", Country: "RU\nX-Header: injected"},
		{HolderRole: "self", Region: "RU-MOW"},
		{HolderRole: "self", Country: "US", Region: "RU-MOW"},
		{HolderRole: "self", Country: "RU", Region: "RU-"},
		{HolderRole: "self", Country: "RU", Region: "RU-MOSC"},
		{HolderRole: "self", Country: "RU", Region: "RU-A-B"},
		{HolderRole: "self", Country: "RU", Region: "RU-../"},
		{HolderRole: "self", Country: "RU", Region: "RU-ſ"},
		{HolderRole: "self", Country: "RU", Region: "RU-МОW"},
		{HolderRole: "self", Country: "RU", Region: "RU-A\nB"},
		{HolderRole: "self", Country: "RU", Region: "RU-A@example.com"},
		{HolderRole: "self", Country: "RU", Region: "RU-MOW, 1 Main St"},
	}
	for _, input := range tests {
		got, err := input.normalized()
		if err != domain.ErrInvalid || got != (ProfileInput{}) {
			t.Errorf("input %+v: got %+v, %v; want empty input and ErrInvalid", input, got, err)
		}
	}
}
