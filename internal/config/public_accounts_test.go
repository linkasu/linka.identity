package config

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
	"time"
)

func publicAccountValues() map[string]string {
	values := validValues(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	values["PUBLIC_ACCOUNT_ENABLED"] = "true"
	values["PUBLIC_ACCOUNT_PRODUCTS"] = "linka-plays;linka-looks"
	values["PUBLIC_ACCOUNT_POLICY_VERSION"] = " registration-v1 "
	values["PUBLIC_ACCOUNT_OTP_KEY_BASE64"] = base64.StdEncoding.EncodeToString(make([]byte, 32))
	values["PUBLIC_ACCOUNT_SMTP_ADDR"] = "smtp.example.test:587"
	values["PUBLIC_ACCOUNT_SMTP_USER"] = "smtp-user"
	values["PUBLIC_ACCOUNT_SMTP_PASSWORD"] = " password with spaces "
	values["PUBLIC_ACCOUNT_SMTP_FROM"] = "accounts@example.test"
	return values
}

func TestLoadPublicAccountsDefaultsAndLegacyConfiguration(t *testing.T) {
	values := validValues(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	cfg, err := load(mapLookup(values))
	if err != nil {
		t.Fatal(err)
	}
	want := PublicAccountConfig{Products: map[string]struct{}{}, OTPKeyID: "otp-v1", DailyLimit: 200}
	if !reflect.DeepEqual(cfg.PublicAccounts, want) {
		t.Fatal("unexpected public account defaults")
	}
	if cfg.TokenTTL != 5*time.Minute || cfg.TokenMaxTTL != 15*time.Minute || cfg.PublicPolicyVersion != values["PUBLIC_INSTALLATION_POLICY_VERSION"] {
		t.Fatal("legacy configuration changed")
	}
	// Provisioning disabled credentials must neither enable accounts nor expose credentials.
	for key, value := range publicAccountValues() {
		if strings.HasPrefix(key, "PUBLIC_ACCOUNT_") && key != "PUBLIC_ACCOUNT_ENABLED" {
			values[key] = value
		}
	}
	values["PUBLIC_ACCOUNT_OTP_KEY_BASE64"] = "invalid"
	values["PUBLIC_ACCOUNT_SMTP_ADDR"] = "not-an-address"
	cfg, err = load(mapLookup(values))
	if err != nil || cfg.PublicAccounts.Enabled || len(cfg.PublicAccounts.OTPKey) != 0 || cfg.PublicAccounts.SMTPPassword != "" || cfg.PublicAccounts.SMTPFrom != "" {
		t.Fatal("disabled provisioned credentials were parsed or exposed")
	}
	// Existing short legacy token lifetimes remain accepted when accounts are off.
	values["TOKEN_TTL"], values["TOKEN_MAX_TTL"] = "1m", "2m"
	if _, err := load(mapLookup(values)); err != nil {
		t.Fatal(err)
	}
}

func TestLoadPublicAccountsValid(t *testing.T) {
	values := publicAccountValues()
	cfg, err := load(mapLookup(values))
	if err != nil {
		t.Fatal(err)
	}
	accounts := cfg.PublicAccounts
	if !accounts.Enabled || len(accounts.Products) != 2 || accounts.PolicyVersion != "registration-v1" || accounts.OTPKeyID != "otp-v1" || len(accounts.OTPKey) != 32 || accounts.DailyLimit != 200 || accounts.SMTPAddr != values["PUBLIC_ACCOUNT_SMTP_ADDR"] || accounts.SMTPUser != values["PUBLIC_ACCOUNT_SMTP_USER"] || accounts.SMTPPassword != values["PUBLIC_ACCOUNT_SMTP_PASSWORD"] || accounts.SMTPFrom != values["PUBLIC_ACCOUNT_SMTP_FROM"] {
		t.Fatal("unexpected public account configuration")
	}
	if cfg.TokenTTL != 5*time.Minute || cfg.PublicPolicyVersion != values["PUBLIC_INSTALLATION_POLICY_VERSION"] {
		t.Fatal("account policy or token lifetime replaced installation configuration")
	}
}

func TestLoadPublicAccountsEmptySignupKeepsEnabled(t *testing.T) {
	values := publicAccountValues()
	delete(values, "PUBLIC_ACCOUNT_PRODUCTS")
	cfg, err := load(mapLookup(values))
	if err != nil || !cfg.PublicAccounts.Enabled || len(cfg.PublicAccounts.Products) != 0 || len(cfg.PublicAccounts.OTPKey) == 0 {
		t.Fatal("empty signup allowlist must retain enabled account configuration")
	}
	delete(values, "PUBLIC_INSTALLATION_PRODUCTS")
	if _, err := load(mapLookup(values)); err == nil || !strings.Contains(err.Error(), "PUBLIC_INSTALLATION_PRODUCTS") {
		t.Fatal("enabled accounts accepted without installation context")
	}
}

func TestLoadPublicAccountsRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name, field, value string
	}{
		{"boolean", "PUBLIC_ACCOUNT_ENABLED", "yes"},
		{"empty boolean", "PUBLIC_ACCOUNT_ENABLED", ""},
		{"spaced boolean", "PUBLIC_ACCOUNT_ENABLED", " true "},
		{"unknown product", "PUBLIC_ACCOUNT_PRODUCTS", "unknown"},
		{"not bootstrap allowed", "PUBLIC_ACCOUNT_PRODUCTS", "linka-tts"},
		{"invalid product", "PUBLIC_ACCOUNT_PRODUCTS", "invalid@example.test"},
		{"missing policy", "PUBLIC_ACCOUNT_POLICY_VERSION", ""},
		{"long policy", "PUBLIC_ACCOUNT_POLICY_VERSION", strings.Repeat("x", 101)},
		{"invalid UTF-8 policy", "PUBLIC_ACCOUNT_POLICY_VERSION", "policy\xff"},
		{"policy control", "PUBLIC_ACCOUNT_POLICY_VERSION", "policy\u0085version"},
		{"policy trailing control", "PUBLIC_ACCOUNT_POLICY_VERSION", "policy\n"},
		{"policy email", "PUBLIC_ACCOUNT_POLICY_VERSION", "secret@example.test"},
		{"missing key ID", "PUBLIC_ACCOUNT_OTP_KEY_ID", ""},
		{"key ID email", "PUBLIC_ACCOUNT_OTP_KEY_ID", "secret@example.test"},
		{"key ID control", "PUBLIC_ACCOUNT_OTP_KEY_ID", "otp\x00id"},
		{"long key ID", "PUBLIC_ACCOUNT_OTP_KEY_ID", strings.Repeat("x", 101)},
		{"missing key", "PUBLIC_ACCOUNT_OTP_KEY_BASE64", ""},
		{"partial key", "PUBLIC_ACCOUNT_OTP_KEY_BASE64", base64.StdEncoding.EncodeToString(make([]byte, 31))},
		{"oversized key", "PUBLIC_ACCOUNT_OTP_KEY_BASE64", base64.StdEncoding.EncodeToString(make([]byte, 129))},
		{"bad base64", "PUBLIC_ACCOUNT_OTP_KEY_BASE64", "secret-not-base64"},
		{"noncanonical base64", "PUBLIC_ACCOUNT_OTP_KEY_BASE64", strings.Repeat("A", 42) + "B="},
		{"key newline", "PUBLIC_ACCOUNT_OTP_KEY_BASE64", base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"},
		{"zero daily limit", "PUBLIC_ACCOUNT_DAILY_LIMIT", "0"},
		{"excessive daily limit", "PUBLIC_ACCOUNT_DAILY_LIMIT", "10001"},
		{"nonnumeric daily limit", "PUBLIC_ACCOUNT_DAILY_LIMIT", "secret"},
		{"missing SMTP addr", "PUBLIC_ACCOUNT_SMTP_ADDR", ""},
		{"missing SMTP port", "PUBLIC_ACCOUNT_SMTP_ADDR", "smtp.example.test"},
		{"missing SMTP host", "PUBLIC_ACCOUNT_SMTP_ADDR", ":587"},
		{"SMTP URL", "PUBLIC_ACCOUNT_SMTP_ADDR", "smtp://smtp.example.test:587"},
		{"SMTP userinfo", "PUBLIC_ACCOUNT_SMTP_ADDR", "secret@smtp.example.test:587"},
		{"SMTP query", "PUBLIC_ACCOUNT_SMTP_ADDR", "smtp.example.test:587?secret"},
		{"SMTP invalid host", "PUBLIC_ACCOUNT_SMTP_ADDR", "bad_host:587"},
		{"SMTP invalid label", "PUBLIC_ACCOUNT_SMTP_ADDR", "-smtp.example.test:587"},
		{"SMTP zero port", "PUBLIC_ACCOUNT_SMTP_ADDR", "smtp.example.test:0"},
		{"SMTP excessive port", "PUBLIC_ACCOUNT_SMTP_ADDR", "smtp.example.test:65536"},
		{"SMTP signed port", "PUBLIC_ACCOUNT_SMTP_ADDR", "smtp.example.test:+587"},
		{"SMTP empty user", "PUBLIC_ACCOUNT_SMTP_USER", ""},
		{"SMTP user CRLF", "PUBLIC_ACCOUNT_SMTP_USER", "secret\r\ninjected"},
		{"SMTP empty password", "PUBLIC_ACCOUNT_SMTP_PASSWORD", ""},
		{"SMTP password CRLF", "PUBLIC_ACCOUNT_SMTP_PASSWORD", "secret\r\ninjected"},
		{"SMTP empty from", "PUBLIC_ACCOUNT_SMTP_FROM", ""},
		{"SMTP invalid from", "PUBLIC_ACCOUNT_SMTP_FROM", "secret"},
		{"SMTP display name", "PUBLIC_ACCOUNT_SMTP_FROM", "Secret <secret@example.test>"},
		{"SMTP bracketed from", "PUBLIC_ACCOUNT_SMTP_FROM", "<secret@example.test>"},
		{"SMTP from control", "PUBLIC_ACCOUNT_SMTP_FROM", "secret\r\n@example.test"},
		{"SMTP from multiple", "PUBLIC_ACCOUNT_SMTP_FROM", "one@example.test,two@example.test"},
		{"SMTP from comment", "PUBLIC_ACCOUNT_SMTP_FROM", "secret@example.test (Secret)"},
		{"SMTP from whitespace", "PUBLIC_ACCOUNT_SMTP_FROM", " secret@example.test "},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := publicAccountValues()
			values[test.field] = test.value
			_, err := load(mapLookup(values))
			if err == nil || !strings.Contains(err.Error(), test.field) {
				t.Fatalf("expected field-only validation error for %s", test.field)
			}
			if test.value != "" && len(test.value) > 8 && strings.Contains(err.Error(), test.value) {
				t.Fatal("validation error leaked configured value")
			}
		})
	}
}

func TestLoadPublicAccountsRejectsDisabledProductDrift(t *testing.T) {
	for _, product := range []string{"unknown", "linka-tts"} {
		values := publicAccountValues()
		values["PUBLIC_ACCOUNT_ENABLED"] = "false"
		values["PUBLIC_ACCOUNT_PRODUCTS"] = product
		if _, err := load(mapLookup(values)); err == nil || !strings.Contains(err.Error(), "PUBLIC_ACCOUNT_PRODUCTS") {
			t.Fatal("disabled feature accepted product drift")
		}
	}
}

func TestLoadPublicAccountsBoundariesAndOperatorRegistry(t *testing.T) {
	for _, host := range []string{"localhost:1", "smtp.example.test.:65535", "127.0.0.1:587", "[::1]:587"} {
		for _, size := range []int{32, 128} {
			values := publicAccountValues()
			values["PUBLIC_ACCOUNT_SMTP_ADDR"] = host
			values["PUBLIC_ACCOUNT_OTP_KEY_BASE64"] = base64.StdEncoding.EncodeToString(make([]byte, size))
			values["PUBLIC_ACCOUNT_POLICY_VERSION"] = strings.Repeat("я", 100)
			values["PUBLIC_ACCOUNT_OTP_KEY_ID"] = " otp-v2 "
			values["PUBLIC_ACCOUNT_DAILY_LIMIT"] = "10000"
			values["PUBLIC_ACCOUNT_PRODUCTS"] = "operator-product"
			cfg, err := loadPublicAccounts(mapLookup(values), map[string]Product{"operator-product": {}}, map[string]struct{}{"operator-product": {}}, 5*time.Minute)
			if err != nil || cfg.OTPKeyID != "otp-v2" || cfg.DailyLimit != 10000 || len(cfg.OTPKey) != size {
				t.Fatal("valid boundary or operator-defined product rejected")
			}
		}
	}
	values := publicAccountValues()
	values["TOKEN_TTL"], values["TOKEN_MAX_TTL"] = "1m", "4m59s"
	if _, err := load(mapLookup(values)); err == nil || !strings.Contains(err.Error(), "TOKEN_MAX_TTL") {
		t.Fatal("insufficient max token TTL accepted")
	}
	values["TOKEN_MAX_TTL"] = "5m"
	cfg, err := load(mapLookup(values))
	if err != nil || cfg.TokenTTL != time.Minute {
		t.Fatal("account configuration changed legacy token TTL")
	}
}
