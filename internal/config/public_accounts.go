package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type PublicAccountConfig struct {
	Enabled                                    bool
	Products                                   map[string]struct{}
	PolicyVersion, OTPKeyID                    string
	OTPKey                                     []byte
	DailyLimit                                 int
	SMTPAddr, SMTPUser, SMTPPassword, SMTPFrom string
}

func loadPublicAccounts(lookup func(string) (string, bool), products map[string]Product, installationProducts map[string]struct{}, tokenMaxTTL time.Duration) (PublicAccountConfig, error) {
	cfg := PublicAccountConfig{OTPKeyID: "otp-v1", DailyLimit: 200}
	var err error
	cfg.Enabled, err = boolValue(lookup, "PUBLIC_ACCOUNT_ENABLED", false)
	if err != nil {
		return PublicAccountConfig{}, err
	}
	cfg.Products, err = stringSet(lookup, "PUBLIC_ACCOUNT_PRODUCTS")
	if err != nil {
		return PublicAccountConfig{}, err
	}
	for product := range cfg.Products {
		if _, ok := products[product]; !ok {
			return PublicAccountConfig{}, errors.New("PUBLIC_ACCOUNT_PRODUCTS references an unknown product")
		}
		if _, ok := installationProducts[product]; !ok {
			return PublicAccountConfig{}, errors.New("PUBLIC_ACCOUNT_PRODUCTS must be a subset of PUBLIC_INSTALLATION_PRODUCTS")
		}
	}
	if !cfg.Enabled {
		return cfg, nil
	}
	if len(products) == 0 || len(installationProducts) == 0 {
		return PublicAccountConfig{}, errors.New("PUBLIC_ACCOUNT_ENABLED requires PRODUCTS_JSON and PUBLIC_INSTALLATION_PRODUCTS")
	}
	if tokenMaxTTL < 5*time.Minute {
		return PublicAccountConfig{}, errors.New("PUBLIC_ACCOUNT_ENABLED requires TOKEN_MAX_TTL of at least 5 minutes")
	}
	cfg.PolicyVersion, err = publicAccountIdentifier(lookup, "PUBLIC_ACCOUNT_POLICY_VERSION", "")
	if err != nil {
		return PublicAccountConfig{}, err
	}
	cfg.OTPKeyID, err = publicAccountIdentifier(lookup, "PUBLIC_ACCOUNT_OTP_KEY_ID", cfg.OTPKeyID)
	if err != nil {
		return PublicAccountConfig{}, err
	}
	encoded := valueOrDefault(lookup, "PUBLIC_ACCOUNT_OTP_KEY_BASE64", "")
	cfg.OTPKey, err = base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(cfg.OTPKey) < 32 || len(cfg.OTPKey) > 128 || base64.StdEncoding.EncodeToString(cfg.OTPKey) != encoded {
		return PublicAccountConfig{}, errors.New("PUBLIC_ACCOUNT_OTP_KEY_BASE64 must be canonical standard base64 encoding of 32 to 128 bytes")
	}
	cfg.DailyLimit, err = intValue(lookup, "PUBLIC_ACCOUNT_DAILY_LIMIT", cfg.DailyLimit, 1, 10000)
	if err != nil {
		return PublicAccountConfig{}, err
	}
	cfg.SMTPAddr, err = required(lookup, "PUBLIC_ACCOUNT_SMTP_ADDR")
	if err != nil {
		return PublicAccountConfig{}, err
	}
	host, port, splitErr := net.SplitHostPort(cfg.SMTPAddr)
	portNumber, portErr := strconv.Atoi(port)
	if splitErr != nil || !publicAccountSMTPHost(host) || portErr != nil || portNumber < 1 || portNumber > 65535 || strings.Trim(port, "0123456789") != "" {
		return PublicAccountConfig{}, errors.New("PUBLIC_ACCOUNT_SMTP_ADDR must contain a valid host and port")
	}
	for _, field := range []struct {
		name string
		dest *string
	}{
		{"PUBLIC_ACCOUNT_SMTP_USER", &cfg.SMTPUser},
		{"PUBLIC_ACCOUNT_SMTP_PASSWORD", &cfg.SMTPPassword},
		{"PUBLIC_ACCOUNT_SMTP_FROM", &cfg.SMTPFrom},
	} {
		*field.dest, err = required(lookup, field.name)
		if err != nil {
			return PublicAccountConfig{}, err
		}
		if strings.ContainsAny(*field.dest, "\r\n") {
			return PublicAccountConfig{}, fmt.Errorf("%s must not contain CR or LF", field.name)
		}
	}
	from, err := mail.ParseAddress(cfg.SMTPFrom)
	if err != nil || from.Name != "" || from.Address != cfg.SMTPFrom || strings.ContainsFunc(cfg.SMTPFrom, unicode.IsControl) {
		return PublicAccountConfig{}, errors.New("PUBLIC_ACCOUNT_SMTP_FROM must be a bare email address without controls")
	}
	return cfg, nil
}

func publicAccountIdentifier(lookup func(string) (string, bool), name, fallback string) (string, error) {
	raw := valueOrDefault(lookup, name, fallback)
	value := strings.TrimSpace(raw)
	if !utf8.ValidString(raw) || utf8.RuneCountInString(value) < 1 || utf8.RuneCountInString(value) > 100 || strings.ContainsRune(value, '@') || strings.ContainsFunc(raw, unicode.IsControl) {
		return "", fmt.Errorf("%s must contain 1 to 100 UTF-8 characters without controls or @", name)
	}
	return value, nil
}

func publicAccountSMTPHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
