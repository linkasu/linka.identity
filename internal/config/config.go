package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/linka-cloud/linka.identity/internal/authz"
)

type Product struct {
	TelemetryAudience string `json:"telemetry_audience"`
}

type Config struct {
	Environment              string
	HTTPAddr                 string
	DatabaseURL              string
	DatabaseMaxConnections   int32
	Workloads                []authz.Workload
	Products                 map[string]Product
	PairwiseIDKey            []byte
	EmailKeyProvider         string
	EmailKeyActiveID         string
	EmailLocalKEKs           map[string][]byte
	EmailYandexKMSKeys       map[string]string
	BlindIndexKeys           map[int][]byte
	BlindIndexCurrentVersion int
	TokenSigningSeeds        map[string][]byte
	TokenActiveKeyID         string
	TokenIssuer              string
	TokenTTL                 time.Duration
	TokenMaxTTL              time.Duration
	MinorCrossProductLinking bool
	OutboxURL                string
	OutboxPollInterval       time.Duration
	OutboxMaxAttempts        int
	OutboxReadinessMaxAge    time.Duration
	RequireOutboxDelivery    bool
	EmailVerificationTTL     time.Duration
	EmailCleanupInterval     time.Duration
	ShutdownTimeout          time.Duration
}

func Load() (Config, error) {
	return load(os.LookupEnv)
}

func load(lookup func(string) (string, bool)) (Config, error) {
	var cfg Config
	var err error

	cfg.Environment = valueOrDefault(lookup, "DEPLOYMENT_ENVIRONMENT", "development")
	if cfg.Environment != "development" && cfg.Environment != "production" {
		return Config{}, errors.New("DEPLOYMENT_ENVIRONMENT must be development or production")
	}
	cfg.HTTPAddr = valueOrDefault(lookup, "HTTP_ADDR", ":8080")
	cfg.DatabaseURL, err = required(lookup, "DATABASE_URL")
	if err != nil {
		return Config{}, err
	}
	if cfg.Environment == "production" {
		databaseURL, parseErr := url.Parse(cfg.DatabaseURL)
		if parseErr != nil || databaseURL.Query().Get("sslmode") != "verify-full" {
			return Config{}, errors.New("production DATABASE_URL must use sslmode=verify-full")
		}
	}
	cfg.DatabaseMaxConnections, err = int32Value(lookup, "DATABASE_MAX_CONNECTIONS", 10, 1, 100)
	if err != nil {
		return Config{}, err
	}
	cfg.Workloads, err = workloads(lookup)
	if err != nil {
		return Config{}, err
	}
	cfg.Products, err = products(lookup)
	if err != nil {
		return Config{}, err
	}
	for _, workload := range cfg.Workloads {
		for _, product := range workload.Products {
			if _, ok := cfg.Products[product]; !ok {
				return Config{}, fmt.Errorf("workload %s references unknown product %s", workload.ID, product)
			}
		}
	}
	cfg.PairwiseIDKey, err = base64Key(lookup, "PAIRWISE_ID_KEY_BASE64", 32)
	if err != nil {
		return Config{}, err
	}
	cfg.EmailKeyProvider = valueOrDefault(lookup, "EMAIL_KEY_PROVIDER", "local")
	cfg.EmailKeyActiveID, err = required(lookup, "EMAIL_KEY_ACTIVE_ID")
	if err != nil {
		return Config{}, err
	}
	switch cfg.EmailKeyProvider {
	case "local":
		if cfg.Environment == "production" {
			return Config{}, errors.New("local email KEK provider is forbidden in production")
		}
		cfg.EmailLocalKEKs, err = namedKeys(lookup, "EMAIL_LOCAL_KEKS_JSON", 32)
		if err != nil {
			return Config{}, err
		}
		if _, ok := cfg.EmailLocalKEKs[cfg.EmailKeyActiveID]; !ok {
			return Config{}, errors.New("EMAIL_KEY_ACTIVE_ID is absent from EMAIL_LOCAL_KEKS_JSON")
		}
	case "yandex-kms":
		cfg.EmailYandexKMSKeys, err = namedIDs(lookup, "EMAIL_YC_KMS_KEYS_JSON")
		if err != nil {
			return Config{}, err
		}
		if _, ok := cfg.EmailYandexKMSKeys[cfg.EmailKeyActiveID]; !ok {
			return Config{}, errors.New("EMAIL_KEY_ACTIVE_ID is absent from EMAIL_YC_KMS_KEYS_JSON")
		}
	default:
		return Config{}, errors.New("EMAIL_KEY_PROVIDER must be local or yandex-kms")
	}
	cfg.BlindIndexKeys, err = blindIndexKeys(lookup)
	if err != nil {
		return Config{}, err
	}
	current, err := intValue(lookup, "BLIND_INDEX_CURRENT_VERSION", 0, 1, 32767)
	if err != nil {
		return Config{}, err
	}
	if _, ok := cfg.BlindIndexKeys[current]; !ok {
		return Config{}, errors.New("BLIND_INDEX_CURRENT_VERSION is absent from BLIND_INDEX_KEYS_JSON")
	}
	cfg.BlindIndexCurrentVersion = current
	cfg.TokenSigningSeeds, err = namedKeys(lookup, "TOKEN_SIGNING_KEYS_JSON", ed25519.SeedSize)
	if err != nil {
		return Config{}, err
	}
	cfg.TokenActiveKeyID, err = required(lookup, "TOKEN_ACTIVE_KEY_ID")
	if err != nil {
		return Config{}, err
	}
	if _, ok := cfg.TokenSigningSeeds[cfg.TokenActiveKeyID]; !ok {
		return Config{}, errors.New("TOKEN_ACTIVE_KEY_ID is absent from TOKEN_SIGNING_KEYS_JSON")
	}
	cfg.TokenIssuer, err = required(lookup, "TOKEN_ISSUER")
	if err != nil {
		return Config{}, err
	}
	cfg.TokenTTL, err = durationValue(lookup, "TOKEN_TTL", 5*time.Minute)
	if err != nil {
		return Config{}, err
	}
	cfg.TokenMaxTTL, err = durationValue(lookup, "TOKEN_MAX_TTL", 15*time.Minute)
	if err != nil {
		return Config{}, err
	}
	if cfg.TokenTTL <= 0 || cfg.TokenMaxTTL <= 0 || cfg.TokenTTL > cfg.TokenMaxTTL {
		return Config{}, errors.New("token TTL values must be positive and TOKEN_TTL must not exceed TOKEN_MAX_TTL")
	}
	cfg.MinorCrossProductLinking, err = boolValue(lookup, "MINOR_CROSS_PRODUCT_LINKING_ENABLED", false)
	if err != nil {
		return Config{}, err
	}
	cfg.OutboxURL = valueOrDefault(lookup, "OUTBOX_DELIVERY_URL", "")
	cfg.RequireOutboxDelivery, err = boolValue(lookup, "REQUIRE_OUTBOX_DELIVERY", false)
	if err != nil {
		return Config{}, err
	}
	if cfg.Environment == "production" && !cfg.RequireOutboxDelivery {
		return Config{}, errors.New("REQUIRE_OUTBOX_DELIVERY must be true in production")
	}
	if cfg.OutboxURL != "" {
		parsed, parseErr := url.ParseRequestURI(cfg.OutboxURL)
		if parseErr != nil || parsed == nil {
			return Config{}, errors.New("OUTBOX_DELIVERY_URL must be HTTPS (or loopback HTTP) without credentials, query, or fragment")
		}
		loopbackHTTP := parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1")
		if parsed.Host == "" || (parsed.Scheme != "https" && !loopbackHTTP) || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return Config{}, errors.New("OUTBOX_DELIVERY_URL must be HTTPS (or loopback HTTP) without credentials, query, or fragment")
		}
	}
	if cfg.RequireOutboxDelivery && cfg.OutboxURL == "" {
		return Config{}, errors.New("OUTBOX_DELIVERY_URL is required when REQUIRE_OUTBOX_DELIVERY=true")
	}
	cfg.OutboxPollInterval, err = durationValue(lookup, "OUTBOX_POLL_INTERVAL", 2*time.Second)
	if err != nil || cfg.OutboxPollInterval <= 0 {
		return Config{}, errors.New("OUTBOX_POLL_INTERVAL must be a positive duration")
	}
	cfg.OutboxMaxAttempts, err = intValue(lookup, "OUTBOX_MAX_ATTEMPTS", 12, 1, 100)
	if err != nil {
		return Config{}, err
	}
	cfg.OutboxReadinessMaxAge, err = durationValue(lookup, "OUTBOX_READINESS_MAX_AGE", 5*time.Minute)
	if err != nil || cfg.OutboxReadinessMaxAge <= 0 {
		return Config{}, errors.New("OUTBOX_READINESS_MAX_AGE must be a positive duration")
	}
	cfg.EmailVerificationTTL, err = durationValue(lookup, "EMAIL_VERIFICATION_TTL", 15*time.Minute)
	if err != nil || cfg.EmailVerificationTTL <= 0 || cfg.EmailVerificationTTL > 24*time.Hour {
		return Config{}, errors.New("EMAIL_VERIFICATION_TTL must be positive and at most 24 hours")
	}
	cfg.EmailCleanupInterval, err = durationValue(lookup, "EMAIL_VERIFICATION_CLEANUP_INTERVAL", time.Minute)
	if err != nil || cfg.EmailCleanupInterval < time.Second {
		return Config{}, errors.New("EMAIL_VERIFICATION_CLEANUP_INTERVAL must be at least one second")
	}
	cfg.ShutdownTimeout, err = durationValue(lookup, "SHUTDOWN_TIMEOUT", 10*time.Second)
	if err != nil || cfg.ShutdownTimeout <= 0 {
		return Config{}, errors.New("SHUTDOWN_TIMEOUT must be a positive duration")
	}

	return cfg, nil
}

func workloads(lookup func(string) (string, bool)) ([]authz.Workload, error) {
	raw, err := required(lookup, "WORKLOADS_JSON")
	if err != nil {
		return nil, err
	}
	var encoded []struct {
		ID       string   `json:"id"`
		Token    string   `json:"token"`
		Roles    []string `json:"roles"`
		Products []string `json:"products"`
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&encoded); err != nil || len(encoded) == 0 {
		return nil, errors.New("WORKLOADS_JSON must be a non-empty strict JSON array")
	}
	result := make([]authz.Workload, 0, len(encoded))
	for _, workload := range encoded {
		roles := make([]authz.Role, len(workload.Roles))
		for index, role := range workload.Roles {
			roles[index] = authz.Role(role)
		}
		result = append(result, authz.Workload{ID: workload.ID, Token: workload.Token, Roles: roles, Products: workload.Products})
	}
	if _, err := authz.New(result); err != nil {
		return nil, fmt.Errorf("WORKLOADS_JSON: %w", err)
	}
	return result, nil
}

func products(lookup func(string) (string, bool)) (map[string]Product, error) {
	raw, err := required(lookup, "PRODUCTS_JSON")
	if err != nil {
		return nil, err
	}
	var result map[string]Product
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || len(result) == 0 {
		return nil, errors.New("PRODUCTS_JSON must be a non-empty strict JSON object")
	}
	for id, product := range result {
		if id == "" || product.TelemetryAudience == "" {
			return nil, errors.New("PRODUCTS_JSON contains an invalid product")
		}
	}
	return result, nil
}

func namedKeys(lookup func(string) (string, bool), name string, size int) (map[string][]byte, error) {
	raw, err := required(lookup, name)
	if err != nil {
		return nil, err
	}
	var encoded map[string]string
	if err := json.Unmarshal([]byte(raw), &encoded); err != nil || len(encoded) == 0 {
		return nil, fmt.Errorf("%s must be a non-empty JSON object", name)
	}
	keys := make(map[string][]byte, len(encoded))
	for id, value := range encoded {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if id == "" || err != nil || len(decoded) != size {
			return nil, fmt.Errorf("%s key %q must be base64 encoding of exactly %d bytes", name, id, size)
		}
		keys[id] = decoded
	}
	return keys, nil
}

func namedIDs(lookup func(string) (string, bool), name string) (map[string]string, error) {
	raw, err := required(lookup, name)
	if err != nil {
		return nil, err
	}
	var values map[string]string
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&values); err != nil || len(values) == 0 {
		return nil, fmt.Errorf("%s must be a non-empty JSON object", name)
	}
	for alias, value := range values {
		if strings.TrimSpace(alias) == "" || strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("%s contains an empty alias or ID", name)
		}
	}
	return values, nil
}

func required(lookup func(string) (string, bool), name string) (string, error) {
	value, ok := lookup(name)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

func valueOrDefault(lookup func(string) (string, bool), name, fallback string) string {
	if value, ok := lookup(name); ok {
		return value
	}
	return fallback
}

func base64Key(lookup func(string) (string, bool), name string, size int) ([]byte, error) {
	encoded, err := required(lookup, name)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != size {
		return nil, fmt.Errorf("%s must be standard base64 encoding of exactly %d bytes", name, size)
	}
	return decoded, nil
}

func blindIndexKeys(lookup func(string) (string, bool)) (map[int][]byte, error) {
	raw, err := required(lookup, "BLIND_INDEX_KEYS_JSON")
	if err != nil {
		return nil, err
	}
	var encoded map[string]string
	if err := json.Unmarshal([]byte(raw), &encoded); err != nil || len(encoded) == 0 {
		return nil, errors.New("BLIND_INDEX_KEYS_JSON must be a non-empty JSON object")
	}
	keys := make(map[int][]byte, len(encoded))
	for rawVersion, rawKey := range encoded {
		version, err := strconv.Atoi(rawVersion)
		if err != nil || version < 1 || version > 32767 {
			return nil, errors.New("blind-index versions must be integers between 1 and 32767")
		}
		key, err := base64.StdEncoding.DecodeString(rawKey)
		if err != nil || len(key) < 32 {
			return nil, fmt.Errorf("blind-index key version %d must be base64 encoding of at least 32 bytes", version)
		}
		keys[version] = key
	}
	return keys, nil
}

func intValue(lookup func(string) (string, bool), name string, fallback, min, max int) (int, error) {
	raw := valueOrDefault(lookup, name, strconv.Itoa(fallback))
	value, err := strconv.Atoi(raw)
	if err != nil || value < min || value > max {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", name, min, max)
	}
	return value, nil
}

func int32Value(lookup func(string) (string, bool), name string, fallback, min, max int) (int32, error) {
	value, err := intValue(lookup, name, fallback, min, max)
	return int32(value), err
}

func durationValue(lookup func(string) (string, bool), name string, fallback time.Duration) (time.Duration, error) {
	raw := valueOrDefault(lookup, name, fallback.String())
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid duration", name)
	}
	return value, nil
}

func boolValue(lookup func(string) (string, bool), name string, fallback bool) (bool, error) {
	raw := valueOrDefault(lookup, name, strconv.FormatBool(fallback))
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", name)
	}
	return value, nil
}
