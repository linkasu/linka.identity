package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestLoadRejectsMissingSecrets(t *testing.T) {
	_, err := load(func(string) (string, bool) { return "", false })
	if err == nil || !strings.Contains(err.Error(), "YDB_ENDPOINT") {
		t.Fatalf("expected missing YDB_ENDPOINT error, got %v", err)
	}
}

func TestLoadRejectsUnknownCurrentBlindIndexVersion(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	values := validValues(key)
	values["BLIND_INDEX_CURRENT_VERSION"] = "2"

	_, err := load(mapLookup(values))
	if err == nil || !strings.Contains(err.Error(), "absent") {
		t.Fatalf("expected absent version error, got %v", err)
	}
}

func TestLoadValidConfiguration(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg, err := load(mapLookup(validValues(key)))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.MinorCrossProductLinking {
		t.Fatal("minor linking must default to disabled")
	}
}

func TestLoadRejectsNonTLSOutboxURL(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	values := validValues(key)
	values["OUTBOX_DELIVERY_URL"] = "http://metric.internal/v2/privacy/requests"
	if _, err := load(mapLookup(values)); err == nil {
		t.Fatal("non-loopback HTTP outbox URL was accepted")
	}
}

func TestLoadRejectsLocalKEKAndOptionalOutboxInProduction(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	values := validValues(key)
	values["DEPLOYMENT_ENVIRONMENT"] = "production"
	values["YDB_ENDPOINT"] = "grpcs://ydb.serverless.yandexcloud.net:2135"
	values["YDB_METADATA_CREDENTIALS"] = "1"
	if _, err := load(mapLookup(values)); err == nil || !strings.Contains(err.Error(), "local") {
		t.Fatalf("production local KEK error = %v", err)
	}
	values["EMAIL_KEY_PROVIDER"] = "yandex-kms"
	delete(values, "EMAIL_LOCAL_KEKS_JSON")
	values["EMAIL_KEY_ACTIVE_ID"] = "active"
	values["EMAIL_YC_KMS_KEYS_JSON"] = `{"active":"kms-key-id"}`
	if _, err := load(mapLookup(values)); err == nil || !strings.Contains(err.Error(), "REQUIRE_OUTBOX_DELIVERY") {
		t.Fatalf("production optional outbox error = %v", err)
	}
	values["REQUIRE_OUTBOX_DELIVERY"] = "true"
	values["OUTBOX_DELIVERY_URL"] = "https://metric.example.test/v2/privacy/requests"
	if _, err := load(mapLookup(values)); err != nil {
		t.Fatalf("valid production KMS configuration: %v", err)
	}
}

func TestLoadRejectsServiceAccountKeyInProductionRuntime(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	values := validValues(key)
	values["DEPLOYMENT_ENVIRONMENT"] = "production"
	values["YDB_ENDPOINT"] = "grpcs://ydb.serverless.yandexcloud.net:2135"
	values["YDB_METADATA_CREDENTIALS"] = "1"
	values["YDB_SERVICE_ACCOUNT_KEY_FILE_CREDENTIALS"] = "/run/secrets/ydb.json"
	values["EMAIL_KEY_PROVIDER"] = "yandex-kms"
	delete(values, "EMAIL_LOCAL_KEKS_JSON")
	values["EMAIL_KEY_ACTIVE_ID"] = "active"
	values["EMAIL_YC_KMS_KEYS_JSON"] = `{"active":"kms-key-id"}`
	values["REQUIRE_OUTBOX_DELIVERY"] = "true"
	values["OUTBOX_DELIVERY_URL"] = "https://metric.example.test/v2/privacy/requests"

	if _, err := load(mapLookup(values)); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("production service-account-key error = %v", err)
	}
}

func validValues(key string) map[string]string {
	return map[string]string{
		"DEPLOYMENT_ENVIRONMENT":      "development",
		"YDB_ENDPOINT":                "grpc://localhost:2136",
		"YDB_DATABASE":                "/local",
		"WORKLOADS_JSON":              `[{"id":"plays","token":"` + strings.Repeat("x", 32) + `","roles":["product"],"products":["linka-plays"]}]`,
		"PRODUCTS_JSON":               `{"linka-plays":{"telemetry_audience":"linka-metric"}}`,
		"PAIRWISE_ID_KEY_BASE64":      key,
		"EMAIL_KEY_PROVIDER":          "local",
		"EMAIL_LOCAL_KEKS_JSON":       `{"test-key":"` + key + `"}`,
		"EMAIL_KEY_ACTIVE_ID":         "test-key",
		"BLIND_INDEX_KEYS_JSON":       `{"1":"` + key + `"}`,
		"BLIND_INDEX_CURRENT_VERSION": "1",
		"TOKEN_SIGNING_KEYS_JSON":     `{"test-signing-key":"` + key + `"}`,
		"TOKEN_ACTIVE_KEY_ID":         "test-signing-key",
		"TOKEN_ISSUER":                "test-issuer",
	}
}

func mapLookup(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}
