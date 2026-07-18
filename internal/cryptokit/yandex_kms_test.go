package cryptokit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type staticIAMToken string

func (s staticIAMToken) Token(context.Context) (string, error) { return string(s), nil }

func TestYandexKMSKeyringWrapsAndUnwrapsDataKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer test-token" || !strings.Contains(request.URL.Path, "/kms/v1/keys/kms-key") {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		var input map[string]string
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(request.URL.Path, ":encrypt"):
			plaintext, _ := base64.StdEncoding.DecodeString(input["plaintext"])
			_ = json.NewEncoder(response).Encode(map[string]string{
				"keyId": "kms-key", "versionId": "v1", "ciphertext": base64.StdEncoding.EncodeToString(append([]byte("wrapped:"), plaintext...)),
			})
		case strings.HasSuffix(request.URL.Path, ":decrypt"):
			ciphertext, _ := base64.StdEncoding.DecodeString(input["ciphertext"])
			_ = json.NewEncoder(response).Encode(map[string]string{
				"keyId": "kms-key", "versionId": "v1", "plaintext": base64.StdEncoding.EncodeToString([]byte(strings.TrimPrefix(string(ciphertext), "wrapped:"))),
			})
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	provider, err := newYandexKMSKeyring("active", map[string]string{"active": "kms-key", "retiring": "old-kms-key"}, staticIAMToken("test-token"), server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	dataKey, err := provider.GenerateDataKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if dataKey.KeyID != "active" || len(dataKey.Plaintext) != 32 || len(dataKey.Wrapped) == 0 {
		t.Fatalf("invalid data key: %#v", dataKey)
	}
	decrypted, err := provider.DecryptDataKey(context.Background(), dataKey.KeyID, dataKey.Wrapped)
	if err != nil || string(decrypted) != string(dataKey.Plaintext) {
		t.Fatalf("decrypt data key: equal=%v err=%v", string(decrypted) == string(dataKey.Plaintext), err)
	}
	if _, err := provider.DecryptDataKey(context.Background(), "removed", dataKey.Wrapped); err == nil {
		t.Fatal("unknown KMS alias was accepted")
	}
}
