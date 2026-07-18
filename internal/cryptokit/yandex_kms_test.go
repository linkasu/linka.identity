package cryptokit

import (
	"bytes"
	"context"
	"os"
	"testing"

	kms "github.com/yandex-cloud/go-genproto/yandex/cloud/kms/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type staticIAMToken string

func (s staticIAMToken) Token(context.Context) (string, error) { return string(s), nil }

type fakeYandexKMSClient struct{}

func (fakeYandexKMSClient) Encrypt(ctx context.Context, input *kms.SymmetricEncryptRequest, _ ...grpc.CallOption) (*kms.SymmetricEncryptResponse, error) {
	if !validKMSRequest(ctx, input.GetKeyId(), input.GetAadContext()) {
		return nil, context.Canceled
	}
	return &kms.SymmetricEncryptResponse{KeyId: input.GetKeyId(), VersionId: "v1", Ciphertext: append([]byte("wrapped:"), input.GetPlaintext()...)}, nil
}

func (fakeYandexKMSClient) Decrypt(ctx context.Context, input *kms.SymmetricDecryptRequest, _ ...grpc.CallOption) (*kms.SymmetricDecryptResponse, error) {
	if !validKMSRequest(ctx, input.GetKeyId(), input.GetAadContext()) || !bytes.HasPrefix(input.GetCiphertext(), []byte("wrapped:")) {
		return nil, context.Canceled
	}
	return &kms.SymmetricDecryptResponse{KeyId: input.GetKeyId(), VersionId: "v1", Plaintext: bytes.TrimPrefix(input.GetCiphertext(), []byte("wrapped:"))}, nil
}

func validKMSRequest(ctx context.Context, keyID string, aad []byte) bool {
	values, ok := metadata.FromOutgoingContext(ctx)
	return ok && len(values.Get("authorization")) == 1 && values.Get("authorization")[0] == "Bearer test-token" &&
		keyID == "kms-key" && bytes.Equal(aad, keyWrapAAD)
}

func TestYandexKMSKeyringWrapsAndUnwrapsDataKey(t *testing.T) {
	provider, err := newYandexKMSKeyring("active", map[string]string{"active": "kms-key", "retiring": "old-kms-key"}, staticIAMToken("test-token"), fakeYandexKMSClient{})
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

func TestYandexKMSKeyringIntegration(t *testing.T) {
	keyID, token := os.Getenv("TEST_YC_KMS_KEY_ID"), os.Getenv("TEST_YC_IAM_TOKEN")
	if keyID == "" || token == "" {
		t.Skip("TEST_YC_KMS_KEY_ID and TEST_YC_IAM_TOKEN are required")
	}
	provider, err := NewYandexKMSKeyring("active", map[string]string{"active": keyID}, staticIAMToken(token))
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	dataKey, err := provider.GenerateDataKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := provider.DecryptDataKey(context.Background(), dataKey.KeyID, dataKey.Wrapped)
	if err != nil || !bytes.Equal(decrypted, dataKey.Plaintext) {
		t.Fatalf("decrypt real data key: equal=%v err=%v", bytes.Equal(decrypted, dataKey.Plaintext), err)
	}
}
