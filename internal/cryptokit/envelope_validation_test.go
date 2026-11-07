package cryptokit

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

func TestEnvelopeRejectsMalformedNonceWithoutPanic(t *testing.T) {
	provider, err := NewLocalAESKeyProvider("test", bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	envelope := NewEnvelope(provider)
	valid, err := envelope.Encrypt(context.Background(), []byte("fixture"), []byte("purpose"))
	if err != nil {
		t.Fatal(err)
	}
	for _, nonce := range [][]byte{nil, {1}, make([]byte, 13)} {
		invalid := valid
		invalid.Nonce = nonce
		if _, err := envelope.Decrypt(context.Background(), invalid, []byte("purpose")); err == nil {
			t.Fatal("invalid nonce was accepted")
		}
	}
}

type weakEnvelopeKeyProvider struct{}

func (weakEnvelopeKeyProvider) GenerateDataKey(context.Context) (DataKey, error) {
	return DataKey{}, nil
}

func (weakEnvelopeKeyProvider) DecryptDataKey(context.Context, string, []byte) ([]byte, error) {
	return make([]byte, 16), nil
}

func TestEnvelopeCannotDowngradeDeclaredAES256ToAES128(t *testing.T) {
	block, _ := aes.NewCipher(make([]byte, 16))
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	weak := Ciphertext{Algorithm: Algorithm, KeyID: "test", WrappedDataKey: []byte{1}, Nonce: nonce, Data: gcm.Seal(nil, nonce, []byte("fixture"), nil)}
	if _, err := NewEnvelope(weakEnvelopeKeyProvider{}).Decrypt(context.Background(), weak, nil); err == nil {
		t.Fatal("AES-128 key was accepted as the AES-256 envelope algorithm")
	}
}
