package cryptokit

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

const Algorithm = "AES-256-GCM-ENVELOPE-V1"

type DataKey struct {
	Plaintext []byte
	Wrapped   []byte
	KeyID     string
}

type KeyProvider interface {
	GenerateDataKey(context.Context) (DataKey, error)
	DecryptDataKey(context.Context, string, []byte) ([]byte, error)
}

type Envelope struct {
	provider KeyProvider
}

type Ciphertext struct {
	Algorithm      string
	KeyID          string
	WrappedDataKey []byte
	Nonce          []byte
	Data           []byte
}

func NewEnvelope(provider KeyProvider) *Envelope {
	return &Envelope{provider: provider}
}

func (e *Envelope) Encrypt(ctx context.Context, plaintext, aad []byte) (Ciphertext, error) {
	dataKey, err := e.provider.GenerateDataKey(ctx)
	if err != nil {
		return Ciphertext{}, fmt.Errorf("generate data key: %w", err)
	}
	defer clear(dataKey.Plaintext)
	if len(dataKey.Plaintext) != 32 || len(dataKey.Wrapped) == 0 || dataKey.KeyID == "" {
		return Ciphertext{}, errors.New("key provider returned an invalid data key")
	}

	block, err := aes.NewCipher(dataKey.Plaintext)
	if err != nil {
		return Ciphertext{}, fmt.Errorf("create data cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Ciphertext{}, fmt.Errorf("create data AEAD: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Ciphertext{}, fmt.Errorf("generate data nonce: %w", err)
	}
	return Ciphertext{
		Algorithm:      Algorithm,
		KeyID:          dataKey.KeyID,
		WrappedDataKey: append([]byte(nil), dataKey.Wrapped...),
		Nonce:          nonce,
		Data:           gcm.Seal(nil, nonce, plaintext, aad),
	}, nil
}

func (e *Envelope) Decrypt(ctx context.Context, encrypted Ciphertext, aad []byte) ([]byte, error) {
	if encrypted.Algorithm != Algorithm {
		return nil, errors.New("unsupported envelope algorithm")
	}
	dataKey, err := e.provider.DecryptDataKey(ctx, encrypted.KeyID, encrypted.WrappedDataKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt data key: %w", err)
	}
	defer clear(dataKey)
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, errors.New("invalid data key")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("create data AEAD")
	}
	plaintext, err := gcm.Open(nil, encrypted.Nonce, encrypted.Data, aad)
	if err != nil {
		return nil, errors.New("decrypt envelope")
	}
	return plaintext, nil
}
