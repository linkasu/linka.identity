package cryptokit

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
)

var keyWrapAAD = []byte("linka.identity/data-key/v1")

type LocalAESKeyProvider struct {
	activeKeyID string
	keys        map[string][]byte
}

func NewLocalAESKeyProvider(keyID string, kek []byte) (*LocalAESKeyProvider, error) {
	return NewLocalAESKeyring(keyID, map[string][]byte{keyID: kek})
}

func NewLocalAESKeyring(activeKeyID string, keys map[string][]byte) (*LocalAESKeyProvider, error) {
	if activeKeyID == "" || len(keys) == 0 {
		return nil, errors.New("local key provider requires an active key ID and keyring")
	}
	cloned := make(map[string][]byte, len(keys))
	for keyID, key := range keys {
		if keyID == "" || len(key) != 32 {
			return nil, errors.New("local keyring contains an invalid KEK")
		}
		cloned[keyID] = append([]byte(nil), key...)
	}
	if _, ok := cloned[activeKeyID]; !ok {
		return nil, errors.New("active KEK is absent from local keyring")
	}
	return &LocalAESKeyProvider{activeKeyID: activeKeyID, keys: cloned}, nil
}

func (p *LocalAESKeyProvider) GenerateDataKey(context.Context) (DataKey, error) {
	plaintext := make([]byte, 32)
	if _, err := rand.Read(plaintext); err != nil {
		return DataKey{}, fmt.Errorf("generate random data key: %w", err)
	}
	wrapped, err := p.wrap(p.keys[p.activeKeyID], plaintext)
	if err != nil {
		clear(plaintext)
		return DataKey{}, err
	}
	return DataKey{Plaintext: plaintext, Wrapped: wrapped, KeyID: p.activeKeyID}, nil
}

func (p *LocalAESKeyProvider) DecryptDataKey(_ context.Context, keyID string, wrapped []byte) ([]byte, error) {
	var kek []byte
	for candidateID, candidateKey := range p.keys {
		if subtle.ConstantTimeCompare([]byte(keyID), []byte(candidateID)) == 1 {
			kek = candidateKey
		}
	}
	if kek == nil {
		return nil, errors.New("unknown key ID")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, errors.New("invalid KEK")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("create wrapping AEAD")
	}
	if len(wrapped) < gcm.NonceSize() {
		return nil, errors.New("wrapped data key is truncated")
	}
	plaintext, err := gcm.Open(nil, wrapped[:gcm.NonceSize()], wrapped[gcm.NonceSize():], keyWrapAAD)
	if err != nil {
		return nil, errors.New("unwrap data key")
	}
	return plaintext, nil
}

func (p *LocalAESKeyProvider) wrap(kek, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, errors.New("invalid KEK")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("create wrapping AEAD")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate wrapping nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, keyWrapAAD), nil
}
