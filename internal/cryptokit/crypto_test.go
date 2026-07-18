package cryptokit

import (
	"bytes"
	"context"
	"testing"
)

func TestEnvelopeRoundTripAndAADBinding(t *testing.T) {
	provider, err := NewLocalAESKeyProvider("test-kek", bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	envelope := NewEnvelope(provider)
	encrypted, err := envelope.Encrypt(context.Background(), []byte("private@example.test"), []byte("scope-a"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	plaintext, err := envelope.Decrypt(context.Background(), encrypted, []byte("scope-a"))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(plaintext) != "private@example.test" {
		t.Fatalf("unexpected plaintext: %q", plaintext)
	}
	if _, err := envelope.Decrypt(context.Background(), encrypted, []byte("scope-b")); err == nil {
		t.Fatal("expected different AAD to fail")
	}
}

func TestBlindIndexesAreVersionedAndScoped(t *testing.T) {
	indexer, err := NewBlindIndexer(2, map[int][]byte{
		1: bytes.Repeat([]byte{1}, 32),
		2: bytes.Repeat([]byte{2}, 32),
	})
	if err != nil {
		t.Fatalf("create indexer: %v", err)
	}
	all := indexer.All([]byte("account\x00product\x00a\x00user@example.test"))
	if len(all) != 2 || all[1].Version != 2 {
		t.Fatalf("unexpected indexes: %#v", all)
	}
	other := indexer.Current([]byte("donation\x00product\x00a\x00user@example.test"))
	if bytes.Equal(all[1].Value, other.Value) {
		t.Fatal("identity namespaces must produce different indexes")
	}
}

func TestLocalKeyringDecryptsHistoricalKeyIDs(t *testing.T) {
	oldProvider, err := NewLocalAESKeyProvider("old", bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := NewEnvelope(oldProvider).Encrypt(context.Background(), []byte("historical"), []byte("scope"))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := NewLocalAESKeyring("new", map[string][]byte{
		"old": bytes.Repeat([]byte{1}, 32), "new": bytes.Repeat([]byte{2}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := NewEnvelope(rotated).Decrypt(context.Background(), encrypted, []byte("scope"))
	if err != nil || string(plaintext) != "historical" {
		t.Fatalf("decrypt historical envelope: %q %v", plaintext, err)
	}
}
