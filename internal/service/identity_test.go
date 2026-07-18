package service

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/cryptokit"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/store"
)

func TestDonationAndDefaultIdentityScopesAreProductLocal(t *testing.T) {
	service := &IdentityService{}
	for _, namespace := range []string{"account", "donation"} {
		scope, key, err := service.linkageScope(RegisterEmailIdentityInput{
			Namespace: namespace, ProductID: "plays", AgeCategory: "adult",
		})
		if err != nil || scope != "product" || key != "plays" {
			t.Fatalf("unexpected %s scope: %s %s %v", namespace, scope, key, err)
		}
	}
}

func TestBeginEmailVerificationPersistsOnlyProtectedEmailForms(t *testing.T) {
	provider, err := cryptokit.NewLocalAESKeyProvider("test-kek", bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	indexer, err := cryptokit.NewBlindIndexer(1, map[int][]byte{1: bytes.Repeat([]byte{2}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeIdentityStore{}
	service := NewIdentityServiceWithVerification(fake, cryptokit.NewEnvelope(provider), indexer, false, time.Minute)
	if _, _, err := service.BeginEmailVerification(context.Background(), BeginEmailVerificationInput{
		ProductID: "plays", Email: "Private@Example.test", Namespace: "account", AgeCategory: "adult",
	}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bytes.ToLower(fake.verification.EncryptedEmail.Data), []byte("private@example.test")) {
		t.Fatal("ciphertext contains raw email")
	}
	if len(fake.verification.BlindIndex) != 32 || strings.Contains(string(fake.verification.BlindIndex), "example.test") {
		t.Fatal("blind index does not protect the email")
	}
}

type fakeIdentityStore struct {
	verification store.EmailVerification
}

func (f *fakeIdentityStore) CreateEmailVerification(_ context.Context, verification store.EmailVerification) error {
	f.verification = verification
	return nil
}

func (*fakeIdentityStore) ClaimVerifiedEmail(context.Context, string, string, string, time.Time, time.Duration) (store.EmailVerification, error) {
	return store.EmailVerification{}, domain.ErrNotFound
}

func (*fakeIdentityStore) ReleaseEmailVerification(context.Context, string, string) error {
	return nil
}

func (*fakeIdentityStore) ConsumeEmailVerification(context.Context, string, string, string, time.Time) error {
	return nil
}

func (*fakeIdentityStore) RegisterEmailIdentity(context.Context, store.NewEmailIdentity, []cryptokit.BlindIndex) (store.EmailIdentity, bool, error) {
	return store.EmailIdentity{}, false, nil
}

func TestDonationCannotBeGloballyLinked(t *testing.T) {
	service := &IdentityService{minorCrossProductLinking: true}
	scope, _, err := service.linkageScope(RegisterEmailIdentityInput{
		Namespace: "donation", ProductID: "donations", AgeCategory: "adult", LinkAcrossProducts: true,
	})
	if err != nil || scope != "product" {
		t.Fatalf("donation scope must remain product-local: %s %v", scope, err)
	}
}

func TestMinorGlobalLinkingRequiresFeatureFlag(t *testing.T) {
	service := &IdentityService{}
	_, _, err := service.linkageScope(RegisterEmailIdentityInput{
		Namespace: "account", ProductID: "plays", AgeCategory: "minor", LinkAcrossProducts: true,
	})
	if err != domain.ErrForbidden {
		t.Fatalf("expected forbidden, got %v", err)
	}
	service.minorCrossProductLinking = true
	scope, _, err := service.linkageScope(RegisterEmailIdentityInput{
		Namespace: "account", ProductID: "plays", AgeCategory: "minor", LinkAcrossProducts: true,
	})
	if err != nil || scope != "global" {
		t.Fatalf("expected explicitly enabled global scope, got %s %v", scope, err)
	}
}

func TestNormalizeEmailRejectsDisplayName(t *testing.T) {
	if _, err := normalizeEmail("User <user@example.test>"); err == nil {
		t.Fatal("expected display-name email to be rejected")
	}
	value, err := normalizeEmail(" User@Example.Test ")
	if err != nil || value != "user@example.test" {
		t.Fatalf("unexpected normalization: %q %v", value, err)
	}
}
