package service

import (
	"bytes"
	"context"
	"errors"
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
	verification                                       store.EmailVerification
	atomicCalls, registerCalls, consumeCalls, releases int
	atomicErr                                          error
}

func (f *fakeIdentityStore) CreateEmailVerification(_ context.Context, verification store.EmailVerification) error {
	f.verification = verification
	return nil
}

func (f *fakeIdentityStore) ClaimVerifiedEmail(context.Context, string, string, string, time.Time, time.Duration) (store.EmailVerification, error) {
	return f.verification, nil
}

func (f *fakeIdentityStore) ReleaseEmailVerification(context.Context, string, string) error {
	f.releases++
	return nil
}

func (f *fakeIdentityStore) ConsumeEmailVerification(context.Context, string, string, string, time.Time) error {
	f.consumeCalls++
	return nil
}

func (f *fakeIdentityStore) RegisterEmailIdentity(context.Context, store.NewEmailIdentity, []cryptokit.BlindIndex) (store.EmailIdentity, bool, error) {
	f.registerCalls++
	return store.EmailIdentity{}, false, nil
}

func (f *fakeIdentityStore) RegisterVerifiedEmailIdentity(_ context.Context, id, product, token string, identity store.NewEmailIdentity, indexes []cryptokit.BlindIndex) (store.EmailIdentity, bool, error) {
	f.atomicCalls++
	if id != f.verification.ID || product != f.verification.ProductID || token == "" || !identity.VerifiedAt.Equal(*f.verification.VerifiedAt) || len(indexes) == 0 {
		return store.EmailIdentity{}, false, domain.ErrInvalid
	}
	return store.EmailIdentity{PersonID: "person", AccountID: "account"}, true, f.atomicErr
}

func TestCompleteEmailVerificationUsesAtomicStoreOperation(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure releases claim"}[failure], func(t *testing.T) {
			provider, err := cryptokit.NewLocalAESKeyProvider("test-kek", bytes.Repeat([]byte{1}, 32))
			if err != nil {
				t.Fatal(err)
			}
			indexer, err := cryptokit.NewBlindIndexer(1, map[int][]byte{1: bytes.Repeat([]byte{2}, 32)})
			if err != nil {
				t.Fatal(err)
			}
			fake := &fakeIdentityStore{}
			service := NewIdentityService(fake, cryptokit.NewEnvelope(provider), indexer, false)
			id, _, err := service.BeginEmailVerification(context.Background(), BeginEmailVerificationInput{
				ProductID: "plays", Email: "Owner@Example.test", Namespace: "account", AgeCategory: "adult",
			})
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			fake.verification.VerifiedAt = &now
			if failure {
				fake.atomicErr = errors.New("consume failed")
			}
			result, err := service.CompleteEmailVerification(context.Background(), id, "plays", true)
			if !errors.Is(err, fake.atomicErr) {
				t.Fatalf("completion error: %v", err)
			}
			if !failure && (result.PersonID != "person" || result.AccountID != "account" || !result.Created) {
				t.Fatalf("result: %#v", result)
			}
			if fake.atomicCalls != 1 || fake.registerCalls != 0 || fake.consumeCalls != 0 {
				t.Fatalf("calls atomic=%d registration=%d consume=%d", fake.atomicCalls, fake.registerCalls, fake.consumeCalls)
			}
			if (fake.releases == 1) != failure {
				t.Fatalf("claim releases=%d", fake.releases)
			}
		})
	}
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
