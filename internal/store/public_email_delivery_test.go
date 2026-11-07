package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/cryptokit"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/ids"
)

func publicDeliveryID(t *testing.T) string {
	t.Helper()
	id, err := ids.NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func publicDeliveryFixture(t *testing.T, now time.Time) (PublicEmailChallenge, EmailVerification) {
	t.Helper()
	id, installation := publicDeliveryID(t), publicDeliveryID(t)
	cipher := cryptokit.Ciphertext{Data: []byte{1}, Nonce: []byte{2}, WrappedDataKey: []byte{3}, KeyID: "delivery-test", Algorithm: "test"}
	c := PublicEmailChallenge{ID: id, ProductID: "delivery-" + id, InstallationID: installation, Purpose: "product_registration", HolderRole: "self",
		RequestFingerprint: bytes.Repeat([]byte{1}, 32), NonceHash: bytes.Repeat([]byte{2}, 32), CodeHash: bytes.Repeat([]byte{3}, 32), OTPKeyID: "test", Code: cipher,
		EmailBlindIndexVersion: 1, EmailBlindIndex: bytes.Repeat([]byte{4}, 32), State: domain.PublicChallengeRequested,
		MailAvailableAt: now, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(10 * time.Minute), Version: 1}
	v := EmailVerification{ID: id, ProductID: c.ProductID, InstallationID: &installation, Namespace: "account", AgeCategory: "unknown", BlindIndexVersion: 1, BlindIndex: c.EmailBlindIndex, EncryptedEmail: cipher, ExpiresAt: c.ExpiresAt, Version: 1}
	return c, v
}

func TestPublicEmailDeliveryGuards(t *testing.T) {
	s := &Store{}
	owner := publicDeliveryID(t)
	for _, tc := range []struct {
		owner    string
		products []string
		want     error
	}{
		{owner, nil, domain.ErrNotFound}, {"bad", []string{"test"}, domain.ErrInvalid},
		{owner, []string{"test", "test"}, domain.ErrInvalid}, {owner, []string{"bad product"}, domain.ErrInvalid},
		{owner, make([]string, 101), domain.ErrInvalid},
	} {
		c, v, err := s.ClaimPublicEmailDelivery(context.Background(), tc.owner, tc.products, 200)
		if !errors.Is(err, tc.want) || c.ID != "" || v.ID != "" {
			t.Fatalf("claim guard: %v", err)
		}
	}
	for _, limit := range []uint64{0, 10001} {
		if _, _, err := s.ClaimPublicEmailDelivery(context.Background(), owner, []string{"test"}, limit); !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("daily limit %d accepted: %v", limit, err)
		}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	s.now = func() time.Time { return now }
	for _, retry := range []time.Time{now, now.Add(-time.Second), now.Add(24*time.Hour + time.Microsecond)} {
		if err := s.DeferPublicEmailDelivery(context.Background(), publicDeliveryID(t), owner, retry); !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("invalid defer retry accepted: %v", err)
		}
	}
	if err := s.DeferPublicEmailDelivery(context.Background(), "bad", owner, now.Add(time.Minute)); !errors.Is(err, domain.ErrInvalid) {
		t.Fatal(err)
	}
	if err := s.DeferPublicEmailDelivery(context.Background(), publicDeliveryID(t), "bad", now.Add(time.Minute)); !errors.Is(err, domain.ErrInvalid) {
		t.Fatal(err)
	}
	for _, state := range []domain.PublicChallengeState{domain.PublicChallengeRequested, domain.PublicChallengeDelivering, domain.PublicChallengeVerified, domain.PublicChallengeConsumed, domain.PublicChallengeCancelled, domain.PublicChallengeExpired, domain.PublicChallengeLocked, "invalid"} {
		if err := s.FinishPublicEmailDelivery(context.Background(), publicDeliveryID(t), owner, state); !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("finish accepted %s", state)
		}
	}
	if err := s.FinishPublicEmailDelivery(context.Background(), "bad", owner, domain.PublicChallengeDelivered); !errors.Is(err, domain.ErrInvalid) {
		t.Fatal(err)
	}
	if err := s.FinishPublicEmailDelivery(context.Background(), publicDeliveryID(t), "bad", domain.PublicChallengeDelivered); !errors.Is(err, domain.ErrInvalid) {
		t.Fatal(err)
	}
}

func TestPublicEmailDeliveryBinding(t *testing.T) {
	mutations := map[string]func(*PublicEmailChallenge, *EmailVerification){
		"id":                   func(_ *PublicEmailChallenge, v *EmailVerification) { v.ID = publicDeliveryID(t) },
		"product":              func(_ *PublicEmailChallenge, v *EmailVerification) { v.ProductID = "other" },
		"installation missing": func(_ *PublicEmailChallenge, v *EmailVerification) { v.InstallationID = nil },
		"installation":         func(_ *PublicEmailChallenge, v *EmailVerification) { id := publicDeliveryID(t); v.InstallationID = &id },
		"namespace":            func(_ *PublicEmailChallenge, v *EmailVerification) { v.Namespace = "other" },
		"age":                  func(_ *PublicEmailChallenge, v *EmailVerification) { v.AgeCategory = "adult" },
		"guardian":             func(_ *PublicEmailChallenge, v *EmailVerification) { s := "parent"; v.GuardianRelationship = &s },
		"cross product":        func(_ *PublicEmailChallenge, v *EmailVerification) { v.LinkAcrossProducts = true },
		"index version":        func(_ *PublicEmailChallenge, v *EmailVerification) { v.BlindIndexVersion++ },
		"index":                func(_ *PublicEmailChallenge, v *EmailVerification) { v.BlindIndex = bytes.Repeat([]byte{9}, 32) },
		"proof":                func(c *PublicEmailChallenge, _ *EmailVerification) { c.CodeHash = nil },
		"code":                 func(c *PublicEmailChallenge, _ *EmailVerification) { c.Code.Data = nil },
		"address":              func(_ *PublicEmailChallenge, v *EmailVerification) { v.EncryptedEmail.Data = nil },
		"verified":             func(_ *PublicEmailChallenge, v *EmailVerification) { now := time.Now(); v.VerifiedAt = &now },
		"verified by":          func(_ *PublicEmailChallenge, v *EmailVerification) { value := "verifier"; v.VerifiedBy = &value },
		"claimed":              func(_ *PublicEmailChallenge, v *EmailVerification) { s := "worker"; v.ProcessingToken = &s },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			c, v := publicDeliveryFixture(t, time.Now().UTC())
			if !validPublicEmailDeliveryBinding(c, v) {
				t.Fatal("valid fixture rejected")
			}
			mutate(&c, &v)
			if validPublicEmailDeliveryBinding(c, v) {
				t.Fatal("corrupt binding accepted")
			}
		})
	}
}

func TestPublicEmailDeliveryAcknowledgmentMatrix(t *testing.T) {
	for _, state := range []domain.PublicChallengeState{domain.PublicChallengeRequested, domain.PublicChallengeDelivering, domain.PublicChallengeDelivered, domain.PublicChallengeVerified, domain.PublicChallengeConsumed, domain.PublicChallengeDeliveryFailed, domain.PublicChallengeDeliveryUncertain, domain.PublicChallengeExpired, domain.PublicChallengeLocked, domain.PublicChallengeCancelled, "invalid"} {
		want := state == domain.PublicChallengeConsumed || state == domain.PublicChallengeDeliveryFailed || state == domain.PublicChallengeDeliveryUncertain || state == domain.PublicChallengeDelivered || state == domain.PublicChallengeExpired || state == domain.PublicChallengeLocked || state == domain.PublicChallengeCancelled
		if publicEmailDeliveryAcknowledged(state) != want {
			t.Fatalf("ack state %s", state)
		}
	}
	cause := errors.New("private bound value")
	err := publicEmailDeliveryError{cause: cause}
	if err.Error() == cause.Error() || !errors.Is(err, cause) {
		t.Fatal("storage error leaked values or lost retry cause")
	}
}
