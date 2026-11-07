//go:build integration

package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/cryptokit"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/schema"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

func TestYDBPublicEmailDelivery(t *testing.T) {
	endpoint, path := os.Getenv("TEST_YDB_ENDPOINT"), os.Getenv("TEST_YDB_DATABASE")
	if endpoint == "" || path == "" {
		t.Skip("explicit local YDB fixture is not configured")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "grpc" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1") || path != "/local" {
		t.Fatal("delivery tests require an explicit loopback /local YDB fixture")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	s, err := Open(ctx, endpoint, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := schema.Apply(ctx, s.Client(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	// Advance a private server clock, not wall time; remove only this test's rate reservations.
	now := time.Now().UTC().Truncate(time.Microsecond).Add(24 * time.Hour)
	s.now = func() time.Time { return now }
	owner := publicDeliveryID(t)
	events := []string{owner}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		for _, event := range events {
			if err := s.Client().Exec(cleanup, `DECLARE $event AS Utf8; DELETE FROM public_auth_events WHERE event_id=$event;`, query.WithParameters(ydb.ParamsBuilder().Param("$event").Text(event).Build()), query.WithTxControl(query.SerializableReadWriteTxControl(query.CommitTx()))); err != nil {
				t.Error(err)
			}
		}
	}()
	seed := func() (PublicEmailChallenge, EmailVerification) {
		t.Helper()
		c, v := publicDeliveryFixture(t, now)
		events = append(events, c.ID)
		provider, err := cryptokit.NewLocalAESKeyProvider("integration-kek", bytes.Repeat([]byte{1}, 32))
		if err != nil {
			t.Fatal(err)
		}
		envelope := cryptokit.NewEnvelope(provider)
		c.Code, err = envelope.Encrypt(ctx, []byte("123456"), []byte(c.ID))
		if err != nil {
			t.Fatal(err)
		}
		v.EncryptedEmail, err = envelope.Encrypt(ctx, []byte(c.ID+"@example.test"), []byte(c.ID))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.CreateInstallation(ctx, Installation{ID: c.InstallationID, ProductID: c.ProductID, Platform: "integration"}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.CreatePublicEmailChallenge(ctx, c, v, 10000); err != nil {
			t.Fatal(err)
		}
		return c, v
	}
	claim := func(c PublicEmailChallenge) PublicEmailChallenge {
		t.Helper()
		now = now.Add(2 * time.Second)
		got, v, err := s.ClaimPublicEmailDelivery(ctx, owner, []string{c.ProductID}, 10000)
		if err != nil || got.ID != c.ID || got.State != domain.PublicChallengeDelivering || got.MailAttempts != 1 || got.MailClaimToken == nil || *got.MailClaimToken != owner || v.ID != c.ID || !got.MailClaimUntil.Equal(now.Add(90*time.Second)) {
			t.Fatalf("claim: state=%s error=%v", got.State, err)
		}
		return got
	}
	assertScrubbed := func(id string, state domain.PublicChallengeState, hash bool) PublicEmailChallenge {
		t.Helper()
		got, err := s.PublicEmailChallenge(ctx, id)
		if err != nil || got.State != state || len(got.Code.Data) != 0 || len(got.Code.Nonce) != 0 || len(got.Code.WrappedDataKey) != 0 || got.Code.KeyID != "" || got.Code.Algorithm != "" || got.MailClaimToken != nil || got.MailClaimUntil != nil || (len(got.CodeHash) == 32) != hash {
			t.Fatalf("scrub: state=%s error=%v", got.State, err)
		}
		return got
	}
	complete := func(c PublicEmailChallenge, v EmailVerification) {
		t.Helper()
		refreshHash := sha256.Sum256([]byte(c.ID))
		identity := NewEmailIdentity{ID: publicDeliveryID(t), PersonID: publicDeliveryID(t), AccountID: publicDeliveryID(t), ProductID: c.ProductID, Namespace: "account", LinkageScope: "product", ScopeKey: c.ProductID, BlindIndexVersion: 1, BlindIndex: v.BlindIndex, EncryptedEmail: v.EncryptedEmail, AgeCategory: "unknown", VerifiedAt: now, CreateAccount: true, InstallationID: v.InstallationID}
		result, err := s.CompletePublicEmailChallenge(ctx, PublicEmailCompletion{ChallengeID: c.ID, ProductID: c.ProductID, InstallationID: c.InstallationID, NonceHash: c.NonceHash, CodeHash: c.CodeHash, OTPKeyID: c.OTPKeyID, Identity: identity, Indexes: []cryptokit.BlindIndex{{Version: 1, Value: v.BlindIndex}}, SessionID: publicDeliveryID(t), RefreshHash: refreshHash[:], RefreshExpiresAt: now.Add(time.Hour)})
		if err != nil || result.Session.ID == "" {
			t.Fatalf("proof after delivery: %v", err)
		}
	}

	t.Run("claim once and global rate boundary", func(t *testing.T) {
		first, _ := seed()
		second, _ := seed()
		if _, _, err := s.ClaimPublicEmailDelivery(ctx, owner, []string{"not-registered"}, 10000); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("allowlist escaped: %v", err)
		}
		claim(first)
		if _, _, err := s.ClaimPublicEmailDelivery(ctx, owner, []string{first.ProductID}, 10000); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("claimed twice: %v", err)
		}
		_, v, err := s.ClaimPublicEmailDelivery(ctx, owner, []string{second.ProductID}, 10000)
		var rate *PublicRateLimitError
		if !errors.As(err, &rate) || v.ID != "" || !rate.RetryAt.Equal(now.Add(time.Second)) {
			t.Fatalf("global rate boundary: %v", err)
		}
		unchanged, err := s.PublicEmailChallenge(ctx, second.ID)
		if err != nil || unchanged.State != domain.PublicChallengeRequested || unchanged.MailAttempts != 0 || unchanged.Version != 1 {
			t.Fatalf("rate limit mutated queue: %v", err)
		}
		if err := s.FinishPublicEmailDelivery(ctx, first.ID, publicDeliveryID(t), domain.PublicChallengeDelivered); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("stale owner accepted: %v", err)
		}
		if err := s.FinishPublicEmailDelivery(ctx, first.ID, owner, domain.PublicChallengeDelivered); err != nil {
			t.Fatal(err)
		}
		assertScrubbed(first.ID, domain.PublicChallengeDelivered, true)
		claim(second)
		if err := s.FinishPublicEmailDelivery(ctx, second.ID, owner, domain.PublicChallengeDeliveryFailed); err != nil {
			t.Fatal(err)
		}
		assertScrubbed(second.ID, domain.PublicChallengeDeliveryFailed, false)
	})
	t.Run("interrupted send remains uncertain and accepts proof", func(t *testing.T) {
		c, v := seed()
		claim(c)
		now = now.Add(91 * time.Second)
		got, private, err := s.ClaimPublicEmailDelivery(ctx, publicDeliveryID(t), []string{c.ProductID}, 10000)
		if err != nil || got.ID != c.ID || got.State != domain.PublicChallengeDeliveryUncertain || private.ID != "" {
			t.Fatalf("interrupted claim: %v", err)
		}
		assertScrubbed(c.ID, domain.PublicChallengeDeliveryUncertain, true)
		if err := s.DeferPublicEmailDelivery(ctx, c.ID, owner, now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		assertScrubbed(c.ID, domain.PublicChallengeDeliveryUncertain, true)
		if err := s.FinishPublicEmailDelivery(ctx, c.ID, owner, domain.PublicChallengeDelivered); err != nil {
			t.Fatal(err)
		}
		assertScrubbed(c.ID, domain.PublicChallengeDeliveryUncertain, true)
		if _, _, err := s.ClaimPublicEmailDelivery(ctx, owner, []string{c.ProductID}, 10000); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("uncertain message requeued: %v", err)
		}
		complete(c, v)
		assertScrubbed(c.ID, domain.PublicChallengeConsumed, false)
		if err := s.FinishPublicEmailDelivery(ctx, c.ID, owner, domain.PublicChallengeDeliveryFailed); err != nil {
			t.Fatal(err)
		}
		assertScrubbed(c.ID, domain.PublicChallengeConsumed, false)
	})
	t.Run("consume while SMTP in flight", func(t *testing.T) {
		c, v := seed()
		claim(c)
		complete(c, v)
		if err := s.FinishPublicEmailDelivery(ctx, c.ID, owner, domain.PublicChallengeDelivered); err != nil {
			t.Fatal(err)
		}
		assertScrubbed(c.ID, domain.PublicChallengeConsumed, false)
	})
	t.Run("null interrupted claim takes priority over requested", func(t *testing.T) {
		c, _ := seed()
		claim(c)
		queued, _ := seed()
		if err := s.Client().Exec(ctx, `DECLARE $id AS Utf8; UPDATE public_email_challenges SET mail_claim_until=NULL WHERE id=$id;`, query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(c.ID).Build()), query.WithTxControl(query.SerializableReadWriteTxControl(query.CommitTx()))); err != nil {
			t.Fatal(err)
		}
		got, v, err := s.ClaimPublicEmailDelivery(ctx, owner, []string{queued.ProductID, c.ProductID}, 10000)
		if err != nil || got.ID != c.ID || got.State != domain.PublicChallengeDeliveryUncertain || v.ID != "" {
			t.Fatalf("interrupted priority: %v", err)
		}
		claim(queued)
		if err := s.FinishPublicEmailDelivery(ctx, queued.ID, owner, domain.PublicChallengeDeliveryUncertain); err != nil {
			t.Fatal(err)
		}
		assertScrubbed(queued.ID, domain.PublicChallengeDeliveryUncertain, true)
	})
	t.Run("cancel while SMTP in flight", func(t *testing.T) {
		c, _ := seed()
		claim(c)
		if err := s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
			current, err := readPublicChallenge(ctx, tx, c.ID)
			if err != nil {
				return err
			}
			return finishPublicChallengeTx(ctx, tx, current, domain.PublicChallengeCancelled, now, nil)
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.FinishPublicEmailDelivery(ctx, c.ID, owner, domain.PublicChallengeDelivered); err != nil {
			t.Fatal(err)
		}
		assertScrubbed(c.ID, domain.PublicChallengeCancelled, false)
	})
	t.Run("superseded and expired never send", func(t *testing.T) {
		c, _ := seed()
		if err := s.Client().Exec(ctx, `DECLARE $product AS Utf8; DECLARE $installation AS Utf8; DELETE FROM public_registration_flows WHERE product_id=$product AND installation_id=$installation;`, query.WithParameters(ydb.ParamsBuilder().Param("$product").Text(c.ProductID).Param("$installation").Text(c.InstallationID).Build()), query.WithTxControl(query.SerializableReadWriteTxControl(query.CommitTx()))); err != nil {
			t.Fatal(err)
		}
		got, v, err := s.ClaimPublicEmailDelivery(ctx, owner, []string{c.ProductID}, 10000)
		if err != nil || got.State != domain.PublicChallengeCancelled || v.ID != "" {
			t.Fatalf("superseded: %v", err)
		}
		assertScrubbed(c.ID, domain.PublicChallengeCancelled, false)
		c, _ = seed()
		now = c.ExpiresAt
		got, v, err = s.ClaimPublicEmailDelivery(ctx, owner, []string{c.ProductID}, 10000)
		if err != nil || got.State != domain.PublicChallengeExpired || v.ID != "" {
			t.Fatalf("expired: %v", err)
		}
		assertScrubbed(c.ID, domain.PublicChallengeExpired, false)
	})
}
