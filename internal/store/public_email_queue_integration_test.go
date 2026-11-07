//go:build integration

package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/schema"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

func TestYDBPublicEmailQueue(t *testing.T) {
	endpoint, database := os.Getenv("TEST_YDB_ENDPOINT"), os.Getenv("TEST_YDB_DATABASE")
	if endpoint == "" || database == "" {
		t.Skip("explicit local YDB fixture is not configured")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "grpc" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1") || database != "/local" {
		t.Fatal("queue tests require an explicit loopback /local YDB fixture")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	s, err := Open(ctx, endpoint, database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := schema.Apply(ctx, s.Client(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	// Isolate shared budgets with a private clock; delete only our own reservations.
	now := time.Now().UTC().Truncate(time.Microsecond).Add(7 * 24 * time.Hour)
	s.now = func() time.Time { return now }
	var events, challenges []string
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		for _, id := range challenges {
			if err := s.serializable(cleanup, func(ctx context.Context, tx query.TxActor) error {
				c, err := readPublicChallenge(ctx, tx, id)
				if errors.Is(err, domain.ErrNotFound) {
					return nil
				}
				if err != nil || publicEmailDeliveryAcknowledged(c.State) {
					return err
				}
				return finishPublicChallengeTx(ctx, tx, c, domain.PublicChallengeCancelled, now, nil)
			}); err != nil {
				t.Error(err)
			}
		}
		for _, id := range events {
			if err := s.Client().Exec(cleanup, `DECLARE $id AS Utf8; DELETE FROM public_auth_events WHERE event_id=$id;`, query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(id).Build()), query.WithTxControl(query.SerializableReadWriteTxControl(query.CommitTx()))); err != nil {
				t.Error(err)
			}
		}
	}()
	owner := func() string {
		id := publicDeliveryID(t)
		events = append(events, id)
		return id
	}
	input := func() (PublicEmailChallenge, EmailVerification) {
		c, v := publicDeliveryFixture(t, now)
		index := sha256.Sum256([]byte(c.ID))
		c.EmailBlindIndex, v.BlindIndex = index[:], index[:]
		c.ExpiresAt = now.Add(domain.PublicEmailQueueTTL)
		v.ExpiresAt = c.ExpiresAt
		if _, _, err := s.CreateInstallation(ctx, Installation{ID: c.InstallationID, ProductID: c.ProductID, Platform: "integration"}); err != nil {
			t.Fatal(err)
		}
		events, challenges = append(events, c.ID), append(challenges, c.ID)
		return c, v
	}
	seed := func() PublicEmailChallenge {
		c, v := input()
		if _, created, err := s.CreatePublicEmailChallenge(ctx, c, v, 10000); err != nil || !created {
			t.Fatalf("queue create: created=%v error=%v", created, err)
		}
		return c
	}
	read := func(id string) PublicEmailChallenge {
		c, err := s.PublicEmailChallenge(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	private := func(id string) EmailVerification {
		var v EmailVerification
		if err := s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
			var err error
			v, err = readEmailVerification(ctx, tx, id)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return v
	}
	claim := func(c PublicEmailChallenge, id string, limit uint64) PublicEmailChallenge {
		got, v, err := s.ClaimPublicEmailDelivery(ctx, id, []string{c.ProductID}, limit)
		if err != nil || got.State != domain.PublicChallengeDelivering || got.ID != c.ID || !got.ExpiresAt.Equal(now.Add(domain.PublicEmailCodeTTL)) || !v.ExpiresAt.Equal(got.ExpiresAt) || !got.MailClaimUntil.Equal(now.Add(90*time.Second)) || !got.CreatedAt.Equal(c.CreatedAt) {
			t.Fatalf("activate queued proof: challenge=%+v private_expiry=%v error=%v", got, v.ExpiresAt, err)
		}
		if persisted := private(c.ID); !persisted.ExpiresAt.Equal(v.ExpiresAt) || persisted.Version != v.Version {
			t.Fatal("private verification expiry was not committed atomically")
		}
		return got
	}

	t.Run("capacity rejects before writes and replay is free", func(t *testing.T) {
		first, v := input()
		if _, _, err := s.CreatePublicEmailChallenge(ctx, first, v, 1); err != nil {
			t.Fatal(err)
		}
		if _, created, err := s.CreatePublicEmailChallenge(ctx, first, v, 1); err != nil || created {
			t.Fatalf("full-queue replay: created=%v error=%v", created, err)
		}
		second, v := input()
		_, _, err := s.CreatePublicEmailChallenge(ctx, second, v, 1)
		var rate *PublicRateLimitError
		if !errors.As(err, &rate) || !rate.RetryAt.Equal(now.Add(time.Minute)) {
			t.Fatalf("capacity: %v", err)
		}
		if _, err := s.PublicEmailChallenge(ctx, second.ID); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("full queue wrote challenge: %v", err)
		}
		for _, sql := range []string{
			`DECLARE $id AS Utf8; SELECT COUNT(*) FROM email_verifications WHERE id=$id;`,
			`DECLARE $id AS Utf8; SELECT COUNT(*) FROM public_auth_events WHERE event_id=$id;`,
		} {
			row, err := s.Client().QueryRow(ctx, sql, query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(second.ID).Build()), query.WithTxControl(query.SnapshotReadOnlyTxControl()))
			if err != nil {
				t.Fatal(err)
			}
			var count uint64
			if err := row.Scan(&count); err != nil || count != 0 {
				t.Fatalf("full queue left private rows: %d, %v", count, err)
			}
		}
		if read(first.ID).State != domain.PublicChallengeRequested {
			t.Fatal("capacity rejection cancelled an existing flow")
		}
		correction, correctionV := input()
		correction.ProductID, correction.InstallationID = first.ProductID, first.InstallationID
		correctionV.ProductID, correctionV.InstallationID = first.ProductID, &correction.InstallationID
		// The full-queue exemption must not bypass the same-contact resend limit.
		correction.EmailBlindIndex, correctionV.BlindIndex = first.EmailBlindIndex, first.EmailBlindIndex
		if _, _, err := s.CreatePublicEmailChallenge(ctx, correction, correctionV, 1); !errors.As(err, &rate) {
			t.Fatalf("replacement bypassed resend limit: %v", err)
		}
		if old := read(first.ID); old.State != domain.PublicChallengeRequested || old.Version != 1 || !bytes.Equal(old.Code.Data, first.Code.Data) {
			t.Fatal("rejected replacement mutated old job")
		}
		index := sha256.Sum256([]byte(correction.ID))
		correction.EmailBlindIndex, correctionV.BlindIndex = index[:], index[:]
		if _, created, err := s.CreatePublicEmailChallenge(ctx, correction, correctionV, 1); err != nil || !created {
			t.Fatalf("full-queue correction failed: created=%v error=%v", created, err)
		}
		if old := read(first.ID); old.State != domain.PublicChallengeCancelled || len(old.Code.Data) != 0 || len(old.CodeHash) != 0 {
			t.Fatal("successful correction retained old queued proof")
		}
		if read(correction.ID).State != domain.PublicChallengeRequested {
			t.Fatal("successful correction did not replace the queue slot")
		}
		now = now.Add(49 * time.Hour)
	})
	t.Run("daily budget preserves queue beyond old proof TTL", func(t *testing.T) {
		first, second := seed(), seed()
		firstOwner := owner()
		claimed := claim(first, firstOwner, 1)
		if err := s.FinishPublicEmailDelivery(ctx, first.ID, firstOwner, domain.PublicChallengeDelivered); err != nil {
			t.Fatal(err)
		}
		now = now.Add(2 * time.Second)
		_, _, err := s.ClaimPublicEmailDelivery(ctx, owner(), []string{second.ProductID}, 1)
		var rate *PublicRateLimitError
		if !errors.As(err, &rate) || !rate.RetryAt.Equal(claimed.UpdatedAt.Add(24*time.Hour)) {
			t.Fatalf("daily retry boundary: %v", err)
		}
		queued := read(second.ID)
		if queued.State != domain.PublicChallengeRequested || queued.MailAttempts != 0 || queued.Version != 1 || !bytes.Equal(queued.Code.Data, second.Code.Data) || !bytes.Equal(queued.CodeHash, second.CodeHash) || !queued.ExpiresAt.Equal(second.ExpiresAt) {
			t.Fatal("daily exhaustion mutated queued proof")
		}
		now = first.CreatedAt.Add(25 * time.Hour)
		secondOwner := owner()
		claim(second, secondOwner, 1)
		if err := s.FinishPublicEmailDelivery(ctx, second.ID, secondOwner, domain.PublicChallengeDelivered); err != nil {
			t.Fatal(err)
		}
		now = now.Add(49 * time.Hour)
	})
	t.Run("definite rejection restores queue and increments attempts", func(t *testing.T) {
		c, id := seed(), owner()
		first := claim(c, id, 200)
		retry := now.Add(time.Hour)
		if err := s.DeferPublicEmailDelivery(ctx, c.ID, owner(), retry); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("foreign owner deferred delivery: %v", err)
		}
		if err := s.DeferPublicEmailDelivery(ctx, c.ID, id, retry); err != nil {
			t.Fatal(err)
		}
		queued, v := read(c.ID), private(c.ID)
		if queued.State != domain.PublicChallengeRequested || queued.MailAttempts != 1 || queued.Version != first.Version+1 || queued.MailClaimToken != nil || queued.MailClaimUntil != nil || !queued.ExpiresAt.Equal(c.CreatedAt.Add(domain.PublicEmailQueueTTL)) || !v.ExpiresAt.Equal(queued.ExpiresAt) || v.Version != 3 || !queued.MailAvailableAt.Equal(retry) || !bytes.Equal(queued.Code.Data, c.Code.Data) || !bytes.Equal(queued.CodeHash, c.CodeHash) {
			t.Fatal("defer lost encrypted proof, owner isolation, or queue window")
		}
		row, err := s.Client().QueryRow(ctx, `DECLARE $id AS Utf8; SELECT action FROM public_account_audit WHERE id=$id;`, query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(c.ID+"-deferred-1").Build()), query.WithTxControl(query.SnapshotReadOnlyTxControl()))
		if err != nil {
			t.Fatal(err)
		}
		var action string
		if err := row.Scan(&action); err != nil || action != "email.delivery_deferred" {
			t.Fatalf("defer audit: %q %v", action, err)
		}
		if _, _, err := s.ClaimPublicEmailDelivery(ctx, owner(), []string{c.ProductID}, 200); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("deferred job ignored available-at: %v", err)
		}
		now = retry
		if _, _, err := s.ClaimPublicEmailDelivery(ctx, owner(), []string{c.ProductID}, 1); err == nil {
			t.Fatal("deferral refunded a reserved outbound attempt")
		} else {
			var rate *PublicRateLimitError
			if !errors.As(err, &rate) || !rate.RetryAt.Equal(first.UpdatedAt.Add(24*time.Hour)) {
				t.Fatalf("defer lost reserved attempt: %v", err)
			}
		}
		secondOwner := owner()
		if got := claim(c, secondOwner, 200); got.MailAttempts != 2 {
			t.Fatalf("mail attempts reset: %d", got.MailAttempts)
		}
		if err := s.FinishPublicEmailDelivery(ctx, c.ID, secondOwner, domain.PublicChallengeDelivered); err != nil {
			t.Fatal(err)
		}
		if err := s.DeferPublicEmailDelivery(ctx, c.ID, id, now.Add(time.Minute)); err != nil || read(c.ID).State != domain.PublicChallengeDelivered {
			t.Fatalf("terminal defer resurrected delivery: %v", err)
		}
		now = now.Add(49 * time.Hour)
	})
	t.Run("defer at queue deadline expires and scrubs", func(t *testing.T) {
		c, id := seed(), owner()
		now = c.CreatedAt.Add(domain.PublicEmailQueueTTL - time.Hour)
		claim(c, id, 200)
		if err := s.DeferPublicEmailDelivery(ctx, c.ID, id, c.CreatedAt.Add(domain.PublicEmailQueueTTL)); err != nil {
			t.Fatal(err)
		}
		if got := read(c.ID); got.State != domain.PublicChallengeExpired || len(got.Code.Data) != 0 || len(got.CodeHash) != 0 || got.MailClaimToken != nil {
			t.Fatal("deadline retained sendable proof")
		}
		now = now.Add(49 * time.Hour)
	})
	t.Run("concurrent daily-one claims send exactly once", func(t *testing.T) {
		first, second := seed(), seed()
		owners := []string{owner(), owner()}
		jobs := []PublicEmailChallenge{first, second}
		var wg sync.WaitGroup
		results := make([]error, 2)
		for i := range jobs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, _, results[i] = s.ClaimPublicEmailDelivery(ctx, owners[i], []string{jobs[i].ProductID}, 1)
			}(i)
		}
		wg.Wait()
		claimed, limited := 0, 0
		for i, err := range results {
			var rate *PublicRateLimitError
			if err == nil {
				claimed++
				if err := s.FinishPublicEmailDelivery(ctx, jobs[i].ID, owners[i], domain.PublicChallengeDelivered); err != nil {
					t.Fatal(err)
				}
			} else if errors.As(err, &rate) && rate.RetryAt.Equal(now.Add(24*time.Hour)) {
				limited++
				if read(jobs[i].ID).State != domain.PublicChallengeRequested {
					t.Fatal("losing concurrent claim mutated queue")
				}
			} else {
				t.Fatalf("concurrent claim: %v", err)
			}
		}
		if claimed != 1 || limited != 1 {
			t.Fatalf("claims=%d limited=%d", claimed, limited)
		}
	})
	t.Run("concurrent queue capacity has no phantoms", func(t *testing.T) {
		now = now.Add(49 * time.Hour)
		first, firstV := input()
		second, secondV := input()
		jobs := []PublicEmailChallenge{first, second}
		verifications := []EmailVerification{firstV, secondV}
		results := make([]error, 2)
		var wg sync.WaitGroup
		for i := range jobs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, _, results[i] = s.CreatePublicEmailChallenge(ctx, jobs[i], verifications[i], 1)
			}(i)
		}
		wg.Wait()
		created, limited := 0, 0
		for _, err := range results {
			var rate *PublicRateLimitError
			if err == nil {
				created++
			} else if errors.As(err, &rate) && rate.RetryAt.Equal(now.Add(time.Minute)) {
				limited++
			} else {
				t.Fatalf("concurrent create: %v", err)
			}
		}
		if created != 1 || limited != 1 {
			t.Fatalf("created=%d limited=%d", created, limited)
		}
	})
}
