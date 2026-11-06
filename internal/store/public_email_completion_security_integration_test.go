//go:build integration

package store_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

func TestYDBPublicOTPCompletionLocksAfterFiveIncorrectCodes(t *testing.T) {
	ctx, db := directoryIntegrationStore(t)
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	c, input := securityCompletionFixture(t, ctx, db)
	wrong := input
	wrong.CodeHash = bytes.Repeat([]byte{9}, 32)
	for attempt := uint64(1); attempt <= 5; attempt++ {
		if _, err := db.CompletePublicEmailChallenge(ctx, wrong); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("incorrect code attempt %d: %v", attempt, err)
		}
		snapshot, err := db.PublicEmailChallenge(ctx, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		wantState := domain.PublicChallengeDelivered
		if attempt == 5 {
			wantState = domain.PublicChallengeLocked
		}
		if snapshot.Attempts != attempt || snapshot.State != wantState || snapshot.VerifiedAt != nil || snapshot.ConsumedAt != nil {
			t.Fatalf("attempt %d: attempts=%d state=%s verified=%v consumed=%v", attempt, snapshot.Attempts, snapshot.State, snapshot.VerifiedAt != nil, snapshot.ConsumedAt != nil)
		}
		if attempt == 5 && (len(snapshot.CodeHash) != 0 || len(snapshot.Code.Data) != 0 || len(snapshot.Code.Nonce) != 0 || len(snapshot.Code.WrappedDataKey) != 0 || snapshot.Code.KeyID != "" || snapshot.Code.Algorithm != "") {
			t.Fatal("locked challenge retained OTP material")
		}
	}
	if _, err := db.CompletePublicEmailChallenge(ctx, input); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("correct proof after lock: %v", err)
	}
	verification, err := db.EmailVerification(ctx, c.ID)
	if err != nil || verification.VerifiedAt != nil || verification.ProcessingToken != nil {
		t.Fatalf("locked proof invented verification or claim: %v", err)
	}
	assertSecurityCompletionRows(t, ctx, db, input, input.SessionID, 0, 0)
	for _, check := range []struct{ sql, id string }{
		{`DECLARE $id AS Utf8; SELECT COUNT(*) FROM accounts WHERE id=$id;`, input.Identity.AccountID},
		{`DECLARE $id AS Utf8; SELECT COUNT(*) FROM persons WHERE id=$id;`, input.Identity.PersonID},
	} {
		assertSecurityCompletionCount(t, ctx, db, check.sql, query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(check.id).Build()), 0)
	}
}

func TestYDBPublicOTPCompletionConcurrentProofHasOneWinner(t *testing.T) {
	ctx, db := directoryIntegrationStore(t)
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	c, first := securityCompletionFixture(t, ctx, db)
	second := first
	second.SessionID, second.RefreshHash = newID(t), sessionTestHash(t)
	inputs := []store.PublicEmailCompletion{first, second}
	type completionResult struct {
		input        store.PublicEmailCompletion
		registration store.PublicEmailRegistration
		err          error
	}
	start := make(chan struct{})
	results := make(chan completionResult, len(inputs))
	for _, input := range inputs {
		go func() {
			<-start
			registration, err := db.CompletePublicEmailChallenge(ctx, input)
			results <- completionResult{input: input, registration: registration, err: err}
		}()
	}
	close(start)
	winners, rejected := 0, 0
	for range inputs {
		result := <-results
		switch {
		case result.err == nil:
			winners++
			if result.registration.Session.ID != result.input.SessionID || result.registration.Account.AccountID == "" {
				t.Fatal("winner did not receive its prepared session/account")
			}
			if _, _, err := db.AuthorizedPublicAccountSession(ctx, result.input.SessionID, first.ProductID); err != nil {
				t.Fatalf("winning session is not valid: %v", err)
			}
		case errors.Is(result.err, domain.ErrNotFound):
			rejected++
			if _, _, err := db.AuthorizedPublicAccountSession(ctx, result.input.SessionID, first.ProductID); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("losing session became valid: %v", err)
			}
		default:
			t.Errorf("concurrent completion: %v", result.err)
		}
	}
	if winners != 1 || rejected != 1 {
		t.Fatalf("expected one success and one not-found: successes=%d not-found=%d", winners, rejected)
	}
	assertSecurityCompletionRows(t, ctx, db, first, second.SessionID, 1, 1)
	snapshot, err := db.PublicEmailChallenge(ctx, c.ID)
	if err != nil || snapshot.State != domain.PublicChallengeConsumed || snapshot.VerifiedAt == nil || snapshot.ConsumedAt == nil || len(snapshot.CodeHash) != 0 || len(snapshot.Code.Data) != 0 {
		t.Fatalf("winner did not consume/scrub proof: %v", err)
	}
	for _, input := range inputs {
		if _, err := db.CompletePublicEmailChallenge(ctx, input); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("consumed proof replay: %v", err)
		}
	}
	assertSecurityCompletionRows(t, ctx, db, first, second.SessionID, 1, 1)
}

func securityCompletionFixture(t *testing.T, ctx context.Context, db *store.Store) (store.PublicEmailChallenge, store.PublicEmailCompletion) {
	t.Helper()
	product, installation := "otp-security-"+newID(t), newID(t)
	if _, _, err := db.CreateInstallation(ctx, store.Installation{ID: installation, ProductID: product, Platform: "integration"}); err != nil {
		t.Fatal(err)
	}
	c, v, preparer := makePublicChallengeInput(t, ctx, product, installation, product+"@example.test")
	if _, created, err := db.CreatePublicEmailChallenge(ctx, c, v, 200); err != nil || !created {
		t.Fatalf("create owned challenge: created=%v error=%v", created, err)
	}
	if err := db.Client().Exec(ctx, `DECLARE $id AS Utf8; UPDATE public_email_challenges SET state='delivered',version=version+1u WHERE id=$id;`, query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(c.ID).Build())); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	identity, indexes, err := preparer.PreparePublicIdentity(ctx, v, now)
	if err != nil {
		t.Fatal(err)
	}
	return c, store.PublicEmailCompletion{ChallengeID: c.ID, ProductID: product, InstallationID: installation, OTPKeyID: c.OTPKeyID,
		NonceHash: c.NonceHash, CodeHash: c.CodeHash, Identity: identity, Indexes: indexes, SessionID: newID(t), RefreshHash: sessionTestHash(t), RefreshExpiresAt: now.Add(89 * 24 * time.Hour)}
}

func assertSecurityCompletionRows(t *testing.T, ctx context.Context, db *store.Store, input store.PublicEmailCompletion, otherSession string, sessions, identities uint64) {
	t.Helper()
	assertSecurityCompletionCount(t, ctx, db, `DECLARE $product AS Utf8; DECLARE $first AS Utf8; DECLARE $second AS Utf8;
SELECT COUNT(*) FROM account_sessions WHERE product_id=$product AND (id=$first OR id=$second);`,
		query.WithParameters(ydb.ParamsBuilder().Param("$product").Text(input.ProductID).Param("$first").Text(input.SessionID).Param("$second").Text(otherSession).Build()), sessions)
	assertSecurityCompletionCount(t, ctx, db, `DECLARE $product AS Utf8; SELECT COUNT(*) FROM product_accounts WHERE product_id=$product;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$product").Text(input.ProductID).Build()), identities)
	assertSecurityCompletionCount(t, ctx, db, `DECLARE $product AS Utf8; SELECT COUNT(*) FROM email_identities WHERE product_id=$product;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$product").Text(input.ProductID).Build()), identities)
}

func assertSecurityCompletionCount(t *testing.T, ctx context.Context, db *store.Store, sql string, params query.ExecuteOption, want uint64) {
	t.Helper()
	row, err := db.Client().QueryRow(ctx, sql, params, query.WithTxControl(query.SnapshotReadOnlyTxControl()))
	if err != nil {
		t.Fatal(err)
	}
	var count uint64
	if err := row.Scan(&count); err != nil || count != want {
		t.Fatalf("owned fixture row count: got=%d want=%d error=%v", count, want, err)
	}
}
