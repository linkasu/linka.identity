//go:build integration

package store_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

func TestYDBPublicAccountDeletionTransactionAndDurableStatus(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
	defer cancel()
	db := openIntegrationStore(t, ctx)
	f := seedPublicSession(t, ctx, db)
	if err := db.EnsureSubjectAlias(ctx, opaqueKey(t), f.product, "test-metric", "account", f.account); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("test-only-status-secret"))
	input := store.PublicAccountDeletion{SessionID: f.session, AccountID: f.account, ProductID: f.product, RequestID: newID(t), StatusSecretHash: hex.EncodeToString(digest[:]), RequestedAt: time.Now().UTC().Truncate(time.Microsecond)}
	products := map[string]string{f.product: "test-metric"}
	for _, name := range []string{"wrong account", "wrong product", "wrong session"} {
		bad := input
		switch name {
		case "wrong account":
			bad.AccountID = newID(t)
		case "wrong product":
			bad.ProductID = "other-product"
			products[bad.ProductID] = "other-metric"
		case "wrong session":
			bad.SessionID = newID(t)
		}
		if _, err := db.CreatePublicAccountDeletion(ctx, bad, products); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := db.PublicAccountDeletionStatus(ctx, bad.RequestID, bad.ProductID, bad.StatusSecretHash); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("failed creation left capability: %v", err)
		}
	}
	result, err := db.CreatePublicAccountDeletion(ctx, input, products)
	if err != nil || result.Status != "requested" || result.Scope != "product" || result.ProductID == nil || *result.ProductID != f.product {
		t.Fatalf("create: %+v %v", result, err)
	}
	if _, _, err := db.AuthorizedPublicAccountSession(ctx, f.session, f.product); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("pending deletion did not fence session: %v", err)
	}
	if _, err := db.CreatePublicAccountDeletion(ctx, input, products); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("replay bypassed pending fence: %v", err)
	}
	if got, err := db.PublicAccountDeletionStatus(ctx, input.RequestID, f.product, input.StatusSecretHash); err != nil || got.Status != "requested" {
		t.Fatalf("requested status: %+v %v", got, err)
	}
	for _, bad := range []struct{ request, product, hash string }{{newID(t), f.product, input.StatusSecretHash}, {input.RequestID, "other-product", input.StatusSecretHash}, {input.RequestID, f.product, hex.EncodeToString(make([]byte, 32))}} {
		if _, err := db.PublicAccountDeletionStatus(ctx, bad.request, bad.product, bad.hash); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("mismatched capability: %v", err)
		}
	}
	row, err := db.Client().QueryRow(ctx, `DECLARE $request AS Utf8; SELECT id FROM privacy_request_steps WHERE privacy_request_id=$request AND step_type='ydb';`, query.WithParameters(ydb.ParamsBuilder().Param("$request").Text(result.ID).Build()), query.WithTxControl(query.SnapshotReadOnlyTxControl()))
	if err != nil {
		t.Fatal(err)
	}
	var step string
	if err := row.Scan(&step); err != nil {
		t.Fatal(err)
	}
	assertPublicErasureCount(t, ctx, db, "outbox_events", "privacy_request_id", result.ID, 1)
	// Claim this fixture's job only; never consume other integration tests' jobs.
	erasureExec(t, ctx, db, `DECLARE $request AS Utf8; DECLARE $step AS Utf8;
UPDATE privacy_requests SET status='processing' WHERE id=$request;
UPDATE privacy_request_steps SET status='processing',version=2u,attempts=1u WHERE id=$step;`, ydb.ParamsBuilder().Param("$request").Text(result.ID).Param("$step").Text(step).Build())
	if got, err := db.PublicAccountDeletionStatus(ctx, input.RequestID, f.product, input.StatusSecretHash); err != nil || got.Status != "processing" {
		t.Fatalf("processing status: %+v %v", got, err)
	}
	job := store.PrivacyErasureJob{RequestID: result.ID, StepID: step, PersonID: &f.person, ProductID: &f.product, Scope: "product", Version: 2}
	if err := db.ErasePrivacyJob(ctx, job); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("erasure did not wait for downstream receipt: %v", err)
	}
	erasureExec(t, ctx, db, `DECLARE $request AS Utf8;
UPDATE privacy_request_steps SET status='completed' WHERE privacy_request_id=$request AND step_type='metric';`, ydb.ParamsBuilder().Param("$request").Text(result.ID).Build())
	if err := db.ErasePrivacyJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	assertPublicErasureCount(t, ctx, db, "account_sessions", "id", f.session, 0)
	assertPublicErasureCount(t, ctx, db, "product_accounts", "account_id", f.account, 0)
	if got, err := db.PublicAccountDeletionStatus(ctx, input.RequestID, f.product, input.StatusSecretHash); err != nil || got.Status != "completed" || got.CompletedAt == nil {
		t.Fatalf("post-erasure status: %+v %v", got, err)
	}
}

func TestYDBPublicDeletionRechecksRevokedAndExpiredSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	db := openIntegrationStore(t, ctx)
	for _, name := range []string{"revoked", "expired"} {
		t.Run(name, func(t *testing.T) {
			f := seedPublicSession(t, ctx, db)
			if name == "revoked" {
				if err := db.RevokePublicAccountSession(ctx, f.session, f.product); err != nil {
					t.Fatal(err)
				}
			} else {
				mutatePublicSessionFixture(t, ctx, db, f, `UPDATE account_sessions SET expires_at=$now WHERE id=$session;`)
			}
			input := store.PublicAccountDeletion{SessionID: f.session, AccountID: f.account, ProductID: f.product, RequestID: newID(t), StatusSecretHash: hex.EncodeToString(make([]byte, 32)), RequestedAt: time.Now().UTC()}
			if _, err := db.CreatePublicAccountDeletion(ctx, input, map[string]string{f.product: "test-metric"}); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("invalid session accepted: %v", err)
			}
			if _, err := db.PublicAccountDeletionStatus(ctx, input.RequestID, f.product, input.StatusSecretHash); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("invalid session left deletion: %v", err)
			}
		})
	}
}
