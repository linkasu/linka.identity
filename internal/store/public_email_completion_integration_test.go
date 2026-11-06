//go:build integration

package store_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/ydb-platform/ydb-go-genproto/protos/Ydb"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

func TestYDBPublicOTPCompletionCommitsAttemptsAndAtomicallyIssuesSession(t *testing.T) {
	endpoint := os.Getenv("TEST_YDB_ENDPOINT")
	if endpoint == "" {
		t.Skip("explicit local YDB fixture is not configured")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "grpc" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1") || os.Getenv("TEST_YDB_DATABASE") != "/local" {
		t.Fatal("public OTP tests require a loopback /local emulator")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	database := openIntegrationStore(t, ctx)
	product, installation := "complete-"+newID(t)[:8], newID(t)
	if _, _, err := database.CreateInstallation(ctx, store.Installation{ID: installation, ProductID: product, Platform: "integration"}); err != nil {
		t.Fatal(err)
	}
	c, v, preparer := makePublicChallengeInput(t, ctx, product, installation, product+"@example.test")
	if _, _, err := database.CreatePublicEmailChallenge(ctx, c, v, 200); err != nil {
		t.Fatal(err)
	}
	if err := database.Client().Exec(ctx, `DECLARE $id AS Utf8; UPDATE public_email_challenges SET state='delivered',version=version+1u WHERE id=$id;`, query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(c.ID).Build())); err != nil {
		t.Fatal(err)
	}
	input := store.PublicEmailCompletion{ChallengeID: c.ID, ProductID: product, InstallationID: installation, OTPKeyID: c.OTPKeyID, NonceHash: c.NonceHash, CodeHash: bytes.Repeat([]byte{9}, 32)}
	if _, err := database.CompletePublicEmailChallenge(ctx, input); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("wrong code: %v", err)
	}
	failed, err := database.PublicEmailChallenge(ctx, c.ID)
	if err != nil || failed.Attempts != 1 || failed.State != domain.PublicChallengeDelivered {
		t.Fatalf("failed attempt rolled back or invented success: attempts=%d state=%s error=%v", failed.Attempts, failed.State, err)
	}
	input.NonceHash = bytes.Repeat([]byte{10}, 32)
	if _, err := database.CompletePublicEmailChallenge(ctx, input); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("foreign nonce reached the OTP attempt counter")
	}
	failed, _ = database.PublicEmailChallenge(ctx, c.ID)
	if failed.Attempts != 1 {
		t.Fatal("foreign nonce could lock another flow")
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	input.Identity, input.Indexes, err = preparer.PreparePublicIdentity(ctx, v, now)
	if err != nil {
		t.Fatal(err)
	}
	input.NonceHash, input.CodeHash, input.SessionID = c.NonceHash, c.CodeHash, newID(t)
	refreshHash := sha256.Sum256([]byte(newID(t)))
	input.RefreshHash, input.RefreshExpiresAt = refreshHash[:], now.Add(90*24*time.Hour)
	before := emailRegistrationRowCounts(t, ctx, database)
	if err := database.Client().Exec(ctx, `DECLARE $id AS Utf8; DECLARE $product AS Utf8; DECLARE $now AS Timestamp;
INSERT INTO public_account_audit(id,product_id,session_id,actor,action,entity_id,created_at) VALUES($id,$product,'','fixture','forced-collision','',$now);`, query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(input.SessionID+"-registered").Param("$product").Text(product).Param("$now").Timestamp(now).Build())); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CompletePublicEmailChallenge(ctx, input); !ydb.IsOperationError(err, Ydb.StatusIds_PRECONDITION_FAILED) {
		t.Fatalf("audit failure must reach the real commit: %v", err)
	}
	if after := emailRegistrationRowCounts(t, ctx, database); after != before {
		t.Fatalf("partial identity escaped the failed session/audit transaction: before=%v after=%v", before, after)
	}
	unchanged, err := database.EmailVerification(ctx, c.ID)
	if err != nil || unchanged.VerifiedAt != nil || unchanged.ProcessingToken != nil {
		t.Fatal("failed session transaction left an attested/claimed verification")
	}
	if err := database.Client().Exec(ctx, `DECLARE $id AS Utf8; DELETE FROM public_account_audit WHERE id=$id;`, query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(input.SessionID+"-registered").Build())); err != nil {
		t.Fatal(err)
	}
	result, err := database.CompletePublicEmailChallenge(ctx, input)
	if err != nil || result.Session.ID != input.SessionID || result.Account.AccountID == "" || result.Account.HolderRole != "self" || result.Account.Country != "" {
		t.Fatalf("retry: session=%s account=%s error=%v", result.Session.ID, result.Account.AccountID, err)
	}
	consumed, err := database.PublicEmailChallenge(ctx, c.ID)
	if err != nil || consumed.State != domain.PublicChallengeConsumed || consumed.VerifiedAt == nil || consumed.ConsumedAt == nil || len(consumed.CodeHash) != 0 || len(consumed.Code.Data) != 0 {
		t.Fatal("successful registration did not consume/scrub the OTP")
	}
	if _, err := database.CompletePublicEmailChallenge(ctx, input); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("consumed proof replay: %v", err)
	}
}
