//go:build integration

package store_test

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/cryptokit"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/service"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/ydb-platform/ydb-go-genproto/protos/Ydb"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

func TestYDBEmailVerificationConsumeFailureRollsBackRegistration(t *testing.T) {
	endpoint, path := os.Getenv("TEST_YDB_ENDPOINT"), os.Getenv("TEST_YDB_DATABASE")
	if endpoint == "" || path == "" {
		t.Skip("TEST_YDB_ENDPOINT and TEST_YDB_DATABASE are not set")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "grpc" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1") || path != "/local" {
		t.Fatal("rollback regression requires an explicitly configured loopback /local emulator")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	database := openIntegrationStore(t, ctx)
	productID := "rollback-" + strings.ReplaceAll(newID(t), "-", "")[:12]
	installationID := newID(t)
	if _, _, err := database.CreateInstallation(ctx, store.Installation{
		ID: installationID, ProductID: productID, Platform: "integration",
	}); err != nil {
		t.Fatal(err)
	}
	provider, err := cryptokit.NewLocalAESKeyProvider("integration-kek", bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	indexer, err := cryptokit.NewBlindIndexer(1, map[int][]byte{1: bytes.Repeat([]byte{2}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	identities := service.NewIdentityService(database, cryptokit.NewEnvelope(provider), indexer, false)
	verificationID, _, err := identities.BeginEmailVerification(ctx, service.BeginEmailVerificationInput{
		ProductID: productID, Email: newID(t) + "@example.test", Namespace: "account",
		AgeCategory: "adult", InstallationID: &installationID,
	})
	if err != nil {
		t.Fatal(err)
	}
	verifiedAt := time.Now().UTC().Truncate(time.Microsecond)
	if err := database.VerifyEmailOwnership(ctx, verificationID, productID, "rollback-test", "evidence-"+newID(t), verifiedAt); err != nil {
		t.Fatal(err)
	}
	if err := database.Client().Exec(ctx, `
		DECLARE $verification_id AS Utf8;
		DECLARE $person_id AS Utf8;
		DECLARE $installation_id AS Utf8;
		DECLARE $product_id AS Utf8;
		DECLARE $verified_by AS Utf8;
		DECLARE $evidence_id AS Utf8;
		DECLARE $now AS Timestamp;
		INSERT INTO email_verification_audit (
			verification_id, person_id, installation_id, product_id,
			verified_by, evidence_id, verified_at, consumed_at
		) VALUES (
			$verification_id, $person_id, $installation_id, $product_id,
			$verified_by, $evidence_id, $now, $now
		);`, query.WithParameters(ydb.ParamsBuilder().
		Param("$verification_id").Text(verificationID).
		Param("$person_id").Text(newID(t)).
		Param("$installation_id").Text(installationID).
		Param("$product_id").Text(productID).
		Param("$verified_by").Text("forced-audit-collision").
		Param("$evidence_id").Text(newID(t)).
		Param("$now").Timestamp(verifiedAt).Build())); err != nil {
		t.Fatalf("seed owned audit collision: %v", err)
	}
	before := emailRegistrationRowCounts(t, ctx, database)
	personBefore, versionBefore := emailInstallationLink(t, ctx, database, installationID)
	if personBefore != nil {
		t.Fatal("new installation is already linked")
	}
	if _, err := identities.CompleteEmailVerification(ctx, verificationID, productID, true); !ydb.IsOperationError(err, Ydb.StatusIds_PRECONDITION_FAILED) {
		t.Fatalf("audit collision should fail the actual transaction with PRECONDITION_FAILED: %v", err)
	}
	if after := emailRegistrationRowCounts(t, ctx, database); after != before {
		t.Fatalf("registration writes survived failed consume: before=%v after=%v", before, after)
	}
	personAfter, versionAfter := emailInstallationLink(t, ctx, database, installationID)
	if personAfter != nil || versionAfter != versionBefore {
		t.Fatalf("installation changed after rollback: linked=%v version=%d, want unlinked/version=%d", personAfter != nil, versionAfter, versionBefore)
	}
	row, err := database.Client().QueryRow(ctx, `
		DECLARE $id AS Utf8;
		SELECT verified_at, processing_token, processing_at FROM email_verifications WHERE id = $id;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(verificationID).Build()),
		query.WithTxControl(query.SnapshotReadOnlyTxControl()))
	if err != nil {
		t.Fatalf("challenge disappeared after rollback: %v", err)
	}
	var storedVerifiedAt, processingAt *time.Time
	var claim *string
	if err := row.Scan(&storedVerifiedAt, &claim, &processingAt); err != nil {
		t.Fatal(err)
	}
	if storedVerifiedAt == nil || !storedVerifiedAt.Equal(verifiedAt) || claim != nil || processingAt != nil {
		t.Fatal("failed completion did not preserve verified challenge and release claim")
	}
	if err := database.Client().Exec(ctx, `
		DECLARE $id AS Utf8;
		DELETE FROM email_verification_audit WHERE verification_id = $id;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(verificationID).Build())); err != nil {
		t.Fatalf("remove owned audit collision: %v", err)
	}
	result, err := identities.CompleteEmailVerification(ctx, verificationID, productID, true)
	if err != nil || !result.Created || result.PersonID == "" || result.AccountID == "" {
		t.Fatalf("retry result=%#v err=%v", result, err)
	}
	after := emailRegistrationRowCounts(t, ctx, database)
	for i, count := range after {
		if count != before[i]+1 {
			t.Fatalf("retry row counts=%v, want before=%v plus one in each table", after, before)
		}
	}
	personAfter, versionAfter = emailInstallationLink(t, ctx, database, installationID)
	if personAfter == nil || *personAfter != result.PersonID || versionAfter != versionBefore+1 {
		t.Fatal("retry did not link installation exactly once")
	}
	row, err = database.Client().QueryRow(ctx, `
		DECLARE $id AS Utf8;
		SELECT person_id FROM email_verification_audit WHERE verification_id = $id;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(verificationID).Build()),
		query.WithTxControl(query.SnapshotReadOnlyTxControl()))
	if err != nil {
		t.Fatal(err)
	}
	var auditPerson string
	if err := row.Scan(&auditPerson); err != nil || auditPerson != result.PersonID {
		t.Fatalf("retry audit person=%q err=%v", auditPerson, err)
	}
	if _, err := identities.CompleteEmailVerification(ctx, verificationID, productID, true); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("consumed challenge replay error=%v", err)
	}
	if replay := emailRegistrationRowCounts(t, ctx, database); replay != after {
		t.Fatalf("replay changed registration counts: before=%v after=%v", after, replay)
	}
}

func emailRegistrationRowCounts(t *testing.T, ctx context.Context, database *store.Store) [5]uint64 {
	t.Helper()
	var counts [5]uint64
	for i, table := range [...]string{"persons", "email_identities", "email_blind_indexes", "accounts", "accounts_by_person"} {
		row, err := database.Client().QueryRow(ctx, "SELECT COUNT(*) FROM "+table+";",
			query.WithTxControl(query.SnapshotReadOnlyTxControl()))
		if err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if err := row.Scan(&counts[i]); err != nil {
			t.Fatalf("scan count %s: %v", table, err)
		}
	}
	return counts
}

func emailInstallationLink(t *testing.T, ctx context.Context, database *store.Store, id string) (*string, uint64) {
	t.Helper()
	row, err := database.Client().QueryRow(ctx, `
		DECLARE $id AS Utf8;
		SELECT person_id, version FROM product_installations WHERE id = $id;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(id).Build()),
		query.WithTxControl(query.SnapshotReadOnlyTxControl()))
	if err != nil {
		t.Fatal(err)
	}
	var person *string
	var version uint64
	if err := row.Scan(&person, &version); err != nil {
		t.Fatal(err)
	}
	return person, version
}
