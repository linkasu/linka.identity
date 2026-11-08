//go:build integration

package store

import (
	"context"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/ids"
	"github.com/linka-cloud/linka.identity/internal/schema"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

func TestYDBConsentTransactionRollbackAfterAllWrites(t *testing.T) {
	endpoint, database := os.Getenv("TEST_YDB_ENDPOINT"), os.Getenv("TEST_YDB_DATABASE")
	if endpoint == "" || database == "" {
		t.Skip("isolated TEST_YDB endpoint is not configured")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "grpc" || (u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") || database != "/local" {
		t.Fatal("requires loopback /local emulator")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	db, err := Open(ctx, endpoint, database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if err := schema.Apply(ctx, db.Client(), time.Now()); err != nil {
		t.Fatal(err)
	}
	root, err := ids.NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	event, err := ids.NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	request, err := ids.NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	product, now := "rollback-"+root, time.Now().UTC().Truncate(time.Millisecond)
	subject := Subject{Kind: "installation", ID: root}
	if _, err := db.RegisterPublicInstallation(ctx, PublicInstallationRegistration{Installation: Installation{ID: root, ProductID: product, Platform: "android"},
		OpaqueKey: "rollback-alias-" + root, Audience: "metric", Preference: "unknown", PreferenceAt: now}); err != nil {
		t.Fatal(err)
	}
	rollback := errors.New("intentional rollback after consent, preference, epoch, outbox and ledger writes")
	err = db.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		state, err := installationConsentWith(ctx, tx, subject, product)
		if err != nil {
			return err
		}
		decision := InstallationConsentDecision{Subject: subject, SubjectKey: "rollback-alias-" + root, ProductID: product,
			RequestID: request, ExpectedVersion: 1, Preference: "allowed", PolicyVersion: "base2026-07-19-v3", RecordedAt: now}
		if _, err := writeManagedConsentWith(ctx, tx, decision, state, event, now); err != nil {
			return err
		}
		if err := tx.Exec(ctx, `DECLARE $product AS Utf8; DECLARE $subject AS Utf8; DECLARE $request AS Utf8; DECLARE $fingerprint AS Utf8;
			INSERT INTO installation_consent_requests (product_id, subject_id, request_id, fingerprint) VALUES ($product,$subject,$request,$fingerprint);`,
			query.WithParameters(ydb.ParamsBuilder().Param("$product").Text(product).Param("$subject").Text(root).
				Param("$request").Text(request).Param("$fingerprint").Text(consentFingerprint(decision)).Build())); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("transaction error: %v", err)
	}
	state, err := db.GetInstallationConsent(ctx, subject, product)
	if err != nil || state.Version != 1 || state.ConsentEpoch != 0 || state.Preference != "unknown" {
		t.Fatal("rolled-back preference or epoch became visible")
	}
	for _, statement := range []string{
		`SELECT COUNT(*) FROM consents WHERE id=$event;`,
		`SELECT COUNT(*) FROM outbox_events WHERE id=$event;`,
		`SELECT COUNT(*) FROM installation_consent_epochs WHERE subject_id=$root;`,
		`SELECT COUNT(*) FROM installation_consent_requests WHERE subject_id=$root;`,
	} {
		row, err := db.Client().QueryRow(ctx, `DECLARE $event AS Utf8; DECLARE $root AS Utf8; `+statement,
			query.WithParameters(ydb.ParamsBuilder().Param("$event").Text(event).Param("$root").Text(root).Build()), query.WithTxControl(query.SnapshotReadOnlyTxControl()))
		if err != nil {
			t.Fatal(err)
		}
		var count uint64
		if err := row.Scan(&count); err != nil || count != 0 {
			t.Fatal("rolled-back consent write leaked")
		}
	}
}
