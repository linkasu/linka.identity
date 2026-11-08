//go:build integration

package store_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

func TestYDBInstallationConsentCASReplayWritersAndErasure(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	db := openIntegrationStore(t, ctx)
	root, product, key := newID(t), "consent-"+newID(t), opaqueKey(t)
	subject := store.Subject{Kind: "installation", ID: root}
	now := time.Now().UTC().Truncate(time.Millisecond)
	if _, err := db.RegisterPublicInstallation(ctx, store.PublicInstallationRegistration{Installation: store.Installation{ID: root, ProductID: product, Platform: "android"},
		OpaqueKey: key, Audience: "metric", Preference: "unknown", PreferenceAt: now}); err != nil {
		t.Fatal(err)
	}
	// Leave no pending events for the existing legacy integration suite.
	t.Cleanup(func() {
		_ = db.Client().Exec(context.Background(), `DECLARE $id AS Utf8;
			UPDATE outbox_events SET status = "delivered" WHERE aggregate_type = "telemetry_preference" AND aggregate_id IN
			(SELECT id FROM telemetry_preferences WHERE subject_type = "installation" AND subject_id = $id);`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(root).Build()), query.WithTxControl(query.SerializableReadWriteTxControl(query.CommitTx())))
	})
	initial, err := db.GetInstallationConsent(ctx, subject, product)
	if err != nil || initial.Version != 1 || initial.ConsentEpoch != 0 || initial.Preference != "unknown" || initial.DeliveryState != "completed" {
		t.Fatal("incorrect unknown bootstrap")
	}
	grant := store.InstallationConsentDecision{Subject: subject, SubjectKey: key, ProductID: product, RequestID: newID(t), ExpectedVersion: 1,
		Preference: "allowed", PolicyVersion: "base2026-07-19-v3", RecordedAt: now.Add(-48 * time.Hour)}
	current, err := db.SetInstallationConsent(ctx, grant)
	if err != nil || current.Version != 2 || current.ConsentEpoch != 1 || current.DeliveryState != "pending" {
		t.Fatalf("initial grant: %v", err)
	}
	eventID := current.EventID
	if replay, err := db.SetInstallationConsent(ctx, grant); err != nil || replay.EventID != eventID || replay.Version != 2 {
		t.Fatalf("exact replay: %v", err)
	}
	changed := grant
	changed.Preference = "denied"
	if _, err := db.SetInstallationConsent(ctx, changed); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("changed body accepted")
	}
	stale := changed
	stale.RequestID = newID(t)
	if _, err := db.SetInstallationConsent(ctx, stale); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("stale CAS accepted")
	}
	assertConsentCounts(t, ctx, db, root, product, 1, 1, 1)
	completeConsentEvent(t, ctx, db, eventID)
	current, err = db.GetInstallationConsent(ctx, subject, product)
	if err != nil || current.DeliveryState != "completed" || current.Suppressed {
		t.Fatalf("delivery evidence: %v", err)
	}
	denial := grant
	denial.RequestID, denial.ExpectedVersion, denial.Preference = newID(t), 2, "denied"
	denial.RecordedAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	current, err = db.SetInstallationConsent(ctx, denial)
	if err != nil || current.Version != 3 || current.ConsentEpoch != 1 {
		t.Fatalf("old durable denial: %v", err)
	}
	if replay, err := db.SetInstallationConsent(ctx, grant); err != nil || replay.Preference != "denied" || replay.Version != 3 {
		t.Fatal("exact replay returned obsolete grant")
	}
	completeConsentEvent(t, ctx, db, current.EventID)
	if _, err := db.DenyPublicInstallation(ctx, store.PublicTelemetryDenial{Subject: subject, SubjectKey: key, ProductID: product, RecordedAt: now,
		Consent: store.Consent{ID: newID(t), PolicyVersion: grant.PolicyVersion}, SuppressionID: newID(t)}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetTelemetryPreference(ctx, subject, key, product, "allowed", now, now); err != nil {
		t.Fatal(err)
	}
	current, err = db.GetInstallationConsent(ctx, subject, product)
	if err != nil || current.Version != 4 || current.ConsentEpoch != 2 || current.DeliveryState != "pending" {
		t.Fatal("private writer did not atomically update epoch")
	}
	completeConsentEvent(t, ctx, db, current.EventID)
	deniedAt := now.Add(time.Second)
	if _, err := db.DenyPublicInstallation(ctx, store.PublicTelemetryDenial{Subject: subject, SubjectKey: key, ProductID: product, RecordedAt: deniedAt,
		Consent: store.Consent{ID: newID(t), PolicyVersion: grant.PolicyVersion}, SuppressionID: newID(t)}); err != nil {
		t.Fatal(err)
	}
	current, err = db.GetInstallationConsent(ctx, subject, product)
	if err != nil || current.Version != 5 || current.ConsentEpoch != 2 || current.Preference != "denied" {
		t.Fatal("legacy managed denial did not close same epoch")
	}
	completeConsentEvent(t, ctx, db, current.EventID)
	assertConsentCounts(t, ctx, db, root, product, 2, 4, 4)
	var wg sync.WaitGroup
	errorsOut := make(chan error, 2)
	for range 2 {
		decision := grant
		decision.RequestID, decision.ExpectedVersion = newID(t), 5
		wg.Add(1)
		go func() { defer wg.Done(); _, err := db.SetInstallationConsent(ctx, decision); errorsOut <- err }()
	}
	wg.Wait()
	close(errorsOut)
	wins, conflicts := 0, 0
	for err := range errorsOut {
		if err == nil {
			wins++
		} else if errors.Is(err, domain.ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatal("CAS allowed two concurrent winners")
	}
	assertConsentCounts(t, ctx, db, root, product, 3, 5, 5)
	current, err = db.GetInstallationConsent(ctx, subject, product)
	if err != nil || current.ConsentEpoch != 3 || current.Version != 6 {
		t.Fatal("revoked epoch was reused")
	}
	completeConsentEvent(t, ctx, db, current.EventID)
	privacy, _, err := db.CreatePrivacyRequest(ctx, store.PrivacyRequest{Subject: subject, SubjectKey: key, RequestType: "deletion", Scope: "product", ProductID: &product,
		RequestedAt: now, RequestedByWorkload: "consent-integration", IdempotencyKey: newID(t)}, map[string]string{product: "metric"})
	if err != nil {
		t.Fatal(err)
	}
	current, err = db.GetInstallationConsent(ctx, subject, product)
	if err != nil || !current.Suppressed {
		t.Fatal("pending deletion did not suppress collection")
	}
	blocked := grant
	blocked.RequestID, blocked.ExpectedVersion = newID(t), 6
	if _, err := db.SetInstallationConsent(ctx, blocked); !errors.Is(err, domain.ErrForbidden) {
		t.Fatal("grant bypassed deletion")
	}
	assertConsentCounts(t, ctx, db, root, product, 3, 5, 5)
	row, err := db.Client().QueryRow(ctx, `DECLARE $request AS Utf8; SELECT id FROM outbox_events WHERE privacy_request_id = $request;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$request").Text(privacy.ID).Build()), query.WithTxControl(query.SnapshotReadOnlyTxControl()))
	if err != nil {
		t.Fatal(err)
	}
	var deletionEvent string
	if err := row.Scan(&deletionEvent); err != nil {
		t.Fatal(err)
	}
	completeConsentEvent(t, ctx, db, deletionEvent)
	jobs, err := db.ClaimPrivacyErasures(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	erased := false
	for _, job := range jobs {
		if job.RequestID == privacy.ID {
			if err := db.ErasePrivacyJob(ctx, job); err != nil {
				t.Fatal(err)
			}
			erased = true
		}
	}
	if !erased {
		t.Fatal("erasure not claimed")
	}
	if _, err := db.SetInstallationConsent(ctx, grant); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("erased installation resurrected")
	}
	assertConsentCounts(t, ctx, db, root, product, 0, 0, 0)
}

func assertConsentCounts(t *testing.T, ctx context.Context, db *store.Store, root, product string, requests, consents, events uint64) {
	t.Helper()
	for _, check := range []struct {
		sql  string
		want uint64
	}{
		{`SELECT COUNT(*) FROM installation_consent_requests WHERE subject_id=$root AND product_id=$product;`, requests},
		{`SELECT COUNT(*) FROM consents WHERE subject_type="installation" AND subject_id=$root AND product_id=$product;`, consents},
		{`SELECT COUNT(*) FROM outbox_events WHERE topic="telemetry.consent.changed" AND aggregate_id IN (SELECT id FROM telemetry_preferences WHERE subject_type="installation" AND subject_id=$root AND product_id=$product);`, events},
		{`SELECT COUNT(*) FROM outbox_events WHERE topic="telemetry.suppression.requested" AND aggregate_id IN (SELECT id FROM telemetry_preferences WHERE subject_type="installation" AND subject_id=$root AND product_id=$product);`, 0},
	} {
		row, err := db.Client().QueryRow(ctx, `DECLARE $root AS Utf8; DECLARE $product AS Utf8; `+check.sql,
			query.WithParameters(ydb.ParamsBuilder().Param("$root").Text(root).Param("$product").Text(product).Build()), query.WithTxControl(query.SnapshotReadOnlyTxControl()))
		if err != nil {
			t.Fatal(err)
		}
		var count uint64
		if err := row.Scan(&count); err != nil || count != check.want {
			t.Fatalf("atomic count=%d want=%d err=%v", count, check.want, err)
		}
	}
}

func completeConsentEvent(t *testing.T, ctx context.Context, db *store.Store, event string) {
	t.Helper()
	if err := db.Client().Exec(ctx, `DECLARE $id AS Utf8; UPDATE outbox_events SET status="processing" WHERE id=$id;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(event).Build()), query.WithTxControl(query.SerializableReadWriteTxControl(query.CommitTx()))); err != nil {
		t.Fatal(err)
	}
	completeOutbox(t, ctx, db, store.OutboxEvent{ID: event})
}

func TestYDBManagedConsentCannotBypassLegacySuppression(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	db := openIntegrationStore(t, ctx)
	root, product, key := newID(t), "permanent-"+newID(t), opaqueKey(t)
	subject := store.Subject{Kind: "installation", ID: root}
	now := time.Now().UTC().Truncate(time.Millisecond)
	consent := store.Consent{ID: newID(t), Subject: subject, ProductID: product, ConsentType: "telemetry", PolicyVersion: "base2026-07-19-v3", Status: "withdrawn", RecordedAt: now}
	suppression := newID(t)
	if _, err := db.RegisterPublicInstallation(ctx, store.PublicInstallationRegistration{Installation: store.Installation{ID: root, ProductID: product, Platform: "android"},
		OpaqueKey: key, Audience: "metric", Preference: "denied", PreferenceAt: now, Consent: consent, SuppressionID: suppression}); err != nil {
		t.Fatal(err)
	}
	completeConsentEvent(t, ctx, db, suppression)
	decision := store.InstallationConsentDecision{Subject: subject, SubjectKey: key, ProductID: product, RequestID: newID(t), ExpectedVersion: 1,
		Preference: "allowed", PolicyVersion: consent.PolicyVersion, RecordedAt: now}
	if _, err := db.SetInstallationConsent(ctx, decision); !errors.Is(err, domain.ErrForbidden) {
		t.Fatal("grant bypassed unmanaged denial")
	}
	decision.Preference = "denied"
	state, err := db.SetInstallationConsent(ctx, decision)
	if err != nil {
		t.Fatal(err)
	}
	completeConsentEvent(t, ctx, db, state.EventID)
	decision.RequestID, decision.ExpectedVersion, decision.Preference = newID(t), state.Version, "allowed"
	if _, err := db.SetInstallationConsent(ctx, decision); !errors.Is(err, domain.ErrForbidden) {
		t.Fatal("managed conversion bypassed permanent suppression")
	}
}
