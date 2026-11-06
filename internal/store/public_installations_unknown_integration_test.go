//go:build integration

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

func TestYDBPublicInstallationUnknownBootstrap(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	db := openIntegrationStore(t, ctx)
	root, product, key := newID(t), "unknown-"+newID(t), opaqueKey(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	input := store.PublicInstallationRegistration{
		Installation: store.Installation{ID: root, ProductID: product, Platform: "android"},
		OpaqueKey:    key, Audience: "metric", Preference: "unknown", PreferenceAt: now,
	}
	registered, err := db.RegisterPublicInstallation(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := db.RegisterPublicInstallation(ctx, input)
	if err != nil || replayed.ID != root || !replayed.CreatedAt.Equal(registered.CreatedAt) {
		t.Fatal("unknown registration replay was not stable")
	}
	subject := store.Subject{Kind: "installation", ID: root}
	preference, err := db.GetTelemetryPreference(ctx, subject, product)
	if err != nil || preference.Preference != "unknown" || !preference.RecordedAt.Equal(now) {
		t.Fatal("explicit unknown preference was not persisted")
	}
	alias, err := db.ResolveSubjectAlias(ctx, key, product, input.Audience)
	if err != nil || alias.SubjectID != root || alias.SubjectType != "installation" {
		t.Fatal("bootstrap alias missing")
	}
	if err := db.ResolveTokenSubject(ctx, product, "installation", root); err != nil {
		t.Fatal("bootstrap installation is not resolvable")
	}
	assertUnknownInstallationCounts(t, ctx, db, root, product, 0, 0)
	malformed := input
	malformed.Consent = store.Consent{ID: newID(t), Status: "granted"}
	if _, err := db.RegisterPublicInstallation(ctx, malformed); !errors.Is(err, domain.ErrInvalid) {
		t.Fatal("unknown accepted supplied consent on replay")
	}
	changed := input
	changed.Preference = "denied"
	changed.SuppressionID = newID(t)
	changed.Consent = store.Consent{ID: newID(t), Subject: subject, ProductID: product, ConsentType: "telemetry", PolicyVersion: "v1", Status: "withdrawn", RecordedAt: now}
	if _, err := db.RegisterPublicInstallation(ctx, changed); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("registration replay mutated unknown preference")
	}
	assertUnknownInstallationCounts(t, ctx, db, root, product, 0, 0)
	denial := store.PublicTelemetryDenial{
		Subject: subject, SubjectKey: key, ProductID: product, RecordedAt: now.Add(time.Second), SuppressionID: newID(t),
		Consent: store.Consent{ID: newID(t), Subject: subject, ProductID: product, ConsentType: "telemetry", PolicyVersion: "v1", Status: "withdrawn", RecordedAt: now.Add(time.Second)},
	}
	for range 2 {
		if _, err := db.DenyPublicInstallation(ctx, denial); err != nil {
			t.Fatal(err)
		}
	}
	preference, err = db.GetTelemetryPreference(ctx, subject, product)
	if err != nil || preference.Preference != "denied" {
		t.Fatal("explicit withdrawal was not persisted")
	}
	assertUnknownInstallationCounts(t, ctx, db, root, product, 1, 1)
	row, err := db.Client().QueryRow(ctx, `DECLARE $root AS Utf8; DECLARE $product AS Utf8;
		SELECT status, consent_type, recorded_at FROM consents
		WHERE subject_type="installation" AND subject_id=$root AND product_id=$product;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$root").Text(root).Param("$product").Text(product).Build()), query.WithTxControl(query.SnapshotReadOnlyTxControl()))
	if err != nil {
		t.Fatal(err)
	}
	var status, consentType string
	var recordedAt time.Time
	if err := row.Scan(&status, &consentType, &recordedAt); err != nil || status != "withdrawn" || consentType != "telemetry" || !recordedAt.Equal(denial.RecordedAt) {
		t.Fatal("denial did not create a real scoped withdrawal")
	}
}

func assertUnknownInstallationCounts(t *testing.T, ctx context.Context, db *store.Store, root, product string, consents, events uint64) {
	t.Helper()
	queries := []struct {
		sql  string
		want uint64
	}{
		{`DECLARE $root AS Utf8; DECLARE $product AS Utf8;
		SELECT COUNT(*) FROM consents WHERE subject_type="installation" AND subject_id=$root AND product_id=$product;`, consents},
		{`DECLARE $root AS Utf8; DECLARE $product AS Utf8;
		SELECT COUNT(*) FROM telemetry_preferences WHERE subject_type="installation" AND subject_id=$root AND product_id=$product;`, 1},
		{`DECLARE $root AS Utf8; DECLARE $product AS Utf8;
		SELECT COUNT(*) FROM outbox_events WHERE aggregate_type="telemetry_preference" AND aggregate_id IN
		(SELECT id FROM telemetry_preferences WHERE subject_type="installation" AND subject_id=$root AND product_id=$product);`, events},
		{`DECLARE $root AS Utf8; DECLARE $product AS Utf8;
		SELECT COUNT(*) FROM outbox_events WHERE topic="telemetry.suppression.requested" AND aggregate_type="telemetry_preference" AND aggregate_id IN
		(SELECT id FROM telemetry_preferences WHERE subject_type="installation" AND subject_id=$root AND product_id=$product);`, events},
	}
	for _, check := range queries {
		row, err := db.Client().QueryRow(ctx, check.sql, query.WithParameters(ydb.ParamsBuilder().Param("$root").Text(root).Param("$product").Text(product).Build()), query.WithTxControl(query.SnapshotReadOnlyTxControl()))
		if err != nil {
			t.Fatal(err)
		}
		var count uint64
		if err := row.Scan(&count); err != nil || count != check.want {
			t.Fatalf("bootstrap record count = %d, want %d (error %v)", count, check.want, err)
		}
	}
}
