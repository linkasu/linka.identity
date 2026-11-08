//go:build integration

package store_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/installationbroker"
	"github.com/linka-cloud/linka.identity/internal/pairwise"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/linka-cloud/linka.identity/internal/token"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

func TestYDBInstallationConsentLinkedAccountPrivacyPrecedence(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
	defer cancel()
	db := openIntegrationStore(t, ctx)
	for _, test := range []struct {
		name, preference, deletion, scope string
		permanent                         bool
	}{
		{name: "product opt-out", preference: "denied", scope: "product"},
		{name: "global opt-out", preference: "denied", scope: "all"},
		{name: "permanent suppression despite allowed preference", preference: "allowed", scope: "product", permanent: true},
		{name: "pending product deletion", deletion: "requested", scope: "product"},
		{name: "processing product deletion", deletion: "processing", scope: "product"},
		{name: "completed product deletion", deletion: "completed", scope: "product"},
		{name: "global deletion", deletion: "requested", scope: "all"},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Millisecond)
			person, account, product, other := newID(t), newID(t), "account-a-"+newID(t), "account-b-"+newID(t)
			signer, err := token.NewSigner(bytes.Repeat([]byte{1}, 32), "test", "issuer", time.Minute, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			generator, err := pairwise.New(bytes.Repeat([]byte{2}, 32))
			if err != nil {
				t.Fatal(err)
			}
			broker, err := installationbroker.New(db, signer, generator, installationbroker.Config{
				Products:             map[string]installationbroker.Product{product: {Audience: "metric"}, other: {Audience: "metric"}},
				RegistrationProducts: map[string]struct{}{product: {}, other: {}}, PolicyVersion: "base2026-07-19-v3", RefreshTTL: 24 * time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			decisions := make(map[string]store.InstallationConsentDecision)
			credentials := make(map[string]string)
			for _, p := range []string{product, other} {
				root := newID(t)
				key := generator.Subject(p, "metric", "installation", root)
				if _, err := db.RegisterPublicInstallation(ctx, store.PublicInstallationRegistration{
					Installation: store.Installation{ID: root, ProductID: p, Platform: "android"}, OpaqueKey: key,
					Audience: "metric", Preference: "unknown", PreferenceAt: now}); err != nil {
					t.Fatal(err)
				}
				decision := store.InstallationConsentDecision{Subject: store.Subject{Kind: "installation", ID: root}, SubjectKey: key,
					ProductID: p, RequestID: newID(t), ExpectedVersion: 1, Preference: "allowed", PolicyVersion: "base2026-07-19-v3", RecordedAt: now}
				state, err := db.SetInstallationConsent(ctx, decision)
				if err != nil {
					t.Fatal(err)
				}
				completeConsentEvent(t, ctx, db, state.EventID)
				decision.ExpectedVersion, decision.RequestID = 2, newID(t)
				decisions[p] = decision
				credential, _, err := signer.SignRefresh(p, key, decision.PolicyVersion, 24*time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				credentials[p] = credential
			}
			// Standard typed membership exists only for product A; sharing person_id alone must not link product B.
			if err := db.Client().Exec(ctx, `DECLARE $person AS Utf8; DECLARE $account AS Utf8; DECLARE $product AS Utf8;
				DECLARE $installation AS Utf8; DECLARE $other AS Utf8; DECLARE $identity AS Utf8; DECLARE $now AS Timestamp;
				INSERT INTO persons (id, age_category, created_at, version) VALUES ($person,"unknown",$now,1u);
				INSERT INTO accounts (id,person_id,status,created_at,version) VALUES ($account,$person,"active",$now,1u);
				INSERT INTO accounts_by_person (person_id,account_id) VALUES ($person,$account);
				INSERT INTO product_accounts (product_id,account_id,email_identity_id,holder_role,country,region,status,verified_at,created_at,updated_at,version)
				VALUES ($product,$account,$identity,"self","RU","MOW","active",$now,$now,$now,1u);
				UPDATE product_installations SET person_id=$person WHERE id=$installation OR id=$other;`,
				query.WithParameters(ydb.ParamsBuilder().Param("$person").Text(person).Param("$account").Text(account).Param("$product").Text(product).
					Param("$installation").Text(decisions[product].Subject.ID).Param("$other").Text(decisions[other].Subject.ID).
					Param("$identity").Text(newID(t)).Param("$now").Timestamp(now).Build()), query.WithTxControl(query.SerializableReadWriteTxControl(query.CommitTx()))); err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{product, other} {
				if response, err := broker.GetPreference(ctx, credentials[p]); err != nil || response.MetricsToken == nil {
					t.Fatal("active membership alone suppressed installation")
				}
			}
			if test.preference != "" {
				preferenceID, preferenceProduct := newID(t), product
				if test.scope == "all" {
					preferenceProduct = ""
				}
				if err := db.Client().Exec(ctx, `DECLARE $account AS Utf8; DECLARE $product AS Utf8; DECLARE $id AS Utf8;
					DECLARE $preference AS Utf8; DECLARE $now AS Timestamp;
					INSERT INTO telemetry_preferences (subject_type,subject_id,product_id,id,preference,recorded_at,updated_at,version)
					VALUES ("account",$account,$product,$id,$preference,$now,$now,1u);`, query.WithParameters(ydb.ParamsBuilder().
					Param("$account").Text(account).Param("$product").Text(preferenceProduct).Param("$id").Text(preferenceID).
					Param("$preference").Text(test.preference).Param("$now").Timestamp(now).Build()), query.WithTxControl(query.SerializableReadWriteTxControl(query.CommitTx()))); err != nil {
					t.Fatal(err)
				}
				if test.permanent {
					if err := db.Client().Exec(ctx, `DECLARE $id AS Utf8; DECLARE $aggregate AS Utf8; DECLARE $now AS Timestamp; DECLARE $payload AS Json;
						INSERT INTO outbox_events (id,topic,aggregate_type,aggregate_id,payload,status,attempts,poll_count,available_at,created_at,version)
						VALUES ($id,"telemetry.suppression.requested","telemetry_preference",$aggregate,$payload,"delivered",0u,0u,$now,$now,1u);`,
						query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(newID(t)).Param("$aggregate").Text(preferenceID).
							Param("$payload").JSONFromBytes([]byte(`{}`)).Param("$now").Timestamp(now).Build()), query.WithTxControl(query.SerializableReadWriteTxControl(query.CommitTx()))); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				if err := db.Client().Exec(ctx, `DECLARE $id AS Utf8; DECLARE $account AS Utf8; DECLARE $product AS Utf8;
					DECLARE $scope AS Utf8; DECLARE $status AS Utf8; DECLARE $now AS Timestamp;
					INSERT INTO privacy_requests (id,subject_type,subject_id,request_type,scope,product_id,status,requested_at,
					requested_by_workload,idempotency_key,request_fingerprint,created_at,updated_at,version)
					VALUES ($id,"account",$account,"deletion",$scope,$product,$status,$now,"consent-fixture",$id,"fixture",$now,$now,1u);`,
					query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(newID(t)).Param("$account").Text(account).Param("$product").Text(product).
						Param("$scope").Text(test.scope).Param("$status").Text(test.deletion).Param("$now").Timestamp(now).Build()), query.WithTxControl(query.SerializableReadWriteTxControl(query.CommitTx()))); err != nil {
					t.Fatal(err)
				}
			}
			if response, err := broker.GetPreference(ctx, credentials[product]); err != nil || response.MetricsToken != nil {
				t.Fatal("linked account privacy did not block GET token")
			}
			if _, err := db.SetInstallationConsent(ctx, decisions[product]); !errors.Is(err, domain.ErrForbidden) {
				t.Fatal("new grant bypassed linked account privacy")
			}
			if response, err := broker.GetPreference(ctx, credentials[other]); err != nil || response.MetricsToken == nil {
				t.Fatal("privacy crossed unrelated product membership")
			}
			state, err := db.SetInstallationConsent(ctx, decisions[other])
			if err != nil || state.ConsentEpoch != 1 || state.Version != 3 {
				t.Fatal("unrelated product repeated grant was blocked or changed epoch")
			}
			completeConsentEvent(t, ctx, db, state.EventID)
		})
	}
}
