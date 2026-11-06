//go:build integration

package store_test

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

func directoryIntegrationStore(t *testing.T) (context.Context, *store.Store) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	t.Cleanup(cancel)
	return ctx, openIntegrationStore(t, ctx)
}

func TestYDBDirectoryCandidatesAndAuthoritativeEligibility(t *testing.T) {
	ctx, db := directoryIntegrationStore(t)
	for _, mutation := range []struct{ name, sql string }{
		{"no session", `DELETE FROM account_sessions WHERE id=$session;`},
		{"inactive account", `UPDATE accounts SET status='disabled' WHERE id=$account;`},
		{"inactive profile", `UPDATE product_accounts SET status='disabled' WHERE product_id=$product AND account_id=$account;`},
		{"deleted person", `UPDATE persons SET deleted_at=$now WHERE id=$person;`},
		{"missing email", `DELETE FROM email_identities WHERE id=$email;`},
		{"wrong namespace", `UPDATE email_identities SET identity_namespace='donation' WHERE id=$email;`},
		{"wrong linkage", `UPDATE email_identities SET linkage_scope='global' WHERE id=$email;`},
		{"wrong scope", `UPDATE email_identities SET scope_key='other' WHERE id=$email;`},
		{"wrong product", `UPDATE email_identities SET product_id='other' WHERE id=$email;`},
		{"wrong person", `UPDATE email_identities SET person_id=$installation WHERE id=$email;`},
		{"unverified email", `UPDATE email_identities SET verified_at=$epoch WHERE id=$email;`},
		{"unverified profile", `UPDATE product_accounts SET verified_at=$epoch WHERE product_id=$product AND account_id=$account;`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			f := seedPublicSession(t, ctx, db)
			before, err := db.DirectoryAccount(ctx, f.product, f.account)
			if err != nil || before.Namespace != "account" || before.LinkageScope != "product" || before.ScopeKey != f.product || before.PersonID != f.person || len(before.Email.Data) == 0 {
				t.Fatalf("encrypted contact/AAD metadata: %v", err)
			}
			mutatePublicSessionFixture(t, ctx, db, f, mutation.sql)
			got, err := db.DirectoryAccount(ctx, f.product, f.account)
			candidates, listErr := db.DirectoryAccounts(ctx, f.product, "", 50)
			if mutation.name == "no session" {
				if err != nil || listErr != nil || len(candidates) != 1 || !bytes.Equal(got.Email.Data, before.Email.Data) {
					t.Fatal("contact incorrectly requires a live session")
				}
			} else if !errors.Is(err, domain.ErrNotFound) || listErr != nil || len(candidates) != 0 {
				t.Fatalf("ineligible contact: lookup=%v list=%v count=%d", err, listErr, len(candidates))
			}
		})
	}
	for _, scope := range []string{"product", "all", "installation"} {
		t.Run("pending "+scope, func(t *testing.T) {
			f := seedPublicSession(t, ctx, db)
			kind, subject, requestScope := "person", f.person, scope
			if scope == "installation" {
				kind, subject, requestScope = "installation", f.installation, "product"
			}
			product := f.product
			productScope := &product
			if scope == "all" {
				productScope = nil
			}
			if err := db.EnsureSubjectAlias(ctx, opaqueKey(t), product, "directory-test", "account", f.account); err != nil {
				t.Fatal(err)
			}
			if err := db.EnsureSubjectAlias(ctx, opaqueKey(t), product, "directory-test", "installation", f.installation); err != nil {
				t.Fatal(err)
			}
			if _, _, err := db.CreatePrivacyRequest(ctx, store.PrivacyRequest{Subject: store.Subject{Kind: kind, ID: subject}, RequestType: "deletion", Scope: requestScope, ProductID: productScope, RequestedAt: time.Now().UTC(), RequestedByWorkload: "directory-test", IdempotencyKey: newID(t)}, map[string]string{product: "directory-test"}); err != nil {
				t.Fatal(err)
			}
			candidates, err := db.DirectoryAccounts(ctx, product, "", 1)
			if err != nil || len(candidates) != 1 || candidates[0].Profile.AccountID != f.account {
				t.Fatal("pending deletion swallowed the pagination cursor")
			}
			_, err = db.DirectoryAccount(ctx, product, f.account)
			if scope == "installation" {
				if err != nil {
					t.Fatalf("installation-only deletion hid account contact: %v", err)
				}
			} else if !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("pending person deletion disclosed contact: %v", err)
			}
		})
	}
}

func TestYDBDirectoryLatestAccountCommunicationOnly(t *testing.T) {
	ctx, db := directoryIntegrationStore(t)
	f := seedPublicSession(t, ctx, db)
	now := time.Now().UTC().Truncate(time.Microsecond)
	initial, err := db.DirectoryAccount(ctx, f.product, f.account)
	if err != nil || initial.TelemetryPreference != "unknown" {
		t.Fatalf("missing telemetry: %v", err)
	}
	if err := db.Client().Exec(ctx, `DECLARE $id AS Utf8; DECLARE $account AS Utf8; DECLARE $product AS Utf8; DECLARE $now AS Timestamp;
INSERT INTO telemetry_preferences(subject_type,subject_id,product_id,id,preference,recorded_at,updated_at,version)
VALUES('account',$account,$product,$id,'allowed',$now,$now,1u);`, query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(newID(t)).Param("$account").Text(f.account).Param("$product").Text(f.product).Param("$now").Timestamp(now).Build())); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"news", "research", "service"} {
		if err := db.CreateConsent(ctx, store.Consent{ID: newID(t), Subject: store.Subject{Kind: "person", ID: f.person}, ProductID: f.product, ConsentType: "product_" + kind, PolicyVersion: "v1", Status: "granted", RecordedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	a, err := db.DirectoryAccount(ctx, f.product, f.account)
	if err != nil || a.TelemetryPreference != "allowed" {
		t.Fatalf("telemetry: %v", err)
	}
	for _, p := range a.Permissions {
		if p.Status != "unknown" {
			t.Fatal("person consent or telemetry granted account communication")
		}
	}
	grant := store.Consent{ID: newID(t), Subject: store.Subject{Kind: "account", ID: f.account}, ProductID: f.product, ConsentType: "product_news", PolicyVersion: "v2", Status: "granted", RecordedAt: now.Add(time.Second)}
	if err := directoryInsertAccountConsent(ctx, db, grant); err != nil {
		t.Fatal(err)
	}
	a, err = db.DirectoryAccount(ctx, f.product, f.account)
	if err != nil || a.Permissions["news"].Status != "granted" || a.Permissions["news"].ID != grant.ID || a.Permissions["news"].PolicyVersion != "v2" || !a.Permissions["news"].RecordedAt.Equal(grant.RecordedAt) {
		t.Fatalf("grant metadata: %v", err)
	}
	withdrawn := grant
	withdrawn.ID, withdrawn.Status, withdrawn.RecordedAt = newID(t), "withdrawn", now.Add(2*time.Second)
	if err := directoryInsertAccountConsent(ctx, db, withdrawn); err != nil {
		t.Fatal(err)
	}
	a, err = db.DirectoryAccount(ctx, f.product, f.account)
	if err != nil || a.Permissions["news"].Status != "withdrawn" || a.Permissions["news"].ID != withdrawn.ID {
		t.Fatalf("latest withdrawal: %v", err)
	}
	malformed := withdrawn
	malformed.ID, malformed.PolicyVersion, malformed.Status, malformed.RecordedAt = newID(t), "", "granted", now.Add(3*time.Second)
	if err := directoryInsertAccountConsent(ctx, db, malformed); err != nil {
		t.Fatal(err)
	}
	a, err = db.DirectoryAccount(ctx, f.product, f.account)
	if err != nil || a.Permissions["news"].Status != "unknown" {
		t.Fatalf("latest malformed grant fell back to older grant: %v", err)
	}
	tieIDs := []string{newID(t), newID(t)}
	sort.Strings(tieIDs)
	for i := 1; i >= 0; i-- {
		c := grant
		c.ID, c.ConsentType = tieIDs[i], "product_research"
		if i == 1 {
			c.Status = "withdrawn"
		}
		if err := directoryInsertAccountConsent(ctx, db, c); err != nil {
			t.Fatal(err)
		}
	}
	a, err = db.DirectoryAccount(ctx, f.product, f.account)
	if err != nil || a.Permissions["research"].Status != "withdrawn" || a.Permissions["research"].ID != tieIDs[1] {
		t.Fatalf("equal timestamp ID ordering: %v", err)
	}
	mutatePublicSessionFixture(t, ctx, db, f, `UPDATE telemetry_preferences SET preference='malformed' WHERE subject_type='account' AND subject_id=$account AND product_id=$product;`)
	a, err = db.DirectoryAccount(ctx, f.product, f.account)
	if err != nil || a.TelemetryPreference != "unknown" {
		t.Fatalf("malformed telemetry: %v", err)
	}
}

// Legacy mutation APIs accept only person/installation subjects; directory tests
// seed their own account-scoped records without changing that write contract.
func directoryInsertAccountConsent(ctx context.Context, db *store.Store, c store.Consent) error {
	return db.Client().Exec(ctx, `DECLARE $id AS Utf8; DECLARE $account AS Utf8; DECLARE $product AS Utf8; DECLARE $kind AS Utf8;
DECLARE $policy AS Utf8; DECLARE $status AS Utf8; DECLARE $recorded AS Timestamp; DECLARE $created AS Timestamp;
INSERT INTO consents(id,subject_type,subject_id,product_id,consent_type,policy_version,status,recorded_at,created_at)
VALUES($id,'account',$account,$product,$kind,$policy,$status,$recorded,$created);`, query.WithParameters(ydb.ParamsBuilder().
		Param("$id").Text(c.ID).Param("$account").Text(c.Subject.ID).Param("$product").Text(c.ProductID).Param("$kind").Text(c.ConsentType).
		Param("$policy").Text(c.PolicyVersion).Param("$status").Text(c.Status).Param("$recorded").Timestamp(c.RecordedAt).Param("$created").Timestamp(c.RecordedAt).Build()))
}

func TestYDBDirectoryProductKeysetPaging(t *testing.T) {
	ctx, db := directoryIntegrationStore(t)
	f := seedPublicSession(t, ctx, db)
	other := seedPublicSession(t, ctx, db)
	if rows, err := db.DirectoryAccounts(ctx, other.product, "", 50); err != nil || len(rows) != 1 || rows[0].Profile.AccountID != other.account {
		t.Fatalf("product scope: %v", err)
	}
	if _, err := db.DirectoryAccount(ctx, other.product, f.account); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-product lookup: %v", err)
	}
	ids := []string{f.account}
	for range 2 {
		id := newID(t)
		ids = append(ids, id)
		err := db.Client().Exec(ctx, `DECLARE $product AS Utf8; DECLARE $account AS Utf8; DECLARE $person AS Utf8; DECLARE $email AS Utf8; DECLARE $now AS Timestamp;
INSERT INTO accounts(id,person_id,status,created_at,version) VALUES($account,$person,'active',$now,1u);
INSERT INTO product_accounts(product_id,account_id,email_identity_id,holder_role,country,region,status,verified_at,created_at,updated_at,version)
VALUES($product,$account,$email,'self','','','active',$now,$now,$now,1u);`, query.WithParameters(ydb.ParamsBuilder().Param("$product").Text(f.product).Param("$account").Text(id).Param("$person").Text(f.person).Param("$email").Text(f.email).Param("$now").Timestamp(time.Now().UTC()).Build()))
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(ids)
	after := ""
	for _, id := range ids {
		rows, err := db.DirectoryAccounts(ctx, f.product, after, 1)
		if err != nil || len(rows) != 1 || rows[0].Profile.AccountID != id {
			t.Fatalf("keyset order/limit: %v", err)
		}
		after = id
	}
	if rows, err := db.DirectoryAccounts(ctx, f.product, after, 50); err != nil || len(rows) != 0 {
		t.Fatalf("exclusive after: %v", err)
	}
}
