//go:build integration

package store_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/cryptokit"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/service"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

type publicSessionFixture struct {
	product, installation, session, account, person, email string
	hash                                                   []byte
	expires                                                time.Time
}

func TestYDBPublicAccountSessionPersistence(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
	defer cancel()
	db := openIntegrationStore(t, ctx)

	t.Run("rotation replay revokes current family", func(t *testing.T) {
		f := seedPublicSession(t, ctx, db)
		before, p, err := db.AuthorizedPublicAccountSession(ctx, f.session, f.product)
		if err != nil || before.Version != 1 || p.AccountID != f.account {
			t.Fatalf("authorize: %v", err)
		}
		next := sessionTestHash(t)
		after, _, err := db.RotatePublicAccountRefresh(ctx, f.hash, next)
		if err != nil || after.Version != 2 || !after.ExpiresAt.Equal(f.expires) {
			t.Fatalf("rotate: %v", err)
		}
		row, err := db.Client().QueryRow(ctx, `DECLARE $hash AS Bytes; SELECT expires_at FROM account_refresh_tokens WHERE token_hash=$hash;`, query.WithParameters(ydb.ParamsBuilder().Param("$hash").Bytes(next).Build()), query.WithTxControl(query.SnapshotReadOnlyTxControl()))
		if err != nil {
			t.Fatal(err)
		}
		var expires time.Time
		if err := row.Scan(&expires); err != nil || !expires.Equal(f.expires) {
			t.Fatalf("refresh extended absolute expiry: %v", err)
		}
		if _, _, err := db.RotatePublicAccountRefresh(ctx, f.hash, sessionTestHash(t)); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("replay: %v", err)
		}
		if _, _, err := db.AuthorizedPublicAccountSession(ctx, f.session, f.product); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("access after replay: %v", err)
		}
		if _, _, err := db.RotatePublicAccountRefresh(ctx, next, sessionTestHash(t)); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("current refresh after replay: %v", err)
		}
		row, err = db.Client().QueryRow(ctx, `DECLARE $session AS Utf8;
SELECT COUNT(*) FROM public_account_audit WHERE session_id=$session AND action='session.revoked.refresh_replay';`,
			query.WithParameters(ydb.ParamsBuilder().Param("$session").Text(f.session).Build()), query.WithTxControl(query.SnapshotReadOnlyTxControl()))
		if err != nil {
			t.Fatal(err)
		}
		var audits uint64
		if err := row.Scan(&audits); err != nil || audits != 1 {
			t.Fatalf("replay revocation audit count=%d error=%v", audits, err)
		}
	})
	t.Run("concurrent refresh strict replay", func(t *testing.T) {
		f := seedPublicSession(t, ctx, db)
		start, results := make(chan struct{}), make(chan error, 2)
		for range 2 {
			next := sessionTestHash(t)
			go func() { <-start; _, _, err := db.RotatePublicAccountRefresh(ctx, f.hash, next); results <- err }()
		}
		close(start)
		successes := 0
		for range 2 {
			err := <-results
			if err == nil {
				successes++
			} else if !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("concurrent refresh: %v", err)
			}
		}
		if successes != 1 {
			t.Fatalf("successful rotations=%d", successes)
		}
		if _, _, err := db.AuthorizedPublicAccountSession(ctx, f.session, f.product); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("race did not revoke: %v", err)
		}
	})
	t.Run("profile CAS preserves identity and declarations only", func(t *testing.T) {
		f := seedPublicSession(t, ctx, db)
		_, before, err := db.AuthorizedPublicAccountSession(ctx, f.session, f.product)
		if err != nil {
			t.Fatal(err)
		}
		after, err := db.UpdatePublicAccountProfile(ctx, f.session, f.product, 1, "representative", "ru", "ru-mow")
		if err != nil {
			t.Fatal(err)
		}
		if after.Version != 2 || after.HolderRole != "representative" || after.Country != "RU" || after.Region != "RU-MOW" || after.EmailIdentityID != before.EmailIdentityID || !after.VerifiedAt.Equal(before.VerifiedAt) || !after.CreatedAt.Equal(before.CreatedAt) || after.Status != before.Status {
			t.Fatal("profile update modified immutable fields")
		}
		if _, err := db.UpdatePublicAccountProfile(ctx, f.session, f.product, 1, "self", "", ""); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("stale profile: %v", err)
		}
		if _, err := db.UpdatePublicAccountProfile(ctx, f.session, f.product, 2, "self", "street address", ""); !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("coarse PII rejection: %v", err)
		}
		_, persisted, err := db.AuthorizedPublicAccountSession(ctx, f.session, f.product)
		if err != nil || persisted.Version != after.Version || persisted.HolderRole != after.HolderRole || persisted.Country != after.Country || persisted.Region != after.Region || !persisted.UpdatedAt.Equal(after.UpdatedAt) {
			t.Fatalf("failed updates modified profile: %v", err)
		}
		row, err := db.Client().QueryRow(ctx, `DECLARE $person AS Utf8; SELECT age_category,guardian_relationship,version FROM persons WHERE id=$person;`, query.WithParameters(ydb.ParamsBuilder().Param("$person").Text(f.person).Build()), query.WithTxControl(query.SnapshotReadOnlyTxControl()))
		if err != nil {
			t.Fatal(err)
		}
		var age string
		var guardian *string
		var version uint64
		if err := row.Scan(&age, &guardian, &version); err != nil || age != "unknown" || guardian != nil || version != 1 {
			t.Fatalf("profile changed person/counters: %v", err)
		}
	})
	t.Run("idempotent revoke and exact product", func(t *testing.T) {
		f := seedPublicSession(t, ctx, db)
		if _, _, err := db.AuthorizedPublicAccountSession(ctx, f.session, "wrong-product"); !errors.Is(err, domain.ErrNotFound) {
			t.Fatal(err)
		}
		if err := db.RevokePublicAccountSession(ctx, f.session, "wrong-product"); !errors.Is(err, domain.ErrNotFound) {
			t.Fatal(err)
		}
		for range 2 {
			if err := db.RevokePublicAccountSession(ctx, f.session, f.product); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := db.AuthorizedPublicAccountSession(ctx, f.session, f.product); !errors.Is(err, domain.ErrNotFound) {
			t.Fatal(err)
		}
	})
	for _, mutation := range []struct{ name, sql string }{
		{"flow mismatch", `UPDATE public_registration_flows SET session_id=NULL WHERE product_id=$product AND installation_id=$installation;`},
		{"disabled installation", `UPDATE product_installations SET disabled_at=$now WHERE id=$installation;`},
		{"inactive account", `UPDATE accounts SET status='disabled' WHERE id=$account;`},
		{"inactive profile", `UPDATE product_accounts SET status='disabled' WHERE product_id=$product AND account_id=$account;`},
		{"unverified profile", `UPDATE product_accounts SET verified_at=$epoch WHERE product_id=$product AND account_id=$account;`},
		{"unverified email", `UPDATE email_identities SET verified_at=$epoch WHERE id=$email;`},
		{"erased email", `DELETE FROM email_identities WHERE id=$email;`},
		{"email namespace mismatch", `UPDATE email_identities SET identity_namespace='donation' WHERE id=$email;`},
		{"email scope mismatch", `UPDATE email_identities SET scope_key='other-product' WHERE id=$email;`},
		{"email product mismatch", `UPDATE email_identities SET product_id='other-product' WHERE id=$email;`},
		{"installation person mismatch", `UPDATE product_installations SET person_id=NULL WHERE id=$installation;`},
		{"installation product mismatch", `UPDATE product_installations SET product_id='other-product' WHERE id=$installation;`},
		{"deleted person", `UPDATE persons SET deleted_at=$now WHERE id=$person;`},
		{"expired session", `UPDATE account_sessions SET expires_at=$now WHERE id=$session;`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			f := seedPublicSession(t, ctx, db)
			mutatePublicSessionFixture(t, ctx, db, f, mutation.sql)
			if _, _, err := db.AuthorizedPublicAccountSession(ctx, f.session, f.product); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("authorization: %v", err)
			}
			if _, _, err := db.RotatePublicAccountRefresh(ctx, f.hash, sessionTestHash(t)); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("refresh: %v", err)
			}
			if _, err := db.UpdatePublicAccountProfile(ctx, f.session, f.product, 1, "self", "", ""); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("profile: %v", err)
			}
			if err := db.RevokePublicAccountSession(ctx, f.session, f.product); err != nil {
				t.Fatalf("revocation should not require active identity: %v", err)
			}
		})
	}
	t.Run("expired and unknown refresh cannot revoke", func(t *testing.T) {
		f := seedPublicSession(t, ctx, db)
		mutatePublicSessionFixture(t, ctx, db, f, `UPDATE account_refresh_tokens SET expires_at=$now,consumed_at=$now WHERE token_hash=$hash;`)
		for _, hash := range [][]byte{f.hash, sessionTestHash(t)} {
			if _, _, err := db.RotatePublicAccountRefresh(ctx, hash, sessionTestHash(t)); !errors.Is(err, domain.ErrNotFound) {
				t.Fatal(err)
			}
		}
		if _, _, err := db.AuthorizedPublicAccountSession(ctx, f.session, f.product); err != nil {
			t.Fatalf("unrelated family revoked: %v", err)
		}
	})
}

func sessionTestHash(t *testing.T) []byte {
	t.Helper()
	return []byte(newID(t)[:32])
}

func seedPublicSession(t *testing.T, ctx context.Context, db *store.Store) publicSessionFixture {
	t.Helper()
	f := publicSessionFixture{product: "session-" + newID(t), installation: newID(t), session: newID(t), hash: sessionTestHash(t)}
	if _, _, err := db.CreateInstallation(ctx, store.Installation{ID: f.installation, ProductID: f.product, Platform: "integration"}); err != nil {
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
	preparer := service.NewIdentityService(nil, cryptokit.NewEnvelope(provider), indexer, false)
	now := time.Now().UTC().Truncate(time.Microsecond)
	v, err := preparer.PreparePublicVerification(ctx, service.PublicVerificationInput{ID: newID(t), ProductID: f.product, InstallationID: f.installation, Email: f.product + "@example.test", ExpiresAt: now.Add(9 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	identity, indexes, err := preparer.PreparePublicIdentity(ctx, v, now)
	if err != nil {
		t.Fatal(err)
	}
	registered, _, err := db.RegisterEmailIdentity(ctx, identity, indexes)
	if err != nil {
		t.Fatal(err)
	}
	f.account, f.person, f.email, f.expires = registered.AccountID, registered.PersonID, registered.IdentityID, now.Add(90*24*time.Hour)
	err = db.Client().Exec(ctx, `DECLARE $product AS Utf8; DECLARE $account AS Utf8; DECLARE $email AS Utf8; DECLARE $installation AS Utf8;
DECLARE $session AS Utf8; DECLARE $challenge AS Utf8; DECLARE $hash AS Bytes; DECLARE $now AS Timestamp; DECLARE $expires AS Timestamp;
INSERT INTO product_accounts(product_id,account_id,email_identity_id,holder_role,country,region,status,verified_at,created_at,updated_at,version)
VALUES($product,$account,$email,'self','','','active',$now,$now,$now,1u);
INSERT INTO account_sessions(id,product_id,account_id,installation_id,status,created_at,expires_at,revoked_at,version)
VALUES($session,$product,$account,$installation,'active',$now,$expires,NULL,1u);
INSERT INTO public_registration_flows(product_id,installation_id,challenge_id,session_id,updated_at,version) VALUES($product,$installation,$challenge,$session,$now,1u);
INSERT INTO account_refresh_tokens(token_hash,session_id,issued_at,expires_at,consumed_at,version) VALUES($hash,$session,$now,$expires,NULL,1u);`,
		query.WithParameters(ydb.ParamsBuilder().Param("$product").Text(f.product).Param("$account").Text(f.account).Param("$email").Text(f.email).Param("$installation").Text(f.installation).
			Param("$session").Text(f.session).Param("$challenge").Text(v.ID).Param("$hash").Bytes(f.hash).Param("$now").Timestamp(now).Param("$expires").Timestamp(f.expires).Build()), query.WithTxControl(query.SerializableReadWriteTxControl(query.CommitTx())))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func mutatePublicSessionFixture(t *testing.T, ctx context.Context, db *store.Store, f publicSessionFixture, sql string) {
	t.Helper()
	err := db.Client().Exec(ctx, `DECLARE $product AS Utf8; DECLARE $account AS Utf8; DECLARE $person AS Utf8; DECLARE $email AS Utf8;
DECLARE $installation AS Utf8; DECLARE $session AS Utf8; DECLARE $hash AS Bytes; DECLARE $now AS Timestamp; DECLARE $epoch AS Timestamp; `+sql,
		query.WithParameters(ydb.ParamsBuilder().Param("$product").Text(f.product).Param("$account").Text(f.account).Param("$person").Text(f.person).Param("$email").Text(f.email).
			Param("$installation").Text(f.installation).Param("$session").Text(f.session).Param("$hash").Bytes(f.hash).Param("$now").Timestamp(time.Now().UTC().Add(-time.Second)).Param("$epoch").Timestamp(time.Unix(0, 0).UTC()).Build()), query.WithTxControl(query.SerializableReadWriteTxControl(query.CommitTx())))
	if err != nil {
		t.Fatal(err)
	}
}
