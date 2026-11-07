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

func TestYDBPublicAccountErasure(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
	defer cancel()
	db := openIntegrationStore(t, ctx)

	t.Run("installation removes only its device state", func(t *testing.T) {
		f := seedPublicSession(t, ctx, db)
		other := copyPublicDevice(t, ctx, db, f)
		challenge, verification, _ := makePublicChallengeInput(t, ctx, f.product, f.installation, "correction-"+f.product+"@example.test")
		if _, _, err := db.CreatePublicEmailChallenge(ctx, challenge, verification, 200); err != nil {
			t.Fatal(err)
		}
		seedPublicErasureAudit(t, ctx, db, f)
		job := seedPublicDeletion(t, ctx, db, "installation", f.installation, &f.product)
		if err := db.ErasePrivacyJob(ctx, job); err != nil {
			t.Fatal(err)
		}
		assertPublicErasureCount(t, ctx, db, "account_sessions", "id", f.session, 0)
		assertPublicErasureCount(t, ctx, db, "account_refresh_tokens", "session_id", f.session, 0)
		assertPublicErasureCount(t, ctx, db, "public_registration_flows", "installation_id", f.installation, 0)
		assertPublicChallengeErased(t, ctx, db, challenge.ID)
		assertPublicErasureCount(t, ctx, db, "public_auth_events", "event_id", challenge.ID, 2)
		assertPublicErasureCount(t, ctx, db, "public_account_audit", "session_id", f.session, 0)
		assertPublicErasureCount(t, ctx, db, "product_accounts", "account_id", f.account, 1)
		if _, _, err := db.AuthorizedPublicAccountSession(ctx, other.session, other.product); err != nil {
			t.Fatalf("other device lost its shared account: %v", err)
		}
		if _, _, err := db.RotatePublicAccountRefresh(ctx, f.hash, sessionTestHash(t)); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("erased refresh survived: %v", err)
		}
	})

	for _, scope := range []string{"person product", "person all", "installation product"} {
		for _, terminal := range []string{"cancelled", "rejected"} {
			t.Run(scope+" fences until "+terminal, func(t *testing.T) {
				f := seedPublicSession(t, ctx, db)
				c, v, preparer := makePublicChallengeInput(t, ctx, f.product, f.installation, f.product+"@example.test")
				if _, _, err := db.CreatePublicEmailChallenge(ctx, c, v, 200); err != nil {
					t.Fatal(err)
				}
				erasureExec(t, ctx, db, `DECLARE $id AS Utf8; UPDATE public_email_challenges SET state='delivered' WHERE id=$id;`, ydb.ParamsBuilder().Param("$id").Text(c.ID).Build())
				now := time.Now().UTC().Truncate(time.Microsecond)
				identity, indexes, err := preparer.PreparePublicIdentity(ctx, v, now)
				if err != nil {
					t.Fatal(err)
				}
				input := store.PublicEmailCompletion{ChallengeID: c.ID, ProductID: f.product, InstallationID: f.installation, OTPKeyID: c.OTPKeyID, NonceHash: c.NonceHash, CodeHash: c.CodeHash, Identity: identity, Indexes: indexes, SessionID: newID(t), RefreshHash: sessionTestHash(t), RefreshExpiresAt: now.Add(89 * 24 * time.Hour)}
				subjectType, subject, product := "person", f.person, &f.product
				if scope == "person all" {
					product = nil
				} else if scope == "installation product" {
					subjectType, subject = "installation", f.installation
				}
				job := seedPublicDeletion(t, ctx, db, subjectType, subject, product)
				if _, _, err := db.AuthorizedPublicAccountSession(ctx, f.session, f.product); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("pending deletion allowed access: %v", err)
				}
				if _, _, err := db.RotatePublicAccountRefresh(ctx, f.hash, sessionTestHash(t)); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("pending deletion allowed refresh: %v", err)
				}
				if _, err := db.CompletePublicEmailChallenge(ctx, input); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("pending deletion issued OTP session: %v", err)
				}
				assertPublicErasureCount(t, ctx, db, "account_sessions", "id", input.SessionID, 0)
				assertPublicErasureCount(t, ctx, db, "account_sessions", "id", f.session, 1)
				unchanged, err := db.PublicEmailChallenge(ctx, c.ID)
				if err != nil || unchanged.State != domain.PublicChallengeDelivered || unchanged.Version != 1 {
					t.Fatalf("fence mutated proof: %v", err)
				}
				erasureExec(t, ctx, db, `DECLARE $id AS Utf8; DECLARE $status AS Utf8; UPDATE privacy_requests SET status=$status WHERE id=$id;`, ydb.ParamsBuilder().Param("$id").Text(job.RequestID).Param("$status").Text(terminal).Build())
				if session, _, err := db.AuthorizedPublicAccountSession(ctx, f.session, f.product); err != nil || session.Version != 1 {
					t.Fatalf("terminal deletion changed stored session: %v", err)
				}
				if _, _, err := db.RotatePublicAccountRefresh(ctx, f.hash, sessionTestHash(t)); err != nil {
					t.Fatalf("terminal deletion still fences refresh: %v", err)
				}
				if _, err := db.CompletePublicEmailChallenge(ctx, input); err != nil {
					t.Fatalf("terminal deletion still fences OTP: %v", err)
				}
			})
		}
	}

	for _, global := range []bool{false, true} {
		name := "person product"
		if global {
			name = "person global"
		}
		t.Run(name+" includes unlinked recovery proof", func(t *testing.T) {
			f := seedPublicSession(t, ctx, db)
			other := seedPublicSession(t, ctx, db)
			// Keep a second product identity on the same person, as legacy data can.
			erasureExec(t, ctx, db, `DECLARE $person AS Utf8; DECLARE $account AS Utf8; DECLARE $email AS Utf8; DECLARE $installation AS Utf8;
UPDATE accounts SET person_id=$person WHERE id=$account;
UPDATE email_identities SET person_id=$person WHERE id=$email;
UPDATE product_installations SET person_id=$person WHERE id=$installation;`, ydb.ParamsBuilder().Param("$person").Text(f.person).Param("$account").Text(other.account).Param("$email").Text(other.email).Param("$installation").Text(other.installation).Build())
			recovery := newID(t)
			if _, _, err := db.CreateInstallation(ctx, store.Installation{ID: recovery, ProductID: f.product, Platform: "integration"}); err != nil {
				t.Fatal(err)
			}
			c, v, _ := makePublicChallengeInput(t, ctx, f.product, recovery, f.product+"@example.test")
			if _, _, err := db.CreatePublicEmailChallenge(ctx, c, v, 200); err != nil {
				t.Fatal(err)
			}
			seedPublicErasureAudit(t, ctx, db, f)
			var product *string
			if !global {
				product = &f.product
			}
			if err := db.ErasePrivacyJob(ctx, seedPublicDeletion(t, ctx, db, "person", f.person, product)); err != nil {
				t.Fatal(err)
			}
			assertPublicChallengeErased(t, ctx, db, c.ID)
			assertPublicErasureCount(t, ctx, db, "public_registration_flows", "installation_id", recovery, 0)
			assertPublicErasureCount(t, ctx, db, "product_accounts", "account_id", f.account, 0)
			assertPublicErasureCount(t, ctx, db, "account_sessions", "id", f.session, 0)
			assertPublicErasureCount(t, ctx, db, "account_refresh_tokens", "session_id", f.session, 0)
			assertPublicErasureCount(t, ctx, db, "email_identities", "id", f.email, 0)
			assertPublicErasureCount(t, ctx, db, "email_blind_indexes", "identity_id", f.email, 0)
			assertPublicErasureCount(t, ctx, db, "public_account_audit", "entity_id", f.account, 0)
			if global {
				assertPublicErasureCount(t, ctx, db, "product_accounts", "account_id", other.account, 0)
				assertPublicErasureCount(t, ctx, db, "account_sessions", "id", other.session, 0)
			} else if _, _, err := db.AuthorizedPublicAccountSession(ctx, other.session, other.product); err != nil {
				t.Fatalf("other product was erased: %v", err)
			}
		})
	}

	t.Run("unproved request cannot erase unrelated current session", func(t *testing.T) {
		victim := seedPublicSession(t, ctx, db)
		unrelated := seedPublicSession(t, ctx, db)
		// Use the same product, but retain the unrelated person's active family.
		erasureExec(t, ctx, db, `DECLARE $old AS Utf8; DECLARE $product AS Utf8; DECLARE $installation AS Utf8; DECLARE $session AS Utf8; DECLARE $account AS Utf8; DECLARE $email AS Utf8;
UPDATE product_installations SET product_id=$product WHERE id=$installation;
UPDATE account_sessions SET product_id=$product WHERE id=$session;
UPDATE email_identities SET product_id=$product,scope_key=$product WHERE id=$email;
INSERT INTO product_accounts SELECT $product AS product_id,account_id,email_identity_id,holder_role,country,region,status,verified_at,created_at,updated_at,version FROM product_accounts WHERE product_id=$old AND account_id=$account;
INSERT INTO public_registration_flows SELECT $product AS product_id,installation_id,challenge_id,session_id,updated_at,version FROM public_registration_flows WHERE product_id=$old AND installation_id=$installation;
DELETE FROM product_accounts WHERE product_id=$old AND account_id=$account;
DELETE FROM public_registration_flows WHERE product_id=$old AND installation_id=$installation;`, ydb.ParamsBuilder().Param("$old").Text(unrelated.product).Param("$product").Text(victim.product).Param("$installation").Text(unrelated.installation).Param("$session").Text(unrelated.session).Param("$account").Text(unrelated.account).Param("$email").Text(unrelated.email).Build())
		c, v, _ := makePublicChallengeInput(t, ctx, victim.product, unrelated.installation, victim.product+"@example.test")
		if _, _, err := db.CreatePublicEmailChallenge(ctx, c, v, 200); err != nil {
			t.Fatal(err)
		}
		if err := db.ErasePrivacyJob(ctx, seedPublicDeletion(t, ctx, db, "person", victim.person, &victim.product)); err != nil {
			t.Fatal(err)
		}
		assertPublicChallengeErased(t, ctx, db, c.ID)
		if _, _, err := db.AuthorizedPublicAccountSession(ctx, unrelated.session, victim.product); err != nil {
			t.Fatalf("unproved email request invalidated current family: %v", err)
		}
	})
}

func erasureExec(t *testing.T, ctx context.Context, db *store.Store, statement string, parameters ydb.Params) {
	t.Helper()
	if err := db.Client().Exec(ctx, statement, query.WithParameters(parameters), query.WithTxControl(query.SerializableReadWriteTxControl(query.CommitTx()))); err != nil {
		t.Fatal(err)
	}
}

func seedPublicDeletion(t *testing.T, ctx context.Context, db *store.Store, subjectType, subject string, product *string) store.PrivacyErasureJob {
	t.Helper()
	job := store.PrivacyErasureJob{RequestID: newID(t), StepID: newID(t), ProductID: product, Scope: "all", Version: 1}
	if subjectType == "person" {
		job.PersonID = &subject
	} else {
		job.InstallationID = &subject
	}
	value := ""
	if product != nil {
		job.Scope, value = "product", *product
	}
	erasureExec(t, ctx, db, `DECLARE $id AS Utf8; DECLARE $step AS Utf8; DECLARE $subject AS Utf8; DECLARE $type AS Utf8; DECLARE $scope AS Utf8; DECLARE $product AS Utf8; DECLARE $now AS Timestamp;
INSERT INTO privacy_requests(id,subject_type,subject_id,request_type,scope,product_id,status,requested_at,requested_by_workload,idempotency_key,request_fingerprint,created_at,updated_at,version)
VALUES($id,$type,$subject,'deletion',$scope,$product,'requested',$now,'integration',$id,$id,$now,$now,1u);
INSERT INTO privacy_request_steps(id,privacy_request_id,step_type,status,attempts,available_at,created_at,updated_at,version)
VALUES($step,$id,'ydb','processing',1u,$now,$now,$now,1u);`, ydb.ParamsBuilder().Param("$id").Text(job.RequestID).Param("$step").Text(job.StepID).Param("$subject").Text(subject).Param("$type").Text(subjectType).Param("$scope").Text(job.Scope).Param("$product").Text(value).Param("$now").Timestamp(time.Now().UTC()).Build())
	return job
}

func assertPublicErasureCount(t *testing.T, ctx context.Context, db *store.Store, table, column, id string, want uint64) {
	t.Helper()
	row, err := db.Client().QueryRow(ctx, `DECLARE $id AS Utf8; SELECT COUNT(*) FROM `+table+` WHERE `+column+`=$id;`, query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(id).Build()), query.WithTxControl(query.SnapshotReadOnlyTxControl()))
	if err != nil {
		t.Fatal(err)
	}
	var got uint64
	if err := row.Scan(&got); err != nil || got != want {
		t.Fatalf("%s.%s count=%d want=%d error=%v", table, column, got, want, err)
	}
}

func assertPublicChallengeErased(t *testing.T, ctx context.Context, db *store.Store, challenge string) {
	t.Helper()
	for _, table := range []string{"public_email_challenges", "email_verifications"} {
		assertPublicErasureCount(t, ctx, db, table, "id", challenge, 0)
	}
	assertPublicErasureCount(t, ctx, db, "public_account_audit", "entity_id", challenge, 0)
}

func seedPublicErasureAudit(t *testing.T, ctx context.Context, db *store.Store, f publicSessionFixture) {
	t.Helper()
	erasureExec(t, ctx, db, `DECLARE $id AS Utf8; DECLARE $product AS Utf8; DECLARE $session AS Utf8; DECLARE $account AS Utf8; DECLARE $now AS Timestamp;
INSERT INTO public_account_audit(id,product_id,session_id,actor,action,entity_id,created_at) VALUES($id,$product,$session,'integration','registration.verified',$account,$now);`, ydb.ParamsBuilder().Param("$id").Text(newID(t)).Param("$product").Text(f.product).Param("$session").Text(f.session).Param("$account").Text(f.account).Param("$now").Timestamp(time.Now().UTC()).Build())
}

func copyPublicDevice(t *testing.T, ctx context.Context, db *store.Store, f publicSessionFixture) publicSessionFixture {
	t.Helper()
	other := f
	other.installation, other.session, other.hash = newID(t), newID(t), sessionTestHash(t)
	if _, _, err := db.CreateInstallation(ctx, store.Installation{ID: other.installation, ProductID: f.product, Platform: "integration"}); err != nil {
		t.Fatal(err)
	}
	erasureExec(t, ctx, db, `DECLARE $product AS Utf8; DECLARE $person AS Utf8; DECLARE $account AS Utf8; DECLARE $installation AS Utf8; DECLARE $session AS Utf8; DECLARE $hash AS Bytes; DECLARE $now AS Timestamp; DECLARE $expires AS Timestamp;
UPDATE product_installations SET person_id=$person WHERE id=$installation;
INSERT INTO account_sessions(id,product_id,account_id,installation_id,status,created_at,expires_at,version) VALUES($session,$product,$account,$installation,'active',$now,$expires,1u);
INSERT INTO account_refresh_tokens(token_hash,session_id,issued_at,expires_at,version) VALUES($hash,$session,$now,$expires,1u);
INSERT INTO public_registration_flows(product_id,installation_id,challenge_id,session_id,updated_at,version) VALUES($product,$installation,$session,$session,$now,1u);`, ydb.ParamsBuilder().Param("$product").Text(f.product).Param("$person").Text(f.person).Param("$account").Text(f.account).Param("$installation").Text(other.installation).Param("$session").Text(other.session).Param("$hash").Bytes(other.hash).Param("$now").Timestamp(time.Now().UTC()).Param("$expires").Timestamp(f.expires).Build())
	return other
}
