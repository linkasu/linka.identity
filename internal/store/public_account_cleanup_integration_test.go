//go:build integration

package store_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

func TestYDBPublicAccountCleanupPreservesLiveProofsAndReplay(t *testing.T) {
	ctx, db := directoryIntegrationStore(t)
	f := seedPublicSession(t, ctx, db)
	c, v, _ := makePublicChallengeInput(t, ctx, f.product, f.installation, "cleanup-"+f.product+"@example.test")
	if _, _, err := db.CreatePublicEmailChallenge(ctx, c, v, 200); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	// The active code's envelope and blind-index references must fence key removal.
	if err := db.ValidatePublicOTPKeyID(ctx, "rotated", now); err == nil {
		t.Fatal("rotation silently invalidated an active OTP")
	}
	if err := db.Client().Exec(ctx, `DECLARE $id AS Utf8; UPDATE public_email_challenges SET code_kms_key_id='retiring-cleanup-key',email_blind_index_version=99u WHERE id=$id;`, query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(c.ID).Build())); err != nil {
		t.Fatal(err)
	}
	if err := db.ValidateEnvelopeKeyIDs(ctx, map[string]struct{}{"integration-kek": {}}); err == nil {
		t.Fatal("active encrypted OTP was ignored by envelope-key guard")
	}
	if err := db.ValidateBlindIndexVersions(ctx, map[int][]byte{1: bytes.Repeat([]byte{2}, 32)}); err == nil {
		t.Fatal("challenge identity lookup was ignored by blind-index guard")
	}
	if err := db.Client().Exec(ctx, `DECLARE $id AS Utf8; UPDATE public_email_challenges SET code_kms_key_id='integration-kek',email_blind_index_version=1u WHERE id=$id;`, query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(c.ID).Build())); err != nil {
		t.Fatal(err)
	}
	if err := db.CleanupPublicAccountState(ctx, now, 1000); err != nil {
		t.Fatal(err)
	}
	live, err := db.PublicEmailChallenge(ctx, c.ID)
	if err != nil || live.State != domain.PublicChallengeRequested || len(live.Code.Data) == 0 {
		t.Fatal("cleanup touched a live proof")
	}
	if _, _, err := db.AuthorizedPublicAccountSession(ctx, f.session, f.product); err != nil {
		t.Fatalf("cleanup touched a live session: %v", err)
	}
	// Expiry scrubs the code immediately, retaining an idempotency tombstone.
	if err := db.Client().Exec(ctx, `DECLARE $id AS Utf8; DECLARE $expires AS Timestamp;
UPDATE public_email_challenges SET expires_at=$expires WHERE id=$id;`, query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(c.ID).Param("$expires").Timestamp(now.Add(-time.Minute)).Build())); err != nil {
		t.Fatal(err)
	}
	if err := db.CleanupPublicAccountState(ctx, now, 1000); err != nil {
		t.Fatal(err)
	}
	expired, err := db.PublicEmailChallenge(ctx, c.ID)
	if err != nil || expired.State != domain.PublicChallengeExpired || len(expired.Code.Data) != 0 || len(expired.CodeHash) != 0 {
		t.Fatal("expired challenge retained a reusable code")
	}
	if err := db.Client().Exec(ctx, `DECLARE $id AS Utf8; DECLARE $expires AS Timestamp;
UPDATE public_email_challenges SET expires_at=$expires WHERE id=$id;`, query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(c.ID).Param("$expires").Timestamp(now.Add(-49*time.Hour)).Build())); err != nil {
		t.Fatal(err)
	}
	// Budget retention is independent of deleting an installation or challenge.
	oldEvent, freshEvent := newID(t), newID(t)
	if err := db.Client().Exec(ctx, `DECLARE $old AS Utf8; DECLARE $fresh AS Utf8; DECLARE $bucket AS Utf8; DECLARE $before AS Timestamp; DECLARE $now AS Timestamp;
INSERT INTO public_auth_events(bucket,created_at,event_id) VALUES($bucket,$before,$old),($bucket,$now,$fresh);`,
		query.WithParameters(ydb.ParamsBuilder().Param("$old").Text(oldEvent).Param("$fresh").Text(freshEvent).Param("$bucket").Text("cleanup-"+f.product).Param("$before").Timestamp(now.Add(-49*time.Hour)).Param("$now").Timestamp(now).Build())); err != nil {
		t.Fatal(err)
	}
	if err := db.CleanupPublicAccountState(ctx, now, 1000); err != nil {
		t.Fatal(err)
	}
	assertPublicErasureCount(t, ctx, db, "public_email_challenges", "id", c.ID, 0)
	assertPublicErasureCount(t, ctx, db, "email_verifications", "id", c.ID, 0)
	assertPublicErasureCount(t, ctx, db, "public_auth_events", "event_id", oldEvent, 0)
	assertPublicErasureCount(t, ctx, db, "public_auth_events", "event_id", freshEvent, 1)
	// Used refresh hashes must survive until the absolute family expiry.
	if _, _, err := db.RotatePublicAccountRefresh(ctx, f.hash, sessionTestHash(t)); err != nil {
		t.Fatal(err)
	}
	if err := db.CleanupPublicAccountState(ctx, now, 1000); err != nil {
		t.Fatal(err)
	}
	assertPublicErasureCount(t, ctx, db, "account_refresh_tokens", "session_id", f.session, 2)
	if _, _, err := db.RotatePublicAccountRefresh(ctx, f.hash, sessionTestHash(t)); err == nil {
		t.Fatal("cleanup erased the replay barrier")
	}
	mutatePublicSessionFixture(t, ctx, db, f, `UPDATE account_sessions SET expires_at=$now WHERE id=$session; UPDATE account_refresh_tokens SET expires_at=$now WHERE session_id=$session;`)
	if err := db.CleanupPublicAccountState(ctx, time.Now().UTC(), 1000); err != nil {
		t.Fatal(err)
	}
	assertPublicErasureCount(t, ctx, db, "account_sessions", "id", f.session, 0)
	assertPublicErasureCount(t, ctx, db, "account_refresh_tokens", "session_id", f.session, 0)
	assertPublicErasureCount(t, ctx, db, "public_registration_flows", "installation_id", f.installation, 0)
	assertPublicErasureCount(t, ctx, db, "product_accounts", "account_id", f.account, 1)
}
