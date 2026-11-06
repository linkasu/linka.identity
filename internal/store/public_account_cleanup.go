package store

import (
	"context"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

// CleanupPublicAccountState bounds transient security-state retention. It never
// deletes product accounts, legal evidence, or unexpired refresh replay records.
func (s *Store) CleanupPublicAccountState(ctx context.Context, now time.Time, limit int) error {
	if now.IsZero() || limit < 1 || limit > 1000 {
		return domain.ErrInvalid
	}
	now = now.UTC().Truncate(time.Microsecond)
	return s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		rows, err := tx.QueryResultSet(ctx, `DECLARE $now AS Timestamp; DECLARE $limit AS Uint64;
SELECT id FROM public_email_challenges WHERE expires_at <= $now
AND state IN ('requested','delivering','delivered','delivery_uncertain') ORDER BY expires_at,id LIMIT $limit;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$now").Timestamp(now).Param("$limit").Uint64(uint64(limit)).Build()))
		if err != nil {
			return err
		}
		var expired []string
		for row, rowErr := range rows.Rows(ctx) {
			if rowErr != nil {
				_ = rows.Close(ctx)
				return rowErr
			}
			var id string
			if err := row.Scan(&id); err != nil {
				_ = rows.Close(ctx)
				return err
			}
			expired = append(expired, id)
		}
		_ = rows.Close(ctx)
		for _, id := range expired {
			c, err := readPublicChallenge(ctx, tx, id)
			if err != nil {
				return err
			}
			if err := finishPublicChallengeTx(ctx, tx, c, domain.PublicChallengeExpired, now, nil); err != nil {
				return err
			}
		}
		// Keep request tombstones for retry diagnostics, and budgets for twice the
		// largest rolling window. Neither survives as a reusable OTP/capability.
		return tx.Exec(ctx, `DECLARE $now AS Timestamp; DECLARE $before AS Timestamp; DECLARE $limit AS Uint64;
$challenges = SELECT id,product_id,installation_id FROM public_email_challenges WHERE expires_at < $before ORDER BY expires_at,id LIMIT $limit;
DELETE FROM email_verifications WHERE id IN (SELECT id FROM $challenges);
DELETE FROM public_registration_flows ON SELECT f.product_id AS product_id,f.installation_id AS installation_id FROM public_registration_flows AS f
INNER JOIN $challenges AS c ON f.product_id=c.product_id AND f.installation_id=c.installation_id AND f.challenge_id=c.id WHERE f.session_id IS NULL;
DELETE FROM public_email_challenges WHERE id IN (SELECT id FROM $challenges);
$refresh = SELECT token_hash FROM account_refresh_tokens WHERE expires_at <= $now ORDER BY expires_at,token_hash LIMIT $limit;
DELETE FROM account_refresh_tokens WHERE token_hash IN (SELECT token_hash FROM $refresh);
$sessions = SELECT id FROM account_sessions WHERE expires_at <= $now ORDER BY expires_at,id LIMIT $limit;
UPDATE public_registration_flows SET session_id=NULL WHERE session_id IN (SELECT id FROM $sessions);
DELETE FROM account_sessions WHERE id IN (SELECT id FROM $sessions);
$orphan_flows = SELECT f.product_id AS product_id,f.installation_id AS installation_id FROM public_registration_flows AS f
LEFT JOIN public_email_challenges AS c ON c.id=f.challenge_id WHERE f.session_id IS NULL AND c.id IS NULL
ORDER BY product_id,installation_id LIMIT $limit;
DELETE FROM public_registration_flows ON SELECT product_id,installation_id FROM $orphan_flows;
$events = SELECT bucket,created_at,event_id FROM public_auth_events WHERE created_at < $before ORDER BY created_at,bucket,event_id LIMIT $limit;
DELETE FROM public_auth_events ON SELECT bucket,created_at,event_id FROM $events;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$now").Timestamp(now).Param("$before").Timestamp(now.Add(-48*time.Hour)).Param("$limit").Uint64(uint64(limit)).Build()))
	})
}
