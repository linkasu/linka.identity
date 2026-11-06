package store

import (
	"context"
	"errors"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

// The single active OTP key cannot be replaced while a live proof references it.
// Rotation waits at most the OTP lifetime; it never silently invalidates a code.
func (s *Store) ValidatePublicOTPKeyID(ctx context.Context, key string, now time.Time) error {
	if key == "" || now.IsZero() {
		return domain.ErrInvalid
	}
	row, err := s.client.QueryRow(ctx, `DECLARE $key AS Utf8; DECLARE $now AS Timestamp;
SELECT id FROM public_email_challenges WHERE otp_key_id <> $key AND expires_at > $now
AND state IN ('requested','delivering','delivered','delivery_uncertain') LIMIT 1;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$key").Text(key).Param("$now").Timestamp(now.UTC()).Build()), query.WithTxControl(query.SnapshotReadOnlyTxControl()))
	if errors.Is(err, query.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var id string
	if err := row.Scan(&id); err != nil {
		return err
	}
	return errors.New("a live public email challenge still references a different OTP key")
}
