package store

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

type publicAuthLimit struct {
	Bucket string
	Window time.Duration
	Max    uint64
}

type PublicRateLimitError struct {
	RetryAt time.Time
}

func (*PublicRateLimitError) Error() string { return "public account rate limit exceeded" }

// Keep SDK retry classification without exposing SQL or bound values in errors.
type publicAuthLimitQueryError struct{ cause error }

func (publicAuthLimitQueryError) Error() string   { return "public account rate limit storage failed" }
func (e publicAuthLimitQueryError) Unwrap() error { return e.cause }

// The caller supplies server time and an event ID fixed outside transaction retries.
// Buckets must contain only HMACs or opaque identifiers, never raw email addresses.
func consumePublicAuthLimits(ctx context.Context, tx query.TxActor, now time.Time, eventID string, limits []publicAuthLimit) error {
	if now.IsZero() || !domain.ValidUUID(eventID) || len(limits) < 1 || len(limits) > 8 {
		return errors.New("invalid public account rate limit parameters")
	}
	limits = slices.Clone(limits)
	slices.SortFunc(limits, func(a, b publicAuthLimit) int { return strings.Compare(a.Bucket, b.Bucket) })
	for i, limit := range limits {
		if len(limit.Bucket) < 1 || len(limit.Bucket) > 256 || !utf8.ValidString(limit.Bucket) ||
			strings.ContainsRune(limit.Bucket, '@') || strings.ContainsFunc(limit.Bucket, unicode.IsControl) ||
			strings.TrimSpace(limit.Bucket) != limit.Bucket || (i > 0 && limits[i-1].Bucket == limit.Bucket) ||
			limit.Window <= 0 || limit.Window > 24*time.Hour || limit.Max < 1 || limit.Max > 10000 {
			return errors.New("invalid public account rate limit parameters")
		}
	}
	now = now.UTC().Truncate(time.Microsecond)
	var retryAt time.Time
	for _, limit := range limits {
		row, err := tx.QueryRow(ctx, `
			DECLARE $bucket AS Utf8;
			DECLARE $from AS Timestamp;
			SELECT COUNT(*), MIN(created_at) FROM public_auth_events
			WHERE bucket = $bucket AND created_at >= $from;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$bucket").Text(limit.Bucket).
				Param("$from").Timestamp(now.Add(-limit.Window)).Build()))
		if err != nil {
			return publicAuthLimitQueryError{cause: err}
		}
		var count uint64
		var first *time.Time
		if err := row.Scan(&count, &first); err != nil {
			return publicAuthLimitQueryError{cause: err}
		}
		if count > 0 && first == nil {
			return errors.New("invalid public account rate limit state")
		}
		if count >= limit.Max {
			if next := first.Add(limit.Window); next.After(retryAt) {
				retryAt = next
			}
		}
	}
	if !retryAt.IsZero() {
		return &PublicRateLimitError{RetryAt: retryAt}
	}
	for _, limit := range limits {
		if err := tx.Exec(ctx, `
			DECLARE $bucket AS Utf8;
			DECLARE $created_at AS Timestamp;
			DECLARE $event_id AS Utf8;
			INSERT INTO public_auth_events (bucket, created_at, event_id)
			VALUES ($bucket, $created_at, $event_id);`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$bucket").Text(limit.Bucket).
				Param("$created_at").Timestamp(now).
				Param("$event_id").Text(eventID).Build())); err != nil {
			return publicAuthLimitQueryError{cause: err}
		}
	}
	return nil
}
