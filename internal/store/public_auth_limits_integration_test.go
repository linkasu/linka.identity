//go:build integration

package store

import (
	"context"
	"errors"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/ids"
	"github.com/linka-cloud/linka.identity/internal/schema"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

func publicLimitIntegrationStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	endpoint, path := os.Getenv("TEST_YDB_ENDPOINT"), os.Getenv("TEST_YDB_DATABASE")
	if endpoint == "" || path == "" {
		t.Skip("TEST_YDB_ENDPOINT and TEST_YDB_DATABASE are not set")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "grpc" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1") || path != "/local" || os.Getenv("YDB_ANONYMOUS_CREDENTIALS") != "1" {
		t.Fatal("rate limit regression requires anonymous loopback /local YDB")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	database, err := Open(ctx, endpoint, path)
	if err != nil {
		t.Fatal("open integration YDB failed")
	}
	t.Cleanup(database.Close)
	if err := schema.Apply(ctx, database.Client(), time.Now().UTC()); err != nil {
		t.Fatal("apply integration schema failed")
	}
	return database, ctx
}

func publicLimitIntegrationID(t *testing.T) string {
	t.Helper()
	id, err := ids.NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func publicLimitIntegrationCount(t *testing.T, ctx context.Context, database *Store, bucket string) uint64 {
	t.Helper()
	row, err := database.Client().QueryRow(ctx, `DECLARE $bucket AS Utf8;
		SELECT COUNT(*) FROM public_auth_events WHERE bucket = $bucket;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$bucket").Text(bucket).Build()),
		query.WithTxControl(query.SnapshotReadOnlyTxControl()))
	if err != nil {
		t.Fatal("count owned rate limit events failed")
	}
	var count uint64
	if err := row.Scan(&count); err != nil {
		t.Fatal("scan owned rate limit events failed")
	}
	return count
}

type publicLimitBarrierTx struct {
	query.TxActor
	once    *sync.Once
	arrived chan<- struct{}
	release <-chan struct{}
}

func (tx publicLimitBarrierTx) QueryRow(ctx context.Context, sql string, opts ...query.ExecuteOption) (query.Row, error) {
	row, err := tx.TxActor.QueryRow(ctx, sql, opts...)
	if err != nil {
		return nil, err
	}
	return publicLimitBarrierRow{Row: row, tx: tx, ctx: ctx}, nil
}

type publicLimitBarrierRow struct {
	query.Row
	tx  publicLimitBarrierTx
	ctx context.Context
}

func (row publicLimitBarrierRow) Scan(dst ...any) error {
	if err := row.Row.Scan(dst...); err != nil {
		return err
	}
	row.tx.once.Do(func() {
		row.tx.arrived <- struct{}{}
		select {
		case <-row.tx.release:
		case <-row.ctx.Done():
		}
	})
	return row.ctx.Err()
}

func TestYDBPublicAuthLimitsConcurrentEmptyRange(t *testing.T) {
	database, ctx := publicLimitIntegrationStore(t)
	bucket := "limit-test-" + publicLimitIntegrationID(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	arrived, release := make(chan struct{}, 2), make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		eventID := publicLimitIntegrationID(t)
		go func() {
			var once sync.Once
			results <- database.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
				return consumePublicAuthLimits(ctx, publicLimitBarrierTx{tx, &once, arrived, release}, now, eventID,
					[]publicAuthLimit{{bucket, time.Hour, 1}})
			})
		}()
	}
	for range 2 {
		select {
		case <-arrived:
		case <-ctx.Done():
			close(release)
			t.Fatal("concurrent range reads did not complete")
		}
	}
	close(release)
	winners, blocked := 0, 0
	for range 2 {
		err := <-results
		var limited *PublicRateLimitError
		switch {
		case err == nil:
			winners++
		case errors.As(err, &limited):
			blocked++
		default:
			t.Fatal("unexpected concurrent limiter error")
		}
	}
	if count := publicLimitIntegrationCount(t, ctx, database, bucket); winners != 1 || blocked != 1 || count != 1 {
		t.Fatalf("phantom range protection failed: winners=%d blocked=%d events=%d", winners, blocked, count)
	}
}

func TestYDBPublicAuthLimitsWindowAndRollback(t *testing.T) {
	database, ctx := publicLimitIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, offset := range []time.Duration{-time.Hour, time.Hour} {
		bucket := "limit-test-" + publicLimitIntegrationID(t)
		eventID := publicLimitIntegrationID(t)
		if err := database.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
			return consumePublicAuthLimits(ctx, tx, now.Add(offset), eventID, []publicAuthLimit{{bucket, time.Hour, 1}})
		}); err != nil {
			t.Fatal("seed owned rate limit event failed")
		}
		emptyBucket := "a-limit-test-" + publicLimitIntegrationID(t)
		eventID = publicLimitIntegrationID(t)
		err := database.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
			return consumePublicAuthLimits(ctx, tx, now, eventID, []publicAuthLimit{{emptyBucket, time.Hour, 1}, {bucket, time.Hour, 1}})
		})
		var limited *PublicRateLimitError
		if !errors.As(err, &limited) || !limited.RetryAt.Equal(now.Add(offset+time.Hour)) {
			t.Fatal("inclusive boundary or future event was not blocked")
		}
		if publicLimitIntegrationCount(t, ctx, database, emptyBucket) != 0 || publicLimitIntegrationCount(t, ctx, database, bucket) != 1 {
			t.Fatal("blocked call left partial events")
		}
	}
	bucket := "limit-test-" + publicLimitIntegrationID(t)
	eventID := publicLimitIntegrationID(t)
	rollback := errors.New("forced caller rollback")
	err := database.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		if err := consumePublicAuthLimits(ctx, tx, now, eventID, []publicAuthLimit{{bucket, time.Hour, 1}}); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) || publicLimitIntegrationCount(t, ctx, database, bucket) != 0 {
		t.Fatal("caller rollback did not roll back rate limit events")
	}
}
