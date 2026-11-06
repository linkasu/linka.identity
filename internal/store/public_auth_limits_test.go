package store

import (
	"context"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

const publicLimitEventID = "e252aefe-c471-4c1b-8746-8344ae9ce86d"

type publicLimitTx struct {
	query.TxActor
	rows       []publicLimitRow
	reads      []string
	writes     []string
	queryError error
	execError  error
}

func (tx *publicLimitTx) QueryRow(_ context.Context, sql string, opts ...query.ExecuteOption) (query.Row, error) {
	if !strings.Contains(sql, "created_at >= $from") || strings.Contains(sql, "created_at <=") || strings.Contains(sql, "$now") {
		return nil, errors.New("unexpected range predicate")
	}
	tx.reads = append(tx.reads, publicLimitBucket(opts))
	if tx.queryError != nil {
		return nil, tx.queryError
	}
	row := tx.rows[len(tx.reads)-1]
	return row, nil
}

func (tx *publicLimitTx) Exec(_ context.Context, _ string, opts ...query.ExecuteOption) error {
	tx.writes = append(tx.writes, publicLimitBucket(opts))
	return tx.execError
}

// The SDK exposes no execute-option getter; inspect only the bound bucket in this fake.
func publicLimitBucket(opts []query.ExecuteOption) string {
	params := reflect.ValueOf(opts[0]).FieldByName("params").Elem().Elem()
	for i := 0; i < params.Len(); i++ {
		param := params.Index(i).Elem()
		if param.FieldByName("name").String() == "$bucket" {
			return param.FieldByName("value").Elem().String()
		}
	}
	return ""
}

type publicLimitRow struct {
	query.Row
	count uint64
	first *time.Time
	err   error
}

func (row publicLimitRow) Scan(dst ...any) error {
	if row.err != nil {
		return row.err
	}
	*dst[0].(*uint64), *dst[1].(**time.Time) = row.count, row.first
	return nil
}

func TestPublicAuthLimitsSortedAndUnchanged(t *testing.T) {
	limits := []publicAuthLimit{{"z", time.Hour, 2}, {"a", time.Minute, 1}}
	original := append([]publicAuthLimit(nil), limits...)
	tx := &publicLimitTx{rows: make([]publicLimitRow, 2)}
	if err := consumePublicAuthLimits(context.Background(), tx, time.Now(), publicLimitEventID, limits); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tx.reads, []string{"a", "z"}) || !reflect.DeepEqual(tx.writes, tx.reads) || !reflect.DeepEqual(limits, original) {
		t.Fatalf("reads=%v writes=%v limits=%v", tx.reads, tx.writes, limits)
	}
}

func TestPublicAuthLimitsBlockedBeforeAnyWrite(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	first, future := now.Add(-time.Minute), now.Add(time.Hour)
	for _, count := range []uint64{1, math.MaxUint64} {
		tx := &publicLimitTx{rows: []publicLimitRow{{}, {count: count, first: &first}, {count: count, first: &future}}}
		err := consumePublicAuthLimits(context.Background(), tx, now, publicLimitEventID,
			[]publicAuthLimit{{"a", time.Hour, 1}, {"b", time.Hour, 1}, {"c", time.Hour, 1}})
		var limited *PublicRateLimitError
		if !errors.As(err, &limited) || !limited.RetryAt.Equal(future.Add(time.Hour)) || len(tx.reads) != 3 || len(tx.writes) != 0 {
			t.Fatalf("count=%d err=%v reads=%v writes=%v", count, err, tx.reads, tx.writes)
		}
		if err.Error() != "public account rate limit exceeded" {
			t.Fatal("rate limit error exposed details")
		}
	}
}

func TestPublicAuthLimitsInvalidParameters(t *testing.T) {
	valid := publicAuthLimit{"opaque", time.Hour, 1}
	now := time.Now()
	for name, limit := range map[string]publicAuthLimit{
		"empty": {"", time.Hour, 1}, "long": {strings.Repeat("x", 257), time.Hour, 1},
		"email": {"a@b", time.Hour, 1}, "control": {"a\u0085b", time.Hour, 1},
		"leading": {"\u2003a", time.Hour, 1}, "trailing": {"a ", time.Hour, 1},
		"utf8": {"\xff", time.Hour, 1}, "zero window": {"a", 0, 1},
		"negative window": {"a", -1, 1}, "long window": {"a", 24*time.Hour + 1, 1},
		"zero capacity": {"a", time.Hour, 0}, "large capacity": {"a", time.Hour, 10001},
	} {
		t.Run(name, func(t *testing.T) {
			assertPublicLimitInvalid(t, now, publicLimitEventID, []publicAuthLimit{valid, limit})
		})
	}
	assertPublicLimitInvalid(t, time.Time{}, publicLimitEventID, []publicAuthLimit{valid})
	assertPublicLimitInvalid(t, now, "invalid", []publicAuthLimit{valid})
	assertPublicLimitInvalid(t, now, publicLimitEventID, nil)
	assertPublicLimitInvalid(t, now, publicLimitEventID, []publicAuthLimit{valid, valid})
	assertPublicLimitInvalid(t, now, publicLimitEventID, make([]publicAuthLimit, 9))
}

func assertPublicLimitInvalid(t *testing.T, now time.Time, id string, limits []publicAuthLimit) {
	t.Helper()
	tx := &publicLimitTx{}
	if err := consumePublicAuthLimits(context.Background(), tx, now, id, limits); err == nil || len(tx.reads) != 0 || len(tx.writes) != 0 {
		t.Fatalf("invalid parameters reached database: err=%v", err)
	}
}

func TestPublicAuthLimitsErrorsClosedAndRedacted(t *testing.T) {
	failure := errors.New("private SQL and parameter values")
	for name, tx := range map[string]*publicLimitTx{
		"query":           {queryError: failure},
		"scan":            {rows: []publicLimitRow{{err: failure}}},
		"missing minimum": {rows: []publicLimitRow{{count: 1}}},
		"insert":          {rows: []publicLimitRow{{}}, execError: failure},
	} {
		t.Run(name, func(t *testing.T) {
			err := consumePublicAuthLimits(context.Background(), tx, time.Now(), publicLimitEventID, []publicAuthLimit{{"opaque", time.Hour, 2}})
			if err == nil || strings.Contains(err.Error(), failure.Error()) {
				t.Fatalf("unsafe error: %v", err)
			}
			if name != "missing minimum" && !errors.Is(err, failure) {
				t.Fatal("SDK retry cause lost")
			}
			if name != "insert" && len(tx.writes) != 0 {
				t.Fatal("error permitted writes")
			}
		})
	}
}
