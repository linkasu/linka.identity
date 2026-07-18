package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/schema"
	"github.com/ydb-platform/ydb-go-sdk-auth-environ"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
	"github.com/ydb-platform/ydb-go-sdk/v3/types"
	yc "github.com/ydb-platform/ydb-go-yc"
)

type Store struct {
	driver *ydb.Driver
	client query.Client
	now    func() time.Time
}

func Open(ctx context.Context, endpoint, database string) (*Store, error) {
	if strings.TrimSpace(endpoint) == "" || !strings.HasPrefix(database, "/") {
		return nil, errors.New("invalid YDB endpoint or database path")
	}
	dsn := strings.TrimRight(endpoint, "/") + database
	driver, err := ydb.Open(ctx, dsn, environ.WithEnvironCredentials(), yc.WithInternalCA())
	if err != nil {
		return nil, fmt.Errorf("open YDB failed (%T)", err)
	}
	return &Store{driver: driver, client: driver.Query(), now: time.Now}, nil
}

func New(driver *ydb.Driver) *Store {
	return &Store{driver: driver, client: driver.Query(), now: time.Now}
}

func (s *Store) Client() query.Client {
	return s.client
}

func (s *Store) Ping(ctx context.Context) error {
	row, err := s.client.QueryRow(ctx, `SELECT 1u AS value;`, query.WithTxControl(query.SnapshotReadOnlyTxControl()))
	if err != nil {
		return err
	}
	var value uint32
	return row.Scan(&value)
}

func (s *Store) Ready(ctx context.Context) error {
	row, err := s.client.QueryRow(ctx, `
		DECLARE $name AS Utf8;
		SELECT version FROM schema_meta WHERE name = $name;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$name").Text("identity").Build()),
		query.WithTxControl(query.SnapshotReadOnlyTxControl()))
	if err != nil {
		return err
	}
	var version uint64
	if err := row.Scan(&version); err != nil {
		return err
	}
	if version != schema.Version {
		return fmt.Errorf("YDB schema version is %d, expected %d", version, schema.Version)
	}
	return nil
}

func (s *Store) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.driver.Close(ctx)
}

func (s *Store) serializable(ctx context.Context, operation query.TxOperation) error {
	return s.client.DoTx(ctx, operation,
		query.WithTxSettings(query.TxSettings(query.WithSerializableReadWrite())),
		query.WithIdempotent(),
	)
}

func noRows(err error) error {
	if errors.Is(err, query.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}

func nullableText(value *string) types.Value {
	return types.NullableUTF8Value(value)
}

func nullableTimestamp(value *time.Time) types.Value {
	return types.NullableTimestampValueFromTime(value)
}
