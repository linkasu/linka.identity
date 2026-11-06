package store

import (
	"context"
	"testing"

	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

type schemaReadinessClient struct {
	query.Client
	version uint64
}

func (c schemaReadinessClient) QueryRow(context.Context, string, ...query.ExecuteOption) (query.Row, error) {
	return schemaReadinessRow{version: c.version}, nil
}

type schemaReadinessRow struct {
	query.Row
	version uint64
}

func (r schemaReadinessRow) Scan(values ...any) error {
	*values[0].(*uint64) = r.version
	return nil
}

func TestPublicAccountBinaryRequiresSchemaTwo(t *testing.T) {
	for _, version := range []uint64{0, 1, 2, 3, ^uint64(0)} {
		db := &Store{client: schemaReadinessClient{version: version}}
		if err := db.Ready(t.Context()); (err == nil) != (version == 2) {
			t.Fatalf("schema %d readiness: %v", version, err)
		}
	}
}
