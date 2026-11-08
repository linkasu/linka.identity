package schema

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

type migrationExecutor struct {
	version  uint64
	exists   bool
	commands []string
	fail     string
}

func (e *migrationExecutor) Exec(_ context.Context, sql string, _ ...query.ExecuteOption) error {
	e.commands = append(e.commands, sql)
	if e.fail != "" && strings.Contains(sql, e.fail) {
		return errors.New("injected schema failure")
	}
	if strings.Contains(sql, "UPSERT INTO schema_meta") || strings.Contains(sql, "INSERT INTO schema_meta") {
		e.exists, e.version = true, Version
	}
	return nil
}

func (e *migrationExecutor) QueryRow(context.Context, string, ...query.ExecuteOption) (query.Row, error) {
	if !e.exists {
		return nil, query.ErrNoRows
	}
	return migrationVersionRow{version: e.version}, nil
}

type migrationVersionRow struct {
	query.Row
	version uint64
}

func (r migrationVersionRow) Scan(values ...any) error {
	*values[0].(*uint64) = r.version
	return nil
}

func TestPublicAccountsUpgradePreservesVersionUntilDDLComplete(t *testing.T) {
	e := &migrationExecutor{exists: true, version: 1, fail: "CREATE TABLE IF NOT EXISTS account_sessions"}
	if err := Apply(t.Context(), e, time.Now().UTC()); err == nil || e.version != 1 {
		t.Fatal("partial public-account DDL must not promote the schema version")
	}
	e.fail, e.commands = "", nil
	if err := Apply(t.Context(), e, time.Now().UTC()); err != nil || e.version != Version {
		t.Fatalf("schema 1 must upgrade after all DDL: version=%d error=%v", e.version, err)
	}
	joined := strings.Join(e.commands, "\n")
	for _, table := range []string{"public_email_challenges", "public_registration_flows", "product_accounts", "account_sessions", "account_refresh_tokens", "public_auth_events", "public_account_audit"} {
		if !strings.Contains(joined, "CREATE TABLE IF NOT EXISTS "+table) {
			t.Fatalf("missing public account table: %s", table)
		}
	}
	if !strings.Contains(e.commands[len(e.commands)-1], "schema_meta") {
		t.Fatal("schema promotion must be the final write")
	}
}

func TestPublicAccountsSchemaFreshRepeatAndUnknownVersions(t *testing.T) {
	e := &migrationExecutor{}
	if err := Apply(t.Context(), e, time.Now().UTC()); err != nil || e.version != Version {
		t.Fatalf("fresh schema: version=%d error=%v", e.version, err)
	}
	if err := Apply(t.Context(), e, time.Now().UTC()); err != nil || e.version != Version {
		t.Fatalf("repeated migration: %v", err)
	}
	for _, version := range []uint64{0, 4, ^uint64(0)} {
		e := &migrationExecutor{exists: true, version: version}
		if err := Apply(t.Context(), e, time.Now().UTC()); err == nil || e.version != version || len(e.commands) != 1 {
			t.Fatalf("unknown version must remain untouched: %d error=%v", version, err)
		}
	}
}
