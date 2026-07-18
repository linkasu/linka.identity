package migrations

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

//go:embed sql/*.sql
var files embed.FS

const Current = "0005_privacy_fanout_cancellation.sql"

type DB interface {
	Begin(context.Context) (pgx.Tx, error)
}

func Run(ctx context.Context, db DB) error {
	entries, err := fs.ReadDir(files, "sql")
	if err != nil {
		return fmt.Errorf("read embedded migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		contents, err := files.ReadFile("sql/" + entry.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}
		if err := apply(ctx, db, entry.Name(), contents); err != nil {
			return err
		}
	}
	return nil
}

func apply(ctx context.Context, db DB, name string, contents []byte) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", name, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			name text PRIMARY KEY,
			checksum text NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("initialize migrations table: %w", err)
	}
	sum := sha256.Sum256(contents)
	checksum := hex.EncodeToString(sum[:])
	var existing string
	err = tx.QueryRow(ctx, "SELECT checksum FROM schema_migrations WHERE name = $1", name).Scan(&existing)
	switch {
	case err == nil && existing != checksum:
		return fmt.Errorf("migration %s checksum changed after application", name)
	case err == nil:
		return tx.Commit(ctx)
	case err != pgx.ErrNoRows:
		return fmt.Errorf("check migration %s: %w", name, err)
	}
	if _, err := tx.Exec(ctx, string(contents)); err != nil {
		return fmt.Errorf("apply migration %s: %w", name, err)
	}
	if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)", name, checksum); err != nil {
		return fmt.Errorf("record migration %s: %w", name, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migration %s: %w", name, err)
	}
	return nil
}
