package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/linka-cloud/linka.identity/internal/migrations"
)

type Store struct {
	pool *pgxpool.Pool
}

func Open(ctx context.Context, databaseURL string, maxConnections int32) (*Store, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, errorsWithoutDSN("parse database configuration", err)
	}
	config.MaxConns = maxConnections
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, errorsWithoutDSN("create database pool", err)
	}
	return &Store{pool: pool}, nil
}

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

func (s *Store) Begin(ctx context.Context) (pgx.Tx, error) {
	return s.pool.Begin(ctx)
}

func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

func (s *Store) Ready(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return err
	}
	var applied bool
	if err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE name = $1)`, migrations.Current).Scan(&applied); err != nil {
		return err
	}
	if !applied {
		return errors.New("current database migration is not applied")
	}
	return nil
}

func (s *Store) Close() {
	s.pool.Close()
}

// pgx parse errors can echo a DSN. Startup errors should never expose credentials.
func errorsWithoutDSN(operation string, err error) error {
	return fmt.Errorf("%s failed (%T)", operation, err)
}
