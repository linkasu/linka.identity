package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/linka-cloud/linka.identity/internal/schema"
	"github.com/linka-cloud/linka.identity/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	endpoint := os.Getenv("YDB_ENDPOINT")
	databasePath := os.Getenv("YDB_DATABASE")
	if endpoint == "" || databasePath == "" {
		logger.Error("YDB_ENDPOINT and YDB_DATABASE are required")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	database, err := store.Open(ctx, endpoint, databasePath)
	if err != nil {
		logger.Error("open schema database", "error_type", slog.AnyValue(err).Kind().String())
		os.Exit(1)
	}
	defer database.Close()
	if err := schema.Apply(ctx, database.Client(), time.Now().UTC()); err != nil {
		if !errors.Is(err, context.Canceled) {
			logger.Error("schema application failed", "error", err.Error())
		}
		os.Exit(1)
	}
	logger.Info("YDB schema is current", "schema_version", schema.Version)
}
