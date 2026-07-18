package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/linka-cloud/linka.identity/internal/migrations"
	"github.com/linka-cloud/linka.identity/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		logger.Error("DATABASE_URL is required")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	database, err := store.Open(ctx, databaseURL, 5)
	if err != nil {
		logger.Error("open migration database", "error", err.Error())
		os.Exit(1)
	}
	defer database.Close()
	if err := migrations.Run(ctx, database.Pool()); err != nil {
		if !errors.Is(err, context.Canceled) {
			logger.Error("migration failed", "error", err.Error())
		}
		os.Exit(1)
	}
	logger.Info("migrations applied")
}
