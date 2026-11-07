package main

import (
	"context"
	"errors"
	"flag"
	"io"
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
	check, err := parseCheck(os.Args[1:])
	if err != nil {
		logger.Error("invalid schema arguments")
		os.Exit(1)
	}
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
	if err := run(ctx, check, database.Ready, func(ctx context.Context) error {
		return schema.Apply(ctx, database.Client(), time.Now().UTC())
	}); err != nil {
		if !errors.Is(err, context.Canceled) {
			logger.Error("schema operation failed")
		}
		os.Exit(1)
	}
	if check {
		logger.Info("schema check passed", "schema_version", schema.Version)
	} else {
		logger.Info("YDB schema is current", "schema_version", schema.Version)
	}
}

func parseCheck(args []string) (bool, error) {
	flags := flag.NewFlagSet("schema", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	check := flags.Bool("check", false, "check schema readiness without migrations")
	if err := flags.Parse(args); err != nil {
		return false, err
	}
	if flags.NArg() != 0 {
		return false, errors.New("unexpected schema arguments")
	}
	return *check, nil
}

func run(ctx context.Context, check bool, ready, apply func(context.Context) error) error {
	if check {
		return ready(ctx)
	}
	return apply(ctx)
}
