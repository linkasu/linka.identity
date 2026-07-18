package verificationworker

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/linka-cloud/linka.identity/internal/store"
)

type Worker struct {
	store        *store.Store
	pollInterval time.Duration
	logger       *slog.Logger
}

func New(database *store.Store, pollInterval time.Duration, logger *slog.Logger) *Worker {
	return &Worker{store: database, pollInterval: pollInterval, logger: logger}
}

func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()
	for {
		_ = w.Process(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (w *Worker) Process(ctx context.Context) error {
	_, err := w.store.DeleteExpiredEmailVerifications(ctx, time.Now().UTC(), 100)
	if err != nil && !errors.Is(err, context.Canceled) {
		w.logger.Error("expired email verification cleanup failed")
	}
	return err
}
