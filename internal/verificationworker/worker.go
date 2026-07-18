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
		if _, err := w.store.DeleteExpiredEmailVerifications(ctx, time.Now().UTC(), 100); err != nil && !errors.Is(err, context.Canceled) {
			w.logger.Error("expired email verification cleanup failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
