package privacyworker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/linka-cloud/linka.identity/internal/store"
)

type Worker struct {
	store        *store.Store
	pollInterval time.Duration
	maxAttempts  int
	logger       *slog.Logger
}

func New(database *store.Store, pollInterval time.Duration, maxAttempts int, logger *slog.Logger) *Worker {
	return &Worker{store: database, pollInterval: pollInterval, maxAttempts: maxAttempts, logger: logger}
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
	jobs, err := w.store.ClaimPrivacyErasures(ctx, 10)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			w.logger.Error("privacy erasure claim failed", "error_type", fmt.Sprintf("%T", err))
		}
		return err
	}
	for _, job := range jobs {
		if err := w.store.ErasePrivacyJob(ctx, job); err != nil {
			delay := retryDelay(job.Attempts)
			if retryErr := w.store.RetryPrivacyErasure(ctx, job, delay, w.maxAttempts); retryErr != nil {
				if !errors.Is(retryErr, context.Canceled) {
					w.logger.Error("privacy erasure retry failed", "error_type", fmt.Sprintf("%T", retryErr))
				}
				return retryErr
			}
		}
	}
	return nil
}

func retryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 10 {
		attempt = 10
	}
	return time.Duration(1<<uint(attempt-1)) * time.Second
}
