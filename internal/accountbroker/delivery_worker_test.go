package accountbroker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/store"
)

func TestDeliveryWorkerWaitsForDurableCreditAndHonorsContext(t *testing.T) {
	b, repository, _, input := newBeginBroker(t)
	if _, err := b.Begin(context.Background(), "fixture-installation-refresh", input); err != nil {
		t.Fatal(err)
	}
	sender := &fixtureMail{}
	worker, err := NewDeliveryWorker(b, sender, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	repository.claimErrors = []error{&store.PublicRateLimitError{RetryAt: time.Now().Add(5 * time.Millisecond)}}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := worker.Process(ctx); err != nil || sender.calls != 1 || repository.claimCalls != 3 {
		t.Fatalf("budget retry duplicated/skipped delivery: calls=%d claims=%d error=%v", sender.calls, repository.claimCalls, err)
	}
	before := repository.claimCalls
	cancel()
	if err := worker.Process(ctx); !errors.Is(err, context.Canceled) || repository.claimCalls != before {
		t.Fatal("cancelled worker attempted a new claim")
	}
}

func TestDeliveryWorkerDoesNotWaitBeyondRequestBudget(t *testing.T) {
	b, repository, _, _ := newBeginBroker(t)
	sender := &fixtureMail{}
	worker, _ := NewDeliveryWorker(b, sender, slog.New(slog.NewTextHandler(io.Discard, nil)))
	repository.claimErrors = []error{&store.PublicRateLimitError{RetryAt: time.Now().Add(time.Hour)}}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := worker.Process(ctx); err != nil || repository.claimCalls != 1 || sender.calls != 0 {
		t.Fatalf("worker exceeded a deferred request budget: %v", err)
	}
}
