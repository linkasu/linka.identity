package accountbroker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/linka-cloud/linka.identity/internal/ids"
	"github.com/linka-cloud/linka.identity/internal/store"
)

// DeliveryWorker uses the same durable sender jobs from background and IAM ticks.
// A serverless instance may be suspended between requests, so Run is not the
// sole source of progress. The private tick remains the recovery mechanism.
type DeliveryWorker struct {
	broker *Broker
	sender MailSender
	logger *slog.Logger
}

func NewDeliveryWorker(broker *Broker, sender MailSender, logger *slog.Logger) (*DeliveryWorker, error) {
	if broker == nil || sender == nil || logger == nil {
		return nil, errors.New("invalid public account delivery worker")
	}
	return &DeliveryWorker{broker: broker, sender: sender, logger: logger}, nil
}

func (w *DeliveryWorker) Process(ctx context.Context) error {
	for processed := 0; processed < 5; {
		if err := ctx.Err(); err != nil {
			return err
		}
		owner, err := ids.NewUUID()
		if err != nil {
			return errors.New("public account sender lease unavailable")
		}
		worked, err := w.broker.ProcessEmail(ctx, w.sender, owner)
		if err != nil {
			var limited *store.PublicRateLimitError
			if !errors.As(err, &limited) {
				return err
			}
			wait := time.Until(limited.RetryAt) + time.Microsecond
			if wait <= 0 {
				wait = time.Microsecond
			}
			if deadline, ok := ctx.Deadline(); ok && !limited.RetryAt.Before(deadline) {
				return nil
			}
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			continue
		}
		if !worked {
			return nil
		}
		processed++
	}
	return nil
}

func (w *DeliveryWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		processCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		err := w.Process(processCtx)
		cancel()
		if err != nil && ctx.Err() == nil {
			w.logger.Warn("public account delivery unavailable", "error_type", fmt.Sprintf("%T", err))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
