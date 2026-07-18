package outbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/linka-cloud/linka.identity/internal/token"
)

type Worker struct {
	store        *store.Store
	url          string
	signer       *token.Signer
	products     map[string]string
	maxAttempts  int
	pollInterval time.Duration
	client       *http.Client
	logger       *slog.Logger
}

var errDeliveryPending = errors.New("downstream privacy request is not completed")

func New(database *store.Store, url string, signer *token.Signer, products map[string]string, pollInterval time.Duration, maxAttempts int, logger *slog.Logger) *Worker {
	return &Worker{
		store: database, url: url, signer: signer, products: products, pollInterval: pollInterval, maxAttempts: maxAttempts,
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}, logger: logger,
	}
}

func (w *Worker) Run(ctx context.Context) {
	if w.url == "" {
		return
	}
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
	if w.url == "" {
		return nil
	}
	events, err := w.store.ClaimOutbox(ctx, 20)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			w.logger.Error("outbox claim failed", "error_type", fmt.Sprintf("%T", err))
		}
		return err
	}
	for _, event := range events {
		receipt, err := w.deliver(ctx, event)
		if errors.Is(err, errDeliveryPending) {
			if retryErr := w.store.RescheduleOutbox(ctx, event.ID, retryDelay(event.PollCount+1)); retryErr != nil {
				if !errors.Is(retryErr, context.Canceled) {
					w.logger.Error("outbox polling reschedule failed", "error_type", fmt.Sprintf("%T", retryErr))
				}
				return retryErr
			}
			continue
		}
		if err != nil {
			delay := retryDelay(event.Attempt + 1)
			if retryErr := w.store.RetryOutbox(ctx, event.ID, "delivery failed", delay, w.maxAttempts); retryErr != nil {
				if !errors.Is(retryErr, context.Canceled) {
					w.logger.Error("outbox retry scheduling failed", "error_type", fmt.Sprintf("%T", retryErr))
				}
				return retryErr
			}
			continue
		}
		if err := w.store.MarkOutboxDelivered(ctx, event.ID, receipt); err != nil {
			if !errors.Is(err, context.Canceled) {
				w.logger.Error("outbox completion failed", "error_type", fmt.Sprintf("%T", err))
			}
			return err
		}
	}
	return nil
}

func (w *Worker) deliver(ctx context.Context, event store.OutboxEvent) (json.RawMessage, error) {
	var payload struct {
		Scope struct {
			Product    string `json:"product"`
			SubjectKey string `json:"subject_key"`
		} `json:"scope"`
	}
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		return nil, err
	}
	audience, ok := w.products[payload.Scope.Product]
	if !ok || payload.Scope.SubjectKey == "" {
		return nil, errors.New("outbox payload has unknown product scope")
	}
	accessToken, _, err := w.signer.SignClaims(token.SignInput{
		Audience: audience, Product: payload.Scope.Product, Subject: payload.Scope.SubjectKey,
		SubjectType: "service", Scopes: []string{"privacy:write"},
	})
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(event.Payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Idempotency-Key", event.ID)
	response, err := w.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	receipt, err := io.ReadAll(io.LimitReader(response.Body, 16*1024))
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("delivery returned status %d", response.StatusCode)
	}
	if !json.Valid(receipt) {
		return nil, errors.New("delivery returned invalid receipt JSON")
	}
	completed, err := completedReceipt(receipt, event.ID)
	if err != nil {
		return nil, err
	}
	if !completed {
		return receipt, errDeliveryPending
	}
	return receipt, nil
}

func completedReceipt(receipt json.RawMessage, expectedRequestID string) (bool, error) {
	var result struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal(receipt, &result); err != nil {
		return false, err
	}
	if result.RequestID != expectedRequestID {
		return false, errors.New("delivery receipt has mismatched request ID")
	}
	switch result.Status {
	case "completed":
		return true, nil
	case "pending", "processing", "retry":
		return false, nil
	case "failed":
		return false, errors.New("downstream privacy request failed")
	default:
		return false, errors.New("delivery receipt has invalid status")
	}
}

func retryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 8 {
		attempt = 8
	}
	return time.Duration(1<<uint(attempt-1)) * time.Second
}
