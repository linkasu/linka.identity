package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

type OutboxEvent struct {
	ID            string          `json:"id"`
	Topic         string          `json:"topic"`
	AggregateType string          `json:"aggregate_type"`
	AggregateID   string          `json:"aggregate_id"`
	Payload       json.RawMessage `json:"payload"`
	Attempt       int             `json:"attempt"`
	PollCount     int             `json:"poll_count"`
	CreatedAt     time.Time       `json:"created_at"`
	PrivacyStepID *string
}

func (s *Store) ClaimOutbox(ctx context.Context, batchSize int) ([]OutboxEvent, error) {
	rows, err := s.pool.Query(ctx, `
		WITH candidates AS (
			SELECT event.id
			FROM outbox_events event
			LEFT JOIN privacy_request_steps step ON step.id = event.privacy_step_id
			LEFT JOIN privacy_requests request ON request.id = step.privacy_request_id
			WHERE ((event.status = 'pending' AND event.available_at <= now()) OR
			       (event.status = 'processing' AND event.locked_at < now() - interval '5 minutes'))
			  AND (event.privacy_step_id IS NULL OR request.status IN ('requested', 'processing'))
			ORDER BY event.created_at
			FOR UPDATE OF event SKIP LOCKED
			LIMIT $1
		)
		UPDATE outbox_events event
		SET status = 'processing', locked_at = now()
		FROM candidates
		WHERE event.id = candidates.id
		RETURNING event.id::text, event.topic, event.aggregate_type,
		          event.aggregate_id::text, event.payload, event.attempts, event.poll_count,
		          event.created_at, event.privacy_step_id::text`, batchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := make([]OutboxEvent, 0, batchSize)
	for rows.Next() {
		var event OutboxEvent
		if err := rows.Scan(&event.ID, &event.Topic, &event.AggregateType, &event.AggregateID, &event.Payload,
			&event.Attempt, &event.PollCount, &event.CreatedAt, &event.PrivacyStepID); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) MarkOutboxDelivered(ctx context.Context, id string, receipt json.RawMessage) error {
	var result struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal(receipt, &result); err != nil || result.RequestID != id || result.Status != "completed" {
		return errors.New("outbox delivery receipt is not completed")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var stepID *string
	err = tx.QueryRow(ctx, `
		UPDATE outbox_events
		SET status = 'delivered', delivered_at = now(), locked_at = NULL, last_error = NULL, delivery_receipt = $2
		WHERE id = $1 AND status = 'processing'
		RETURNING privacy_step_id::text`, id, receipt).Scan(&stepID)
	if err != nil {
		return err
	}
	if stepID != nil {
		if _, err := tx.Exec(ctx, `
			UPDATE privacy_request_steps
			SET status = 'completed', receipt = $2, completed_at = now(), lease_until = NULL, updated_at = now()
			WHERE id = $1 AND status <> 'completed'`, *stepID, receipt); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) RetryOutbox(ctx context.Context, id, message string, delay time.Duration, maxAttempts int) error {
	if len(message) > 500 {
		message = message[:500]
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE outbox_events
		SET attempts = attempts + 1,
		    status = CASE WHEN attempts + 1 >= $4 THEN 'manual_dlq' ELSE 'pending' END,
		    available_at = now() + $2::interval,
		    locked_at = NULL, last_error = $3
		WHERE id = $1 AND status = 'processing'`, id, pgInterval(delay), message, maxAttempts)
	return err
}

func (s *Store) RescheduleOutbox(ctx context.Context, id string, delay time.Duration) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE outbox_events
		SET status = 'pending', poll_count = poll_count + 1, available_at = now() + $2::interval,
		    locked_at = NULL, last_error = NULL
		WHERE id = $1 AND status = 'processing'`, id, pgInterval(delay))
	return err
}

func (s *Store) OutboxReady(ctx context.Context, maxAge time.Duration) error {
	var dlqCount, staleCount int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status = 'manual_dlq'),
		       count(*) FILTER (WHERE status IN ('pending', 'processing') AND created_at < now() - $1::interval)
		FROM outbox_events`, pgInterval(maxAge)).Scan(&dlqCount, &staleCount)
	if err != nil {
		return err
	}
	if dlqCount > 0 || staleCount > 0 {
		return errors.New("outbox has manual DLQ or stale required deliveries")
	}
	return nil
}

func pgInterval(delay time.Duration) string {
	return delay.String()
}
