package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
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
	RequestID     *string
	Version       uint64
}

func (s *Store) ClaimOutbox(ctx context.Context, batchSize int) ([]OutboxEvent, error) {
	var events []OutboxEvent
	err := s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		events = nil
		now := s.now().UTC()
		rows, err := tx.QueryResultSet(ctx, `
			DECLARE $now AS Timestamp;
			DECLARE $stale_before AS Timestamp;
			DECLARE $limit AS Uint64;
			SELECT id, topic, aggregate_type, aggregate_id, payload, attempts, poll_count,
			       created_at, privacy_step_id, privacy_request_id, version
			FROM outbox_events
			WHERE (status = "pending" AND available_at <= $now)
			   OR (status = "processing" AND COALESCE(locked_at < $stale_before, false))
			ORDER BY created_at LIMIT $limit;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$now").Timestamp(now).
				Param("$stale_before").Timestamp(now.Add(-5*time.Minute)).
				Param("$limit").Uint64(uint64(batchSize)).
				Build()))
		if err != nil {
			return err
		}
		defer rows.Close(ctx)
		for row, rowErr := range rows.Rows(ctx) {
			if rowErr != nil {
				return rowErr
			}
			var event OutboxEvent
			var payload string
			var attempts, polls uint64
			if err := row.Scan(&event.ID, &event.Topic, &event.AggregateType, &event.AggregateID, &payload,
				&attempts, &polls, &event.CreatedAt, &event.PrivacyStepID, &event.RequestID, &event.Version); err != nil {
				return err
			}
			event.Payload = json.RawMessage(payload)
			event.Attempt = int(attempts)
			event.PollCount = int(polls)
			if event.RequestID != nil {
				request, err := getPrivacyRequestWith(ctx, tx, *event.RequestID)
				if err != nil {
					return err
				}
				if request.Status != "requested" && request.Status != "processing" {
					continue
				}
			}
			updated, err := tx.QueryRow(ctx, `
				DECLARE $id AS Utf8;
				DECLARE $now AS Timestamp;
				DECLARE $version AS Uint64;
				UPDATE outbox_events
				SET status = "processing", locked_at = $now, version = version + 1u
				WHERE id = $id AND version = $version RETURNING version;`,
				query.WithParameters(ydb.ParamsBuilder().
					Param("$id").Text(event.ID).
					Param("$now").Timestamp(now).
					Param("$version").Uint64(event.Version).
					Build()))
			if err != nil {
				return optimistic(err)
			}
			var next uint64
			if err := updated.Scan(&next); err != nil || next != event.Version+1 {
				return domain.ErrConflict
			}
			event.Version = next
			events = append(events, event)
		}
		return nil
	})
	return events, err
}

func (s *Store) MarkOutboxDelivered(ctx context.Context, id string, receipt json.RawMessage) error {
	var result struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal(receipt, &result); err != nil || result.RequestID != id || result.Status != "completed" {
		return errors.New("outbox delivery receipt is not completed")
	}
	return s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		row, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			SELECT status, privacy_step_id, version FROM outbox_events WHERE id = $id;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(id).Build()))
		if err != nil {
			return noRows(err)
		}
		var status string
		var stepID *string
		var version uint64
		if err := row.Scan(&status, &stepID, &version); err != nil {
			return err
		}
		if status != "processing" {
			return domain.ErrConflict
		}
		now := s.now().UTC()
		updated, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			DECLARE $receipt AS Json;
			DECLARE $now AS Timestamp;
			DECLARE $version AS Uint64;
			UPDATE outbox_events
			SET status = "delivered", delivered_at = $now, locked_at = NULL,
			    last_error = NULL, delivery_receipt = $receipt, version = version + 1u
			WHERE id = $id AND version = $version RETURNING version;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$id").Text(id).
				Param("$receipt").JSONFromBytes(receipt).
				Param("$now").Timestamp(now).
				Param("$version").Uint64(version).
				Build()))
		if err != nil {
			return optimistic(err)
		}
		var next uint64
		if err := updated.Scan(&next); err != nil || next != version+1 {
			return domain.ErrConflict
		}
		if stepID == nil {
			return nil
		}
		stepRow, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			SELECT status, version FROM privacy_request_steps WHERE id = $id;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(*stepID).Build()))
		if err != nil {
			return noRows(err)
		}
		var stepStatus string
		var stepVersion uint64
		if err := stepRow.Scan(&stepStatus, &stepVersion); err != nil {
			return err
		}
		if stepStatus == "completed" {
			return nil
		}
		stepUpdate, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			DECLARE $receipt AS Json;
			DECLARE $now AS Timestamp;
			DECLARE $version AS Uint64;
			UPDATE privacy_request_steps
			SET status = "completed", receipt = $receipt, completed_at = $now,
			    lease_until = NULL, updated_at = $now, version = version + 1u
			WHERE id = $id AND version = $version RETURNING version;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$id").Text(*stepID).
				Param("$receipt").JSONFromBytes(receipt).
				Param("$now").Timestamp(now).
				Param("$version").Uint64(stepVersion).
				Build()))
		if err != nil {
			return optimistic(err)
		}
		if err := stepUpdate.Scan(&next); err != nil || next != stepVersion+1 {
			return domain.ErrConflict
		}
		return nil
	})
}

func (s *Store) RetryOutbox(ctx context.Context, id, message string, delay time.Duration, maxAttempts int) error {
	if len(message) > 500 {
		message = message[:500]
	}
	return s.updateClaimedOutbox(ctx, id, func(attempts, polls uint64, version uint64, tx query.TxActor) error {
		status := "pending"
		if attempts+1 >= uint64(maxAttempts) {
			status = "manual_dlq"
		}
		row, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			DECLARE $status AS Utf8;
			DECLARE $available_at AS Timestamp;
			DECLARE $last_error AS Utf8;
			DECLARE $version AS Uint64;
			UPDATE outbox_events
			SET attempts = attempts + 1u, status = $status, available_at = $available_at,
			    locked_at = NULL, last_error = $last_error, version = version + 1u
			WHERE id = $id AND version = $version RETURNING version;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$id").Text(id).
				Param("$status").Text(status).
				Param("$available_at").Timestamp(s.now().UTC().Add(delay)).
				Param("$last_error").Text(message).
				Param("$version").Uint64(version).
				Build()))
		if err != nil {
			return optimistic(err)
		}
		var next uint64
		if err := row.Scan(&next); err != nil || next != version+1 {
			return domain.ErrConflict
		}
		return nil
	})
}

func (s *Store) RescheduleOutbox(ctx context.Context, id string, delay time.Duration) error {
	return s.updateClaimedOutbox(ctx, id, func(_, _ uint64, version uint64, tx query.TxActor) error {
		row, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			DECLARE $available_at AS Timestamp;
			DECLARE $version AS Uint64;
			UPDATE outbox_events
			SET status = "pending", poll_count = poll_count + 1u, available_at = $available_at,
			    locked_at = NULL, last_error = NULL, version = version + 1u
			WHERE id = $id AND version = $version RETURNING version;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$id").Text(id).
				Param("$available_at").Timestamp(s.now().UTC().Add(delay)).
				Param("$version").Uint64(version).
				Build()))
		if err != nil {
			return optimistic(err)
		}
		var next uint64
		if err := row.Scan(&next); err != nil || next != version+1 {
			return domain.ErrConflict
		}
		return nil
	})
}

func (s *Store) updateClaimedOutbox(ctx context.Context, id string, update func(uint64, uint64, uint64, query.TxActor) error) error {
	return s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		row, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			SELECT status, attempts, poll_count, version FROM outbox_events WHERE id = $id;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(id).Build()))
		if err != nil {
			return noRows(err)
		}
		var status string
		var attempts, polls, version uint64
		if err := row.Scan(&status, &attempts, &polls, &version); err != nil {
			return err
		}
		if status != "processing" {
			return domain.ErrConflict
		}
		return update(attempts, polls, version, tx)
	})
}

func (s *Store) OutboxReady(ctx context.Context, maxAge time.Duration) error {
	rows, err := s.client.QueryResultSet(ctx, `
		SELECT status, created_at FROM outbox_events
		WHERE status = "manual_dlq" OR status IN ("pending", "processing");`,
		query.WithTxControl(query.SnapshotReadOnlyTxControl()))
	if err != nil {
		return err
	}
	defer rows.Close(ctx)
	staleBefore := s.now().UTC().Add(-maxAge)
	for row, rowErr := range rows.Rows(ctx) {
		if rowErr != nil {
			return rowErr
		}
		var status string
		var createdAt time.Time
		if err := row.Scan(&status, &createdAt); err != nil {
			return err
		}
		if status == "manual_dlq" || createdAt.Before(staleBefore) {
			return errors.New("outbox has manual DLQ or stale required deliveries")
		}
	}
	return nil
}
