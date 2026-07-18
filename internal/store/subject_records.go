package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/ids"
)

type Subject struct {
	Kind string
	ID   string
}

type Consent struct {
	ID            string
	Subject       Subject
	ProductID     string
	ConsentType   string
	PolicyVersion string
	Status        string
	RecordedAt    time.Time
}

type PrivacyRequest struct {
	Subject             Subject
	SubjectKey          string
	RequestType         string
	Scope               string
	ProductID           *string
	RequestedAt         time.Time
	RequestedByWorkload string
	IdempotencyKey      string
}

type PrivacyRequestStatus struct {
	ID          string     `json:"id"`
	RequestType string     `json:"request_type"`
	Scope       string     `json:"scope"`
	ProductID   *string    `json:"product_id,omitempty"`
	Status      string     `json:"status"`
	RequestedAt time.Time  `json:"requested_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

type PrivacyStatusUpdate struct {
	ID        string
	Status    string
	Actor     string
	AuditNote string
}

func (s *Store) CreateConsent(ctx context.Context, consent Consent) error {
	personID, installationID := subjectIDs(consent.Subject)
	if err := s.validateSubject(ctx, consent.Subject, consent.ProductID); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO consents (
			id, person_id, installation_id, product_id, consent_type,
			policy_version, status, recorded_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, consent.ID, personID,
		installationID, consent.ProductID, consent.ConsentType, consent.PolicyVersion,
		consent.Status, consent.RecordedAt)
	return err
}

func (s *Store) SetTelemetryPreference(ctx context.Context, subject Subject, subjectKey, productID, preference string, recordedAt, requestedAt time.Time) error {
	if err := s.validateSubject(ctx, subject, productID); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	lockKey := subject.Kind + "|" + subject.ID + "|" + productID
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", lockKey); err != nil {
		return err
	}

	personID, installationID := subjectIDs(subject)
	var previous string
	var previousAt time.Time
	err = tx.QueryRow(ctx, `
		SELECT preference, recorded_at FROM telemetry_preferences
		WHERE (($1::uuid IS NOT NULL AND person_id = $1) OR
		       ($2::uuid IS NOT NULL AND installation_id = $2))
		  AND product_id = $3
		FOR UPDATE`, personID, installationID, productID).Scan(&previous, &previousAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err == nil && (recordedAt.Before(previousAt) || (recordedAt.Equal(previousAt) && preference != previous)) {
		return domain.ErrConflict
	}
	preferenceID, err := ids.NewUUID()
	if err != nil {
		return err
	}
	if personID != nil {
		if _, err := tx.Exec(ctx, `
			INSERT INTO telemetry_preferences (
				id, person_id, installation_id, product_id, preference, recorded_at
			) VALUES ($1, $2, NULL, $3, $4, $5)
			ON CONFLICT (person_id, product_id) WHERE person_id IS NOT NULL DO UPDATE
			SET preference = EXCLUDED.preference, recorded_at = EXCLUDED.recorded_at, updated_at = now()`,
			preferenceID, personID, productID, preference, recordedAt); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(ctx, `
			INSERT INTO telemetry_preferences (
				id, person_id, installation_id, product_id, preference, recorded_at
			) VALUES ($1, NULL, $2, $3, $4, $5)
			ON CONFLICT (installation_id, product_id) WHERE installation_id IS NOT NULL DO UPDATE
			SET preference = EXCLUDED.preference, recorded_at = EXCLUDED.recorded_at, updated_at = now()`,
			preferenceID, installationID, productID, preference, recordedAt); err != nil {
			return err
		}
	}
	if preference == "denied" && previous != "denied" {
		eventID, err := ids.NewUUID()
		if err != nil {
			return err
		}
		payload := map[string]any{
			"schema_version": 2,
			"request_id":     eventID,
			"scope":          map[string]any{"product": productID, "subject_key": subjectKey},
			"action":         "opt_out",
			"requested_at":   requestedAt.UTC(),
		}
		if err := insertOutbox(ctx, tx, eventID, "telemetry.suppression.requested", "telemetry_preference", preferenceID, nil, payload); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) CreatePrivacyRequest(ctx context.Context, request PrivacyRequest, products map[string]string) (PrivacyRequestStatus, bool, error) {
	productID := ""
	if request.ProductID != nil {
		productID = *request.ProductID
	}
	if err := s.validateSubject(ctx, request.Subject, productID); err != nil {
		return PrivacyRequestStatus{}, false, err
	}
	var aliases []ResolvedAlias
	var err error
	if request.RequestType == "deletion" {
		if request.Subject.Kind == "person" {
			aliases, err = s.PrivacyFanoutAliases(ctx, request.Subject.ID, request.ProductID)
			if err != nil {
				return PrivacyRequestStatus{}, false, err
			}
		} else {
			audience, ok := products[productID]
			if !ok {
				return PrivacyRequestStatus{}, false, domain.ErrInvalid
			}
			aliases = []ResolvedAlias{{OpaqueKey: request.SubjectKey, ProductID: productID, Audience: audience, SubjectType: "installation", SubjectID: request.Subject.ID}}
		}
	}
	fingerprintInput := request.Subject.Kind + "\x00" + request.Subject.ID + "\x00" + request.RequestType + "\x00" + request.Scope + "\x00" + productID
	fingerprintSum := sha256.Sum256([]byte(fingerprintInput))
	fingerprint := hex.EncodeToString(fingerprintSum[:])
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return PrivacyRequestStatus{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	lockKey := request.RequestedByWorkload + "|" + request.IdempotencyKey
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", lockKey); err != nil {
		return PrivacyRequestStatus{}, false, err
	}
	var existing PrivacyRequestStatus
	var existingFingerprint string
	err = tx.QueryRow(ctx, `
		SELECT id::text, request_type, scope, product_id, status, requested_at, completed_at, request_fingerprint
		FROM privacy_requests WHERE requested_by_workload = $1 AND idempotency_key = $2`,
		request.RequestedByWorkload, request.IdempotencyKey).Scan(
		&existing.ID, &existing.RequestType, &existing.Scope, &existing.ProductID, &existing.Status,
		&existing.RequestedAt, &existing.CompletedAt, &existingFingerprint)
	if err == nil {
		if existingFingerprint != fingerprint {
			return PrivacyRequestStatus{}, false, domain.ErrConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return PrivacyRequestStatus{}, false, err
		}
		return existing, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return PrivacyRequestStatus{}, false, err
	}
	requestID, err := ids.NewUUID()
	if err != nil {
		return PrivacyRequestStatus{}, false, err
	}
	personID, installationID := subjectIDs(request.Subject)
	if _, err := tx.Exec(ctx, `
		INSERT INTO privacy_requests (
			id, person_id, installation_id, request_type, scope,
			product_id, status, requested_at, requested_by_workload, idempotency_key, request_fingerprint
		) VALUES ($1, $2, $3, $4, $5, $6, 'requested', $7, $8, $9, $10)`, requestID,
		personID, installationID, request.RequestType, request.Scope,
		request.ProductID, request.RequestedAt, request.RequestedByWorkload, request.IdempotencyKey, fingerprint); err != nil {
		return PrivacyRequestStatus{}, false, err
	}
	if request.RequestType == "deletion" {
		for _, alias := range aliases {
			expectedAudience, ok := products[alias.ProductID]
			if !ok || alias.Audience != expectedAudience {
				continue
			}
			stepID, idErr := ids.NewUUID()
			if idErr != nil {
				return PrivacyRequestStatus{}, false, idErr
			}
			eventID, idErr := ids.NewUUID()
			if idErr != nil {
				return PrivacyRequestStatus{}, false, idErr
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO privacy_request_steps (id, privacy_request_id, step_type, product_id, subject_key)
				VALUES ($1, $2, 'metric', $3, $4)`, stepID, requestID, alias.ProductID, alias.OpaqueKey); err != nil {
				return PrivacyRequestStatus{}, false, err
			}
			payload := map[string]any{
				"schema_version": 2,
				"request_id":     eventID,
				"scope":          map[string]any{"product": alias.ProductID, "subject_key": alias.OpaqueKey},
				"action":         "delete",
				"requested_at":   request.RequestedAt.UTC(),
			}
			if err := insertOutbox(ctx, tx, eventID, "telemetry.deletion.requested", "privacy_request", requestID, &stepID, payload); err != nil {
				return PrivacyRequestStatus{}, false, err
			}
		}
		postgresStepID, err := ids.NewUUID()
		if err != nil {
			return PrivacyRequestStatus{}, false, err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO privacy_request_steps (id, privacy_request_id, step_type)
			VALUES ($1, $2, 'postgres')`, postgresStepID, requestID); err != nil {
			return PrivacyRequestStatus{}, false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return PrivacyRequestStatus{}, false, err
	}
	return PrivacyRequestStatus{ID: requestID, RequestType: request.RequestType, Scope: request.Scope, ProductID: request.ProductID, Status: "requested", RequestedAt: request.RequestedAt}, true, nil
}

func (s *Store) GetPrivacyRequest(ctx context.Context, id string) (PrivacyRequestStatus, error) {
	var result PrivacyRequestStatus
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, request_type, scope, product_id, status, requested_at, completed_at
		FROM privacy_requests WHERE id = $1`, id).Scan(
		&result.ID, &result.RequestType, &result.Scope, &result.ProductID,
		&result.Status, &result.RequestedAt, &result.CompletedAt)
	return result, err
}

func (s *Store) UpdatePrivacyRequestStatus(ctx context.Context, update PrivacyStatusUpdate) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var currentStatus string
	if err := tx.QueryRow(ctx, "SELECT status FROM privacy_requests WHERE id = $1 FOR UPDATE", update.ID).Scan(&currentStatus); err != nil {
		return err
	}
	if !domain.ValidPrivacyTransition(currentStatus, update.Status) {
		return domain.ErrConflict
	}
	if update.Status == "rejected" || update.Status == "cancelled" {
		var deliveryStarted bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1
				FROM privacy_request_steps step
				LEFT JOIN outbox_events event ON event.privacy_step_id = step.id
				WHERE step.privacy_request_id = $1
				  AND (step.status <> 'pending' OR event.status <> 'pending' OR event.attempts > 0 OR event.poll_count > 0)
			)`, update.ID).Scan(&deliveryStarted); err != nil {
			return err
		}
		if deliveryStarted {
			return domain.ErrConflict
		}
	}
	_, err = tx.Exec(ctx, `
		UPDATE privacy_requests
		SET status = $2,
		    completed_at = CASE WHEN $2 = 'completed' THEN now() ELSE completed_at END,
		    updated_at = now()
		WHERE id = $1`, update.ID, update.Status)
	if err != nil {
		return err
	}
	if update.Status == "rejected" || update.Status == "cancelled" {
		if _, err := tx.Exec(ctx, `
			UPDATE privacy_request_steps
			SET status = 'cancelled', lease_until = NULL, updated_at = now()
			WHERE privacy_request_id = $1 AND status <> 'completed'`, update.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE outbox_events event
			SET status = 'cancelled', locked_at = NULL, last_error = NULL
			FROM privacy_request_steps step
			WHERE event.privacy_step_id = step.id AND step.privacy_request_id = $1
			  AND event.status IN ('pending', 'processing', 'manual_dlq')`, update.ID); err != nil {
			return err
		}
	}
	auditID, err := ids.NewUUID()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO privacy_request_status_audit (id, privacy_request_id, status, actor, audit_note)
		VALUES ($1, $2, $3, $4, $5)`, auditID, update.ID, update.Status, update.Actor, update.AuditNote); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) validateSubject(ctx context.Context, subject Subject, productID string) error {
	var exists bool
	var err error
	switch subject.Kind {
	case "person":
		err = s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM persons WHERE id = $1 AND deleted_at IS NULL)`, subject.ID).Scan(&exists)
	case "installation":
		if productID == "" {
			err = s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM product_installations WHERE id = $1 AND disabled_at IS NULL)`, subject.ID).Scan(&exists)
		} else {
			err = s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM product_installations WHERE id = $1 AND product_id = $2 AND disabled_at IS NULL)`, subject.ID, productID).Scan(&exists)
		}
	default:
		return pgx.ErrNoRows
	}
	if err != nil {
		return err
	}
	if !exists {
		return pgx.ErrNoRows
	}
	return nil
}

func subjectIDs(subject Subject) (*string, *string) {
	if subject.Kind == "person" {
		return &subject.ID, nil
	}
	return nil, &subject.ID
}

func insertOutbox(ctx context.Context, tx pgx.Tx, id, topic, aggregateType, aggregateID string, privacyStepID *string, payload any) error {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO outbox_events (id, topic, aggregate_type, aggregate_id, privacy_step_id, payload)
		VALUES ($1, $2, $3, $4, $5, $6)`, id, topic, aggregateType, aggregateID, privacyStepID, encoded)
	return err
}
