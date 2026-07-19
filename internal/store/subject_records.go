package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/ids"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
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

type TelemetryPreference struct {
	Preference string
	RecordedAt time.Time
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
	return s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		if err := validateSubjectWith(ctx, tx, consent.Subject, consent.ProductID); err != nil {
			return err
		}
		return tx.Exec(ctx, `
			DECLARE $id AS Utf8;
			DECLARE $subject_type AS Utf8;
			DECLARE $subject_id AS Utf8;
			DECLARE $product_id AS Utf8;
			DECLARE $consent_type AS Utf8;
			DECLARE $policy_version AS Utf8;
			DECLARE $status AS Utf8;
			DECLARE $recorded_at AS Timestamp;
			DECLARE $created_at AS Timestamp;
			INSERT INTO consents (
				id, subject_type, subject_id, product_id, consent_type,
				policy_version, status, recorded_at, created_at
			) VALUES (
				$id, $subject_type, $subject_id, $product_id, $consent_type,
				$policy_version, $status, $recorded_at, $created_at
			);`, query.WithParameters(ydb.ParamsBuilder().
			Param("$id").Text(consent.ID).
			Param("$subject_type").Text(consent.Subject.Kind).
			Param("$subject_id").Text(consent.Subject.ID).
			Param("$product_id").Text(consent.ProductID).
			Param("$consent_type").Text(consent.ConsentType).
			Param("$policy_version").Text(consent.PolicyVersion).
			Param("$status").Text(consent.Status).
			Param("$recorded_at").Timestamp(consent.RecordedAt.UTC()).
			Param("$created_at").Timestamp(s.now().UTC()).
			Build()))
	})
}

func (s *Store) SetTelemetryPreference(ctx context.Context, subject Subject, subjectKey, productID, preference string, recordedAt, requestedAt time.Time) error {
	preferenceID, err := ids.NewUUID()
	if err != nil {
		return err
	}
	eventID, err := ids.NewUUID()
	if err != nil {
		return err
	}
	return s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		if err := validateSubjectWith(ctx, tx, subject, productID); err != nil {
			return err
		}
		var previous string
		var previousAt time.Time
		var version uint64
		row, err := tx.QueryRow(ctx, `
			DECLARE $subject_type AS Utf8;
			DECLARE $subject_id AS Utf8;
			DECLARE $product_id AS Utf8;
			SELECT id, preference, recorded_at, version FROM telemetry_preferences
			WHERE subject_type = $subject_type AND subject_id = $subject_id AND product_id = $product_id;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$subject_type").Text(subject.Kind).
				Param("$subject_id").Text(subject.ID).
				Param("$product_id").Text(productID).
				Build()))
		exists := err == nil
		if exists {
			if err := row.Scan(&preferenceID, &previous, &previousAt, &version); err != nil {
				return err
			}
			if recordedAt.Before(previousAt) || (recordedAt.Equal(previousAt) && preference != previous) {
				return domain.ErrConflict
			}
		} else if !errors.Is(err, query.ErrNoRows) {
			return err
		}

		now := s.now().UTC()
		if exists {
			updated, err := tx.QueryRow(ctx, `
				DECLARE $subject_type AS Utf8;
				DECLARE $subject_id AS Utf8;
				DECLARE $product_id AS Utf8;
				DECLARE $preference AS Utf8;
				DECLARE $recorded_at AS Timestamp;
				DECLARE $updated_at AS Timestamp;
				DECLARE $version AS Uint64;
				UPDATE telemetry_preferences
				SET preference = $preference, recorded_at = $recorded_at,
				    updated_at = $updated_at, version = version + 1u
				WHERE subject_type = $subject_type AND subject_id = $subject_id
				  AND product_id = $product_id AND version = $version
				RETURNING version;`, query.WithParameters(ydb.ParamsBuilder().
				Param("$subject_type").Text(subject.Kind).
				Param("$subject_id").Text(subject.ID).
				Param("$product_id").Text(productID).
				Param("$preference").Text(preference).
				Param("$recorded_at").Timestamp(recordedAt.UTC()).
				Param("$updated_at").Timestamp(now).
				Param("$version").Uint64(version).
				Build()))
			if err != nil {
				return optimistic(err)
			}
			var next uint64
			if err := updated.Scan(&next); err != nil || next != version+1 {
				return domain.ErrConflict
			}
		} else if err := tx.Exec(ctx, `
			DECLARE $subject_type AS Utf8;
			DECLARE $subject_id AS Utf8;
			DECLARE $product_id AS Utf8;
			DECLARE $id AS Utf8;
			DECLARE $preference AS Utf8;
			DECLARE $recorded_at AS Timestamp;
			DECLARE $updated_at AS Timestamp;
			INSERT INTO telemetry_preferences (
				subject_type, subject_id, product_id, id, preference, recorded_at, updated_at, version
			) VALUES ($subject_type, $subject_id, $product_id, $id, $preference, $recorded_at, $updated_at, 1u);`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$subject_type").Text(subject.Kind).
				Param("$subject_id").Text(subject.ID).
				Param("$product_id").Text(productID).
				Param("$id").Text(preferenceID).
				Param("$preference").Text(preference).
				Param("$recorded_at").Timestamp(recordedAt.UTC()).
				Param("$updated_at").Timestamp(now).
				Build())); err != nil {
			return err
		}
		if preference == "denied" && previous != "denied" {
			payload := map[string]any{
				"schema_version": 2,
				"request_id":     eventID,
				"scope":          map[string]any{"product": productID, "subject_key": subjectKey},
				"action":         "opt_out",
				"requested_at":   requestedAt.UTC(),
			}
			return insertOutbox(ctx, tx, eventID, "telemetry.suppression.requested", "telemetry_preference", preferenceID, nil, nil, payload, now)
		}
		return nil
	})
}

func (s *Store) GetTelemetryPreference(ctx context.Context, subject Subject, productID string) (TelemetryPreference, error) {
	row, err := s.client.QueryRow(ctx, `
		DECLARE $subject_type AS Utf8;
		DECLARE $subject_id AS Utf8;
		DECLARE $product_id AS Utf8;
		SELECT preference, recorded_at FROM telemetry_preferences
		WHERE subject_type = $subject_type AND subject_id = $subject_id AND product_id = $product_id;`,
		query.WithParameters(ydb.ParamsBuilder().
			Param("$subject_type").Text(subject.Kind).
			Param("$subject_id").Text(subject.ID).
			Param("$product_id").Text(productID).
			Build()),
		query.WithTxControl(query.SnapshotReadOnlyTxControl()))
	if err != nil {
		return TelemetryPreference{}, noRows(err)
	}
	var result TelemetryPreference
	if err := row.Scan(&result.Preference, &result.RecordedAt); err != nil {
		return TelemetryPreference{}, err
	}
	return result, nil
}

func (s *Store) CreatePrivacyRequest(ctx context.Context, request PrivacyRequest, products map[string]string) (PrivacyRequestStatus, bool, error) {
	productID := ""
	if request.ProductID != nil {
		productID = *request.ProductID
	}
	fingerprintInput := request.Subject.Kind + "\x00" + request.Subject.ID + "\x00" + request.RequestType + "\x00" + request.Scope + "\x00" + productID
	fingerprintSum := sha256.Sum256([]byte(fingerprintInput))
	fingerprint := hex.EncodeToString(fingerprintSum[:])
	requestID, err := ids.NewUUID()
	if err != nil {
		return PrivacyRequestStatus{}, false, err
	}
	var result PrivacyRequestStatus
	var created bool
	err = s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		created = false
		row, err := tx.QueryRow(ctx, `
			DECLARE $workload AS Utf8;
			DECLARE $idempotency_key AS Utf8;
			SELECT request_id, request_fingerprint FROM privacy_idempotency
			WHERE requested_by_workload = $workload AND idempotency_key = $idempotency_key;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$workload").Text(request.RequestedByWorkload).
				Param("$idempotency_key").Text(request.IdempotencyKey).
				Build()))
		if err == nil {
			var existingID, existingFingerprint string
			if err := row.Scan(&existingID, &existingFingerprint); err != nil {
				return err
			}
			if existingFingerprint != fingerprint {
				return domain.ErrConflict
			}
			existing, err := getPrivacyRequestWith(ctx, tx, existingID)
			if err != nil {
				return err
			}
			result = existing
			return nil
		}
		if !errors.Is(err, query.ErrNoRows) {
			return err
		}
		if err := validateSubjectWith(ctx, tx, request.Subject, productID); err != nil {
			return err
		}
		var aliases []ResolvedAlias
		if request.RequestType == "deletion" {
			if request.Subject.Kind == "person" {
				aliases, err = privacyFanoutAliases(ctx, tx, request.Subject.ID, request.ProductID)
				if err != nil {
					return err
				}
			} else {
				audience, ok := products[productID]
				if !ok {
					return domain.ErrInvalid
				}
				aliases = []ResolvedAlias{{OpaqueKey: request.SubjectKey, ProductID: productID, Audience: audience, SubjectType: "installation", SubjectID: request.Subject.ID}}
			}
		}
		now := s.now().UTC()
		if err := tx.Exec(ctx, `
			DECLARE $id AS Utf8;
			DECLARE $subject_type AS Utf8;
			DECLARE $subject_id AS Utf8;
			DECLARE $request_type AS Utf8;
			DECLARE $scope AS Utf8;
			DECLARE $product_id AS Utf8?;
			DECLARE $requested_at AS Timestamp;
			DECLARE $workload AS Utf8;
			DECLARE $idempotency_key AS Utf8;
			DECLARE $fingerprint AS Utf8;
			DECLARE $now AS Timestamp;
			INSERT INTO privacy_requests (
				id, subject_type, subject_id, request_type, scope, product_id, status,
				requested_at, requested_by_workload, idempotency_key, request_fingerprint,
				created_at, updated_at, version
			) VALUES (
				$id, $subject_type, $subject_id, $request_type, $scope, $product_id, "requested",
				$requested_at, $workload, $idempotency_key, $fingerprint, $now, $now, 1u
			);
			INSERT INTO privacy_idempotency (
				requested_by_workload, idempotency_key, request_id, request_fingerprint
			) VALUES ($workload, $idempotency_key, $id, $fingerprint);`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$id").Text(requestID).
				Param("$subject_type").Text(request.Subject.Kind).
				Param("$subject_id").Text(request.Subject.ID).
				Param("$request_type").Text(request.RequestType).
				Param("$scope").Text(request.Scope).
				Param("$product_id").Any(nullableText(request.ProductID)).
				Param("$requested_at").Timestamp(request.RequestedAt.UTC()).
				Param("$workload").Text(request.RequestedByWorkload).
				Param("$idempotency_key").Text(request.IdempotencyKey).
				Param("$fingerprint").Text(fingerprint).
				Param("$now").Timestamp(now).
				Build())); err != nil {
			return err
		}
		if request.RequestType == "deletion" {
			for _, alias := range aliases {
				expectedAudience, ok := products[alias.ProductID]
				if !ok || alias.Audience != expectedAudience {
					continue
				}
				stepID, err := ids.NewUUID()
				if err != nil {
					return err
				}
				eventID, err := ids.NewUUID()
				if err != nil {
					return err
				}
				if err := insertPrivacyStep(ctx, tx, stepID, requestID, "metric", &alias.ProductID, &alias.OpaqueKey, now); err != nil {
					return err
				}
				payload := map[string]any{
					"schema_version": 2,
					"request_id":     eventID,
					"scope":          map[string]any{"product": alias.ProductID, "subject_key": alias.OpaqueKey},
					"action":         "delete",
					"requested_at":   request.RequestedAt.UTC(),
				}
				if err := insertOutbox(ctx, tx, eventID, "telemetry.deletion.requested", "privacy_request", requestID, &stepID, &requestID, payload, now); err != nil {
					return err
				}
			}
			stepID, err := ids.NewUUID()
			if err != nil {
				return err
			}
			if err := insertPrivacyStep(ctx, tx, stepID, requestID, "ydb", nil, nil, now); err != nil {
				return err
			}
		}
		result = PrivacyRequestStatus{ID: requestID, RequestType: request.RequestType, Scope: request.Scope, ProductID: request.ProductID, Status: "requested", RequestedAt: request.RequestedAt}
		created = true
		return nil
	})
	if err != nil {
		return PrivacyRequestStatus{}, false, err
	}
	return result, created, nil
}

func insertPrivacyStep(ctx context.Context, tx query.TxActor, id, requestID, stepType string, productID, subjectKey *string, now time.Time) error {
	return tx.Exec(ctx, `
		DECLARE $id AS Utf8;
		DECLARE $request_id AS Utf8;
		DECLARE $step_type AS Utf8;
		DECLARE $product_id AS Utf8?;
		DECLARE $subject_key AS Utf8?;
		DECLARE $now AS Timestamp;
		INSERT INTO privacy_request_steps (
			id, privacy_request_id, step_type, product_id, subject_key, status,
			attempts, available_at, created_at, updated_at, version
		) VALUES ($id, $request_id, $step_type, $product_id, $subject_key, "pending", 0u, $now, $now, $now, 1u);`,
		query.WithParameters(ydb.ParamsBuilder().
			Param("$id").Text(id).
			Param("$request_id").Text(requestID).
			Param("$step_type").Text(stepType).
			Param("$product_id").Any(nullableText(productID)).
			Param("$subject_key").Any(nullableText(subjectKey)).
			Param("$now").Timestamp(now).
			Build()))
}

func (s *Store) GetPrivacyRequest(ctx context.Context, id string) (PrivacyRequestStatus, error) {
	return getPrivacyRequestWith(ctx, s.client, id)
}

func getPrivacyRequestWith(ctx context.Context, executor query.Executor, id string) (PrivacyRequestStatus, error) {
	row, err := executor.QueryRow(ctx, `
		DECLARE $id AS Utf8;
		SELECT request_type, scope, product_id, status, requested_at, completed_at
		FROM privacy_requests WHERE id = $id;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(id).Build()))
	if err != nil {
		return PrivacyRequestStatus{}, noRows(err)
	}
	result := PrivacyRequestStatus{ID: id}
	if err := row.Scan(&result.RequestType, &result.Scope, &result.ProductID, &result.Status, &result.RequestedAt, &result.CompletedAt); err != nil {
		return PrivacyRequestStatus{}, err
	}
	return result, nil
}

func (s *Store) UpdatePrivacyRequestStatus(ctx context.Context, update PrivacyStatusUpdate) error {
	if update.Status == "completed" {
		return domain.ErrConflict
	}
	auditID, err := ids.NewUUID()
	if err != nil {
		return err
	}
	return s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		row, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			SELECT status, version FROM privacy_requests WHERE id = $id;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(update.ID).Build()))
		if err != nil {
			return noRows(err)
		}
		var currentStatus string
		var version uint64
		if err := row.Scan(&currentStatus, &version); err != nil {
			return err
		}
		if !domain.ValidPrivacyTransition(currentStatus, update.Status) {
			return domain.ErrConflict
		}
		terminal := update.Status == "rejected" || update.Status == "cancelled"
		if terminal {
			started, err := privacyDeliveryStarted(ctx, tx, update.ID)
			if err != nil {
				return err
			}
			if started {
				return domain.ErrConflict
			}
		}
		now := s.now().UTC()
		updated, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			DECLARE $status AS Utf8;
			DECLARE $now AS Timestamp;
			DECLARE $version AS Uint64;
			UPDATE privacy_requests
			SET status = $status, updated_at = $now, version = version + 1u
			WHERE id = $id AND version = $version RETURNING version;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$id").Text(update.ID).
				Param("$status").Text(update.Status).
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
		if terminal {
			if err := cancelPrivacyChildren(ctx, tx, update.ID, now); err != nil {
				return err
			}
		}
		return tx.Exec(ctx, `
			DECLARE $id AS Utf8;
			DECLARE $request_id AS Utf8;
			DECLARE $status AS Utf8;
			DECLARE $actor AS Utf8;
			DECLARE $note AS Utf8;
			DECLARE $now AS Timestamp;
			INSERT INTO privacy_request_status_audit (
				id, privacy_request_id, status, actor, audit_note, changed_at
			) VALUES ($id, $request_id, $status, $actor, $note, $now);`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$id").Text(auditID).
				Param("$request_id").Text(update.ID).
				Param("$status").Text(update.Status).
				Param("$actor").Text(update.Actor).
				Param("$note").Text(update.AuditNote).
				Param("$now").Timestamp(now).
				Build()))
	})
}

func privacyDeliveryStarted(ctx context.Context, tx query.TxActor, requestID string) (bool, error) {
	rows, err := tx.QueryResultSet(ctx, `
		DECLARE $request_id AS Utf8;
		SELECT status, attempts FROM privacy_request_steps WHERE privacy_request_id = $request_id;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$request_id").Text(requestID).Build()))
	if err != nil {
		return false, err
	}
	defer rows.Close(ctx)
	for row, rowErr := range rows.Rows(ctx) {
		if rowErr != nil {
			return false, rowErr
		}
		var status string
		var attempts uint64
		if err := row.Scan(&status, &attempts); err != nil {
			return false, err
		}
		if status != "pending" || attempts > 0 {
			return true, nil
		}
	}
	rows, err = tx.QueryResultSet(ctx, `
		DECLARE $request_id AS Utf8;
		SELECT status, attempts, poll_count FROM outbox_events WHERE privacy_request_id = $request_id;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$request_id").Text(requestID).Build()))
	if err != nil {
		return false, err
	}
	defer rows.Close(ctx)
	for row, rowErr := range rows.Rows(ctx) {
		if rowErr != nil {
			return false, rowErr
		}
		var status string
		var attempts, polls uint64
		if err := row.Scan(&status, &attempts, &polls); err != nil {
			return false, err
		}
		if status != "pending" || attempts > 0 || polls > 0 {
			return true, nil
		}
	}
	return false, nil
}

func cancelPrivacyChildren(ctx context.Context, tx query.TxActor, requestID string, now time.Time) error {
	if err := tx.Exec(ctx, `
		DECLARE $request_id AS Utf8;
		DECLARE $now AS Timestamp;
		UPDATE privacy_request_steps
		SET status = "cancelled", lease_until = NULL, updated_at = $now, version = version + 1u
		WHERE privacy_request_id = $request_id AND status != "completed";`,
		query.WithParameters(ydb.ParamsBuilder().
			Param("$request_id").Text(requestID).
			Param("$now").Timestamp(now).
			Build())); err != nil {
		return err
	}
	return tx.Exec(ctx, `
		DECLARE $request_id AS Utf8;
		UPDATE outbox_events
		SET status = "cancelled", locked_at = NULL, last_error = NULL, version = version + 1u
		WHERE privacy_request_id = $request_id
		  AND status IN ("pending", "processing", "manual_dlq");`,
		query.WithParameters(ydb.ParamsBuilder().Param("$request_id").Text(requestID).Build()))
}

func (s *Store) validateSubject(ctx context.Context, subject Subject, productID string) error {
	return validateSubjectWith(ctx, s.client, subject, productID)
}

func validateSubjectWith(ctx context.Context, executor query.Executor, subject Subject, productID string) error {
	switch subject.Kind {
	case "person":
		row, err := executor.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			SELECT deleted_at FROM persons WHERE id = $id;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(subject.ID).Build()))
		if err != nil {
			return noRows(err)
		}
		var deletedAt *time.Time
		if err := row.Scan(&deletedAt); err != nil {
			return err
		}
		if deletedAt != nil {
			return domain.ErrNotFound
		}
		return nil
	case "installation":
		row, err := executor.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			SELECT product_id, disabled_at FROM product_installations WHERE id = $id;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(subject.ID).Build()))
		if err != nil {
			return noRows(err)
		}
		var storedProduct string
		var disabledAt *time.Time
		if err := row.Scan(&storedProduct, &disabledAt); err != nil {
			return err
		}
		if disabledAt != nil || (productID != "" && storedProduct != productID) {
			return domain.ErrNotFound
		}
		return nil
	default:
		return domain.ErrNotFound
	}
}

func insertOutbox(ctx context.Context, tx query.TxActor, id, topic, aggregateType, aggregateID string, privacyStepID, privacyRequestID *string, payload any, now time.Time) error {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return tx.Exec(ctx, `
		DECLARE $id AS Utf8;
		DECLARE $topic AS Utf8;
		DECLARE $aggregate_type AS Utf8;
		DECLARE $aggregate_id AS Utf8;
		DECLARE $privacy_step_id AS Utf8?;
		DECLARE $privacy_request_id AS Utf8?;
		DECLARE $payload AS Json;
		DECLARE $now AS Timestamp;
		INSERT INTO outbox_events (
			id, topic, aggregate_type, aggregate_id, privacy_step_id, privacy_request_id,
			payload, status, attempts, poll_count, available_at, created_at, version
		) VALUES (
			$id, $topic, $aggregate_type, $aggregate_id, $privacy_step_id, $privacy_request_id,
			$payload, "pending", 0u, 0u, $now, $now, 1u
		);`, query.WithParameters(ydb.ParamsBuilder().
		Param("$id").Text(id).
		Param("$topic").Text(topic).
		Param("$aggregate_type").Text(aggregateType).
		Param("$aggregate_id").Text(aggregateID).
		Param("$privacy_step_id").Any(nullableText(privacyStepID)).
		Param("$privacy_request_id").Any(nullableText(privacyRequestID)).
		Param("$payload").JSONFromBytes(encoded).
		Param("$now").Timestamp(now).
		Build()))
}
