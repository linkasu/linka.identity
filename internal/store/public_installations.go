package store

import (
	"context"
	"errors"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/ids"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

type PublicInstallationRegistration struct {
	Installation  Installation
	OpaqueKey     string
	Audience      string
	Consent       Consent
	Preference    string
	PreferenceAt  time.Time
	SuppressionID string
}

type PublicTelemetryDenial struct {
	Subject       Subject
	SubjectKey    string
	ProductID     string
	Consent       Consent
	RecordedAt    time.Time
	SuppressionID string
}

func (s *Store) RegisterPublicInstallation(ctx context.Context, input PublicInstallationRegistration) (Installation, error) {
	now := s.now().UTC().Truncate(time.Microsecond)
	result := input.Installation
	preferenceID, err := ids.NewUUID()
	if err != nil {
		return Installation{}, err
	}
	err = s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		row, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			SELECT product_id, platform, created_at, disabled_at
			FROM product_installations WHERE id = $id;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(input.Installation.ID).Build()))
		if err == nil {
			var disabledAt *time.Time
			if err := row.Scan(&result.ProductID, &result.Platform, &result.CreatedAt, &disabledAt); err != nil {
				return err
			}
			if disabledAt != nil || result.ProductID != input.Installation.ProductID || result.Platform != input.Installation.Platform {
				return domain.ErrConflict
			}
			preferenceRow, err := tx.QueryRow(ctx, `
				DECLARE $subject_id AS Utf8;
				DECLARE $product_id AS Utf8;
				SELECT preference, recorded_at FROM telemetry_preferences
				WHERE subject_type = "installation" AND subject_id = $subject_id AND product_id = $product_id;`,
				query.WithParameters(ydb.ParamsBuilder().
					Param("$subject_id").Text(input.Installation.ID).
					Param("$product_id").Text(input.Installation.ProductID).
					Build()))
			if err != nil {
				if errors.Is(err, query.ErrNoRows) {
					return domain.ErrConflict
				}
				return err
			}
			var preference string
			var recordedAt time.Time
			if err := preferenceRow.Scan(&preference, &recordedAt); err != nil {
				return err
			}
			if preference != input.Preference || !recordedAt.Equal(input.PreferenceAt) {
				return domain.ErrConflict
			}
			return nil
		}
		if !errors.Is(err, query.ErrNoRows) {
			return err
		}
		if err := tx.Exec(ctx, `
			DECLARE $id AS Utf8;
			DECLARE $product_id AS Utf8;
			DECLARE $platform AS Utf8;
			DECLARE $now AS Timestamp;
			INSERT INTO product_installations (
				id, product_id, platform, created_at, last_seen_at, version
			) VALUES ($id, $product_id, $platform, $now, $now, 1u);`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$id").Text(input.Installation.ID).
				Param("$product_id").Text(input.Installation.ProductID).
				Param("$platform").Text(input.Installation.Platform).
				Param("$now").Timestamp(now).
				Build())); err != nil {
			return err
		}
		if err := tx.Exec(ctx, `
			DECLARE $opaque_key AS Utf8;
			DECLARE $product_id AS Utf8;
			DECLARE $audience AS Utf8;
			DECLARE $subject_id AS Utf8;
			DECLARE $person_id AS Utf8?;
			DECLARE $now AS Timestamp;
			INSERT INTO subject_aliases (
				opaque_key, product_id, audience, subject_type, subject_id, person_id, created_at
			) VALUES ($opaque_key, $product_id, $audience, "installation", $subject_id, $person_id, $now);
			INSERT INTO subject_alias_keys (
				product_id, audience, subject_type, subject_id, opaque_key
			) VALUES ($product_id, $audience, "installation", $subject_id, $opaque_key);`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$opaque_key").Text(input.OpaqueKey).
				Param("$product_id").Text(input.Installation.ProductID).
				Param("$audience").Text(input.Audience).
				Param("$subject_id").Text(input.Installation.ID).
				Param("$person_id").Any(nullableText(nil)).
				Param("$now").Timestamp(now).
				Build())); err != nil {
			return err
		}
		if err := insertConsentWith(ctx, tx, input.Consent, now); err != nil {
			return err
		}
		if err := insertTelemetryPreferenceWith(ctx, tx, input.Consent.Subject, input.Installation.ProductID,
			preferenceID, input.Preference, input.PreferenceAt, now); err != nil {
			return err
		}
		if input.Preference == "denied" {
			return insertSuppressionWith(ctx, tx, input.SuppressionID, input.OpaqueKey, input.Installation.ProductID, preferenceID, input.PreferenceAt, now)
		}
		return nil
	})
	if err != nil {
		return Installation{}, err
	}
	if result.CreatedAt.IsZero() {
		result.CreatedAt = now
	}
	return result, nil
}

func (s *Store) DenyPublicInstallation(ctx context.Context, input PublicTelemetryDenial) (time.Time, error) {
	effectiveAt := input.RecordedAt.UTC()
	err := s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		if err := validateSubjectWith(ctx, tx, input.Subject, input.ProductID); err != nil {
			return err
		}
		var storedID, previous string
		var previousAt time.Time
		var version uint64
		row, err := tx.QueryRow(ctx, `
			DECLARE $subject_type AS Utf8;
			DECLARE $subject_id AS Utf8;
			DECLARE $product_id AS Utf8;
			SELECT id, preference, recorded_at, version FROM telemetry_preferences
			WHERE subject_type = $subject_type AND subject_id = $subject_id AND product_id = $product_id;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$subject_type").Text(input.Subject.Kind).
				Param("$subject_id").Text(input.Subject.ID).
				Param("$product_id").Text(input.ProductID).
				Build()))
		if err != nil {
			return noRows(err)
		}
		if err := row.Scan(&storedID, &previous, &previousAt, &version); err != nil {
			return err
		}
		if input.RecordedAt.Before(previousAt) {
			return domain.ErrConflict
		}
		if input.RecordedAt.Equal(previousAt) && previous != "denied" {
			return domain.ErrConflict
		}
		if previous == "denied" {
			effectiveAt = previousAt
			return nil
		}
		now := s.now().UTC()
		if err := insertConsentWith(ctx, tx, input.Consent, now); err != nil {
			return err
		}
		updated, err := tx.QueryRow(ctx, `
			DECLARE $subject_type AS Utf8;
			DECLARE $subject_id AS Utf8;
			DECLARE $product_id AS Utf8;
			DECLARE $recorded_at AS Timestamp;
			DECLARE $updated_at AS Timestamp;
			DECLARE $version AS Uint64;
			UPDATE telemetry_preferences
			SET preference = "denied", recorded_at = $recorded_at,
			    updated_at = $updated_at, version = version + 1u
			WHERE subject_type = $subject_type AND subject_id = $subject_id
			  AND product_id = $product_id AND version = $version
			RETURNING version;`, query.WithParameters(ydb.ParamsBuilder().
			Param("$subject_type").Text(input.Subject.Kind).
			Param("$subject_id").Text(input.Subject.ID).
			Param("$product_id").Text(input.ProductID).
			Param("$recorded_at").Timestamp(input.RecordedAt.UTC()).
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
		if previous != "denied" {
			return insertSuppressionWith(ctx, tx, input.SuppressionID, input.SubjectKey, input.ProductID, storedID, input.RecordedAt, now)
		}
		return nil
	})
	return effectiveAt, err
}

func insertConsentWith(ctx context.Context, tx query.TxActor, consent Consent, now time.Time) error {
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
		Param("$created_at").Timestamp(now).
		Build()))
}

func insertTelemetryPreferenceWith(ctx context.Context, tx query.TxActor, subject Subject, productID, id, preference string, recordedAt, now time.Time) error {
	return tx.Exec(ctx, `
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
			Param("$id").Text(id).
			Param("$preference").Text(preference).
			Param("$recorded_at").Timestamp(recordedAt.UTC()).
			Param("$updated_at").Timestamp(now).
			Build()))
}

func insertSuppressionWith(ctx context.Context, tx query.TxActor, eventID, subjectKey, productID, aggregateID string, requestedAt, now time.Time) error {
	if eventID == "" {
		return errors.New("suppression event ID is required")
	}
	payload := map[string]any{
		"schema_version": 2,
		"request_id":     eventID,
		"scope":          map[string]any{"product": productID, "subject_key": subjectKey},
		"action":         "opt_out",
		"requested_at":   requestedAt.UTC(),
	}
	return insertOutbox(ctx, tx, eventID, "telemetry.suppression.requested", "telemetry_preference", aggregateID, nil, nil, payload, now)
}
