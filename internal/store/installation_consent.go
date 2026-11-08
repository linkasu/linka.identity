package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/ids"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

type InstallationConsent struct {
	Preference    string
	PolicyVersion string
	RecordedAt    time.Time
	Version       uint64
	ConsentEpoch  uint64
	EventID       string
	DeliveryState string
	Suppressed    bool
	preferenceID  string
}

type InstallationConsentDecision struct {
	Subject         Subject
	SubjectKey      string
	ProductID       string
	RequestID       string
	ExpectedVersion uint64
	Preference      string
	PolicyVersion   string
	RecordedAt      time.Time
}

func (s *Store) GetInstallationConsent(ctx context.Context, subject Subject, product string) (InstallationConsent, error) {
	var result InstallationConsent
	err := s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		if err := validateSubjectWith(ctx, tx, subject, product); err != nil {
			return err
		}
		var err error
		result, err = installationConsentWith(ctx, tx, subject, product)
		return err
	})
	return result, err
}

func installationConsentWith(ctx context.Context, executor query.Executor, subject Subject, product string) (InstallationConsent, error) {
	var result InstallationConsent
	params := ydb.ParamsBuilder().Param("$subject_type").Text(subject.Kind).
		Param("$subject_id").Text(subject.ID).Param("$product_id").Text(product).Build()
	row, err := executor.QueryRow(ctx, `
		DECLARE $subject_type AS Utf8; DECLARE $subject_id AS Utf8; DECLARE $product_id AS Utf8;
		SELECT id, preference, recorded_at, version FROM telemetry_preferences
		WHERE subject_type = $subject_type AND subject_id = $subject_id AND product_id = $product_id;`, query.WithParameters(params))
	if err != nil {
		return result, noRows(err)
	}
	if err := row.Scan(&result.preferenceID, &result.Preference, &result.RecordedAt, &result.Version); err != nil {
		return result, err
	}
	row, err = executor.QueryRow(ctx, `
		DECLARE $subject_type AS Utf8; DECLARE $subject_id AS Utf8; DECLARE $product_id AS Utf8;
		SELECT epoch, version, preference, policy_version, event_id FROM installation_consent_epochs
		WHERE subject_type = $subject_type AND subject_id = $subject_id AND product_id = $product_id;`, query.WithParameters(params))
	result.DeliveryState = "completed"
	if errors.Is(err, query.ErrNoRows) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	var version uint64
	var preference string
	if err := row.Scan(&result.ConsentEpoch, &version, &preference, &result.PolicyVersion, &result.EventID); err != nil {
		return result, err
	}
	if result.ConsentEpoch == 0 || version != result.Version || preference != result.Preference {
		return result, domain.ErrConflict
	}
	result.DeliveryState = "pending"
	row, err = executor.QueryRow(ctx, `DECLARE $id AS Utf8; SELECT status FROM outbox_events WHERE id = $id;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(result.EventID).Build()))
	if errors.Is(err, query.ErrNoRows) {
		return result, nil // Missing delivery evidence must never authorize collection.
	}
	if err != nil {
		return result, err
	}
	var status string
	if err := row.Scan(&status); err != nil {
		return result, err
	}
	if status == "delivered" {
		result.DeliveryState = "completed"
	}
	if result.Preference == "allowed" {
		err := consentGrantPermittedWith(ctx, executor, InstallationConsentDecision{Subject: subject, ProductID: product}, result)
		if errors.Is(err, domain.ErrForbidden) {
			result.Suppressed = true
		} else if err != nil {
			return result, err
		}
	}
	return result, nil
}

func consentFingerprint(input InstallationConsentDecision) string {
	encoded, _ := json.Marshal(struct {
		Version                        uint64
		Preference, Policy, RecordedAt string
	}{input.ExpectedVersion, input.Preference, input.PolicyVersion, input.RecordedAt.UTC().Format("2006-01-02T15:04:05.000Z")})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func validConsentDecision(input InstallationConsentDecision, now time.Time) bool {
	return input.Subject.Kind == "installation" && domain.ValidUUID(input.Subject.ID) && domain.ValidProductID(input.ProductID) &&
		domain.ValidUUID(input.RequestID) && input.ExpectedVersion > 0 && (input.Preference == "allowed" || input.Preference == "denied") &&
		len(input.PolicyVersion) > 0 && len(input.PolicyVersion) <= 100 && strings.TrimSpace(input.PolicyVersion) == input.PolicyVersion &&
		!input.RecordedAt.Before(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)) && input.RecordedAt.Before(time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)) &&
		!input.RecordedAt.After(now.Add(5*time.Minute)) && input.RecordedAt.Nanosecond()%int(time.Millisecond) == 0
}

func (s *Store) SetInstallationConsent(ctx context.Context, input InstallationConsentDecision) (InstallationConsent, error) {
	if !validConsentDecision(input, s.now().UTC()) {
		return InstallationConsent{}, domain.ErrInvalid
	}
	input.RequestID = strings.ToLower(input.RequestID)
	fingerprint := consentFingerprint(input)
	eventID, err := ids.NewUUID()
	if err != nil {
		return InstallationConsent{}, err
	}
	var result InstallationConsent
	err = s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		if err := validateSubjectWith(ctx, tx, input.Subject, input.ProductID); err != nil {
			return err
		}
		current, err := installationConsentWith(ctx, tx, input.Subject, input.ProductID)
		if err != nil {
			return err
		}
		params := ydb.ParamsBuilder().Param("$product").Text(input.ProductID).Param("$subject").Text(input.Subject.ID).
			Param("$request").Text(input.RequestID).Build()
		row, err := tx.QueryRow(ctx, `DECLARE $product AS Utf8; DECLARE $subject AS Utf8; DECLARE $request AS Utf8;
			SELECT fingerprint FROM installation_consent_requests
			WHERE product_id = $product AND subject_id = $subject AND request_id = $request;`, query.WithParameters(params))
		if err == nil {
			var previous string
			if err := row.Scan(&previous); err != nil {
				return err
			}
			if previous != fingerprint {
				return domain.ErrConflict
			}
			result = current
			return nil
		}
		if !errors.Is(err, query.ErrNoRows) {
			return err
		}
		if current.Version != input.ExpectedVersion {
			return domain.ErrConflict
		}
		if input.Preference == "allowed" {
			if err := consentGrantPermittedWith(ctx, tx, input, current); err != nil {
				return err
			}
		}
		result, err = writeManagedConsentWith(ctx, tx, input, current, eventID, s.now().UTC())
		if err != nil {
			return err
		}
		return tx.Exec(ctx, `DECLARE $product AS Utf8; DECLARE $subject AS Utf8; DECLARE $request AS Utf8; DECLARE $fingerprint AS Utf8;
			INSERT INTO installation_consent_requests (product_id, subject_id, request_id, fingerprint)
			VALUES ($product, $subject, $request, $fingerprint);`, query.WithParameters(ydb.ParamsBuilder().
			Param("$product").Text(input.ProductID).Param("$subject").Text(input.Subject.ID).
			Param("$request").Text(input.RequestID).Param("$fingerprint").Text(fingerprint).Build()))
	})
	return result, err
}

func consentGrantPermittedWith(ctx context.Context, tx query.Executor, input InstallationConsentDecision, current InstallationConsent) error {
	if current.ConsentEpoch == 0 && current.Preference == "denied" {
		return domain.ErrForbidden
	}
	if suppressed, err := permanentSuppressionWith(ctx, tx, current.preferenceID); err != nil {
		return err
	} else if suppressed {
		return domain.ErrForbidden
	}
	// Person/account/global privacy is independent authority, never reset by installation consent.
	row, err := tx.QueryRow(ctx, `DECLARE $id AS Utf8; SELECT person_id FROM product_installations WHERE id = $id;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(input.Subject.ID).Build()))
	if err != nil {
		return noRows(err)
	}
	var person *string
	if err := row.Scan(&person); err != nil {
		return err
	}
	personID := ""
	if person != nil {
		personID = *person
	}
	// Follow existing account membership only in this product; person_id alone must not link products.
	requests, err := tx.QueryResultSet(ctx, `DECLARE $id AS Utf8; DECLARE $person AS Utf8; DECLARE $product AS Utf8;
		$accounts = SELECT a.account_id AS account_id FROM accounts_by_person AS a
		INNER JOIN product_accounts AS p ON a.account_id = p.account_id
		WHERE a.person_id = $person AND p.product_id = $product;
		SELECT id FROM privacy_requests WHERE request_type = "deletion" AND status IN ("requested", "processing", "completed")
		AND ((subject_type = "installation" AND subject_id = $id) OR (subject_type = "person" AND subject_id = $person)
		OR (subject_type = "account" AND subject_id IN (SELECT account_id FROM $accounts)))
		AND (scope = "all" OR product_id = $product) LIMIT 1;`, query.WithParameters(ydb.ParamsBuilder().
		Param("$id").Text(input.Subject.ID).Param("$person").Text(personID).Param("$product").Text(input.ProductID).Build()))
	if err != nil {
		return err
	}
	defer requests.Close(ctx)
	for _, err := range requests.Rows(ctx) {
		if err != nil {
			return err
		}
		return domain.ErrForbidden
	}
	if person == nil {
		return nil
	}
	rows, err := tx.QueryResultSet(ctx, `DECLARE $id AS Utf8; DECLARE $product AS Utf8;
		$accounts = SELECT a.account_id AS account_id FROM accounts_by_person AS a
		INNER JOIN product_accounts AS p ON a.account_id = p.account_id
		WHERE a.person_id = $id AND p.product_id = $product;
		SELECT id, preference FROM telemetry_preferences WHERE ((subject_type = "person" AND subject_id = $id)
		OR (subject_type = "account" AND subject_id IN (SELECT account_id FROM $accounts)))
		AND (product_id = $product OR product_id = "");`, query.WithParameters(ydb.ParamsBuilder().
		Param("$id").Text(*person).Param("$product").Text(input.ProductID).Build()))
	if err != nil {
		return err
	}
	defer rows.Close(ctx)
	for row, err := range rows.Rows(ctx) {
		if err != nil {
			return err
		}
		var preferenceID, preference string
		if err := row.Scan(&preferenceID, &preference); err != nil {
			return err
		}
		if preference == "denied" {
			return domain.ErrForbidden
		}
		if suppressed, err := permanentSuppressionWith(ctx, tx, preferenceID); err != nil {
			return err
		} else if suppressed {
			return domain.ErrForbidden
		}
	}
	return nil
}

func permanentSuppressionWith(ctx context.Context, executor query.Executor, preferenceID string) (bool, error) {
	row, err := executor.QueryRow(ctx, `DECLARE $id AS Utf8;
		SELECT id FROM outbox_events WHERE aggregate_type = "telemetry_preference"
		AND aggregate_id = $id AND topic = "telemetry.suppression.requested" LIMIT 1;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(preferenceID).Build()))
	if errors.Is(err, query.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var id string
	if err := row.Scan(&id); err != nil {
		return false, err
	}
	return true, nil
}

func nextConsentEpoch(current InstallationConsent, preference string) (uint64, error) {
	if current.Version == ^uint64(0) || (current.ConsentEpoch == ^uint64(0) && current.Preference == "denied" && preference == "allowed") {
		return 0, domain.ErrConflict
	}
	epoch := current.ConsentEpoch
	if epoch == 0 || (current.Preference == "denied" && preference == "allowed") {
		epoch++
	}
	return epoch, nil
}

func legacyManagedConsentWith(ctx context.Context, tx query.TxActor, subject Subject, subjectKey, product, preference, policy string,
	recordedAt time.Time, eventID string, now time.Time, denialReplay bool) (bool, InstallationConsent, error) {
	if subject.Kind != "installation" {
		return false, InstallationConsent{}, nil
	}
	current, err := installationConsentWith(ctx, tx, subject, product)
	if errors.Is(err, domain.ErrNotFound) {
		return false, InstallationConsent{}, nil
	}
	if err != nil {
		return false, current, err
	}
	if current.ConsentEpoch == 0 {
		return false, current, nil
	}
	if recordedAt.Before(current.RecordedAt) || (recordedAt.Equal(current.RecordedAt) && preference != current.Preference) {
		return true, current, domain.ErrConflict
	}
	if denialReplay && current.Preference == "denied" {
		return true, current, nil
	}
	if policy == "" {
		policy = current.PolicyVersion
	}
	input := InstallationConsentDecision{Subject: subject, SubjectKey: subjectKey, ProductID: product,
		Preference: preference, PolicyVersion: policy, RecordedAt: recordedAt.UTC().Truncate(time.Millisecond)}
	if preference == "allowed" {
		if err := consentGrantPermittedWith(ctx, tx, input, current); err != nil {
			return true, current, err
		}
	}
	result, err := writeManagedConsentWith(ctx, tx, input, current, eventID, now)
	return true, result, err
}

// All writers of an already managed preference use this helper inside their own transaction.
func writeManagedConsentWith(ctx context.Context, tx query.TxActor, input InstallationConsentDecision, current InstallationConsent, eventID string, now time.Time) (InstallationConsent, error) {
	epoch, err := nextConsentEpoch(current, input.Preference)
	if err != nil {
		return InstallationConsent{}, err
	}
	status := "granted"
	if input.Preference == "denied" {
		status = "withdrawn"
	}
	if err := insertConsentWith(ctx, tx, Consent{ID: eventID, Subject: input.Subject, ProductID: input.ProductID,
		ConsentType: "telemetry", PolicyVersion: input.PolicyVersion, Status: status, RecordedAt: input.RecordedAt}, now); err != nil {
		return InstallationConsent{}, err
	}
	updated, err := tx.QueryRow(ctx, `
		DECLARE $type AS Utf8; DECLARE $subject AS Utf8; DECLARE $product AS Utf8; DECLARE $preference AS Utf8;
		DECLARE $recorded AS Timestamp; DECLARE $now AS Timestamp; DECLARE $version AS Uint64;
		UPDATE telemetry_preferences SET preference = $preference, recorded_at = $recorded, updated_at = $now, version = version + 1u
		WHERE subject_type = $type AND subject_id = $subject AND product_id = $product AND version = $version RETURNING version;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$type").Text(input.Subject.Kind).Param("$subject").Text(input.Subject.ID).
			Param("$product").Text(input.ProductID).Param("$preference").Text(input.Preference).Param("$recorded").Timestamp(input.RecordedAt.UTC()).
			Param("$now").Timestamp(now).Param("$version").Uint64(current.Version).Build()))
	if err != nil {
		return InstallationConsent{}, optimistic(err)
	}
	var next uint64
	if err := updated.Scan(&next); err != nil {
		return InstallationConsent{}, err
	}
	if next != current.Version+1 {
		return InstallationConsent{}, domain.ErrConflict
	}
	if err := tx.Exec(ctx, `
		DECLARE $type AS Utf8; DECLARE $subject AS Utf8; DECLARE $product AS Utf8; DECLARE $epoch AS Uint64;
		DECLARE $version AS Uint64; DECLARE $preference AS Utf8; DECLARE $policy AS Utf8; DECLARE $event AS Utf8;
		UPSERT INTO installation_consent_epochs (subject_type, subject_id, product_id, epoch, version, preference, policy_version, event_id)
		VALUES ($type, $subject, $product, $epoch, $version, $preference, $policy, $event);`, query.WithParameters(ydb.ParamsBuilder().
		Param("$type").Text(input.Subject.Kind).Param("$subject").Text(input.Subject.ID).Param("$product").Text(input.ProductID).
		Param("$epoch").Uint64(epoch).Param("$version").Uint64(next).Param("$preference").Text(input.Preference).
		Param("$policy").Text(input.PolicyVersion).Param("$event").Text(eventID).Build())); err != nil {
		return InstallationConsent{}, err
	}
	payload := map[string]any{"schema_version": 2, "request_id": eventID,
		"scope":         map[string]any{"product": input.ProductID, "subject_key": input.SubjectKey},
		"consent_epoch": epoch, "version": next, "preference": input.Preference,
		"recorded_at": input.RecordedAt.UTC().Format("2006-01-02T15:04:05.000Z")}
	if err := insertOutbox(ctx, tx, eventID, "telemetry.consent.changed", "telemetry_preference", current.preferenceID, nil, nil, payload, now); err != nil {
		return InstallationConsent{}, err
	}
	return InstallationConsent{Preference: input.Preference, PolicyVersion: input.PolicyVersion, RecordedAt: input.RecordedAt.UTC(),
		Version: next, ConsentEpoch: epoch, EventID: eventID, DeliveryState: "pending", preferenceID: current.preferenceID}, nil
}
