package store

import (
	"context"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/ids"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

type PrivacyErasureJob struct {
	StepID         string
	RequestID      string
	PersonID       *string
	InstallationID *string
	Scope          string
	ProductID      *string
	Attempts       int
	Version        uint64
}

func (s *Store) ClaimPrivacyErasures(ctx context.Context, limit int) ([]PrivacyErasureJob, error) {
	var jobs []PrivacyErasureJob
	err := s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		jobs = nil
		now := s.now().UTC()
		rows, err := tx.QueryResultSet(ctx, `
			DECLARE $now AS Timestamp;
			DECLARE $limit AS Uint64;
			SELECT id, privacy_request_id, attempts, version
			FROM privacy_request_steps
			WHERE step_type = "ydb"
			  AND ((status IN ("pending", "retry") AND available_at <= $now)
			       OR (status = "processing" AND COALESCE(lease_until < $now, false)))
			ORDER BY created_at LIMIT $limit;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$now").Timestamp(now).
				Param("$limit").Uint64(uint64(limit)).
				Build()))
		if err != nil {
			return err
		}
		defer rows.Close(ctx)
		for row, rowErr := range rows.Rows(ctx) {
			if rowErr != nil {
				return rowErr
			}
			var job PrivacyErasureJob
			var attempts uint64
			if err := row.Scan(&job.StepID, &job.RequestID, &attempts, &job.Version); err != nil {
				return err
			}
			requestRow, err := tx.QueryRow(ctx, `
				DECLARE $id AS Utf8;
				SELECT subject_type, subject_id, scope, product_id, status
				FROM privacy_requests WHERE id = $id;`,
				query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(job.RequestID).Build()))
			if err != nil {
				return noRows(err)
			}
			var subjectType, subjectID, requestStatus string
			if err := requestRow.Scan(&subjectType, &subjectID, &job.Scope, &job.ProductID, &requestStatus); err != nil {
				return err
			}
			if requestStatus != "requested" && requestStatus != "processing" {
				continue
			}
			complete, err := metricStepsComplete(ctx, tx, job.RequestID)
			if err != nil {
				return err
			}
			if !complete {
				continue
			}
			if subjectType == "person" {
				job.PersonID = &subjectID
			} else {
				job.InstallationID = &subjectID
			}
			updated, err := tx.QueryRow(ctx, `
				DECLARE $id AS Utf8;
				DECLARE $lease_until AS Timestamp;
				DECLARE $now AS Timestamp;
				DECLARE $version AS Uint64;
				UPDATE privacy_request_steps
				SET status = "processing", attempts = attempts + 1u, lease_until = $lease_until,
				    updated_at = $now, version = version + 1u
				WHERE id = $id AND version = $version RETURNING attempts, version;`,
				query.WithParameters(ydb.ParamsBuilder().
					Param("$id").Text(job.StepID).
					Param("$lease_until").Timestamp(now.Add(5*time.Minute)).
					Param("$now").Timestamp(now).
					Param("$version").Uint64(job.Version).
					Build()))
			if err != nil {
				return optimistic(err)
			}
			var claimedAttempts, next uint64
			if err := updated.Scan(&claimedAttempts, &next); err != nil || next != job.Version+1 {
				return domain.ErrConflict
			}
			job.Attempts = int(claimedAttempts)
			job.Version = next
			jobs = append(jobs, job)
		}
		return nil
	})
	return jobs, err
}

func metricStepsComplete(ctx context.Context, executor query.Executor, requestID string) (bool, error) {
	rows, err := executor.QueryResultSet(ctx, `
		DECLARE $request_id AS Utf8;
		SELECT status FROM privacy_request_steps
		WHERE privacy_request_id = $request_id AND step_type = "metric";`,
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
		if err := row.Scan(&status); err != nil {
			return false, err
		}
		if status != "completed" {
			return false, nil
		}
	}
	return true, nil
}

func (s *Store) ErasePrivacyJob(ctx context.Context, job PrivacyErasureJob) error {
	auditID, err := ids.NewUUID()
	if err != nil {
		return err
	}
	return s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		requestRow, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			SELECT status, version FROM privacy_requests WHERE id = $id;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(job.RequestID).Build()))
		if err != nil {
			return noRows(err)
		}
		var requestStatus string
		var requestVersion uint64
		if err := requestRow.Scan(&requestStatus, &requestVersion); err != nil {
			return err
		}
		if requestStatus != "requested" && requestStatus != "processing" {
			return domain.ErrNotFound
		}
		stepRow, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			SELECT status, version FROM privacy_request_steps WHERE id = $id;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(job.StepID).Build()))
		if err != nil {
			return noRows(err)
		}
		var stepStatus string
		var stepVersion uint64
		if err := stepRow.Scan(&stepStatus, &stepVersion); err != nil {
			return err
		}
		if stepStatus != "processing" || stepVersion != job.Version {
			return domain.ErrConflict
		}
		complete, err := metricStepsComplete(ctx, tx, job.RequestID)
		if err != nil {
			return err
		}
		if !complete {
			return domain.ErrConflict
		}
		if job.PersonID != nil {
			if job.Scope == "all" {
				if err := erasePerson(ctx, tx, *job.PersonID, s.now().UTC()); err != nil {
					return err
				}
			} else if job.ProductID != nil {
				if err := erasePersonProduct(ctx, tx, *job.PersonID, *job.ProductID, s.now().UTC()); err != nil {
					return err
				}
			}
		} else if job.InstallationID != nil && job.ProductID != nil {
			if err := eraseInstallation(ctx, tx, *job.InstallationID, *job.ProductID, s.now().UTC()); err != nil {
				return err
			}
		}
		now := s.now().UTC()
		receipt := []byte(`{"ydb":"erased"}`)
		stepUpdate, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			DECLARE $receipt AS Json;
			DECLARE $now AS Timestamp;
			DECLARE $version AS Uint64;
			UPDATE privacy_request_steps
			SET status = "completed", receipt = $receipt, completed_at = $now,
			    lease_until = NULL, last_error = NULL, updated_at = $now, version = version + 1u
			WHERE id = $id AND version = $version RETURNING version;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$id").Text(job.StepID).
				Param("$receipt").JSONFromBytes(receipt).
				Param("$now").Timestamp(now).
				Param("$version").Uint64(stepVersion).
				Build()))
		if err != nil {
			return optimistic(err)
		}
		var next uint64
		if err := stepUpdate.Scan(&next); err != nil || next != stepVersion+1 {
			return domain.ErrConflict
		}
		requestUpdate, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			DECLARE $now AS Timestamp;
			DECLARE $version AS Uint64;
			UPDATE privacy_requests
			SET status = "completed", completed_at = $now, updated_at = $now, version = version + 1u
			WHERE id = $id AND version = $version RETURNING version;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$id").Text(job.RequestID).
				Param("$now").Timestamp(now).
				Param("$version").Uint64(requestVersion).
				Build()))
		if err != nil {
			return optimistic(err)
		}
		if err := requestUpdate.Scan(&next); err != nil || next != requestVersion+1 {
			return domain.ErrConflict
		}
		return tx.Exec(ctx, `
			DECLARE $id AS Utf8;
			DECLARE $request_id AS Utf8;
			DECLARE $now AS Timestamp;
			INSERT INTO privacy_request_status_audit (
				id, privacy_request_id, status, actor, audit_note, changed_at
			) VALUES (
				$id, $request_id, "completed", "privacy-orchestrator",
				"all downstream receipts and YDB erasure completed", $now
			);`, query.WithParameters(ydb.ParamsBuilder().
			Param("$id").Text(auditID).
			Param("$request_id").Text(job.RequestID).
			Param("$now").Timestamp(now).
			Build()))
	})
}

func (s *Store) RetryPrivacyErasure(ctx context.Context, job PrivacyErasureJob, delay time.Duration, maxAttempts int) error {
	return s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		row, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			SELECT status, attempts, version FROM privacy_request_steps WHERE id = $id;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(job.StepID).Build()))
		if err != nil {
			return noRows(err)
		}
		var status string
		var attempts, version uint64
		if err := row.Scan(&status, &attempts, &version); err != nil {
			return err
		}
		if status != "processing" {
			return domain.ErrConflict
		}
		nextStatus := "retry"
		if attempts >= uint64(maxAttempts) {
			nextStatus = "manual_dlq"
		}
		updated, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			DECLARE $status AS Utf8;
			DECLARE $available_at AS Timestamp;
			DECLARE $now AS Timestamp;
			DECLARE $version AS Uint64;
			UPDATE privacy_request_steps
			SET status = $status, available_at = $available_at, lease_until = NULL,
			    last_error = "ydb erasure failed", updated_at = $now, version = version + 1u
			WHERE id = $id AND version = $version RETURNING version;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$id").Text(job.StepID).
				Param("$status").Text(nextStatus).
				Param("$available_at").Timestamp(s.now().UTC().Add(delay)).
				Param("$now").Timestamp(s.now().UTC()).
				Param("$version").Uint64(version).
				Build()))
		if err != nil {
			return optimistic(err)
		}
		var next uint64
		if err := updated.Scan(&next); err != nil || next != version+1 {
			return domain.ErrConflict
		}
		return nil
	})
}

func erasePerson(ctx context.Context, tx query.TxActor, personID string, now time.Time) error {
	installations, err := installationIDsForPerson(ctx, tx, personID, nil)
	if err != nil {
		return err
	}
	for _, installation := range installations {
		if err := eraseInstallationRecords(ctx, tx, installation, nil, now); err != nil {
			return err
		}
	}
	if err := erasePersonRecords(ctx, tx, personID, nil); err != nil {
		return err
	}
	return tx.Exec(ctx, `
		DECLARE $person_id AS Utf8;
		DECLARE $now AS Timestamp;
		UPDATE accounts
		SET status = "deleted", last_authenticated_at = NULL, version = version + 1u
		WHERE person_id = $person_id;
		UPDATE product_installations
		SET person_id = NULL, disabled_at = COALESCE(disabled_at, $now), version = version + 1u
		WHERE person_id = $person_id;
		UPDATE persons
		SET age_category = "unknown", guardian_relationship = NULL,
		    deleted_at = COALESCE(deleted_at, $now), version = version + 1u
		WHERE id = $person_id;`,
		query.WithParameters(ydb.ParamsBuilder().
			Param("$person_id").Text(personID).
			Param("$now").Timestamp(now).
			Build()))
}

func erasePersonProduct(ctx context.Context, tx query.TxActor, personID, productID string, now time.Time) error {
	installations, err := installationIDsForPerson(ctx, tx, personID, &productID)
	if err != nil {
		return err
	}
	for _, installation := range installations {
		if err := eraseInstallationRecords(ctx, tx, installation, &productID, now); err != nil {
			return err
		}
	}
	if err := erasePersonRecords(ctx, tx, personID, &productID); err != nil {
		return err
	}
	return tx.Exec(ctx, `
		DECLARE $person_id AS Utf8;
		DECLARE $product_id AS Utf8;
		DECLARE $now AS Timestamp;
		UPDATE product_installations
		SET person_id = NULL, disabled_at = COALESCE(disabled_at, $now), version = version + 1u
		WHERE person_id = $person_id AND product_id = $product_id;`,
		query.WithParameters(ydb.ParamsBuilder().
			Param("$person_id").Text(personID).
			Param("$product_id").Text(productID).
			Param("$now").Timestamp(now).
			Build()))
}

func eraseInstallation(ctx context.Context, tx query.TxActor, installationID, productID string, now time.Time) error {
	if err := eraseInstallationRecords(ctx, tx, installationID, &productID, now); err != nil {
		return err
	}
	return tx.Exec(ctx, `
		DECLARE $id AS Utf8;
		DECLARE $product_id AS Utf8;
		DECLARE $now AS Timestamp;
		UPDATE product_installations
		SET person_id = NULL, disabled_at = COALESCE(disabled_at, $now), version = version + 1u
		WHERE id = $id AND product_id = $product_id;`,
		query.WithParameters(ydb.ParamsBuilder().
			Param("$id").Text(installationID).
			Param("$product_id").Text(productID).
			Param("$now").Timestamp(now).
			Build()))
}

func installationIDsForPerson(ctx context.Context, executor query.Executor, personID string, productID *string) ([]string, error) {
	statement := `DECLARE $person_id AS Utf8; SELECT id FROM product_installations WHERE person_id = $person_id;`
	parameters := ydb.ParamsBuilder().Param("$person_id").Text(personID).Build()
	if productID != nil {
		statement = `DECLARE $person_id AS Utf8; DECLARE $product_id AS Utf8;
			SELECT id FROM product_installations WHERE person_id = $person_id AND product_id = $product_id;`
		parameters = ydb.ParamsBuilder().Param("$person_id").Text(personID).Param("$product_id").Text(*productID).Build()
	}
	rows, err := executor.QueryResultSet(ctx, statement, query.WithParameters(parameters))
	if err != nil {
		return nil, err
	}
	defer rows.Close(ctx)
	var ids []string
	for row, rowErr := range rows.Rows(ctx) {
		if rowErr != nil {
			return nil, rowErr
		}
		var id string
		if err := row.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func erasePersonRecords(ctx context.Context, tx query.TxActor, personID string, productID *string) error {
	identities, err := identityIDsForPerson(ctx, tx, personID, productID)
	if err != nil {
		return err
	}
	for _, identityID := range identities {
		if err := tx.Exec(ctx, `
			DECLARE $identity_id AS Utf8;
			DELETE FROM email_blind_indexes WHERE identity_id = $identity_id;
			DELETE FROM email_identities WHERE id = $identity_id;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$identity_id").Text(identityID).Build())); err != nil {
			return err
		}
	}
	aliases, err := aliasKeysForPerson(ctx, tx, personID, productID)
	if err != nil {
		return err
	}
	for _, alias := range aliases {
		if err := deleteAlias(ctx, tx, alias); err != nil {
			return err
		}
	}
	if productID == nil {
		return tx.Exec(ctx, `
			DECLARE $person_id AS Utf8;
			DELETE FROM memberships WHERE person_id = $person_id;
			DELETE FROM organization_submissions WHERE person_id = $person_id;
			DELETE FROM consents WHERE subject_type = "person" AND subject_id = $person_id;
			DELETE FROM telemetry_preferences WHERE subject_type = "person" AND subject_id = $person_id;
			DELETE FROM email_verification_audit WHERE person_id = $person_id;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$person_id").Text(personID).Build()))
	}
	return tx.Exec(ctx, `
		DECLARE $person_id AS Utf8;
		DECLARE $product_id AS Utf8;
		DELETE FROM memberships WHERE person_id = $person_id AND product_id = $product_id;
		DELETE FROM organization_submissions WHERE person_id = $person_id AND product_id = $product_id;
		DELETE FROM consents WHERE subject_type = "person" AND subject_id = $person_id AND product_id = $product_id;
		DELETE FROM telemetry_preferences WHERE subject_type = "person" AND subject_id = $person_id AND product_id = $product_id;
		DELETE FROM email_verification_audit WHERE person_id = $person_id AND product_id = $product_id;`,
		query.WithParameters(ydb.ParamsBuilder().
			Param("$person_id").Text(personID).
			Param("$product_id").Text(*productID).
			Build()))
}

func eraseInstallationRecords(ctx context.Context, tx query.TxActor, installationID string, productID *string, _ time.Time) error {
	aliases, err := aliasKeysForSubject(ctx, tx, "installation", installationID, productID)
	if err != nil {
		return err
	}
	for _, alias := range aliases {
		if err := deleteAlias(ctx, tx, alias); err != nil {
			return err
		}
	}
	if productID == nil {
		return tx.Exec(ctx, `
			DECLARE $id AS Utf8;
			DELETE FROM email_verifications WHERE installation_id = $id;
			DELETE FROM email_verification_audit WHERE installation_id = $id;
			DELETE FROM organization_submissions WHERE installation_id = $id;
			DELETE FROM consents WHERE subject_type = "installation" AND subject_id = $id;
			DELETE FROM telemetry_preferences WHERE subject_type = "installation" AND subject_id = $id;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(installationID).Build()))
	}
	return tx.Exec(ctx, `
		DECLARE $id AS Utf8;
		DECLARE $product_id AS Utf8;
		DELETE FROM email_verifications WHERE installation_id = $id AND product_id = $product_id;
		DELETE FROM email_verification_audit WHERE installation_id = $id AND product_id = $product_id;
		DELETE FROM organization_submissions WHERE installation_id = $id AND product_id = $product_id;
		DELETE FROM consents WHERE subject_type = "installation" AND subject_id = $id AND product_id = $product_id;
		DELETE FROM telemetry_preferences WHERE subject_type = "installation" AND subject_id = $id AND product_id = $product_id;`,
		query.WithParameters(ydb.ParamsBuilder().
			Param("$id").Text(installationID).
			Param("$product_id").Text(*productID).
			Build()))
}

func identityIDsForPerson(ctx context.Context, executor query.Executor, personID string, productID *string) ([]string, error) {
	statement := `DECLARE $person_id AS Utf8; SELECT id FROM email_identities WHERE person_id = $person_id;`
	parameters := ydb.ParamsBuilder().Param("$person_id").Text(personID).Build()
	if productID != nil {
		statement = `DECLARE $person_id AS Utf8; DECLARE $product_id AS Utf8;
			SELECT id FROM email_identities
			WHERE person_id = $person_id AND product_id = $product_id AND linkage_scope = "product";`
		parameters = ydb.ParamsBuilder().Param("$person_id").Text(personID).Param("$product_id").Text(*productID).Build()
	}
	rows, err := executor.QueryResultSet(ctx, statement, query.WithParameters(parameters))
	if err != nil {
		return nil, err
	}
	defer rows.Close(ctx)
	var result []string
	for row, rowErr := range rows.Rows(ctx) {
		if rowErr != nil {
			return nil, rowErr
		}
		var id string
		if err := row.Scan(&id); err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, nil
}

func aliasKeysForPerson(ctx context.Context, executor query.Executor, personID string, productID *string) ([]ResolvedAlias, error) {
	statement := `DECLARE $person_id AS Utf8;
		SELECT opaque_key, product_id, audience, subject_type, subject_id
		FROM subject_aliases WHERE person_id = $person_id;`
	parameters := ydb.ParamsBuilder().Param("$person_id").Text(personID).Build()
	if productID != nil {
		statement = `DECLARE $person_id AS Utf8; DECLARE $product_id AS Utf8;
			SELECT opaque_key, product_id, audience, subject_type, subject_id
			FROM subject_aliases WHERE person_id = $person_id AND product_id = $product_id;`
		parameters = ydb.ParamsBuilder().Param("$person_id").Text(personID).Param("$product_id").Text(*productID).Build()
	}
	return scanAliases(ctx, executor, statement, parameters)
}

func aliasKeysForSubject(ctx context.Context, executor query.Executor, subjectType, subjectID string, productID *string) ([]ResolvedAlias, error) {
	statement := `DECLARE $subject_type AS Utf8; DECLARE $subject_id AS Utf8;
		SELECT opaque_key, product_id, audience, subject_type, subject_id
		FROM subject_aliases WHERE subject_type = $subject_type AND subject_id = $subject_id;`
	parameters := ydb.ParamsBuilder().Param("$subject_type").Text(subjectType).Param("$subject_id").Text(subjectID).Build()
	if productID != nil {
		statement = `DECLARE $subject_type AS Utf8; DECLARE $subject_id AS Utf8; DECLARE $product_id AS Utf8;
			SELECT opaque_key, product_id, audience, subject_type, subject_id
			FROM subject_aliases
			WHERE subject_type = $subject_type AND subject_id = $subject_id AND product_id = $product_id;`
		parameters = ydb.ParamsBuilder().Param("$subject_type").Text(subjectType).Param("$subject_id").Text(subjectID).Param("$product_id").Text(*productID).Build()
	}
	return scanAliases(ctx, executor, statement, parameters)
}

func scanAliases(ctx context.Context, executor query.Executor, statement string, parameters ydb.Params) ([]ResolvedAlias, error) {
	rows, err := executor.QueryResultSet(ctx, statement, query.WithParameters(parameters))
	if err != nil {
		return nil, err
	}
	defer rows.Close(ctx)
	var aliases []ResolvedAlias
	for row, rowErr := range rows.Rows(ctx) {
		if rowErr != nil {
			return nil, rowErr
		}
		var alias ResolvedAlias
		if err := row.Scan(&alias.OpaqueKey, &alias.ProductID, &alias.Audience, &alias.SubjectType, &alias.SubjectID); err != nil {
			return nil, err
		}
		aliases = append(aliases, alias)
	}
	return aliases, nil
}

func deleteAlias(ctx context.Context, tx query.TxActor, alias ResolvedAlias) error {
	return tx.Exec(ctx, `
		DECLARE $opaque_key AS Utf8;
		DECLARE $product_id AS Utf8;
		DECLARE $audience AS Utf8;
		DECLARE $subject_type AS Utf8;
		DECLARE $subject_id AS Utf8;
		DELETE FROM subject_aliases WHERE opaque_key = $opaque_key;
		DELETE FROM subject_alias_keys
		WHERE product_id = $product_id AND audience = $audience
		  AND subject_type = $subject_type AND subject_id = $subject_id;`,
		query.WithParameters(ydb.ParamsBuilder().
			Param("$opaque_key").Text(alias.OpaqueKey).
			Param("$product_id").Text(alias.ProductID).
			Param("$audience").Text(alias.Audience).
			Param("$subject_type").Text(alias.SubjectType).
			Param("$subject_id").Text(alias.SubjectID).
			Build()))
}
