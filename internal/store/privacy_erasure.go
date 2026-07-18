package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/linka-cloud/linka.identity/internal/ids"
)

type PrivacyErasureJob struct {
	StepID         string
	RequestID      string
	PersonID       *string
	InstallationID *string
	Scope          string
	ProductID      *string
	Attempts       int
}

func (s *Store) ClaimPrivacyErasures(ctx context.Context, limit int) ([]PrivacyErasureJob, error) {
	rows, err := s.pool.Query(ctx, `
		WITH candidates AS (
			SELECT step.id
			FROM privacy_request_steps step
			JOIN privacy_requests request ON request.id = step.privacy_request_id
			WHERE step.step_type = 'postgres'
			  AND request.status IN ('requested', 'processing')
			  AND ((step.status IN ('pending', 'retry') AND step.available_at <= now()) OR
			       (step.status = 'processing' AND step.lease_until < now()))
			  AND NOT EXISTS (
				SELECT 1 FROM privacy_request_steps downstream
				WHERE downstream.privacy_request_id = step.privacy_request_id
				  AND downstream.step_type = 'metric' AND downstream.status <> 'completed'
			  )
			ORDER BY step.created_at
			FOR UPDATE SKIP LOCKED
			LIMIT $1
		)
		UPDATE privacy_request_steps step
		SET status = 'processing', attempts = attempts + 1,
		    lease_until = now() + interval '5 minutes', updated_at = now()
		FROM candidates, privacy_requests request
		WHERE step.id = candidates.id AND request.id = step.privacy_request_id
		RETURNING step.id::text, request.id::text, request.person_id::text,
		          request.installation_id::text, request.scope, request.product_id, step.attempts`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobs []PrivacyErasureJob
	for rows.Next() {
		var job PrivacyErasureJob
		if err := rows.Scan(&job.StepID, &job.RequestID, &job.PersonID, &job.InstallationID, &job.Scope, &job.ProductID, &job.Attempts); err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

func (s *Store) ErasePrivacyJob(ctx context.Context, job PrivacyErasureJob) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var requestStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM privacy_requests WHERE id = $1 FOR UPDATE`, job.RequestID).Scan(&requestStatus); err != nil {
		return err
	}
	if requestStatus != "requested" && requestStatus != "processing" {
		return pgx.ErrNoRows
	}
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM privacy_request_steps WHERE id = $1 FOR UPDATE`, job.StepID).Scan(&status); err != nil {
		return err
	}
	if status != "processing" {
		return pgx.ErrNoRows
	}
	if job.PersonID != nil {
		if job.Scope == "all" {
			if err := erasePerson(ctx, tx, *job.PersonID); err != nil {
				return err
			}
		} else if job.ProductID != nil {
			if err := erasePersonProduct(ctx, tx, *job.PersonID, *job.ProductID); err != nil {
				return err
			}
		}
	} else if job.InstallationID != nil && job.ProductID != nil {
		if err := eraseInstallation(ctx, tx, *job.InstallationID, *job.ProductID); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE privacy_request_steps
		SET status = 'completed', receipt = '{"postgres":"erased"}'::jsonb,
		    completed_at = now(), lease_until = NULL, last_error = NULL, updated_at = now()
		WHERE id = $1`, job.StepID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE privacy_requests request
		SET status = 'completed', completed_at = now(), updated_at = now()
		WHERE request.id = $1 AND NOT EXISTS (
			SELECT 1 FROM privacy_request_steps step
			WHERE step.privacy_request_id = request.id AND step.status <> 'completed'
		)`, job.RequestID); err != nil {
		return err
	}
	auditID, err := ids.NewUUID()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO privacy_request_status_audit (id, privacy_request_id, status, actor, audit_note)
		SELECT $1, $2, 'completed', 'privacy-orchestrator', 'all downstream receipts and PostgreSQL erasure completed'
		WHERE EXISTS (SELECT 1 FROM privacy_requests WHERE id = $2 AND status = 'completed')`, auditID, job.RequestID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) RetryPrivacyErasure(ctx context.Context, job PrivacyErasureJob, delay time.Duration, maxAttempts int) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE privacy_request_steps
		SET status = CASE WHEN attempts >= $4 THEN 'manual_dlq' ELSE 'retry' END,
		    available_at = now() + $2::interval, lease_until = NULL,
		    last_error = 'postgres erasure failed', updated_at = now()
		WHERE id = $1 AND status = 'processing'`, job.StepID, pgInterval(delay), job.Attempts, maxAttempts)
	return err
}

func erasePerson(ctx context.Context, tx pgx.Tx, personID string) error {
	statements := []string{
		`DELETE FROM email_verifications WHERE installation_id IN (SELECT id FROM product_installations WHERE person_id = $1)`,
		`DELETE FROM email_verification_audit WHERE person_id = $1`,
		`DELETE FROM email_identities WHERE person_id = $1`,
		`DELETE FROM memberships WHERE person_id = $1`,
		`DELETE FROM organization_submissions WHERE person_id = $1 OR installation_id IN (SELECT id FROM product_installations WHERE person_id = $1)`,
		`DELETE FROM consents WHERE person_id = $1 OR installation_id IN (SELECT id FROM product_installations WHERE person_id = $1)`,
		`DELETE FROM telemetry_preferences WHERE person_id = $1 OR installation_id IN (SELECT id FROM product_installations WHERE person_id = $1)`,
		`DELETE FROM subject_aliases WHERE (subject_type = 'person' AND subject_id = $1) OR (subject_type = 'account' AND subject_id IN (SELECT id FROM accounts WHERE person_id = $1)) OR (subject_type = 'installation' AND subject_id IN (SELECT id FROM product_installations WHERE person_id = $1))`,
		`UPDATE accounts SET status = 'deleted', last_authenticated_at = NULL WHERE person_id = $1`,
		`UPDATE product_installations SET person_id = NULL, disabled_at = COALESCE(disabled_at, now()) WHERE person_id = $1`,
		`UPDATE persons SET age_category = 'unknown', guardian_relationship = NULL, deleted_at = COALESCE(deleted_at, now()) WHERE id = $1`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement, personID); err != nil {
			return err
		}
	}
	return nil
}

func erasePersonProduct(ctx context.Context, tx pgx.Tx, personID, productID string) error {
	statements := []string{
		`DELETE FROM email_verifications WHERE product_id = $2 AND installation_id IN (SELECT id FROM product_installations WHERE person_id = $1)`,
		`DELETE FROM email_verification_audit WHERE person_id = $1 AND product_id = $2`,
		`DELETE FROM email_identities WHERE person_id = $1 AND product_id = $2 AND linkage_scope = 'product'`,
		`DELETE FROM memberships WHERE person_id = $1 AND product_id = $2`,
		`DELETE FROM organization_submissions WHERE product_id = $2 AND (person_id = $1 OR installation_id IN (SELECT id FROM product_installations WHERE person_id = $1))`,
		`DELETE FROM consents WHERE product_id = $2 AND (person_id = $1 OR installation_id IN (SELECT id FROM product_installations WHERE person_id = $1))`,
		`DELETE FROM telemetry_preferences WHERE product_id = $2 AND (person_id = $1 OR installation_id IN (SELECT id FROM product_installations WHERE person_id = $1))`,
		`DELETE FROM subject_aliases WHERE product_id = $2 AND ((subject_type = 'person' AND subject_id = $1) OR (subject_type = 'account' AND subject_id IN (SELECT id FROM accounts WHERE person_id = $1)) OR (subject_type = 'installation' AND subject_id IN (SELECT id FROM product_installations WHERE person_id = $1)))`,
		`UPDATE product_installations SET person_id = NULL, disabled_at = COALESCE(disabled_at, now()) WHERE person_id = $1 AND product_id = $2`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement, personID, productID); err != nil {
			return err
		}
	}
	return nil
}

func eraseInstallation(ctx context.Context, tx pgx.Tx, installationID, productID string) error {
	statements := []string{
		`DELETE FROM email_verifications WHERE installation_id = $1 AND product_id = $2`,
		`DELETE FROM email_verification_audit WHERE installation_id = $1 AND product_id = $2`,
		`DELETE FROM organization_submissions WHERE installation_id = $1 AND product_id = $2`,
		`DELETE FROM consents WHERE installation_id = $1 AND product_id = $2`,
		`DELETE FROM telemetry_preferences WHERE installation_id = $1 AND product_id = $2`,
		`DELETE FROM subject_aliases WHERE subject_type = 'installation' AND subject_id = $1 AND product_id = $2`,
		`UPDATE product_installations SET person_id = NULL, disabled_at = COALESCE(disabled_at, now()) WHERE id = $1 AND product_id = $2`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement, installationID, productID); err != nil {
			return err
		}
	}
	return nil
}
