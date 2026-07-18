package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/linka-cloud/linka.identity/internal/cryptokit"
)

type EmailVerification struct {
	ID                   string
	ProductID            string
	InstallationID       *string
	Namespace            string
	AgeCategory          string
	GuardianRelationship *string
	LinkAcrossProducts   bool
	BlindIndexVersion    int
	BlindIndex           []byte
	EncryptedEmail       cryptokit.Ciphertext
	ExpiresAt            time.Time
	VerifiedAt           *time.Time
	ConsumedAt           *time.Time
}

func (s *Store) CreateEmailVerification(ctx context.Context, verification EmailVerification) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO email_verifications (
			id, product_id, installation_id, identity_namespace, age_category,
			guardian_relationship, link_across_products, blind_index_version,
			email_blind_index, encrypted_email, email_nonce, wrapped_data_key,
			key_id, encryption_algorithm, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
		verification.ID, verification.ProductID, verification.InstallationID, verification.Namespace,
		verification.AgeCategory, verification.GuardianRelationship, verification.LinkAcrossProducts,
		verification.BlindIndexVersion, verification.BlindIndex, verification.EncryptedEmail.Data,
		verification.EncryptedEmail.Nonce, verification.EncryptedEmail.WrappedDataKey,
		verification.EncryptedEmail.KeyID, verification.EncryptedEmail.Algorithm, verification.ExpiresAt)
	return err
}

func (s *Store) VerifyEmailOwnership(ctx context.Context, id, productID, verifier, evidenceID string, now time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE email_verifications
		SET verified_at = $5, verified_by = $3, evidence_id = $4
		WHERE id = $1 AND product_id = $2 AND verified_at IS NULL AND consumed_at IS NULL AND expires_at > $5`,
		id, productID, verifier, evidenceID, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	return nil
}

func (s *Store) ClaimVerifiedEmail(ctx context.Context, id, productID, claimToken string, now time.Time, lease time.Duration) (EmailVerification, error) {
	var verification EmailVerification
	err := s.pool.QueryRow(ctx, `
		UPDATE email_verifications
		SET processing_token = $3, processing_at = $4
		WHERE id = $1 AND product_id = $2 AND verified_at IS NOT NULL
		  AND consumed_at IS NULL AND expires_at > $4
		  AND (processing_at IS NULL OR processing_at < $5)
		RETURNING id::text, product_id, installation_id::text, identity_namespace, age_category,
		       guardian_relationship, link_across_products, blind_index_version,
		       email_blind_index, encryption_algorithm, key_id, wrapped_data_key,
		       email_nonce, encrypted_email, expires_at, verified_at, consumed_at`,
		id, productID, claimToken, now, now.Add(-lease)).Scan(
		&verification.ID, &verification.ProductID, &verification.InstallationID, &verification.Namespace,
		&verification.AgeCategory, &verification.GuardianRelationship, &verification.LinkAcrossProducts,
		&verification.BlindIndexVersion, &verification.BlindIndex, &verification.EncryptedEmail.Algorithm,
		&verification.EncryptedEmail.KeyID, &verification.EncryptedEmail.WrappedDataKey,
		&verification.EncryptedEmail.Nonce, &verification.EncryptedEmail.Data, &verification.ExpiresAt,
		&verification.VerifiedAt, &verification.ConsumedAt)
	return verification, err
}

func (s *Store) ConsumeEmailVerification(ctx context.Context, id, claimToken, personID string, now time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		WITH consumed AS (
			DELETE FROM email_verifications
			WHERE id = $1 AND processing_token = $2 AND verified_at IS NOT NULL AND consumed_at IS NULL
			RETURNING id, installation_id, product_id, verified_by, evidence_id, verified_at
		)
		INSERT INTO email_verification_audit (
			verification_id, person_id, installation_id, product_id,
			verified_by, evidence_id, verified_at, consumed_at
		)
		SELECT id, $3, installation_id, product_id, verified_by, evidence_id, verified_at, $4
		FROM consumed`, id, claimToken, personID, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	return nil
}

func (s *Store) ReleaseEmailVerification(ctx context.Context, id, claimToken string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE email_verifications SET processing_token = NULL, processing_at = NULL
		WHERE id = $1 AND processing_token = $2 AND consumed_at IS NULL`, id, claimToken)
	return err
}

func (s *Store) DeleteExpiredEmailVerifications(ctx context.Context, now time.Time, limit int) (int64, error) {
	if limit < 1 || limit > 1000 {
		return 0, errors.New("invalid email verification cleanup limit")
	}
	tag, err := s.pool.Exec(ctx, `
		WITH expired AS (
			SELECT id FROM email_verifications
			WHERE expires_at <= $1
			  AND (processing_at IS NULL OR processing_at < $1 - interval '5 minutes')
			ORDER BY expires_at
			FOR UPDATE SKIP LOCKED
			LIMIT $2
		)
		DELETE FROM email_verifications verification
		USING expired
		WHERE verification.id = expired.id`, now, limit)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
