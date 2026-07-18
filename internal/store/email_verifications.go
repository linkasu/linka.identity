package store

import (
	"context"
	"errors"
	"time"

	"github.com/linka-cloud/linka.identity/internal/cryptokit"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
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
	Version              uint64
}

func (s *Store) CreateEmailVerification(ctx context.Context, verification EmailVerification) error {
	return s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		if verification.InstallationID != nil {
			if err := validateSubjectWith(ctx, tx, Subject{Kind: "installation", ID: *verification.InstallationID}, verification.ProductID); err != nil {
				return err
			}
		}
		return tx.Exec(ctx, `
			DECLARE $id AS Utf8;
			DECLARE $product_id AS Utf8;
			DECLARE $installation_id AS Utf8?;
			DECLARE $namespace AS Utf8;
			DECLARE $age_category AS Utf8;
			DECLARE $guardian_relationship AS Utf8?;
			DECLARE $link_across_products AS Bool;
			DECLARE $blind_index_version AS Uint64;
			DECLARE $blind_index AS Bytes;
			DECLARE $encrypted_email AS Bytes;
			DECLARE $email_nonce AS Bytes;
			DECLARE $wrapped_data_key AS Bytes;
			DECLARE $key_id AS Utf8;
			DECLARE $algorithm AS Utf8;
			DECLARE $expires_at AS Timestamp;
			DECLARE $created_at AS Timestamp;
			INSERT INTO email_verifications (
				id, product_id, installation_id, identity_namespace, age_category,
				guardian_relationship, link_across_products, blind_index_version,
				email_blind_index, encrypted_email, email_nonce, wrapped_data_key,
				key_id, encryption_algorithm, expires_at, created_at, version
			) VALUES (
				$id, $product_id, $installation_id, $namespace, $age_category,
				$guardian_relationship, $link_across_products, $blind_index_version,
				$blind_index, $encrypted_email, $email_nonce, $wrapped_data_key,
				$key_id, $algorithm, $expires_at, $created_at, 1u
			);`, query.WithParameters(ydb.ParamsBuilder().
			Param("$id").Text(verification.ID).
			Param("$product_id").Text(verification.ProductID).
			Param("$installation_id").Any(nullableText(verification.InstallationID)).
			Param("$namespace").Text(verification.Namespace).
			Param("$age_category").Text(verification.AgeCategory).
			Param("$guardian_relationship").Any(nullableText(verification.GuardianRelationship)).
			Param("$link_across_products").Bool(verification.LinkAcrossProducts).
			Param("$blind_index_version").Uint64(uint64(verification.BlindIndexVersion)).
			Param("$blind_index").Bytes(verification.BlindIndex).
			Param("$encrypted_email").Bytes(verification.EncryptedEmail.Data).
			Param("$email_nonce").Bytes(verification.EncryptedEmail.Nonce).
			Param("$wrapped_data_key").Bytes(verification.EncryptedEmail.WrappedDataKey).
			Param("$key_id").Text(verification.EncryptedEmail.KeyID).
			Param("$algorithm").Text(verification.EncryptedEmail.Algorithm).
			Param("$expires_at").Timestamp(verification.ExpiresAt.UTC()).
			Param("$created_at").Timestamp(s.now().UTC()).
			Build()))
	})
}

func (s *Store) VerifyEmailOwnership(ctx context.Context, id, productID, verifier, evidenceID string, now time.Time) error {
	return s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		row, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			SELECT product_id, expires_at, verified_at, processing_token, version
			FROM email_verifications WHERE id = $id;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(id).Build()))
		if err != nil {
			return noRows(err)
		}
		var storedProduct string
		var expiresAt time.Time
		var verifiedAt *time.Time
		var processingToken *string
		var version uint64
		if err := row.Scan(&storedProduct, &expiresAt, &verifiedAt, &processingToken, &version); err != nil {
			return err
		}
		if storedProduct != productID || verifiedAt != nil || processingToken != nil || !expiresAt.After(now) {
			return domain.ErrNotFound
		}
		updated, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			DECLARE $verified_at AS Timestamp;
			DECLARE $verified_by AS Utf8;
			DECLARE $evidence_id AS Utf8;
			DECLARE $version AS Uint64;
			UPDATE email_verifications
			SET verified_at = $verified_at, verified_by = $verified_by, evidence_id = $evidence_id,
			    version = version + 1u
			WHERE id = $id AND version = $version RETURNING version;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$id").Text(id).
				Param("$verified_at").Timestamp(now.UTC()).
				Param("$verified_by").Text(verifier).
				Param("$evidence_id").Text(evidenceID).
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

func (s *Store) ClaimVerifiedEmail(ctx context.Context, id, productID, claimToken string, now time.Time, lease time.Duration) (EmailVerification, error) {
	var verification EmailVerification
	err := s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		verification = EmailVerification{ID: id}
		var indexVersion uint64
		var processingAt *time.Time
		row, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			SELECT product_id, installation_id, identity_namespace, age_category,
			       guardian_relationship, link_across_products, blind_index_version,
			       email_blind_index, encryption_algorithm, key_id, wrapped_data_key,
			       email_nonce, encrypted_email, expires_at, verified_at,
			       processing_at, version
			FROM email_verifications WHERE id = $id;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(id).Build()))
		if err != nil {
			return noRows(err)
		}
		if err := row.Scan(
			&verification.ProductID, &verification.InstallationID, &verification.Namespace,
			&verification.AgeCategory, &verification.GuardianRelationship, &verification.LinkAcrossProducts,
			&indexVersion, &verification.BlindIndex, &verification.EncryptedEmail.Algorithm,
			&verification.EncryptedEmail.KeyID, &verification.EncryptedEmail.WrappedDataKey,
			&verification.EncryptedEmail.Nonce, &verification.EncryptedEmail.Data, &verification.ExpiresAt,
			&verification.VerifiedAt, &processingAt, &verification.Version,
		); err != nil {
			return err
		}
		verification.BlindIndexVersion = int(indexVersion)
		if verification.ProductID != productID || verification.VerifiedAt == nil || !verification.ExpiresAt.After(now) ||
			(processingAt != nil && processingAt.After(now.Add(-lease))) {
			return domain.ErrNotFound
		}
		updated, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			DECLARE $claim_token AS Utf8;
			DECLARE $processing_at AS Timestamp;
			DECLARE $version AS Uint64;
			UPDATE email_verifications
			SET processing_token = $claim_token, processing_at = $processing_at, version = version + 1u
			WHERE id = $id AND version = $version RETURNING version;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$id").Text(id).
				Param("$claim_token").Text(claimToken).
				Param("$processing_at").Timestamp(now.UTC()).
				Param("$version").Uint64(verification.Version).
				Build()))
		if err != nil {
			return optimistic(err)
		}
		var next uint64
		if err := updated.Scan(&next); err != nil || next != verification.Version+1 {
			return domain.ErrConflict
		}
		verification.Version = next
		return nil
	})
	return verification, err
}

func (s *Store) ConsumeEmailVerification(ctx context.Context, id, claimToken, personID string, now time.Time) error {
	return s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		row, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			SELECT installation_id, product_id, verified_by, evidence_id, verified_at,
			       processing_token, version
			FROM email_verifications WHERE id = $id;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(id).Build()))
		if err != nil {
			return noRows(err)
		}
		var installationID, verifiedBy, evidenceID, storedClaim *string
		var productID string
		var verifiedAt *time.Time
		var version uint64
		if err := row.Scan(&installationID, &productID, &verifiedBy, &evidenceID, &verifiedAt, &storedClaim, &version); err != nil {
			return err
		}
		if storedClaim == nil || *storedClaim != claimToken || verifiedAt == nil || verifiedBy == nil || evidenceID == nil {
			return domain.ErrNotFound
		}
		if err := tx.Exec(ctx, `
			DECLARE $verification_id AS Utf8;
			DECLARE $person_id AS Utf8;
			DECLARE $installation_id AS Utf8?;
			DECLARE $product_id AS Utf8;
			DECLARE $verified_by AS Utf8;
			DECLARE $evidence_id AS Utf8;
			DECLARE $verified_at AS Timestamp;
			DECLARE $consumed_at AS Timestamp;
			INSERT INTO email_verification_audit (
				verification_id, person_id, installation_id, product_id,
				verified_by, evidence_id, verified_at, consumed_at
			) VALUES (
				$verification_id, $person_id, $installation_id, $product_id,
				$verified_by, $evidence_id, $verified_at, $consumed_at
			);`, query.WithParameters(ydb.ParamsBuilder().
			Param("$verification_id").Text(id).
			Param("$person_id").Text(personID).
			Param("$installation_id").Any(nullableText(installationID)).
			Param("$product_id").Text(productID).
			Param("$verified_by").Text(*verifiedBy).
			Param("$evidence_id").Text(*evidenceID).
			Param("$verified_at").Timestamp(verifiedAt.UTC()).
			Param("$consumed_at").Timestamp(now.UTC()).
			Build())); err != nil {
			return err
		}
		return tx.Exec(ctx, `
			DECLARE $id AS Utf8;
			DECLARE $version AS Uint64;
			DELETE FROM email_verifications WHERE id = $id AND version = $version;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$id").Text(id).
				Param("$version").Uint64(version).
				Build()))
	})
}

func (s *Store) ReleaseEmailVerification(ctx context.Context, id, claimToken string) error {
	return s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		row, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			SELECT processing_token, version FROM email_verifications WHERE id = $id;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(id).Build()))
		if errors.Is(err, query.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		var storedClaim *string
		var version uint64
		if err := row.Scan(&storedClaim, &version); err != nil {
			return err
		}
		if storedClaim == nil || *storedClaim != claimToken {
			return nil
		}
		updated, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			DECLARE $version AS Uint64;
			UPDATE email_verifications
			SET processing_token = NULL, processing_at = NULL, version = version + 1u
			WHERE id = $id AND version = $version RETURNING version;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$id").Text(id).
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

func (s *Store) DeleteExpiredEmailVerifications(ctx context.Context, now time.Time, limit int) (int64, error) {
	if limit < 1 || limit > 1000 {
		return 0, errors.New("invalid email verification cleanup limit")
	}
	var deleted int64
	err := s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		deleted = 0
		rows, err := tx.QueryResultSet(ctx, `
			DECLARE $now AS Timestamp;
			DECLARE $stale_before AS Timestamp;
			DECLARE $limit AS Uint64;
			SELECT id, version FROM email_verifications
			WHERE expires_at <= $now
			  AND (processing_at IS NULL OR processing_at < $stale_before)
			ORDER BY expires_at LIMIT $limit;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$now").Timestamp(now.UTC()).
				Param("$stale_before").Timestamp(now.UTC().Add(-5*time.Minute)).
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
			var id string
			var version uint64
			if err := row.Scan(&id, &version); err != nil {
				return err
			}
			if err := tx.Exec(ctx, `
				DECLARE $id AS Utf8;
				DECLARE $version AS Uint64;
				DELETE FROM email_verifications WHERE id = $id AND version = $version;`,
				query.WithParameters(ydb.ParamsBuilder().
					Param("$id").Text(id).
					Param("$version").Uint64(version).
					Build())); err != nil {
				return err
			}
			deleted++
		}
		return nil
	})
	return deleted, err
}
