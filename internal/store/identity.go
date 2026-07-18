package store

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/linka-cloud/linka.identity/internal/cryptokit"
)

type EmailIdentity struct {
	IdentityID               string
	PersonID                 string
	AccountID                string
	MatchedBlindIndexVersion int
}

type NewEmailIdentity struct {
	ID                string
	PersonID          string
	ProductID         string
	Namespace         string
	LinkageScope      string
	ScopeKey          string
	BlindIndexVersion int
	BlindIndex        []byte
	EncryptedEmail    cryptokit.Ciphertext
	VerifiedAt        time.Time
}

func LockBlindIndex(ctx context.Context, tx pgx.Tx, value []byte) error {
	if len(value) < 8 {
		return fmt.Errorf("blind index is too short")
	}
	key := int64(binary.BigEndian.Uint64(value[:8]))
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", key); err != nil {
		return fmt.Errorf("lock blind index: %w", err)
	}
	return nil
}

func FindEmailIdentity(ctx context.Context, tx pgx.Tx, namespace, linkageScope, scopeKey string, indexes []cryptokit.BlindIndex) (EmailIdentity, error) {
	versions := make([]int16, 0, len(indexes))
	values := make([][]byte, 0, len(indexes))
	for _, index := range indexes {
		versions = append(versions, int16(index.Version))
		values = append(values, index.Value)
	}
	var result EmailIdentity
	err := tx.QueryRow(ctx, `
		SELECT identity.id::text, identity.person_id::text, COALESCE(account.id::text, ''), wanted.version
		FROM email_identities identity
		JOIN email_identity_blind_indexes blind ON blind.identity_id = identity.id
		JOIN unnest($4::smallint[], $5::bytea[]) AS wanted(version, value)
		  ON wanted.version = blind.blind_index_version
		 AND wanted.value = blind.email_blind_index
		LEFT JOIN accounts account ON account.person_id = identity.person_id AND account.status = 'active'
		WHERE identity.identity_namespace = $1
		  AND identity.linkage_scope = $2
		  AND identity.scope_key = $3
		LIMIT 1`, namespace, linkageScope, scopeKey, versions, values).Scan(
		&result.IdentityID, &result.PersonID, &result.AccountID, &result.MatchedBlindIndexVersion)
	if err != nil {
		return EmailIdentity{}, err
	}
	return result, nil
}

func InsertPerson(ctx context.Context, tx pgx.Tx, id, ageCategory string, guardianRelationship *string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO persons (id, age_category, guardian_relationship)
		VALUES ($1, $2, $3)`, id, ageCategory, guardianRelationship)
	return err
}

func InsertEmailIdentity(ctx context.Context, tx pgx.Tx, identity NewEmailIdentity) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO email_identities (
			id, person_id, product_id, identity_namespace, linkage_scope, scope_key,
			blind_index_version, email_blind_index, encrypted_email, email_nonce,
			wrapped_data_key, key_id, encryption_algorithm, verified_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		identity.ID, identity.PersonID, identity.ProductID, identity.Namespace,
		identity.LinkageScope, identity.ScopeKey, identity.BlindIndexVersion,
		identity.BlindIndex, identity.EncryptedEmail.Data, identity.EncryptedEmail.Nonce,
		identity.EncryptedEmail.WrappedDataKey, identity.EncryptedEmail.KeyID,
		identity.EncryptedEmail.Algorithm, identity.VerifiedAt)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO email_identity_blind_indexes (identity_id, blind_index_version, email_blind_index)
		VALUES ($1, $2, $3)`, identity.ID, identity.BlindIndexVersion, identity.BlindIndex)
	return err
}

func UpsertEmailBlindIndex(ctx context.Context, tx pgx.Tx, identityID string, index cryptokit.BlindIndex) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO email_identity_blind_indexes (identity_id, blind_index_version, email_blind_index)
		VALUES ($1, $2, $3)
		ON CONFLICT (identity_id, blind_index_version) DO UPDATE
		SET email_blind_index = EXCLUDED.email_blind_index
		WHERE email_identity_blind_indexes.email_blind_index = EXCLUDED.email_blind_index`,
		identityID, index.Version, index.Value)
	return err
}

func MarkEmailIdentityVerified(ctx context.Context, tx pgx.Tx, identityID string, verifiedAt time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE email_identities SET verified_at = COALESCE(verified_at, $2) WHERE id = $1`, identityID, verifiedAt)
	return err
}

func (s *Store) ValidateBlindIndexVersions(ctx context.Context, configured map[int][]byte) error {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT blind_index_version FROM email_identity_blind_indexes
		UNION
		SELECT DISTINCT blind_index_version FROM email_verifications WHERE consumed_at IS NULL`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return err
		}
		if _, ok := configured[version]; !ok {
			return fmt.Errorf("blind-index key version %d is still referenced by persisted rows", version)
		}
	}
	return rows.Err()
}

func (s *Store) ValidateEnvelopeKeyIDs(ctx context.Context, configured map[string]struct{}) error {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT key_id FROM email_identities
		UNION
		SELECT DISTINCT key_id FROM email_verifications`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var keyID string
		if err := rows.Scan(&keyID); err != nil {
			return err
		}
		if _, ok := configured[keyID]; !ok {
			return fmt.Errorf("envelope key alias %q is still referenced by persisted rows", keyID)
		}
	}
	return rows.Err()
}

func EnsureAccount(ctx context.Context, tx pgx.Tx, id, personID string) (string, error) {
	var accountID string
	err := tx.QueryRow(ctx, `
		INSERT INTO accounts (id, person_id, status)
		VALUES ($1, $2, 'active')
		ON CONFLICT (person_id) DO UPDATE SET person_id = EXCLUDED.person_id
		WHERE accounts.status = 'active'
		RETURNING id::text`, id, personID).Scan(&accountID)
	return accountID, err
}

func LinkInstallation(ctx context.Context, tx pgx.Tx, installationID, productID, personID string) error {
	tag, err := tx.Exec(ctx, `
		UPDATE product_installations
		SET person_id = $3, last_seen_at = now()
		WHERE id = $1 AND product_id = $2 AND disabled_at IS NULL
		  AND (person_id IS NULL OR person_id = $3)`, installationID, productID, personID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	return nil
}
