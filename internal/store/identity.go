package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/linka-cloud/linka.identity/internal/cryptokit"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

type EmailIdentity struct {
	IdentityID               string
	PersonID                 string
	AccountID                string
	MatchedBlindIndexVersion int
}

type NewEmailIdentity struct {
	ID                   string
	PersonID             string
	AccountID            string
	ProductID            string
	Namespace            string
	LinkageScope         string
	ScopeKey             string
	BlindIndexVersion    int
	BlindIndex           []byte
	EncryptedEmail       cryptokit.Ciphertext
	AgeCategory          string
	GuardianRelationship *string
	VerifiedAt           time.Time
	CreateAccount        bool
	InstallationID       *string
}

func (s *Store) RegisterEmailIdentity(ctx context.Context, identity NewEmailIdentity, indexes []cryptokit.BlindIndex) (EmailIdentity, bool, error) {
	var result EmailIdentity
	var created bool
	err := s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		result = EmailIdentity{}
		created = false

		for _, index := range indexes {
			row, err := tx.QueryRow(ctx, `
				DECLARE $namespace AS Utf8;
				DECLARE $linkage_scope AS Utf8;
				DECLARE $scope_key AS Utf8;
				DECLARE $index_version AS Uint64;
				DECLARE $blind_index AS Bytes;
				SELECT identity_id FROM email_blind_indexes
				WHERE identity_namespace = $namespace AND linkage_scope = $linkage_scope
				  AND scope_key = $scope_key AND blind_index_version = $index_version
				  AND email_blind_index = $blind_index;`,
				query.WithParameters(ydb.ParamsBuilder().
					Param("$namespace").Text(identity.Namespace).
					Param("$linkage_scope").Text(identity.LinkageScope).
					Param("$scope_key").Text(identity.ScopeKey).
					Param("$index_version").Uint64(uint64(index.Version)).
					Param("$blind_index").Bytes(index.Value).
					Build()))
			if errors.Is(err, query.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			if err := row.Scan(&result.IdentityID); err != nil {
				return err
			}
			result.MatchedBlindIndexVersion = index.Version
			break
		}

		if result.IdentityID != "" {
			row, err := tx.QueryRow(ctx, `
				DECLARE $id AS Utf8;
				SELECT person_id FROM email_identities WHERE id = $id;`,
				query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(result.IdentityID).Build()))
			if err != nil {
				return err
			}
			if err := row.Scan(&result.PersonID); err != nil {
				return err
			}
			accountID, err := findAccountByPerson(ctx, tx, result.PersonID)
			if err != nil && !errors.Is(err, query.ErrNoRows) {
				return err
			}
			result.AccountID = accountID
			if result.MatchedBlindIndexVersion != identity.BlindIndexVersion {
				if err := insertBlindIndex(ctx, tx, identity, result.IdentityID); err != nil {
					return err
				}
			}
			if identity.CreateAccount && result.AccountID == "" {
				if err := insertAccount(ctx, tx, identity.AccountID, result.PersonID, s.now().UTC()); err != nil {
					return err
				}
				result.AccountID = identity.AccountID
			}
			if identity.InstallationID != nil {
				if err := linkInstallation(ctx, tx, *identity.InstallationID, identity.ProductID, result.PersonID, s.now().UTC()); err != nil {
					return err
				}
			}
			return nil
		}

		now := s.now().UTC()
		if err := tx.Exec(ctx, `
			DECLARE $id AS Utf8;
			DECLARE $age_category AS Utf8;
			DECLARE $guardian_relationship AS Utf8?;
			DECLARE $now AS Timestamp;
			INSERT INTO persons (id, age_category, guardian_relationship, created_at, version)
			VALUES ($id, $age_category, $guardian_relationship, $now, 1u);`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$id").Text(identity.PersonID).
				Param("$age_category").Text(identity.AgeCategory).
				Param("$guardian_relationship").Any(nullableText(identity.GuardianRelationship)).
				Param("$now").Timestamp(now).
				Build())); err != nil {
			return err
		}
		if err := tx.Exec(ctx, `
			DECLARE $id AS Utf8;
			DECLARE $person_id AS Utf8;
			DECLARE $product_id AS Utf8;
			DECLARE $namespace AS Utf8;
			DECLARE $linkage_scope AS Utf8;
			DECLARE $scope_key AS Utf8;
			DECLARE $encrypted_email AS Bytes;
			DECLARE $email_nonce AS Bytes;
			DECLARE $wrapped_data_key AS Bytes;
			DECLARE $key_id AS Utf8;
			DECLARE $algorithm AS Utf8;
			DECLARE $verified_at AS Timestamp;
			DECLARE $now AS Timestamp;
			INSERT INTO email_identities (
				id, person_id, product_id, identity_namespace, linkage_scope, scope_key,
				encrypted_email, email_nonce, wrapped_data_key, key_id, encryption_algorithm,
				verified_at, created_at, version
			) VALUES (
				$id, $person_id, $product_id, $namespace, $linkage_scope, $scope_key,
				$encrypted_email, $email_nonce, $wrapped_data_key, $key_id, $algorithm,
				$verified_at, $now, 1u
			);`, query.WithParameters(ydb.ParamsBuilder().
			Param("$id").Text(identity.ID).
			Param("$person_id").Text(identity.PersonID).
			Param("$product_id").Text(identity.ProductID).
			Param("$namespace").Text(identity.Namespace).
			Param("$linkage_scope").Text(identity.LinkageScope).
			Param("$scope_key").Text(identity.ScopeKey).
			Param("$encrypted_email").Bytes(identity.EncryptedEmail.Data).
			Param("$email_nonce").Bytes(identity.EncryptedEmail.Nonce).
			Param("$wrapped_data_key").Bytes(identity.EncryptedEmail.WrappedDataKey).
			Param("$key_id").Text(identity.EncryptedEmail.KeyID).
			Param("$algorithm").Text(identity.EncryptedEmail.Algorithm).
			Param("$verified_at").Timestamp(identity.VerifiedAt.UTC()).
			Param("$now").Timestamp(now).
			Build())); err != nil {
			return err
		}
		if err := insertBlindIndex(ctx, tx, identity, identity.ID); err != nil {
			return err
		}
		if identity.CreateAccount {
			if err := insertAccount(ctx, tx, identity.AccountID, identity.PersonID, now); err != nil {
				return err
			}
			result.AccountID = identity.AccountID
		}
		if identity.InstallationID != nil {
			if err := linkInstallation(ctx, tx, *identity.InstallationID, identity.ProductID, identity.PersonID, now); err != nil {
				return err
			}
		}
		result.IdentityID = identity.ID
		result.PersonID = identity.PersonID
		result.MatchedBlindIndexVersion = identity.BlindIndexVersion
		created = true
		return nil
	})
	if err != nil {
		return EmailIdentity{}, false, err
	}
	return result, created, nil
}

func insertBlindIndex(ctx context.Context, tx query.TxActor, identity NewEmailIdentity, identityID string) error {
	return tx.Exec(ctx, `
		DECLARE $namespace AS Utf8;
		DECLARE $linkage_scope AS Utf8;
		DECLARE $scope_key AS Utf8;
		DECLARE $index_version AS Uint64;
		DECLARE $blind_index AS Bytes;
		DECLARE $identity_id AS Utf8;
		DECLARE $now AS Timestamp;
		INSERT INTO email_blind_indexes (
			identity_namespace, linkage_scope, scope_key, blind_index_version,
			email_blind_index, identity_id, created_at
		) VALUES ($namespace, $linkage_scope, $scope_key, $index_version, $blind_index, $identity_id, $now);`,
		query.WithParameters(ydb.ParamsBuilder().
			Param("$namespace").Text(identity.Namespace).
			Param("$linkage_scope").Text(identity.LinkageScope).
			Param("$scope_key").Text(identity.ScopeKey).
			Param("$index_version").Uint64(uint64(identity.BlindIndexVersion)).
			Param("$blind_index").Bytes(identity.BlindIndex).
			Param("$identity_id").Text(identityID).
			Param("$now").Timestamp(time.Now().UTC()).
			Build()))
}

func findAccountByPerson(ctx context.Context, executor query.Executor, personID string) (string, error) {
	row, err := executor.QueryRow(ctx, `
		DECLARE $person_id AS Utf8;
		SELECT account_id FROM accounts_by_person WHERE person_id = $person_id;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$person_id").Text(personID).Build()))
	if err != nil {
		return "", err
	}
	var id string
	return id, row.Scan(&id)
}

func insertAccount(ctx context.Context, tx query.TxActor, id, personID string, now time.Time) error {
	if id == "" {
		return errors.New("account ID is required")
	}
	return tx.Exec(ctx, `
		DECLARE $id AS Utf8;
		DECLARE $person_id AS Utf8;
		DECLARE $now AS Timestamp;
		INSERT INTO accounts (id, person_id, status, created_at, version)
		VALUES ($id, $person_id, "active", $now, 1u);
		INSERT INTO accounts_by_person (person_id, account_id) VALUES ($person_id, $id);`,
		query.WithParameters(ydb.ParamsBuilder().
			Param("$id").Text(id).
			Param("$person_id").Text(personID).
			Param("$now").Timestamp(now).
			Build()))
}

func linkInstallation(ctx context.Context, tx query.TxActor, installationID, productID, personID string, now time.Time) error {
	row, err := tx.QueryRow(ctx, `
		DECLARE $id AS Utf8;
		SELECT product_id, person_id, disabled_at, version
		FROM product_installations WHERE id = $id;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(installationID).Build()))
	if err != nil {
		return noRows(err)
	}
	var storedProduct string
	var storedPerson *string
	var disabledAt *time.Time
	var version uint64
	if err := row.Scan(&storedProduct, &storedPerson, &disabledAt, &version); err != nil {
		return err
	}
	if storedProduct != productID || disabledAt != nil || (storedPerson != nil && *storedPerson != personID) {
		return domain.ErrConflict
	}
	updated, err := tx.QueryRow(ctx, `
		DECLARE $id AS Utf8;
		DECLARE $person_id AS Utf8;
		DECLARE $now AS Timestamp;
		DECLARE $version AS Uint64;
		UPDATE product_installations
		SET person_id = $person_id, last_seen_at = $now, version = version + 1u
		WHERE id = $id AND version = $version
		RETURNING version;`, query.WithParameters(ydb.ParamsBuilder().
		Param("$id").Text(installationID).
		Param("$person_id").Text(personID).
		Param("$now").Timestamp(now).
		Param("$version").Uint64(version).
		Build()))
	if err != nil {
		return optimistic(err)
	}
	var nextVersion uint64
	if err := updated.Scan(&nextVersion); err != nil || nextVersion != version+1 {
		return domain.ErrConflict
	}
	return tx.Exec(ctx, `
		DECLARE $installation_id AS Utf8;
		DECLARE $person_id AS Utf8;
		UPDATE subject_aliases SET person_id = $person_id
		WHERE subject_type = "installation" AND subject_id = $installation_id;`,
		query.WithParameters(ydb.ParamsBuilder().
			Param("$installation_id").Text(installationID).
			Param("$person_id").Text(personID).
			Build()))
}

func optimistic(err error) error {
	if errors.Is(err, query.ErrNoRows) {
		return domain.ErrConflict
	}
	return err
}

func (s *Store) ValidateBlindIndexVersions(ctx context.Context, configured map[int][]byte) error {
	for _, statement := range []string{
		`SELECT blind_index_version FROM email_blind_indexes;`,
		`SELECT blind_index_version FROM email_verifications;`,
	} {
		rows, err := s.client.QueryResultSet(ctx, statement, query.WithTxControl(query.SnapshotReadOnlyTxControl()))
		if err != nil {
			return err
		}
		for row, rowErr := range rows.Rows(ctx) {
			if rowErr != nil {
				_ = rows.Close(ctx)
				return rowErr
			}
			var version uint64
			if err := row.Scan(&version); err != nil {
				_ = rows.Close(ctx)
				return err
			}
			if _, ok := configured[int(version)]; !ok {
				_ = rows.Close(ctx)
				return fmt.Errorf("blind-index key version %d is still referenced by persisted rows", version)
			}
		}
		_ = rows.Close(ctx)
	}
	return nil
}

func (s *Store) ValidateEnvelopeKeyIDs(ctx context.Context, configured map[string]struct{}) error {
	for _, statement := range []string{
		`SELECT key_id FROM email_identities;`,
		`SELECT key_id FROM email_verifications;`,
	} {
		rows, err := s.client.QueryResultSet(ctx, statement, query.WithTxControl(query.SnapshotReadOnlyTxControl()))
		if err != nil {
			return err
		}
		for row, rowErr := range rows.Rows(ctx) {
			if rowErr != nil {
				_ = rows.Close(ctx)
				return rowErr
			}
			var keyID string
			if err := row.Scan(&keyID); err != nil {
				_ = rows.Close(ctx)
				return err
			}
			if _, ok := configured[keyID]; !ok {
				_ = rows.Close(ctx)
				return fmt.Errorf("envelope key alias %q is still referenced by persisted rows", keyID)
			}
		}
		_ = rows.Close(ctx)
	}
	return nil
}
