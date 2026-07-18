package store

import (
	"context"
	"errors"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

type ResolvedAlias struct {
	OpaqueKey   string
	SubjectType string
	SubjectID   string
	PersonID    string
	ProductID   string
	Audience    string
}

func (s *Store) EnsureSubjectAlias(ctx context.Context, opaqueKey, productID, audience, subjectType, subjectID string) error {
	return s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		personID, err := aliasPersonID(ctx, tx, subjectType, subjectID)
		if err != nil {
			return err
		}
		row, err := tx.QueryRow(ctx, `
			DECLARE $opaque_key AS Utf8;
			SELECT product_id, audience, subject_type, subject_id
			FROM subject_aliases WHERE opaque_key = $opaque_key;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$opaque_key").Text(opaqueKey).Build()))
		if err == nil {
			var storedProduct, storedAudience, storedType, storedID string
			if err := row.Scan(&storedProduct, &storedAudience, &storedType, &storedID); err != nil {
				return err
			}
			if storedProduct != productID || storedAudience != audience || storedType != subjectType || storedID != subjectID {
				return domain.ErrConflict
			}
			return nil
		}
		if !errors.Is(err, query.ErrNoRows) {
			return err
		}
		keyRow, err := tx.QueryRow(ctx, `
			DECLARE $product_id AS Utf8;
			DECLARE $audience AS Utf8;
			DECLARE $subject_type AS Utf8;
			DECLARE $subject_id AS Utf8;
			SELECT opaque_key FROM subject_alias_keys
			WHERE product_id = $product_id AND audience = $audience
			  AND subject_type = $subject_type AND subject_id = $subject_id;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$product_id").Text(productID).
				Param("$audience").Text(audience).
				Param("$subject_type").Text(subjectType).
				Param("$subject_id").Text(subjectID).
				Build()))
		if err == nil {
			var storedKey string
			if err := keyRow.Scan(&storedKey); err != nil {
				return err
			}
			if storedKey != opaqueKey {
				return domain.ErrConflict
			}
			return nil
		}
		if !errors.Is(err, query.ErrNoRows) {
			return err
		}
		return tx.Exec(ctx, `
			DECLARE $opaque_key AS Utf8;
			DECLARE $product_id AS Utf8;
			DECLARE $audience AS Utf8;
			DECLARE $subject_type AS Utf8;
			DECLARE $subject_id AS Utf8;
			DECLARE $person_id AS Utf8?;
			DECLARE $now AS Timestamp;
			INSERT INTO subject_aliases (
				opaque_key, product_id, audience, subject_type, subject_id, person_id, created_at
			) VALUES ($opaque_key, $product_id, $audience, $subject_type, $subject_id, $person_id, $now);
			INSERT INTO subject_alias_keys (
				product_id, audience, subject_type, subject_id, opaque_key
			) VALUES ($product_id, $audience, $subject_type, $subject_id, $opaque_key);`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$opaque_key").Text(opaqueKey).
				Param("$product_id").Text(productID).
				Param("$audience").Text(audience).
				Param("$subject_type").Text(subjectType).
				Param("$subject_id").Text(subjectID).
				Param("$person_id").Any(nullableText(personID)).
				Param("$now").Timestamp(s.now().UTC()).
				Build()))
	})
}

func aliasPersonID(ctx context.Context, executor query.Executor, subjectType, subjectID string) (*string, error) {
	switch subjectType {
	case "person":
		if err := validateSubjectWith(ctx, executor, Subject{Kind: "person", ID: subjectID}, ""); err != nil {
			return nil, err
		}
		return &subjectID, nil
	case "account":
		row, err := executor.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			SELECT person_id, status FROM accounts WHERE id = $id;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(subjectID).Build()))
		if err != nil {
			return nil, noRows(err)
		}
		var personID, status string
		if err := row.Scan(&personID, &status); err != nil {
			return nil, err
		}
		if status != "active" {
			return nil, domain.ErrNotFound
		}
		return &personID, nil
	case "installation":
		row, err := executor.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			SELECT person_id, disabled_at FROM product_installations WHERE id = $id;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(subjectID).Build()))
		if err != nil {
			return nil, noRows(err)
		}
		var personID *string
		var disabledAt *time.Time
		if err := row.Scan(&personID, &disabledAt); err != nil {
			return nil, err
		}
		if disabledAt != nil {
			return nil, domain.ErrNotFound
		}
		return personID, nil
	default:
		return nil, domain.ErrNotFound
	}
}

func (s *Store) ResolveSubjectAlias(ctx context.Context, opaqueKey, productID, audience string) (ResolvedAlias, error) {
	row, err := s.client.QueryRow(ctx, `
		DECLARE $opaque_key AS Utf8;
		SELECT product_id, audience, subject_type, subject_id, person_id
		FROM subject_aliases WHERE opaque_key = $opaque_key;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$opaque_key").Text(opaqueKey).Build()),
		query.WithTxControl(query.SnapshotReadOnlyTxControl()))
	if err != nil {
		return ResolvedAlias{}, noRows(err)
	}
	result := ResolvedAlias{OpaqueKey: opaqueKey}
	var personID *string
	if err := row.Scan(&result.ProductID, &result.Audience, &result.SubjectType, &result.SubjectID, &personID); err != nil {
		return ResolvedAlias{}, err
	}
	if result.ProductID != productID || result.Audience != audience {
		return ResolvedAlias{}, domain.ErrNotFound
	}
	if personID != nil {
		result.PersonID = *personID
	}
	if _, err := aliasPersonID(ctx, s.client, result.SubjectType, result.SubjectID); err != nil {
		return ResolvedAlias{}, err
	}
	return result, nil
}

func (s *Store) PrivacyFanoutAliases(ctx context.Context, personID string, productID *string) ([]ResolvedAlias, error) {
	return privacyFanoutAliases(ctx, s.client, personID, productID)
}

func privacyFanoutAliases(ctx context.Context, executor query.Executor, personID string, productID *string) ([]ResolvedAlias, error) {
	statement := `
		DECLARE $person_id AS Utf8;
		SELECT opaque_key, subject_type, subject_id, product_id, audience
		FROM subject_aliases WHERE person_id = $person_id
		ORDER BY product_id, subject_type, opaque_key;`
	parameters := ydb.ParamsBuilder().Param("$person_id").Text(personID).Build()
	if productID != nil {
		statement = `
			DECLARE $person_id AS Utf8;
			DECLARE $product_id AS Utf8;
			SELECT opaque_key, subject_type, subject_id, product_id, audience
			FROM subject_aliases WHERE person_id = $person_id AND product_id = $product_id
			ORDER BY subject_type, opaque_key;`
		parameters = ydb.ParamsBuilder().
			Param("$person_id").Text(personID).
			Param("$product_id").Text(*productID).
			Build()
	}
	rows, err := executor.QueryResultSet(ctx, statement, query.WithParameters(parameters))
	if err != nil {
		return nil, err
	}
	defer rows.Close(ctx)
	var result []ResolvedAlias
	for row, rowErr := range rows.Rows(ctx) {
		if rowErr != nil {
			return nil, rowErr
		}
		var alias ResolvedAlias
		alias.PersonID = personID
		if err := row.Scan(&alias.OpaqueKey, &alias.SubjectType, &alias.SubjectID, &alias.ProductID, &alias.Audience); err != nil {
			return nil, err
		}
		result = append(result, alias)
	}
	if len(result) == 0 {
		return nil, errors.New("privacy request has no product aliases")
	}
	return result, nil
}
