package store

import (
	"context"
	"errors"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

type Installation struct {
	ID        string    `json:"id"`
	ProductID string    `json:"product_id"`
	Platform  string    `json:"platform"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) CreateInstallation(ctx context.Context, installation Installation) (Installation, bool, error) {
	var result Installation
	var created bool
	err := s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		created = false
		row, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			SELECT product_id, platform, created_at, disabled_at, version
			FROM product_installations WHERE id = $id;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(installation.ID).Build()))
		if err == nil {
			var disabledAt *time.Time
			var version uint64
			result.ID = installation.ID
			if err := row.Scan(&result.ProductID, &result.Platform, &result.CreatedAt, &disabledAt, &version); err != nil {
				return err
			}
			if disabledAt != nil || result.ProductID != installation.ProductID || result.Platform != installation.Platform {
				return domain.ErrConflict
			}
			updated, err := tx.QueryRow(ctx, `
				DECLARE $id AS Utf8;
				DECLARE $version AS Uint64;
				DECLARE $now AS Timestamp;
				UPDATE product_installations SET last_seen_at = $now, version = version + 1u
				WHERE id = $id AND version = $version RETURNING version;`,
				query.WithParameters(ydb.ParamsBuilder().
					Param("$id").Text(installation.ID).
					Param("$version").Uint64(version).
					Param("$now").Timestamp(s.now().UTC()).
					Build()))
			if err != nil {
				return optimistic(err)
			}
			var next uint64
			if err := updated.Scan(&next); err != nil || next != version+1 {
				return domain.ErrConflict
			}
			return nil
		}
		if !errors.Is(err, query.ErrNoRows) {
			return err
		}
		now := s.now().UTC()
		if err := tx.Exec(ctx, `
			DECLARE $id AS Utf8;
			DECLARE $product_id AS Utf8;
			DECLARE $platform AS Utf8;
			DECLARE $now AS Timestamp;
			INSERT INTO product_installations (
				id, product_id, platform, created_at, last_seen_at, version
			) VALUES ($id, $product_id, $platform, $now, $now, 1u);`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$id").Text(installation.ID).
				Param("$product_id").Text(installation.ProductID).
				Param("$platform").Text(installation.Platform).
				Param("$now").Timestamp(now).
				Build())); err != nil {
			return err
		}
		result = installation
		result.CreatedAt = now
		created = true
		return nil
	})
	return result, created, err
}

func (s *Store) ResolveTokenSubject(ctx context.Context, productID, subjectType, subjectID string) error {
	switch subjectType {
	case "installation":
		row, err := s.client.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			SELECT product_id, disabled_at FROM product_installations WHERE id = $id;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(subjectID).Build()),
			query.WithTxControl(query.SnapshotReadOnlyTxControl()))
		if err != nil {
			return noRows(err)
		}
		var storedProduct string
		var disabledAt *time.Time
		if err := row.Scan(&storedProduct, &disabledAt); err != nil {
			return err
		}
		if storedProduct != productID || disabledAt != nil {
			return domain.ErrNotFound
		}
		return nil
	case "account":
		row, err := s.client.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			SELECT person_id, status FROM accounts WHERE id = $id;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(subjectID).Build()),
			query.WithTxControl(query.SnapshotReadOnlyTxControl()))
		if err != nil {
			return noRows(err)
		}
		var personID, status string
		if err := row.Scan(&personID, &status); err != nil {
			return err
		}
		if status != "active" {
			return domain.ErrNotFound
		}
		rows, err := s.client.QueryResultSet(ctx, `
			DECLARE $person_id AS Utf8;
			SELECT product_id, linkage_scope FROM email_identities
			WHERE person_id = $person_id AND identity_namespace = "account";`,
			query.WithParameters(ydb.ParamsBuilder().Param("$person_id").Text(personID).Build()),
			query.WithTxControl(query.SnapshotReadOnlyTxControl()))
		if err != nil {
			return err
		}
		defer rows.Close(ctx)
		for result, rowErr := range rows.Rows(ctx) {
			if rowErr != nil {
				return rowErr
			}
			var identityProduct, scope string
			if err := result.Scan(&identityProduct, &scope); err != nil {
				return err
			}
			if identityProduct == productID || scope == "global" {
				return nil
			}
		}
		return domain.ErrNotFound
	default:
		return domain.ErrNotFound
	}
}
