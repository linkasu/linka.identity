package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/linka-cloud/linka.identity/internal/domain"
)

type Installation struct {
	ID        string    `json:"id"`
	ProductID string    `json:"product_id"`
	Platform  string    `json:"platform"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) CreateInstallation(ctx context.Context, installation Installation) (Installation, bool, error) {
	var result Installation
	err := s.pool.QueryRow(ctx, `
		INSERT INTO product_installations (id, product_id, platform)
		VALUES ($1, $2, $3)
		ON CONFLICT (id) DO NOTHING
		RETURNING id::text, product_id, platform, created_at`,
		installation.ID, installation.ProductID, installation.Platform).
		Scan(&result.ID, &result.ProductID, &result.Platform, &result.CreatedAt)
	if err == nil {
		return result, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Installation{}, false, err
	}
	err = s.pool.QueryRow(ctx, `
		UPDATE product_installations SET last_seen_at = now()
		WHERE id = $1 AND product_id = $2 AND platform = $3
		RETURNING id::text, product_id, platform, created_at`,
		installation.ID, installation.ProductID, installation.Platform).
		Scan(&result.ID, &result.ProductID, &result.Platform, &result.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Installation{}, false, domain.ErrConflict
	}
	return result, false, err
}

func (s *Store) ResolveTokenSubject(ctx context.Context, productID, subjectType, subjectID string) error {
	var exists bool
	var err error
	switch subjectType {
	case "installation":
		err = s.pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM product_installations
				WHERE id = $1 AND product_id = $2 AND disabled_at IS NULL
			)`, subjectID, productID).Scan(&exists)
	case "account":
		err = s.pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1
				FROM accounts account
				JOIN email_identities identity ON identity.person_id = account.person_id
				WHERE account.id = $1 AND account.status = 'active'
				  AND identity.identity_namespace = 'account'
				  AND identity.verified_at IS NOT NULL
				  AND (identity.product_id = $2 OR identity.linkage_scope = 'global')
			)`, subjectID, productID).Scan(&exists)
	default:
		return pgx.ErrNoRows
	}
	if err != nil {
		return err
	}
	if !exists {
		return pgx.ErrNoRows
	}
	return nil
}
