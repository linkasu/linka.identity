package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
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
	_, err := s.pool.Exec(ctx, `
		INSERT INTO subject_aliases (opaque_key, product_id, audience, subject_type, subject_id)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (product_id, audience, subject_type, subject_id) DO UPDATE
		SET opaque_key = EXCLUDED.opaque_key
		WHERE subject_aliases.opaque_key = EXCLUDED.opaque_key`, opaqueKey, productID, audience, subjectType, subjectID)
	return err
}

func (s *Store) ResolveSubjectAlias(ctx context.Context, opaqueKey, productID, audience string) (ResolvedAlias, error) {
	var result ResolvedAlias
	err := s.pool.QueryRow(ctx, `
		SELECT alias.opaque_key, alias.subject_type, alias.subject_id::text, alias.product_id, alias.audience,
		       CASE alias.subject_type
		           WHEN 'person' THEN alias.subject_id::text
		           WHEN 'account' THEN COALESCE(account.person_id::text, '')
		           WHEN 'installation' THEN COALESCE(installation.person_id::text, '')
		       END
		FROM subject_aliases alias
		LEFT JOIN accounts account ON alias.subject_type = 'account' AND account.id = alias.subject_id AND account.status = 'active'
		LEFT JOIN product_installations installation ON alias.subject_type = 'installation' AND installation.id = alias.subject_id AND installation.disabled_at IS NULL
		WHERE alias.opaque_key = $1 AND alias.product_id = $2 AND alias.audience = $3`,
		opaqueKey, productID, audience).Scan(&result.OpaqueKey, &result.SubjectType, &result.SubjectID, &result.ProductID, &result.Audience, &result.PersonID)
	if err != nil {
		return ResolvedAlias{}, err
	}
	if result.SubjectType == "account" && result.PersonID == "" {
		return ResolvedAlias{}, pgx.ErrNoRows
	}
	return result, nil
}

func (s *Store) PrivacyFanoutAliases(ctx context.Context, personID string, productID *string) ([]ResolvedAlias, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT alias.opaque_key, alias.subject_type, alias.subject_id::text, alias.product_id, alias.audience, $1::uuid::text
		FROM subject_aliases alias
		LEFT JOIN accounts account ON alias.subject_type = 'account' AND account.id = alias.subject_id
		LEFT JOIN product_installations installation ON alias.subject_type = 'installation' AND installation.id = alias.subject_id
		WHERE ($2::text IS NULL OR alias.product_id = $2)
		  AND ((alias.subject_type = 'person' AND alias.subject_id = $1) OR
		       (alias.subject_type = 'account' AND account.person_id = $1) OR
		       (alias.subject_type = 'installation' AND installation.person_id = $1))
		ORDER BY alias.product_id,
		         CASE alias.subject_type WHEN 'person' THEN 1 WHEN 'account' THEN 2 ELSE 3 END,
		         alias.opaque_key`,
		personID, productID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ResolvedAlias
	for rows.Next() {
		var alias ResolvedAlias
		if err := rows.Scan(&alias.OpaqueKey, &alias.SubjectType, &alias.SubjectID, &alias.ProductID, &alias.Audience, &alias.PersonID); err != nil {
			return nil, err
		}
		result = append(result, alias)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, errors.New("privacy request has no product aliases")
	}
	return result, nil
}
