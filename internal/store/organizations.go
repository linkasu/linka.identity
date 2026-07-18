package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/linka-cloud/linka.identity/internal/ids"
)

type OrganizationSubmission struct {
	ID             string
	PersonID       *string
	InstallationID *string
	ProductID      string
	SubmittedName  string
}

type Membership struct {
	ID             string
	PersonID       string
	OrganizationID string
	ProductID      string
	RoleLabel      *string
	Status         string
	StartedAt      *time.Time
	EndedAt        *time.Time
}

func (s *Store) CreateOrganizationSubmission(ctx context.Context, submission OrganizationSubmission) error {
	if submission.InstallationID != nil {
		var exists bool
		if err := s.pool.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM product_installations WHERE id = $1 AND product_id = $2 AND disabled_at IS NULL)`,
			*submission.InstallationID, submission.ProductID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return pgx.ErrNoRows
		}
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO organization_submissions (
			id, person_id, installation_id, product_id, submitted_name, status
		) VALUES ($1, $2, $3, $4, $5, 'pending')`,
		submission.ID, submission.PersonID, submission.InstallationID,
		submission.ProductID, submission.SubmittedName)
	return err
}

func (s *Store) CreateOrganization(ctx context.Context, id, canonicalName string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO organizations (id, canonical_name, status) VALUES ($1, $2, 'active')`, id, canonicalName)
	return err
}

func (s *Store) ResolveOrganizationSubmission(ctx context.Context, id, status string, organizationID *string, actor, note string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE organization_submissions
		SET status = $2, canonical_organization_id = $3, reviewed_at = now(),
		    reviewed_by = $4, audit_note = $5
		WHERE id = $1 AND status = 'pending'`, id, status, organizationID, actor, note)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	return nil
}

func (s *Store) MergeOrganization(ctx context.Context, sourceID, targetID, actor, reason string) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `
		UPDATE organizations source
		SET status = 'merged', merged_into_id = $2, updated_at = now()
		WHERE source.id = $1 AND source.status = 'active'
		  AND EXISTS (SELECT 1 FROM organizations target WHERE target.id = $2 AND target.status = 'active')`,
		sourceID, targetID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	auditID, err := ids.NewUUID()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO organization_merge_audit (
			id, source_organization_id, target_organization_id, actor, reason
		) VALUES ($1, $2, $3, $4, $5)`, auditID, sourceID, targetID, actor, reason); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE organization_submissions
		SET canonical_organization_id = $2, status = 'merged'
		WHERE canonical_organization_id = $1`, sourceID, targetID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE memberships SET organization_id = $2
		WHERE organization_id = $1
		  AND NOT EXISTS (
			SELECT 1 FROM memberships existing
			WHERE existing.person_id = memberships.person_id
			  AND existing.organization_id = $2
			  AND existing.product_id = memberships.product_id
		  )`, sourceID, targetID); err != nil {
		return fmt.Errorf("move memberships: %w", err)
	}
	if _, err := tx.Exec(ctx, "DELETE FROM memberships WHERE organization_id = $1", sourceID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) CreateMembership(ctx context.Context, membership Membership) error {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO memberships (
			id, person_id, organization_id, product_id, role_label, status, started_at, ended_at
		)
		SELECT $1, $2, organization.id, $4, $5, $6, $7, $8
		FROM organizations organization
		WHERE organization.id = $3 AND organization.status = 'active'
		ON CONFLICT (person_id, organization_id, product_id) DO UPDATE
		SET role_label = EXCLUDED.role_label, status = EXCLUDED.status,
		    started_at = EXCLUDED.started_at, ended_at = EXCLUDED.ended_at`,
		membership.ID, membership.PersonID, membership.OrganizationID, membership.ProductID,
		membership.RoleLabel, membership.Status, membership.StartedAt, membership.EndedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}
