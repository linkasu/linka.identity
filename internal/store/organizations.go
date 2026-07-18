package store

import (
	"context"
	"errors"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/ids"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
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
	return s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		if submission.InstallationID != nil {
			if err := validateSubjectWith(ctx, tx, Subject{Kind: "installation", ID: *submission.InstallationID}, submission.ProductID); err != nil {
				return err
			}
		} else if submission.PersonID != nil {
			if err := validateSubjectWith(ctx, tx, Subject{Kind: "person", ID: *submission.PersonID}, submission.ProductID); err != nil {
				return err
			}
		}
		return tx.Exec(ctx, `
			DECLARE $id AS Utf8;
			DECLARE $person_id AS Utf8?;
			DECLARE $installation_id AS Utf8?;
			DECLARE $product_id AS Utf8;
			DECLARE $submitted_name AS Utf8;
			DECLARE $now AS Timestamp;
			INSERT INTO organization_submissions (
				id, person_id, installation_id, product_id, submitted_name,
				status, submitted_at, version
			) VALUES ($id, $person_id, $installation_id, $product_id, $submitted_name, "pending", $now, 1u);`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$id").Text(submission.ID).
				Param("$person_id").Any(nullableText(submission.PersonID)).
				Param("$installation_id").Any(nullableText(submission.InstallationID)).
				Param("$product_id").Text(submission.ProductID).
				Param("$submitted_name").Text(submission.SubmittedName).
				Param("$now").Timestamp(s.now().UTC()).
				Build()))
	})
}

func (s *Store) CreateOrganization(ctx context.Context, id, canonicalName string) error {
	now := s.now().UTC()
	return s.client.Exec(ctx, `
		DECLARE $id AS Utf8;
		DECLARE $canonical_name AS Utf8;
		DECLARE $now AS Timestamp;
		INSERT INTO organizations (
			id, canonical_name, status, created_at, updated_at, version
		) VALUES ($id, $canonical_name, "active", $now, $now, 1u);`,
		query.WithParameters(ydb.ParamsBuilder().
			Param("$id").Text(id).
			Param("$canonical_name").Text(canonicalName).
			Param("$now").Timestamp(now).
			Build()),
		query.WithTxControl(query.SerializableReadWriteTxControl(query.CommitTx())))
}

func (s *Store) ResolveOrganizationSubmission(ctx context.Context, id, status string, organizationID *string, actor, note string) error {
	return s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		row, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			SELECT status, version FROM organization_submissions WHERE id = $id;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(id).Build()))
		if err != nil {
			return noRows(err)
		}
		var current string
		var version uint64
		if err := row.Scan(&current, &version); err != nil {
			return err
		}
		if current != "pending" {
			return domain.ErrNotFound
		}
		if organizationID != nil {
			if err := activeOrganization(ctx, tx, *organizationID); err != nil {
				return err
			}
		}
		updated, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			DECLARE $status AS Utf8;
			DECLARE $organization_id AS Utf8?;
			DECLARE $actor AS Utf8;
			DECLARE $note AS Utf8;
			DECLARE $now AS Timestamp;
			DECLARE $version AS Uint64;
			UPDATE organization_submissions
			SET status = $status, canonical_organization_id = $organization_id,
			    reviewed_at = $now, reviewed_by = $actor, audit_note = $note,
			    version = version + 1u
			WHERE id = $id AND version = $version RETURNING version;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$id").Text(id).
				Param("$status").Text(status).
				Param("$organization_id").Any(nullableText(organizationID)).
				Param("$actor").Text(actor).
				Param("$note").Text(note).
				Param("$now").Timestamp(s.now().UTC()).
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

func (s *Store) MergeOrganization(ctx context.Context, sourceID, targetID, actor, reason string) error {
	auditID, err := ids.NewUUID()
	if err != nil {
		return err
	}
	return s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		if sourceID == targetID {
			return domain.ErrInvalid
		}
		if err := activeOrganization(ctx, tx, targetID); err != nil {
			return err
		}
		row, err := tx.QueryRow(ctx, `
			DECLARE $id AS Utf8;
			SELECT status, version FROM organizations WHERE id = $id;`,
			query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(sourceID).Build()))
		if err != nil {
			return noRows(err)
		}
		var sourceStatus string
		var version uint64
		if err := row.Scan(&sourceStatus, &version); err != nil {
			return err
		}
		if sourceStatus != "active" {
			return domain.ErrNotFound
		}
		now := s.now().UTC()
		updated, err := tx.QueryRow(ctx, `
			DECLARE $source_id AS Utf8;
			DECLARE $target_id AS Utf8;
			DECLARE $now AS Timestamp;
			DECLARE $version AS Uint64;
			UPDATE organizations
			SET status = "merged", merged_into_id = $target_id, updated_at = $now, version = version + 1u
			WHERE id = $source_id AND version = $version RETURNING version;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$source_id").Text(sourceID).
				Param("$target_id").Text(targetID).
				Param("$now").Timestamp(now).
				Param("$version").Uint64(version).
				Build()))
		if err != nil {
			return optimistic(err)
		}
		var next uint64
		if err := updated.Scan(&next); err != nil || next != version+1 {
			return domain.ErrConflict
		}
		if err := tx.Exec(ctx, `
			DECLARE $id AS Utf8;
			DECLARE $source_id AS Utf8;
			DECLARE $target_id AS Utf8;
			DECLARE $actor AS Utf8;
			DECLARE $reason AS Utf8;
			DECLARE $now AS Timestamp;
			INSERT INTO organization_merge_audit (
				id, source_organization_id, target_organization_id, actor, reason, merged_at
			) VALUES ($id, $source_id, $target_id, $actor, $reason, $now);
			UPDATE organization_submissions
			SET canonical_organization_id = $target_id, status = "merged", version = version + 1u
			WHERE canonical_organization_id = $source_id;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$id").Text(auditID).
				Param("$source_id").Text(sourceID).
				Param("$target_id").Text(targetID).
				Param("$actor").Text(actor).
				Param("$reason").Text(reason).
				Param("$now").Timestamp(now).
				Build())); err != nil {
			return err
		}
		return moveMemberships(ctx, tx, sourceID, targetID)
	})
}

func moveMemberships(ctx context.Context, tx query.TxActor, sourceID, targetID string) error {
	rows, err := tx.QueryResultSet(ctx, `
		DECLARE $organization_id AS Utf8;
		SELECT person_id, product_id, id, role_label, status, started_at, ended_at, created_at
		FROM memberships WHERE organization_id = $organization_id;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$organization_id").Text(sourceID).Build()))
	if err != nil {
		return err
	}
	defer rows.Close(ctx)
	for row, rowErr := range rows.Rows(ctx) {
		if rowErr != nil {
			return rowErr
		}
		var membership Membership
		var createdAt time.Time
		if err := row.Scan(&membership.PersonID, &membership.ProductID, &membership.ID, &membership.RoleLabel,
			&membership.Status, &membership.StartedAt, &membership.EndedAt, &createdAt); err != nil {
			return err
		}
		existing, err := tx.QueryRow(ctx, `
			DECLARE $person_id AS Utf8;
			DECLARE $organization_id AS Utf8;
			DECLARE $product_id AS Utf8;
			SELECT id FROM memberships
			WHERE person_id = $person_id AND organization_id = $organization_id AND product_id = $product_id;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$person_id").Text(membership.PersonID).
				Param("$organization_id").Text(targetID).
				Param("$product_id").Text(membership.ProductID).
				Build()))
		if errors.Is(err, query.ErrNoRows) {
			if err := tx.Exec(ctx, `
				DECLARE $person_id AS Utf8;
				DECLARE $target_id AS Utf8;
				DECLARE $product_id AS Utf8;
				DECLARE $id AS Utf8;
				DECLARE $role_label AS Utf8?;
				DECLARE $status AS Utf8;
				DECLARE $started_at AS Timestamp?;
				DECLARE $ended_at AS Timestamp?;
				DECLARE $created_at AS Timestamp;
				INSERT INTO memberships (
					person_id, organization_id, product_id, id, role_label, status,
					started_at, ended_at, created_at, version
				) VALUES (
					$person_id, $target_id, $product_id, $id, $role_label, $status,
					$started_at, $ended_at, $created_at, 1u
				);`,
				query.WithParameters(ydb.ParamsBuilder().
					Param("$person_id").Text(membership.PersonID).
					Param("$target_id").Text(targetID).
					Param("$product_id").Text(membership.ProductID).
					Param("$id").Text(membership.ID).
					Param("$role_label").Any(nullableText(membership.RoleLabel)).
					Param("$status").Text(membership.Status).
					Param("$started_at").Any(nullableTimestamp(membership.StartedAt)).
					Param("$ended_at").Any(nullableTimestamp(membership.EndedAt)).
					Param("$created_at").Timestamp(createdAt).
					Build())); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else {
			var ignored string
			if err := existing.Scan(&ignored); err != nil {
				return err
			}
		}
		if err := tx.Exec(ctx, `
			DECLARE $person_id AS Utf8;
			DECLARE $organization_id AS Utf8;
			DECLARE $product_id AS Utf8;
			DELETE FROM memberships
			WHERE person_id = $person_id AND organization_id = $organization_id AND product_id = $product_id;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$person_id").Text(membership.PersonID).
				Param("$organization_id").Text(sourceID).
				Param("$product_id").Text(membership.ProductID).
				Build())); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) CreateMembership(ctx context.Context, membership Membership) error {
	return s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		if err := activeOrganization(ctx, tx, membership.OrganizationID); err != nil {
			return err
		}
		if err := validateSubjectWith(ctx, tx, Subject{Kind: "person", ID: membership.PersonID}, membership.ProductID); err != nil {
			return err
		}
		row, err := tx.QueryRow(ctx, `
			DECLARE $person_id AS Utf8;
			DECLARE $organization_id AS Utf8;
			DECLARE $product_id AS Utf8;
			SELECT version FROM memberships
			WHERE person_id = $person_id AND organization_id = $organization_id AND product_id = $product_id;`,
			query.WithParameters(ydb.ParamsBuilder().
				Param("$person_id").Text(membership.PersonID).
				Param("$organization_id").Text(membership.OrganizationID).
				Param("$product_id").Text(membership.ProductID).
				Build()))
		if err == nil {
			var version uint64
			if err := row.Scan(&version); err != nil {
				return err
			}
			updated, err := tx.QueryRow(ctx, `
				DECLARE $person_id AS Utf8;
				DECLARE $organization_id AS Utf8;
				DECLARE $product_id AS Utf8;
				DECLARE $role_label AS Utf8?;
				DECLARE $status AS Utf8;
				DECLARE $started_at AS Timestamp?;
				DECLARE $ended_at AS Timestamp?;
				DECLARE $version AS Uint64;
				UPDATE memberships
				SET role_label = $role_label, status = $status, started_at = $started_at,
				    ended_at = $ended_at, version = version + 1u
				WHERE person_id = $person_id AND organization_id = $organization_id
				  AND product_id = $product_id AND version = $version
				RETURNING version;`, query.WithParameters(ydb.ParamsBuilder().
				Param("$person_id").Text(membership.PersonID).
				Param("$organization_id").Text(membership.OrganizationID).
				Param("$product_id").Text(membership.ProductID).
				Param("$role_label").Any(nullableText(membership.RoleLabel)).
				Param("$status").Text(membership.Status).
				Param("$started_at").Any(nullableTimestamp(membership.StartedAt)).
				Param("$ended_at").Any(nullableTimestamp(membership.EndedAt)).
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
		}
		if !errors.Is(err, query.ErrNoRows) {
			return err
		}
		return tx.Exec(ctx, `
			DECLARE $person_id AS Utf8;
			DECLARE $organization_id AS Utf8;
			DECLARE $product_id AS Utf8;
			DECLARE $id AS Utf8;
			DECLARE $role_label AS Utf8?;
			DECLARE $status AS Utf8;
			DECLARE $started_at AS Timestamp?;
			DECLARE $ended_at AS Timestamp?;
			DECLARE $now AS Timestamp;
			INSERT INTO memberships (
				person_id, organization_id, product_id, id, role_label, status,
				started_at, ended_at, created_at, version
			) VALUES (
				$person_id, $organization_id, $product_id, $id, $role_label, $status,
				$started_at, $ended_at, $now, 1u
			);`, query.WithParameters(ydb.ParamsBuilder().
			Param("$person_id").Text(membership.PersonID).
			Param("$organization_id").Text(membership.OrganizationID).
			Param("$product_id").Text(membership.ProductID).
			Param("$id").Text(membership.ID).
			Param("$role_label").Any(nullableText(membership.RoleLabel)).
			Param("$status").Text(membership.Status).
			Param("$started_at").Any(nullableTimestamp(membership.StartedAt)).
			Param("$ended_at").Any(nullableTimestamp(membership.EndedAt)).
			Param("$now").Timestamp(s.now().UTC()).
			Build()))
	})
}

func activeOrganization(ctx context.Context, executor query.Executor, id string) error {
	row, err := executor.QueryRow(ctx, `
		DECLARE $id AS Utf8;
		SELECT status FROM organizations WHERE id = $id;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$id").Text(id).Build()))
	if err != nil {
		return noRows(err)
	}
	var status string
	if err := row.Scan(&status); err != nil {
		return err
	}
	if status != "active" {
		return domain.ErrNotFound
	}
	return nil
}
