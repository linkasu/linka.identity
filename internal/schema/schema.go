package schema

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

const Version = uint64(1)

var statements = []string{
	`CREATE TABLE IF NOT EXISTS schema_meta (
		name Utf8 NOT NULL,
		version Uint64 NOT NULL,
		applied_at Timestamp NOT NULL,
		PRIMARY KEY (name)
	)`,
	`CREATE TABLE IF NOT EXISTS persons (
		id Utf8 NOT NULL,
		age_category Utf8 NOT NULL,
		guardian_relationship Utf8,
		created_at Timestamp NOT NULL,
		deleted_at Timestamp,
		version Uint64 NOT NULL,
		PRIMARY KEY (id)
	)`,
	`CREATE TABLE IF NOT EXISTS email_identities (
		id Utf8 NOT NULL,
		person_id Utf8 NOT NULL,
		product_id Utf8 NOT NULL,
		identity_namespace Utf8 NOT NULL,
		linkage_scope Utf8 NOT NULL,
		scope_key Utf8 NOT NULL,
		encrypted_email Bytes NOT NULL,
		email_nonce Bytes NOT NULL,
		wrapped_data_key Bytes NOT NULL,
		key_id Utf8 NOT NULL,
		encryption_algorithm Utf8 NOT NULL,
		verified_at Timestamp NOT NULL,
		created_at Timestamp NOT NULL,
		version Uint64 NOT NULL,
		INDEX email_identities_person GLOBAL ON (person_id),
		PRIMARY KEY (id)
	)`,
	`CREATE TABLE IF NOT EXISTS email_blind_indexes (
		identity_namespace Utf8 NOT NULL,
		linkage_scope Utf8 NOT NULL,
		scope_key Utf8 NOT NULL,
		blind_index_version Uint64 NOT NULL,
		email_blind_index Bytes NOT NULL,
		identity_id Utf8 NOT NULL,
		created_at Timestamp NOT NULL,
		PRIMARY KEY (identity_namespace, linkage_scope, scope_key, blind_index_version, email_blind_index)
	)`,
	`CREATE TABLE IF NOT EXISTS accounts (
		id Utf8 NOT NULL,
		person_id Utf8 NOT NULL,
		status Utf8 NOT NULL,
		created_at Timestamp NOT NULL,
		last_authenticated_at Timestamp,
		version Uint64 NOT NULL,
		PRIMARY KEY (id)
	)`,
	`CREATE TABLE IF NOT EXISTS accounts_by_person (
		person_id Utf8 NOT NULL,
		account_id Utf8 NOT NULL,
		PRIMARY KEY (person_id)
	)`,
	`CREATE TABLE IF NOT EXISTS product_installations (
		id Utf8 NOT NULL,
		product_id Utf8 NOT NULL,
		platform Utf8 NOT NULL,
		person_id Utf8,
		created_at Timestamp NOT NULL,
		last_seen_at Timestamp NOT NULL,
		disabled_at Timestamp,
		version Uint64 NOT NULL,
		INDEX installations_person GLOBAL ON (person_id),
		PRIMARY KEY (id)
	)`,
	`CREATE TABLE IF NOT EXISTS subject_aliases (
		opaque_key Utf8 NOT NULL,
		product_id Utf8 NOT NULL,
		audience Utf8 NOT NULL,
		subject_type Utf8 NOT NULL,
		subject_id Utf8 NOT NULL,
		person_id Utf8,
		created_at Timestamp NOT NULL,
		INDEX aliases_person GLOBAL ON (person_id, product_id),
		PRIMARY KEY (opaque_key)
	)`,
	`CREATE TABLE IF NOT EXISTS subject_alias_keys (
		product_id Utf8 NOT NULL,
		audience Utf8 NOT NULL,
		subject_type Utf8 NOT NULL,
		subject_id Utf8 NOT NULL,
		opaque_key Utf8 NOT NULL,
		PRIMARY KEY (product_id, audience, subject_type, subject_id)
	)`,
	`CREATE TABLE IF NOT EXISTS organizations (
		id Utf8 NOT NULL,
		canonical_name Utf8 NOT NULL,
		status Utf8 NOT NULL,
		merged_into_id Utf8,
		created_at Timestamp NOT NULL,
		updated_at Timestamp NOT NULL,
		version Uint64 NOT NULL,
		PRIMARY KEY (id)
	)`,
	`CREATE TABLE IF NOT EXISTS organization_submissions (
		id Utf8 NOT NULL,
		person_id Utf8,
		installation_id Utf8,
		product_id Utf8 NOT NULL,
		submitted_name Utf8 NOT NULL,
		status Utf8 NOT NULL,
		canonical_organization_id Utf8,
		submitted_at Timestamp NOT NULL,
		reviewed_at Timestamp,
		reviewed_by Utf8,
		audit_note Utf8,
		version Uint64 NOT NULL,
		PRIMARY KEY (id)
	)`,
	`CREATE TABLE IF NOT EXISTS organization_merge_audit (
		id Utf8 NOT NULL,
		source_organization_id Utf8 NOT NULL,
		target_organization_id Utf8 NOT NULL,
		actor Utf8 NOT NULL,
		reason Utf8 NOT NULL,
		merged_at Timestamp NOT NULL,
		PRIMARY KEY (id)
	)`,
	`CREATE TABLE IF NOT EXISTS memberships (
		person_id Utf8 NOT NULL,
		organization_id Utf8 NOT NULL,
		product_id Utf8 NOT NULL,
		id Utf8 NOT NULL,
		role_label Utf8,
		status Utf8 NOT NULL,
		started_at Timestamp,
		ended_at Timestamp,
		created_at Timestamp NOT NULL,
		version Uint64 NOT NULL,
		PRIMARY KEY (person_id, organization_id, product_id)
	)`,
	`CREATE TABLE IF NOT EXISTS consents (
		id Utf8 NOT NULL,
		subject_type Utf8 NOT NULL,
		subject_id Utf8 NOT NULL,
		product_id Utf8 NOT NULL,
		consent_type Utf8 NOT NULL,
		policy_version Utf8 NOT NULL,
		status Utf8 NOT NULL,
		recorded_at Timestamp NOT NULL,
		created_at Timestamp NOT NULL,
		PRIMARY KEY (id)
	)`,
	`CREATE TABLE IF NOT EXISTS telemetry_preferences (
		subject_type Utf8 NOT NULL,
		subject_id Utf8 NOT NULL,
		product_id Utf8 NOT NULL,
		id Utf8 NOT NULL,
		preference Utf8 NOT NULL,
		recorded_at Timestamp NOT NULL,
		updated_at Timestamp NOT NULL,
		version Uint64 NOT NULL,
		PRIMARY KEY (subject_type, subject_id, product_id)
	)`,
	`CREATE TABLE IF NOT EXISTS privacy_requests (
		id Utf8 NOT NULL,
		subject_type Utf8 NOT NULL,
		subject_id Utf8 NOT NULL,
		request_type Utf8 NOT NULL,
		scope Utf8 NOT NULL,
		product_id Utf8,
		status Utf8 NOT NULL,
		requested_at Timestamp NOT NULL,
		completed_at Timestamp,
		requested_by_workload Utf8 NOT NULL,
		idempotency_key Utf8 NOT NULL,
		request_fingerprint Utf8 NOT NULL,
		created_at Timestamp NOT NULL,
		updated_at Timestamp NOT NULL,
		version Uint64 NOT NULL,
		PRIMARY KEY (id)
	)`,
	`CREATE TABLE IF NOT EXISTS privacy_idempotency (
		requested_by_workload Utf8 NOT NULL,
		idempotency_key Utf8 NOT NULL,
		request_id Utf8 NOT NULL,
		request_fingerprint Utf8 NOT NULL,
		PRIMARY KEY (requested_by_workload, idempotency_key)
	)`,
	`CREATE TABLE IF NOT EXISTS privacy_request_steps (
		id Utf8 NOT NULL,
		privacy_request_id Utf8 NOT NULL,
		step_type Utf8 NOT NULL,
		product_id Utf8,
		subject_key Utf8,
		status Utf8 NOT NULL,
		attempts Uint64 NOT NULL,
		available_at Timestamp NOT NULL,
		lease_until Timestamp,
		receipt Json,
		last_error Utf8,
		completed_at Timestamp,
		created_at Timestamp NOT NULL,
		updated_at Timestamp NOT NULL,
		version Uint64 NOT NULL,
		INDEX privacy_steps_request GLOBAL ON (privacy_request_id, step_type),
		INDEX privacy_steps_claim GLOBAL ON (step_type, status, available_at),
		PRIMARY KEY (id)
	)`,
	`CREATE TABLE IF NOT EXISTS outbox_events (
		id Utf8 NOT NULL,
		topic Utf8 NOT NULL,
		aggregate_type Utf8 NOT NULL,
		aggregate_id Utf8 NOT NULL,
		privacy_step_id Utf8,
		privacy_request_id Utf8,
		payload Json NOT NULL,
		status Utf8 NOT NULL,
		attempts Uint64 NOT NULL,
		poll_count Uint64 NOT NULL,
		available_at Timestamp NOT NULL,
		locked_at Timestamp,
		delivered_at Timestamp,
		last_error Utf8,
		delivery_receipt Json,
		created_at Timestamp NOT NULL,
		version Uint64 NOT NULL,
		INDEX outbox_claim GLOBAL ON (status, available_at, created_at),
		PRIMARY KEY (id)
	)`,
	`CREATE TABLE IF NOT EXISTS privacy_request_status_audit (
		id Utf8 NOT NULL,
		privacy_request_id Utf8 NOT NULL,
		status Utf8 NOT NULL,
		actor Utf8 NOT NULL,
		audit_note Utf8 NOT NULL,
		changed_at Timestamp NOT NULL,
		PRIMARY KEY (id)
	)`,
	`CREATE TABLE IF NOT EXISTS email_verifications (
		id Utf8 NOT NULL,
		product_id Utf8 NOT NULL,
		installation_id Utf8,
		identity_namespace Utf8 NOT NULL,
		age_category Utf8 NOT NULL,
		guardian_relationship Utf8,
		link_across_products Bool NOT NULL,
		blind_index_version Uint64 NOT NULL,
		email_blind_index Bytes NOT NULL,
		encrypted_email Bytes NOT NULL,
		email_nonce Bytes NOT NULL,
		wrapped_data_key Bytes NOT NULL,
		key_id Utf8 NOT NULL,
		encryption_algorithm Utf8 NOT NULL,
		expires_at Timestamp NOT NULL,
		verified_at Timestamp,
		verified_by Utf8,
		evidence_id Utf8,
		processing_token Utf8,
		processing_at Timestamp,
		created_at Timestamp NOT NULL,
		version Uint64 NOT NULL,
		INDEX email_verification_expiry GLOBAL ON (expires_at),
		PRIMARY KEY (id)
	)`,
	`CREATE TABLE IF NOT EXISTS email_verification_audit (
		verification_id Utf8 NOT NULL,
		person_id Utf8 NOT NULL,
		installation_id Utf8,
		product_id Utf8 NOT NULL,
		verified_by Utf8 NOT NULL,
		evidence_id Utf8 NOT NULL,
		verified_at Timestamp NOT NULL,
		consumed_at Timestamp NOT NULL,
		PRIMARY KEY (verification_id)
	)`,
}

type Executor interface {
	Exec(context.Context, string, ...query.ExecuteOption) error
	QueryRow(context.Context, string, ...query.ExecuteOption) (query.Row, error)
}

func Apply(ctx context.Context, db Executor, now time.Time) error {
	if err := db.Exec(ctx, statements[0], query.WithTxControl(query.ImplicitTxControl())); err != nil {
		return fmt.Errorf("initialize YDB schema metadata: %w", err)
	}

	row, err := db.QueryRow(ctx, `
		DECLARE $name AS Utf8;
		SELECT version FROM schema_meta WHERE name = $name;`,
		query.WithParameters(ydb.ParamsBuilder().Param("$name").Text("identity").Build()),
		query.WithTxControl(query.SnapshotReadOnlyTxControl()))
	if err == nil {
		var version uint64
		if err := row.Scan(&version); err != nil {
			return fmt.Errorf("scan YDB schema version: %w", err)
		}
		if version != Version {
			return fmt.Errorf("YDB schema version is %d, binary requires %d", version, Version)
		}
	} else if !errors.Is(err, query.ErrNoRows) {
		return fmt.Errorf("read YDB schema version: %w", err)
	}

	for i, statement := range statements[1:] {
		if err := db.Exec(ctx, statement, query.WithTxControl(query.ImplicitTxControl())); err != nil {
			return fmt.Errorf("apply YDB schema statement %d: %w", i+2, err)
		}
	}
	if err == nil {
		return nil
	}

	return db.Exec(ctx, `
		DECLARE $name AS Utf8;
		DECLARE $version AS Uint64;
		DECLARE $applied_at AS Timestamp;
		INSERT INTO schema_meta (name, version, applied_at)
		VALUES ($name, $version, $applied_at);`,
		query.WithParameters(ydb.ParamsBuilder().
			Param("$name").Text("identity").
			Param("$version").Uint64(Version).
			Param("$applied_at").Timestamp(now.UTC()).
			Build()),
		query.WithTxControl(query.SerializableReadWriteTxControl(query.CommitTx())),
	)
}
