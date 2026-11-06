package schema

// Schema 2 adds public registration state without rewriting legacy identities.
// Promotion happens only after all idempotent DDL, under an operator write fence.
var publicAccountStatements = []string{
	`CREATE TABLE IF NOT EXISTS public_email_challenges (
		id Utf8 NOT NULL,
		product_id Utf8 NOT NULL,
		installation_id Utf8 NOT NULL,
		purpose Utf8 NOT NULL,
		holder_role Utf8 NOT NULL,
		request_fingerprint Bytes NOT NULL,
		nonce_hash Bytes NOT NULL,
		code_hash Bytes NOT NULL,
		otp_key_id Utf8 NOT NULL,
		encrypted_code Bytes NOT NULL,
		code_nonce Bytes NOT NULL,
		wrapped_code_key Bytes NOT NULL,
		code_kms_key_id Utf8 NOT NULL,
		code_encryption_algorithm Utf8 NOT NULL,
		email_blind_index_version Uint64 NOT NULL,
		email_blind_index Bytes NOT NULL,
		state Utf8 NOT NULL,
		attempts Uint64 NOT NULL,
		mail_attempts Uint64 NOT NULL,
		mail_available_at Timestamp NOT NULL,
		mail_claim_token Utf8,
		mail_claim_until Timestamp,
		created_at Timestamp NOT NULL,
		updated_at Timestamp NOT NULL,
		expires_at Timestamp NOT NULL,
		verified_at Timestamp,
		consumed_at Timestamp,
		version Uint64 NOT NULL,
		INDEX public_email_mail_queue GLOBAL ON (state, mail_available_at),
		INDEX public_email_installation GLOBAL ON (product_id, installation_id),
		INDEX public_email_identity GLOBAL ON (product_id, email_blind_index_version, email_blind_index),
		PRIMARY KEY (id)
	)`,
	`CREATE TABLE IF NOT EXISTS public_registration_flows (
		product_id Utf8 NOT NULL,
		installation_id Utf8 NOT NULL,
		challenge_id Utf8 NOT NULL,
		session_id Utf8,
		updated_at Timestamp NOT NULL,
		version Uint64 NOT NULL,
		PRIMARY KEY (product_id, installation_id)
	)`,
	`CREATE TABLE IF NOT EXISTS product_accounts (
		product_id Utf8 NOT NULL,
		account_id Utf8 NOT NULL,
		email_identity_id Utf8 NOT NULL,
		holder_role Utf8 NOT NULL,
		country Utf8 NOT NULL,
		region Utf8 NOT NULL,
		status Utf8 NOT NULL,
		verified_at Timestamp NOT NULL,
		created_at Timestamp NOT NULL,
		updated_at Timestamp NOT NULL,
		version Uint64 NOT NULL,
		INDEX product_accounts_account GLOBAL ON (account_id),
		PRIMARY KEY (product_id, account_id)
	)`,
	`CREATE TABLE IF NOT EXISTS account_sessions (
		id Utf8 NOT NULL,
		product_id Utf8 NOT NULL,
		account_id Utf8 NOT NULL,
		installation_id Utf8 NOT NULL,
		status Utf8 NOT NULL,
		created_at Timestamp NOT NULL,
		expires_at Timestamp NOT NULL,
		revoked_at Timestamp,
		version Uint64 NOT NULL,
		INDEX account_sessions_account GLOBAL ON (account_id),
		INDEX account_sessions_installation GLOBAL ON (installation_id),
		PRIMARY KEY (id)
	)`,
	`CREATE TABLE IF NOT EXISTS account_refresh_tokens (
		token_hash Bytes NOT NULL,
		session_id Utf8 NOT NULL,
		issued_at Timestamp NOT NULL,
		expires_at Timestamp NOT NULL,
		consumed_at Timestamp,
		version Uint64 NOT NULL,
		INDEX account_refresh_session GLOBAL ON (session_id),
		PRIMARY KEY (token_hash)
	)`,
	`CREATE TABLE IF NOT EXISTS public_auth_events (
		bucket Utf8 NOT NULL,
		created_at Timestamp NOT NULL,
		event_id Utf8 NOT NULL,
		PRIMARY KEY (bucket, created_at, event_id)
	)`,
	`CREATE TABLE IF NOT EXISTS public_account_audit (
		id Utf8 NOT NULL,
		product_id Utf8 NOT NULL,
		session_id Utf8 NOT NULL,
		actor Utf8 NOT NULL,
		action Utf8 NOT NULL,
		entity_id Utf8 NOT NULL,
		created_at Timestamp NOT NULL,
		PRIMARY KEY (id)
	)`,
}
