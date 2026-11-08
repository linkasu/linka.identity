package schema

var consentStatements = []string{
	`CREATE TABLE IF NOT EXISTS installation_consent_epochs (
		subject_type Utf8 NOT NULL,
		subject_id Utf8 NOT NULL,
		product_id Utf8 NOT NULL,
		epoch Uint64 NOT NULL,
		version Uint64 NOT NULL,
		preference Utf8 NOT NULL,
		policy_version Utf8 NOT NULL,
		event_id Utf8 NOT NULL,
		PRIMARY KEY (subject_type, subject_id, product_id)
	)`,
	`CREATE TABLE IF NOT EXISTS installation_consent_requests (
		product_id Utf8 NOT NULL,
		subject_id Utf8 NOT NULL,
		request_id Utf8 NOT NULL,
		fingerprint Utf8 NOT NULL,
		PRIMARY KEY (product_id, subject_id, request_id)
	)`,
}
