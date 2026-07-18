CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE subject_aliases (
    opaque_key char(64) PRIMARY KEY,
    product_id text NOT NULL,
    audience text NOT NULL,
    subject_type text NOT NULL CHECK (subject_type IN ('person', 'account', 'installation')),
    subject_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (product_id, audience, subject_type, subject_id),
    CHECK (opaque_key ~ '^[a-f0-9]{64}$')
);
CREATE INDEX subject_aliases_subject_idx ON subject_aliases(subject_type, subject_id);

CREATE TABLE email_identity_blind_indexes (
    identity_id uuid NOT NULL REFERENCES email_identities(id) ON DELETE CASCADE,
    blind_index_version smallint NOT NULL CHECK (blind_index_version > 0),
    email_blind_index bytea NOT NULL CHECK (octet_length(email_blind_index) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (identity_id, blind_index_version),
    UNIQUE (blind_index_version, email_blind_index)
);
INSERT INTO email_identity_blind_indexes (identity_id, blind_index_version, email_blind_index)
SELECT id, blind_index_version, email_blind_index FROM email_identities;

ALTER TABLE email_identities ADD COLUMN verified_at timestamptz;

CREATE TABLE email_verifications (
    id uuid PRIMARY KEY,
    product_id text NOT NULL,
    installation_id uuid REFERENCES product_installations(id),
    identity_namespace text NOT NULL CHECK (identity_namespace IN ('account', 'donation')),
    age_category text NOT NULL CHECK (age_category IN ('unknown', 'adult', 'minor')),
    guardian_relationship text,
    link_across_products boolean NOT NULL,
    blind_index_version smallint NOT NULL CHECK (blind_index_version > 0),
    email_blind_index bytea NOT NULL CHECK (octet_length(email_blind_index) = 32),
    encrypted_email bytea NOT NULL,
    email_nonce bytea NOT NULL,
    wrapped_data_key bytea NOT NULL,
    key_id text NOT NULL,
    encryption_algorithm text NOT NULL,
    expires_at timestamptz NOT NULL,
    verified_at timestamptz,
    verified_by text,
    evidence_id text,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (expires_at > created_at),
    CHECK (guardian_relationship IS NULL OR char_length(guardian_relationship) BETWEEN 1 AND 120),
    CHECK ((verified_at IS NULL AND verified_by IS NULL AND evidence_id IS NULL) OR
           (verified_at IS NOT NULL AND verified_by IS NOT NULL AND evidence_id IS NOT NULL))
);

ALTER TABLE privacy_requests
    ADD COLUMN requested_by_workload text,
    ADD COLUMN idempotency_key text,
    ADD COLUMN request_fingerprint char(64),
    ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();
UPDATE privacy_requests
SET requested_by_workload = 'legacy', idempotency_key = id::text
WHERE requested_by_workload IS NULL;
ALTER TABLE privacy_requests
    ALTER COLUMN requested_by_workload SET NOT NULL,
    ALTER COLUMN idempotency_key SET NOT NULL;
UPDATE privacy_requests SET request_fingerprint = encode(sha256(id::text::bytea), 'hex')
WHERE request_fingerprint IS NULL;
ALTER TABLE privacy_requests ALTER COLUMN request_fingerprint SET NOT NULL;
CREATE UNIQUE INDEX privacy_requests_idempotency_uniq
    ON privacy_requests(requested_by_workload, idempotency_key);

CREATE TABLE privacy_request_steps (
    id uuid PRIMARY KEY,
    privacy_request_id uuid NOT NULL REFERENCES privacy_requests(id) ON DELETE CASCADE,
    step_type text NOT NULL CHECK (step_type IN ('metric', 'postgres')),
    product_id text,
    subject_key char(64),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'retry', 'manual_dlq')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at timestamptz NOT NULL DEFAULT now(),
    lease_until timestamptz,
    receipt jsonb,
    last_error text,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (privacy_request_id, step_type, product_id),
    CHECK ((step_type = 'metric' AND product_id IS NOT NULL AND subject_key IS NOT NULL) OR
           (step_type = 'postgres' AND product_id IS NULL AND subject_key IS NULL))
);

ALTER TABLE outbox_events ADD COLUMN privacy_step_id uuid REFERENCES privacy_request_steps(id);
ALTER TABLE outbox_events ADD COLUMN delivery_receipt jsonb;
ALTER TABLE outbox_events DROP CONSTRAINT outbox_events_status_check;
ALTER TABLE outbox_events ADD CONSTRAINT outbox_events_status_check
    CHECK (status IN ('pending', 'processing', 'delivered', 'manual_dlq'));

CREATE OR REPLACE FUNCTION enforce_privacy_completion() RETURNS trigger AS $$
BEGIN
    IF NEW.status = 'completed' AND OLD.status <> 'completed' AND EXISTS (
        SELECT 1 FROM privacy_request_steps
        WHERE privacy_request_id = NEW.id AND status <> 'completed'
    ) THEN
        RAISE EXCEPTION 'privacy request has incomplete steps' USING ERRCODE = '23514';
    END IF;
    IF NEW.status = 'completed' AND NOT EXISTS (
        SELECT 1 FROM privacy_request_steps
        WHERE privacy_request_id = NEW.id AND step_type = 'postgres' AND status = 'completed'
    ) THEN
        RAISE EXCEPTION 'privacy request has no completed postgres erasure step' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER privacy_completion_guard
BEFORE UPDATE OF status ON privacy_requests
FOR EACH ROW EXECUTE FUNCTION enforce_privacy_completion();
