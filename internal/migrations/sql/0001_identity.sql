CREATE TABLE persons (
    id uuid PRIMARY KEY,
    age_category text NOT NULL CHECK (age_category IN ('unknown', 'adult', 'minor')),
    guardian_relationship text,
    created_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz,
    CHECK (guardian_relationship IS NULL OR char_length(guardian_relationship) BETWEEN 1 AND 120)
);

CREATE TABLE email_identities (
    id uuid PRIMARY KEY,
    person_id uuid NOT NULL REFERENCES persons(id),
    product_id text NOT NULL,
    identity_namespace text NOT NULL CHECK (identity_namespace IN ('account', 'donation')),
    linkage_scope text NOT NULL CHECK (linkage_scope IN ('product', 'global')),
    scope_key text NOT NULL,
    blind_index_version smallint NOT NULL CHECK (blind_index_version > 0),
    email_blind_index bytea NOT NULL CHECK (octet_length(email_blind_index) = 32),
    encrypted_email bytea NOT NULL,
    email_nonce bytea NOT NULL,
    wrapped_data_key bytea NOT NULL,
    key_id text NOT NULL,
    encryption_algorithm text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (identity_namespace <> 'donation' OR linkage_scope = 'product'),
    CHECK ((linkage_scope = 'global' AND scope_key = 'global') OR
           (linkage_scope = 'product' AND scope_key = product_id)),
    UNIQUE (identity_namespace, linkage_scope, scope_key, blind_index_version, email_blind_index)
);
CREATE INDEX email_identities_person_idx ON email_identities(person_id);

CREATE TABLE accounts (
    id uuid PRIMARY KEY,
    person_id uuid NOT NULL UNIQUE REFERENCES persons(id),
    status text NOT NULL CHECK (status IN ('active', 'disabled', 'deleted')),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_authenticated_at timestamptz
);

CREATE TABLE product_installations (
    id uuid PRIMARY KEY,
    product_id text NOT NULL,
    platform text NOT NULL,
    person_id uuid REFERENCES persons(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz,
    CHECK (char_length(platform) BETWEEN 1 AND 64)
);
CREATE INDEX product_installations_person_idx ON product_installations(person_id) WHERE person_id IS NOT NULL;

CREATE TABLE organizations (
    id uuid PRIMARY KEY,
    canonical_name text NOT NULL,
    status text NOT NULL CHECK (status IN ('active', 'merged', 'archived')),
    merged_into_id uuid REFERENCES organizations(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (char_length(canonical_name) BETWEEN 1 AND 240),
    CHECK ((status = 'merged' AND merged_into_id IS NOT NULL) OR
           (status <> 'merged' AND merged_into_id IS NULL)),
    CHECK (merged_into_id IS NULL OR merged_into_id <> id)
);

CREATE TABLE organization_submissions (
    id uuid PRIMARY KEY,
    person_id uuid REFERENCES persons(id),
    installation_id uuid REFERENCES product_installations(id),
    product_id text NOT NULL,
    submitted_name text NOT NULL,
    status text NOT NULL CHECK (status IN ('pending', 'matched', 'rejected', 'merged')),
    canonical_organization_id uuid REFERENCES organizations(id),
    submitted_at timestamptz NOT NULL DEFAULT now(),
    reviewed_at timestamptz,
    reviewed_by text,
    audit_note text,
    CHECK (char_length(submitted_name) BETWEEN 1 AND 240),
    CHECK ((person_id IS NOT NULL)::int + (installation_id IS NOT NULL)::int = 1),
    CHECK ((status IN ('matched', 'merged') AND canonical_organization_id IS NOT NULL) OR
           (status IN ('pending', 'rejected')))
);

CREATE TABLE organization_merge_audit (
    id uuid PRIMARY KEY,
    source_organization_id uuid NOT NULL REFERENCES organizations(id),
    target_organization_id uuid NOT NULL REFERENCES organizations(id),
    actor text NOT NULL,
    reason text NOT NULL,
    merged_at timestamptz NOT NULL DEFAULT now(),
    CHECK (source_organization_id <> target_organization_id),
    CHECK (char_length(actor) BETWEEN 1 AND 200),
    CHECK (char_length(reason) BETWEEN 1 AND 1000)
);

CREATE TABLE memberships (
    id uuid PRIMARY KEY,
    person_id uuid NOT NULL REFERENCES persons(id),
    organization_id uuid NOT NULL REFERENCES organizations(id),
    product_id text NOT NULL,
    role_label text,
    status text NOT NULL CHECK (status IN ('active', 'inactive', 'pending')),
    started_at timestamptz,
    ended_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (role_label IS NULL OR char_length(role_label) BETWEEN 1 AND 120),
    CHECK (ended_at IS NULL OR started_at IS NULL OR ended_at >= started_at),
    UNIQUE (person_id, organization_id, product_id)
);

CREATE TABLE consents (
    id uuid PRIMARY KEY,
    person_id uuid REFERENCES persons(id),
    installation_id uuid REFERENCES product_installations(id),
    product_id text NOT NULL,
    consent_type text NOT NULL,
    policy_version text NOT NULL,
    status text NOT NULL CHECK (status IN ('granted', 'withdrawn')),
    recorded_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((person_id IS NOT NULL)::int + (installation_id IS NOT NULL)::int = 1),
    CHECK (char_length(consent_type) BETWEEN 1 AND 100),
    CHECK (char_length(policy_version) BETWEEN 1 AND 100)
);
CREATE INDEX consents_person_idx ON consents(person_id, product_id, consent_type, recorded_at DESC)
    WHERE person_id IS NOT NULL;
CREATE INDEX consents_installation_idx ON consents(installation_id, product_id, consent_type, recorded_at DESC)
    WHERE installation_id IS NOT NULL;

CREATE TABLE telemetry_preferences (
    id uuid PRIMARY KEY,
    person_id uuid REFERENCES persons(id),
    installation_id uuid REFERENCES product_installations(id),
    product_id text NOT NULL,
    preference text NOT NULL CHECK (preference IN ('allowed', 'denied')),
    recorded_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((person_id IS NOT NULL)::int + (installation_id IS NOT NULL)::int = 1)
);
CREATE UNIQUE INDEX telemetry_preferences_person_uniq
    ON telemetry_preferences(person_id, product_id) WHERE person_id IS NOT NULL;
CREATE UNIQUE INDEX telemetry_preferences_installation_uniq
    ON telemetry_preferences(installation_id, product_id) WHERE installation_id IS NOT NULL;

CREATE TABLE privacy_requests (
    id uuid PRIMARY KEY,
    person_id uuid REFERENCES persons(id),
    installation_id uuid REFERENCES product_installations(id),
    request_type text NOT NULL CHECK (request_type IN ('export', 'deletion')),
    scope text NOT NULL CHECK (scope IN ('product', 'all')),
    product_id text,
    status text NOT NULL CHECK (status IN ('requested', 'processing', 'completed', 'rejected', 'cancelled')),
    requested_at timestamptz NOT NULL,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((person_id IS NOT NULL)::int + (installation_id IS NOT NULL)::int = 1),
    CHECK ((scope = 'product' AND product_id IS NOT NULL) OR
           (scope = 'all' AND product_id IS NULL)),
    CHECK (completed_at IS NULL OR completed_at >= requested_at)
);

CREATE TABLE privacy_request_status_audit (
    id uuid PRIMARY KEY,
    privacy_request_id uuid NOT NULL REFERENCES privacy_requests(id),
    status text NOT NULL CHECK (status IN ('processing', 'completed', 'rejected', 'cancelled')),
    actor text NOT NULL,
    audit_note text NOT NULL,
    changed_at timestamptz NOT NULL DEFAULT now(),
    CHECK (char_length(actor) BETWEEN 1 AND 200),
    CHECK (char_length(audit_note) BETWEEN 1 AND 1000)
);

CREATE TABLE outbox_events (
    id uuid PRIMARY KEY,
    topic text NOT NULL,
    aggregate_type text NOT NULL,
    aggregate_id uuid NOT NULL,
    payload jsonb NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'delivered')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at timestamptz NOT NULL DEFAULT now(),
    locked_at timestamptz,
    delivered_at timestamptz,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX outbox_events_delivery_idx ON outbox_events(status, available_at, created_at);
