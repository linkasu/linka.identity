CREATE TABLE email_verification_audit (
    verification_id uuid PRIMARY KEY,
    person_id uuid NOT NULL REFERENCES persons(id),
    installation_id uuid REFERENCES product_installations(id),
    product_id text NOT NULL,
    verified_by text NOT NULL,
    evidence_id text NOT NULL,
    verified_at timestamptz NOT NULL,
    consumed_at timestamptz NOT NULL
);

CREATE INDEX email_verification_audit_person_idx
    ON email_verification_audit(person_id, product_id);
