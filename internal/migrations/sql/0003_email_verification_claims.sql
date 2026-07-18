ALTER TABLE email_verifications
    ADD COLUMN processing_token uuid,
    ADD COLUMN processing_at timestamptz,
    ADD CONSTRAINT email_verifications_processing_check CHECK (
        (processing_token IS NULL AND processing_at IS NULL) OR
        (processing_token IS NOT NULL AND processing_at IS NOT NULL)
    );

CREATE INDEX email_verifications_claim_idx
    ON email_verifications(processing_at)
    WHERE consumed_at IS NULL AND processing_at IS NOT NULL;
