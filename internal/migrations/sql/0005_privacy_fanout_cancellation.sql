ALTER TABLE privacy_request_steps
    DROP CONSTRAINT privacy_request_steps_status_check;
ALTER TABLE privacy_request_steps
    ADD CONSTRAINT privacy_request_steps_status_check
    CHECK (status IN ('pending', 'processing', 'completed', 'retry', 'manual_dlq', 'cancelled'));

ALTER TABLE privacy_request_steps
    DROP CONSTRAINT privacy_request_steps_privacy_request_id_step_type_product__key;
CREATE UNIQUE INDEX privacy_request_steps_metric_uniq
    ON privacy_request_steps(privacy_request_id, product_id, subject_key)
    WHERE step_type = 'metric';
CREATE UNIQUE INDEX privacy_request_steps_postgres_uniq
    ON privacy_request_steps(privacy_request_id)
    WHERE step_type = 'postgres';

ALTER TABLE outbox_events
    DROP CONSTRAINT outbox_events_status_check;
ALTER TABLE outbox_events
    ADD CONSTRAINT outbox_events_status_check
    CHECK (status IN ('pending', 'processing', 'delivered', 'manual_dlq', 'cancelled'));
ALTER TABLE outbox_events
    ADD COLUMN poll_count integer NOT NULL DEFAULT 0 CHECK (poll_count >= 0);
