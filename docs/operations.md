# Operations

## Startup and readiness

Run `schema` as a one-shot step before starting a new application revision. It is safe to rerun: every DDL statement is idempotent and the `schema_meta` version must equal the binary's version. `/healthz` reports process liveness. `/readyz` verifies YDB access, schema version, and, when required, outbox age/DLQ state.

Use `REQUIRE_OUTBOX_DELIVERY=true` in production. Configuration then requires an HTTPS Metric privacy URL; delivery uses a short-lived Identity-signed `privacy:write` JWT.

## YDB credentials

- Local YDB uses `YDB_ANONYMOUS_CREDENTIALS=1`.
- CI or a local operator may set `YDB_SERVICE_ACCOUNT_KEY_FILE_CREDENTIALS` to a mounted service-account-key JSON file.
- Production runtime must set `YDB_METADATA_CREDENTIALS=1`; startup rejects service-account-key file or inline JSON credentials.
- The deployment schema job mounts the mode-`0600` deploy service-account key read-only, runs only the one-shot schema process as container root so it can read that mount, and removes the key after use. The runtime image remains UID/GID `65532`.

Never put key JSON, IAM tokens, email, blind-index values, root IDs, or workload credentials in logs or command arguments.

## Secret rotation

Blind-index rotation:

1. Add a new random key under a new integer version while retaining old versions.
2. Deploy with the new `BLIND_INDEX_CURRENT_VERSION`; reads use every configured version and writes use the current one.
3. Run a separately reviewed decrypt/re-index backfill if old-key removal is required.
4. Verify no identity or unconsumed verification references the old version.
5. Remove the old key only after retention and rollback windows close.

Token rotation adds a new seed/key ID, changes `TOKEN_ACTIVE_KEY_ID`, and retains the old public key through maximum TTL plus skew and rollback windows. KMS rotation similarly retains every alias referenced by persisted envelopes.

## Outbox and privacy

Metric must return the matching event `request_id` with `status=completed`. Pending responses increment `poll_count`; transport failures increment `attempts` and eventually enter `manual_dlq`. Alert on oldest active event, active count, attempt growth, manual DLQ, and expired five-minute leases.

Cancellation/rejection is atomic with child-step/outbox cancellation. The YDB erasure step remains blocked until every Metric alias receipt completes. Successful email-verification consumption replaces challenge ciphertext with email-free audit metadata; the cleanup worker deletes expired unconsumed ciphertext in bounded batches.

## Backup and restore

Production uses the Serverless YDB system backup retained for 7 days. This is not point-in-time recovery and documentation must not claim PITR. Test restoration into an isolated database, run `schema`, verify schema version and privacy-step consistency, and document how backup expiration fits the approved deletion policy.

## Observability

The service emits structured logs without bodies, query strings, headers, SQL/YQL parameters, or email. Infrastructure body/header capture and crash-dump handling must follow the same rule. Do not use person, account, installation, organization text, blind index, or token as metric labels.
