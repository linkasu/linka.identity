# Operations

## Startup and readiness

Run `migrate` as a one-shot deployment step before starting new application instances. `/healthz` reports process liveness. `/readyz` verifies PostgreSQL connectivity and the current migration marker with a two-second deadline. Readiness does not currently verify the external outbox sink.

Use `REQUIRE_OUTBOX_DELIVERY=true` in environments where telemetry control delivery is mandatory. Configuration then fails unless an absolute HTTP(S) Metric privacy URL is present. Delivery uses a short-lived Identity-signed `privacy:write` JWT.

## Secrets

Inject secrets at runtime; never put them in Git, image layers, compose files, command lines visible to other users, or logs. Required secret classes are independent:

- one independent credential per workload;
- pairwise-ID HMAC key;
- active and historical email envelope KEKs/KMS authorities;
- one HMAC key per blind-index version;
- active and retiring Ed25519 token signing seeds;
- PostgreSQL credentials.

The local key provider is development-only. Production uses YC KMS envelope wrapping through the runtime service-account metadata token. Preserve old KMS aliases and key IDs until all envelopes that reference them are deleted or rewrapped.

## Blind-index rotation

1. Add a new random key under a new integer version while retaining all old versions.
2. Deploy with `BLIND_INDEX_CURRENT_VERSION` set to the new version. Reads query every configured version; writes use the new version.
3. Backfill old rows by decrypting and re-indexing only in a controlled, audited job. No such high-privilege job is included here.
4. Verify no rows reference the old version.
5. Remove the old lookup key after retention and rollback windows close.

Do not change a key's value without changing its version. Doing so makes identities unreachable and can create duplicates.

## Token-key rotation

Add a new seed under a new key ID, set `TOKEN_ACTIVE_KEY_ID` to it, and keep the previous seed configured as retiring. JWKS publishes both. Remove the previous key only after maximum token TTL plus verifier skew and rollback windows have elapsed.

## Outbox

Delivery is at least once. Metric deduplicates by event `id`. A `202 pending/processing/retry` receipt increments `poll_count`, not transport attempts, and never completes a privacy step; only a matching `request_id` with `completed` unblocks PostgreSQL erasure. Alert on:

- oldest non-delivered event age;
- pending/processing row count;
- rapidly increasing attempts;
- processing leases older than five minutes.

Cancellation or rejection atomically cancels pending/processing outbox and privacy steps. Claims and erasure transactions re-check the parent request state, so a terminal request cannot later complete or erase PostgreSQL data.

Transport failures use bounded exponential retry and then `manual_dlq`. Accepted downstream work is polled without consuming the transport-failure budget.

Delivered rows are retained indefinitely by the current schema. Add a reviewed retention job after audit requirements are known.

## Email verification cleanup

`EMAIL_VERIFICATION_CLEANUP_INTERVAL` controls a worker that deletes expired, unconsumed verification envelopes in bounded batches. A fresh processing claim is protected for five minutes; stale claims and standalone expired ciphertext are removed. Successful consumption atomically replaces the encrypted challenge with email-free audit metadata linked to person/installation erasure.

## Database

Use TLS, least-privilege roles, encrypted backups, PITR, and tested restoration. Separate migration and application roles if the platform supports it. The application currently expects schema access sufficient for its tables; a production permission migration should narrow this.

Applied migrations are identified by filename and SHA-256 checksum. Never edit an applied migration; add a new ordered file.

## Observability

The service emits structured JSON logs without request bodies or query strings. Infrastructure must also disable body/header capture for this service. Do not use person, account, installation, token, organization text, or blind index as metric labels.
