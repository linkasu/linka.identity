# Architecture

## Components

- `cmd/identity` runs the HTTP API and workers.
- `cmd/schema` applies the idempotent YDB schema before a revision starts.
- `internal/service` owns identity-linking policy and in-memory email processing.
- `internal/store` owns native YDB Query API persistence and transactions.
- `internal/schema` defines the current YDB tables and schema marker.
- `internal/cryptokit` provides envelope encryption, YC KMS wrapping, and versioned blind indexes.
- `internal/authz`, `internal/pairwise`, and `internal/token` provide workload RBAC, pairwise IDs, and Ed25519 JWTs.
- `internal/outbox`, `internal/privacyworker`, and `internal/verificationworker` deliver controls, orchestrate deletion, and remove expired challenges.

The HTTP process never applies DDL. Deployment runs the schema binary from the same exact image digest before creating a new revision.

## YDB model

`persons` is the internal subject root. Accounts are optional and installations can remain anonymous. `subject_aliases` stores product/audience/type-separated pairwise identifiers; root IDs never cross the API boundary.

Email data is split between:

- `email_identities`, containing envelope ciphertext, nonce, wrapped data key, KMS alias, algorithm, and ownership metadata;
- `email_blind_indexes`, keyed by namespace, linkage scope, scope key, key version, and HMAC value;
- `email_verifications`, containing short-lived encrypted challenges and optimistic claim state;
- `email_verification_audit`, containing email-free ownership evidence after successful consumption.

The blind-index message is `namespace NUL linkage_scope NUL scope_key NUL normalized_email`. Every configured version is queried and only the current version is written. A deterministic blind-index primary key replaces PostgreSQL advisory locks: concurrent creators touch the same key and YDB serializable conflict handling retries one transaction against committed state.

Organization, membership, consent, preference, privacy request/step, outbox, and audit tables use explicit keys. Mutable race-sensitive rows have a `version` column. Operations read the expected version and use `UPDATE ... WHERE version = $version RETURNING version`; a mismatch is a conflict. Multi-row business operations use native YDB `SerializableReadWrite` transactions.

## Linkage policy

- Product scope is the default.
- Donation scope is always product-local.
- Global account linkage requires explicit `link_across_products=true` and a known age category.
- Unknown age cannot use global linkage.
- Minor global linkage additionally requires the disabled-by-default feature flag.

The feature flag is only a technical gate and does not establish consent, guardian authority, or legal basis.

## Privacy and outbox

A transition to telemetry `denied` persists the preference and suppression event atomically. Repeated denial creates no duplicate event.

A deletion request creates one Metric step for each relevant person/account/linked-installation alias and one final `ydb` erasure step. The erasure worker re-checks the parent finite-state-machine state and all Metric receipts in the same serializable transaction before deleting or anonymizing live data. Only then does it mark the request `completed` and append audit evidence.

Workers claim rows by expected version and five-minute lease. Concurrent claims conflict serializably; stale leases can be reclaimed. Delivery is at least once and the consumer deduplicates by event ID. Cancellation/rejection and claims read the same parent request, so they cannot race into later erasure.

## Tokens

JWTs contain issuer, audience/product, pairwise subject, subject type, scopes, issued/expiry time, and token ID. Account tokens may include a separate pairwise person key. Email, root IDs, organization text, age, consent, and preferences are excluded.
