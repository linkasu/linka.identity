# Architecture

## Components

- `cmd/identity` runs the HTTP API and optional outbox delivery worker.
- `cmd/migrate` applies embedded, checksummed PostgreSQL migrations.
- `internal/service` owns identity-linking policy and the email encryption flow.
- `internal/store` owns SQL persistence and transactions.
- `internal/cryptokit` defines the injectable `KeyProvider`, local envelope implementation, and versioned blind indexes.
- `internal/authz` authenticates independent workloads and enforces role/product scopes.
- `internal/pairwise` derives product/audience/type-separated opaque subject keys.
- `internal/token` signs Ed25519 JWTs and exposes active and retiring public keys as JWKS.
- `internal/outbox` delivers suppression/deletion events with at-least-once semantics.

The HTTP process does not apply migrations automatically. Deployment must complete the migration job before replacing service instances.

## Identity model

`persons` is the internal subject root. Root UUIDs remain inside PostgreSQL. Product responses and JWTs use aliases from `subject_aliases`; aliases are pairwise across product, audience, and subject type. A person can have zero or one `accounts` row, and installations can remain anonymous indefinitely.

An email identity records:

- envelope ciphertext, nonce, wrapped data key, algorithm, and KMS key ID;
- an HMAC-SHA-256 blind index and explicit key version;
- identity namespace (`account` or `donation`);
- linkage scope (`product` or `global`) and scope key;
- origin product and owning person.

The blind-index message is `namespace NUL linkage_scope NUL scope_key NUL normalized_email`. This prevents the same email from producing a common index across donation/account or product/global boundaries. All configured versions are queried, while only the current version is inserted. Rotation therefore supports a read-old/write-new interval.

Email enters a pending encrypted verification row. Only an `email_verifier` workload can attach external evidence; only then may a product workload consume the challenge. Identity creation uses a PostgreSQL transaction and `pg_advisory_xact_lock` derived from the current blind index.

## Linkage policy

- Product scope is the default.
- Donation namespace is forced to product scope even if a caller asks for global linkage.
- Global account linkage requires `link_across_products=true` and an explicit age category.
- `unknown` age cannot use global linkage.
- `minor` cannot use global linkage unless the deployment explicitly sets `MINOR_CROSS_PRODUCT_LINKING_ENABLED=true`.

The feature flag only opens the technical path. It does not establish consent, legal basis, guardian verification, or product policy. Those controls must be designed before enabling it.

## Organizations

Free-text `organization_submissions` remain separate from canonical `organizations`. Internal review either rejects a pending submission or matches it to a canonical row with actor and audit note. Canonical merges are serializable transactions that:

- mark the source as merged;
- write immutable `organization_merge_audit` data;
- redirect matched submissions;
- move non-conflicting memberships and remove duplicates.

## Privacy control and outbox

Telemetry preference is explicit `allowed` or `denied`; absence means no preference has been recorded. A transition to `denied` writes `telemetry.suppression.requested` in the same transaction. Repeating `denied` does not create another event.

A deletion request creates one Metric step for every relevant person, account, and linked-installation alias in every product plus one PostgreSQL step. PostgreSQL erasure cannot claim until every alias receipt is completed. A database trigger independently prevents premature request completion.

Manual state changes follow a finite-state machine but cannot set `completed`; completion belongs exclusively to the erasure orchestrator. Every accepted change records the authenticated workload actor, note, status, and time.

Workers claim rows with `FOR UPDATE SKIP LOCKED`, lease them for five minutes, and send JSON over authenticated HTTP. Delivery is at least once; consumers must deduplicate by outbox event `id`. Payloads contain opaque IDs, product/scope, and timestamps, never email.

## Token model

JWTs use Ed25519 and include only:

- issuer, audience/product, subject, subject type;
- issued/expiry time and unique token ID.

The subject is a 64-character pairwise opaque key. JWTs also contain scopes and a unique token ID. Email, root UUIDs, organization text, age, consent, and telemetry preference are excluded. TTL is bounded and active/retiring public keys are available through `/.well-known/jwks.json`.
