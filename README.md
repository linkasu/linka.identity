# LINKa Identity

Minimal identity and privacy-control service for LINKa products. It keeps accounts optional, supports anonymous installations, encrypts email identities before persistence, and issues short-lived product-scoped tokens that contain no email.

## Security invariants

- Raw email is accepted only when beginning `POST /v1/email-verifications`. It is normalized in memory, envelope-encrypted, and never stored as plaintext.
- Logs record method, URL path, status, timing, request ID, and error type only. Bodies, query strings, authorization values, tokens, and email are excluded.
- Email lookup uses a versioned HMAC-SHA-256 blind index. The HMAC input includes identity namespace and linkage scope.
- Donation identities use the separate `donation` namespace and are always product-scoped. They are never automatically linked to account identities.
- Accounts are optional. An installation can remain anonymous indefinitely and can receive an installation token.
- Cross-product linkage is opt-in per identity request. Unknown-age subjects cannot use it. Minor linkage additionally requires `MINOR_CROSS_PRODUCT_LINKING_ENABLED=true`, which defaults to false.
- Consent and telemetry values must be supplied explicitly with their source timestamp. No legal consent or telemetry default is inferred.
- Telemetry denial and privacy deletion create outbox records in the same PostgreSQL transaction as the source record.
- A separate `email_verifier` workload must attest ownership before a product workload can consume a verification and create an identity.
- Root UUIDs and email remain inside PostgreSQL. Product responses and JWT subjects use product/audience/type-specific pairwise opaque keys.
- Privacy completion is orchestrator-only: Metric must return `completed` before PostgreSQL erasure can run.

## Local development

Requirements: Go 1.24 or later and PostgreSQL 17. Docker Compose is optional.

1. Copy `.env.example` to `.env` and replace every placeholder.
2. Generate independent local keys with `openssl rand -base64 32` and independent workload tokens with `openssl rand -hex 32`.
3. Run `docker compose up postgres migrate identity` to start the full local stack.
4. Check `curl http://127.0.0.1:8080/readyz`.

For a host-run service, set `DATABASE_URL` to a host-reachable address, then run:

```sh
go run ./cmd/migrate
go run ./cmd/identity
```

Every `/v1` route requires a workload bearer credential with the route-specific role and product scope. Health, readiness, and JWKS are public. See `openapi/openapi.yaml` for the contract.

## Commands

```sh
go test ./...
go vet ./...
go build ./...
TEST_DATABASE_URL='postgres://...' go test -tags=integration ./...
```

Migrations are embedded in the migration binary. Applied checksums are immutable; editing an applied migration fails instead of silently changing history.

## Configuration

Required settings:

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | PostgreSQL connection URL. Never logged by the service. |
| `WORKLOADS_JSON` | Workload IDs, independent bearer credentials, roles, and allowed products. |
| `PRODUCTS_JSON` | Product registry and exact telemetry JWT audiences. |
| `PAIRWISE_ID_KEY_BASE64` | Stable 32-byte HMAC key for pairwise opaque identifiers. |
| `EMAIL_KEY_PROVIDER` | `local` for development or `yandex-kms` for production. Local is rejected in production. |
| `EMAIL_KEY_ACTIVE_ID` | Alias used for new envelopes; historical aliases remain decrypt-only during rotation. |
| `EMAIL_LOCAL_KEKS_JSON` | Development-only active/historical 32-byte local KEKs. |
| `EMAIL_YC_KMS_KEYS_JSON` | Production alias-to-YC-KMS-key-ID keyring. |
| `BLIND_INDEX_KEYS_JSON` | JSON map from positive version to base64 HMAC key, each at least 32 bytes. |
| `BLIND_INDEX_CURRENT_VERSION` | Version used for new blind indexes. Older configured versions remain lookup-only. |
| `TOKEN_SIGNING_KEYS_JSON` | Active and retiring 32-byte Ed25519 seeds keyed by immutable IDs. |
| `TOKEN_ACTIVE_KEY_ID` | Signing key used for new JWTs; all configured keys remain in JWKS for verification. |
| `TOKEN_ISSUER` | Exact token issuer. |

Operational settings are documented in `docs/operations.md` and `docs/production.md`. Architecture, privacy properties, and threats are in `docs/architecture.md`, `docs/privacy.md`, and `docs/threat-model.md`.

## Deliberately unresolved deployment work

- Define KMS break-glass and rotation ownership; production code uses the YC KMS provider and refuses the local provider.
- Put the service behind authenticated service-to-service networking, rate limits, and abuse monitoring in addition to workload credentials.
- Select the telemetry control sink and set `REQUIRE_OUTBOX_DELIVERY=true`; configure alerting for age and size of pending outbox rows.
- Define retention periods, privacy-request identity verification, approvers, export packaging, deletion completion, backup erasure policy, and applicable legal text with counsel. The code intentionally invents none of these.
- Add production observability without PII, PostgreSQL backups/PITR, HA, connection proxying if needed, and external secret injection.
- Assign production ownership for workload/product registry changes and pairwise/signing/encryption key rotation ceremonies.
