# LINKa Identity

Minimal identity and privacy-control service for LINKa products. Accounts remain optional, installations may stay anonymous, email is envelope-encrypted before persistence, and issued product tokens contain no email or root UUID.

## Security invariants

- Raw email is accepted only by `POST /v1/email-verifications`, normalized in memory, encrypted, and never persisted or logged as plaintext.
- Logs include method, URL path, status, timing, request ID, and error type only. Bodies, query strings, authorization values, tokens, and email are excluded.
- Email lookup uses a versioned HMAC-SHA-256 blind index bound to identity namespace and linkage scope.
- Donation identities use the separate `donation` namespace, remain product-scoped, and are never automatically linked to account identities.
- Cross-product linkage is explicit, forbidden for unknown age, and disabled for minors unless `MINOR_CROSS_PRODUCT_LINKING_ENABLED=true`.
- Consent and telemetry values are explicit and carry their source timestamp; absence is not consent.
- Telemetry denial and privacy deletion create outbox records in the same YDB serializable transaction as their source state.
- Only an `email_verifier` workload may attest ownership before a product workload consumes a verification.
- Root IDs and encrypted email remain in YDB. Responses and JWTs use product/audience/type-specific pairwise opaque keys.
- Metric must return a matching `completed` deletion receipt before YDB erasure can complete.

## Local development

Requirements: Go 1.24 or later and Docker for the official local YDB image.

```sh
docker compose up -d ydb
export YDB_ENDPOINT=grpc://127.0.0.1:2136
export YDB_DATABASE=/local
export YDB_ANONYMOUS_CREDENTIALS=1
go run ./cmd/schema
go run ./cmd/identity
```

Copy the remaining settings from `.env.example`, replacing every key and workload-token placeholder with independent random values. Every `/v1` route requires a role- and product-scoped workload credential. Health, readiness, and JWKS routes are public; see `openapi/openapi.yaml`.

## Verification

```sh
go test -race ./...
go vet ./...
go build ./...
TEST_YDB_ENDPOINT=grpc://127.0.0.1:2136 TEST_YDB_DATABASE=/local \
  YDB_ANONYMOUS_CREDENTIALS=1 go test -tags=integration ./...
```

`cmd/schema` is idempotent. It creates missing YDB objects and accepts only the schema version embedded in the binary; the HTTP process never changes schema on startup.

## Configuration

| Variable | Purpose |
| --- | --- |
| `YDB_ENDPOINT` | `grpc` local endpoint or production `grpcs` Serverless YDB endpoint. |
| `YDB_DATABASE` | Absolute YDB database path. |
| `YDB_METADATA_CREDENTIALS` | Must be `1` in production runtime; obtains IAM tokens from workload metadata. |
| `YDB_SERVICE_ACCOUNT_KEY_FILE_CREDENTIALS` | CI/local schema jobs only; forbidden in production runtime configuration. |
| `WORKLOADS_JSON` | Workload IDs, independent bearer credentials, roles, and products. |
| `PRODUCTS_JSON` | Product registry and exact telemetry JWT audiences. |
| `PAIRWISE_ID_KEY_BASE64` | Stable 32-byte HMAC key for pairwise opaque identifiers. |
| `EMAIL_KEY_PROVIDER` | `local` for development or `yandex-kms` for production. |
| `EMAIL_KEY_ACTIVE_ID` | Alias used for new email envelopes. |
| `EMAIL_LOCAL_KEKS_JSON` | Development-only local KEK keyring. |
| `EMAIL_YC_KMS_KEYS_JSON` | Production alias-to-YC-KMS-key-ID keyring. |
| `BLIND_INDEX_KEYS_JSON` | Versioned base64 HMAC keyring; each key is at least 32 bytes. |
| `BLIND_INDEX_CURRENT_VERSION` | Version used for new indexes; older configured versions remain lookup-only. |
| `TOKEN_SIGNING_KEYS_JSON` | Active and retiring 32-byte Ed25519 seeds by immutable key ID. |
| `TOKEN_ACTIVE_KEY_ID` | Signing key used for new JWTs. |
| `TOKEN_ISSUER` | Exact token issuer. |

Operational settings and deployment controls are in `docs/operations.md` and `docs/production.md`.

## Deliberately unresolved policy

- Define KMS break-glass and rotation ownership.
- Put the service behind authenticated service-to-service routing, rate limits, and abuse monitoring.
- Select the production telemetry control sink and alert on stale/manual-DLQ outbox events.
- Define retention, privacy-request identity verification, approvers, exports, deletion evidence, backup-expiry handling, and legal text with counsel.
- Assign ownership for workload/product registry and signing/encryption/blind-index key rotation.
