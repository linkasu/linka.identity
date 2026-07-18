# Threat model

## Assets

- Email plaintext and envelope keys.
- Blind-index keys and their version history.
- Token signing keys, pairwise-ID key, and independent workload credentials.
- Linkage graph among persons, accounts, installations, products, and organizations.
- Consent, age category, guardian relationship, telemetry preference, and privacy-request evidence.

## Trust boundaries

- Product backend to identity HTTP API.
- Identity process to PostgreSQL.
- Identity process to KMS/key provider.
- Identity outbox worker to telemetry-control sink.
- Token consumer to the JWKS endpoint.
- Internal organization reviewer to merge/review endpoints.

The service authenticates configured workloads and enforces roles/product scopes. It is not intended to be exposed directly to untrusted clients without a gateway, rate limits, and stronger platform workload identity.

## Threats and controls

| Threat | Controls in this repository | Remaining work |
| --- | --- | --- |
| Database disclosure reveals email | Per-record random data key, AEAD ciphertext, wrapped key, no plaintext column | Production KMS, restricted decrypt role, rotation and audit |
| Blind-index enumeration | HMAC with independent secret, namespace/scope binding, key versions | Protect keys in KMS/secret manager; rate-limit lookups |
| Donation identity becomes account linkage | Separate namespace in index and schema; global donation scope rejected | Review every future reconciliation/export pipeline |
| Minor linked across products accidentally | Product scope default, unknown age blocked, feature flag false by default | Formal consent/guardian and authorization design before enablement |
| Email leaks through observability | No body/query/header logging; generic errors; no email claims/events | Configure proxies/APM/body capture and crash dumps consistently |
| Token replay or cross-product use | Short configurable TTL, product audience, opaque subject, Ed25519 signature, token ID | Consumer audience/issuer checks, replay policy where required, key rotation |
| Unauthenticated token minting | Constant-time per-workload credentials, roles, product scopes, verified-email gate | Add mTLS/platform workload identity and credential rotation automation |
| Outbox event loss | Source and event share a transaction; retries, leases, terminal DLQ, required-delivery readiness | Alerting and escalation ownership |
| Outbox duplication | Stable event ID, at-least-once contract | Consumer must persist idempotency key |
| Forged organization audit actor | Audit actor is derived from the authenticated admin workload, never the request body | Add human reviewer identity where policy requires it |
| Premature privacy completion | Metric request-ID-bound terminal receipt, downstream steps, PostgreSQL erasure step, completion trigger | Backup expiry and external evidence retention policy |
| Privacy request abuse | Internal authentication, opaque IDs, explicit scope | Data-subject verification, anti-automation, approval workflow |
| SQL injection | Parameterized SQL and strict enum/length checks | Dependency and query review |
| Resource exhaustion | Request body/header/time limits, DB pool limit | Gateway rate limits, connection budgets, load tests |

## Explicit non-goals

- Password authentication, social login, MFA, or account recovery.
- A legal determination that a consent event is valid.
- Guardian identity proofing.
- Automatic organization matching.
- Direct ClickHouse or analytics writes.
- Immediate erasure from backups; live PostgreSQL erasure is orchestrated, backup expiry remains operational policy.

## Security review triggers

Require a fresh review before enabling minor linkage, adding any email decryption endpoint, changing normalization, introducing identity reconciliation, sending new outbox topics, exposing APIs to clients, changing token claims, or adding analytics integrations.
