# Threat model

## Assets and boundaries

Assets include email plaintext/envelopes, blind-index/signing/pairwise keys, workload credentials, linkage graph, organization text, consent, age, preferences, and privacy evidence.

Trust boundaries are product backend to HTTP API, native client to the narrow public installation broker, Identity to Serverless YDB, Identity to YC KMS/metadata/Lockbox, outbox to Metric, token consumer to JWKS, and organization/privacy administrators to internal routes.

## Threats and controls

| Threat | Repository control | Remaining work |
| --- | --- | --- |
| YDB disclosure reveals email | Per-record data key, AEAD ciphertext, KMS-wrapped key, no plaintext column | Restrict decrypt role, audit and rotate keys |
| Blind-index enumeration | Independent HMAC key, scope/namespace binding, versions | Protect keyring and rate-limit lookups |
| Donation becomes account linkage | Separate namespace and forced product scope | Review future reconciliation/export jobs |
| Minor linked accidentally | Product default, unknown blocked, minor flag off | Consent/guardian design before enablement |
| Email leaks through observability | No body/query/header/parameter logging; generic errors; no email claims/events | Align gateway/APM/crash dumps |
| Token replay/cross-product use | Short TTL, exact audience/product, pairwise subject, Ed25519, token ID | Consumer validation and replay policy |
| Unauthorized token minting | Constant-time workload credentials, RBAC/product scopes, verified-email gate | Platform workload identity and rotation |
| Lost/duplicate outbox event | Source/event serializable transaction, leases/retry/DLQ, stable ID | Consumer persists idempotency key |
| Concurrent identity duplication | Deterministic blind-index primary key, serializable retry | Load-test hot keys and monitor aborts |
| Stale worker overwrites state | `version` compare/update and serializable transactions | Alert on repeated conflicts/expired leases |
| Premature privacy completion | Parent FSM, request-bound Metric receipts, final YDB step, same-transaction re-check | Backup expiry and external evidence policy |
| Credential theft | Runtime metadata auth; key JSON only mounted in CI/local schema job | Short-lived CI federation when available |
| Resource exhaustion/free-tier limit | Bounded HTTP/work batches, YDB limits and indexes | Gateway limits, capacity alerts, load tests |
| Anonymous client injects telemetry | Closed products/platforms/kinds, explicit consent, pairwise subject, short Metrics JWT, global gateway limit | Per-source edge limits and optional platform attestation |
| Refresh capability theft | Separate audience/scope, bounded lifetime, live installation/preference check, no server/log persistence | OS keychain/Keystore and client compromise response |
| Denied subject is re-enabled | Public API accepts denial only; later consent creates a new installation | Monitor repeated registrations and document client UX |

The public Serverless YDB endpoint uses TLS and IAM; no VPC connector is required. Public endpoint does not mean anonymous access.

## Non-goals and review triggers

Password auth, social login, MFA, guardian proofing, automatic organization matching, direct analytics writes, and immediate backup erasure are out of scope.

The public installation broker review permits only the documented no-PII native-client routes, closed product allowlist, audience-separated refresh capability, exact policy version, and durable denial flow. Require a new security review before browser origins, platform attestation, new public fields/routes, minor linkage, email decryption/export, changing normalization, reconciliation, outbox topics, Metrics token claims, YDB key/index design, or new analytics payloads.
