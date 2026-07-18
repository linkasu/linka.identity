# Privacy design

## Data classification

| Data | Classification | Storage |
| --- | --- | --- |
| Raw email | Direct identifier, highest sensitivity in this service | Never persisted; transient process memory only |
| Encrypted email envelope | Sensitive encrypted data | Pending `email_verifications` and active `email_identities`; consumed verification envelopes are deleted |
| Verification evidence metadata | Sensitive audit data without email | PostgreSQL `email_verification_audit`, linked to person/installation for erasure |
| Email blind index | Sensitive pseudonymous lookup key | PostgreSQL `email_identities` |
| Person/account/installation UUID | Pseudonymous root identifier | PostgreSQL only |
| Pairwise subject key | Product/audience-specific pseudonym | Product responses, JWT, and Metric control events |
| Age category and guardian relationship | Sensitive profile data | PostgreSQL `persons`; never JWT or outbox |
| Organization submission | Potentially identifying free text | PostgreSQL only |
| Consent/privacy status | Sensitive compliance record | PostgreSQL only |
| Outbox payload | Pseudonymous control-plane event | PostgreSQL and configured telemetry-control sink |

No email field belongs in ClickHouse, telemetry events, JWTs, logs, traces, metrics labels, error messages, or organization records. This is an architectural rule, not merely a current implementation detail.

## Email processing

1. The authenticated request body is decoded with a strict size limit and unknown-field rejection.
2. A mailbox-only address is normalized by trimming outer whitespace and applying lowercase. Display-name forms are rejected.
3. The service computes namespace/scope-bound HMAC indexes for lookup.
4. For a new identity, the key provider generates a random 256-bit data key and returns it wrapped by the configured KEK/KMS key.
5. The normalized email is encrypted with AES-256-GCM and bound to identity metadata as additional authenticated data.
6. The plaintext data key is cleared after use. Go strings cannot be reliably zeroized, so process memory remains a residual risk.

The bundled local AES key provider satisfies dependency injection and local operation. Production must replace it with a cloud/HSM KMS implementation so the service does not hold a long-lived KEK in an environment variable.

## Isolation rules

Donation identities are intentionally non-transitive: the `donation` namespace is separate and the database rejects global donation scope. No background process reconciles donation indexes with account indexes.

Anonymous installation records require no person or account. Linking occurs only after a separately attested email verification and uses an installation pairwise key, never a caller-supplied root UUID.

Minor cross-product linkage is disabled by default. Age category and optional guardian relationship are records, not verification. The code does not infer guardian authority or consent from relationship text.

## Consent and telemetry

The API requires consent type, policy version, status, and source timestamp. It does not define policy versions, infer a lawful basis, or turn silence into consent.

Telemetry preference likewise has no default row. `denied` creates a suppression control event transactionally. This service does not send behavioral telemetry.

## Privacy requests

The service records product-scoped or person-wide deletion requests and exposes request status. Anonymous installations can request only product scope. Deletion fans out all relevant person/account/installation pairwise keys per product, aggregates terminal receipts, then erases or anonymizes PostgreSQL records. Cancellation/rejection cancels worker steps and cannot complete or erase. Export requests are rejected until export assembly and approval policy exists.

The database trigger rejects `completed` while any downstream or PostgreSQL step is incomplete. A pending HTTP acceptance from Metric is not evidence of deletion completion.

## Retention

No retention periods are encoded because they are legal/product decisions. Production owners must define and implement periods for encrypted identities, anonymous installations, organization submissions, consent evidence, privacy requests, delivered outbox records, logs, and backups. Database deletion and backup expiry must be aligned.

## Export constraints

Any future export worker must decrypt email only for a verified request, through a narrowly authorized KMS path, and write to a short-lived encrypted artifact store. It must never put decrypted email into job payloads, logs, filenames, or analytics systems.
