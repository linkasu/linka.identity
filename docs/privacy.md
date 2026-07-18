# Privacy design

## Data classification

| Data | Classification | Storage |
| --- | --- | --- |
| Raw email | Direct identifier, highest sensitivity | Transient process memory only; never persisted |
| Encrypted email envelope | Sensitive encrypted data | YDB `email_verifications` and `email_identities` |
| Verification evidence | Sensitive email-free audit | YDB `email_verification_audit` |
| Email blind index | Sensitive pseudonymous lookup | YDB `email_blind_indexes` |
| Root person/account/installation ID | Pseudonymous root | YDB only |
| Pairwise subject key | Product/audience pseudonym | API, JWT, and Metric controls |
| Age/guardian relationship | Sensitive profile | YDB `persons`; never JWT/outbox |
| Organization submission | Potentially identifying free text | YDB only |
| Consent/privacy/preference | Sensitive compliance state | YDB only |
| Outbox payload | Pseudonymous control event | YDB and Metric control sink |

Email never belongs in telemetry, JWTs, logs, traces, metric labels, error messages, organization records, or outbox payloads.

## Email processing

The API strictly bounds and decodes the body, rejects display-name addresses, normalizes the mailbox in memory, computes scope-bound HMAC indexes, and encrypts with a random AES-256-GCM data key. YC KMS wraps that data key in production. Ciphertext additional authenticated data binds the identity or verification ID and scope metadata.

Consumed verification ciphertext is deleted and replaced by email-free evidence metadata. Expired unconsumed challenges are removed by a bounded cleanup worker. Go strings cannot be reliably zeroized, so process memory remains a documented residual risk.

## Isolation and control

Donation and account namespaces have distinct blind-index keys and donation scope cannot become global. Anonymous installations need no person/account. Minor global linkage is disabled by default; age/relationship records are not proof of authority or consent.

Consent and telemetry preference have no inferred default. A denial atomically emits a suppression event. Deletion fans out all relevant pairwise aliases, waits for request-ID-bound Metric completion receipts, then erases/anonymizes live YDB records. Cancellation/rejection and erasure are mutually serialized and optimistic version checks reject stale workers.

## Retention and backup

Retention periods remain legal/product decisions. Production owners must define periods for encrypted identities, installations, submissions, consent evidence, privacy requests, delivered outbox/audit rows, and logs. Live deletion does not immediately remove the data from the Serverless YDB 7-day system backup; expiry and restoration controls must be included in the approved policy. No PITR claim is made.

Any future export path requires separately verified authorization and short-lived encrypted artifacts. It must never put decrypted email into job payloads, logs, filenames, or analytics.
