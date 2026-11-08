# Installation consent: schema 3 (not deployed)

This change does not authorize or perform a production migration. Runtime never
applies schema. The deployment workflow checks schema 3 from the exact reviewed
image digest with `schema -check` before starting normal traffic.

## Operator gate

1. Review and record a native backup receipt and a successful isolated restore
   rehearsal; fence all schema-2 writers/workers using the existing maintenance
   procedure in `public-account-release.md`. A maintenance revision has no DB/KMS
   or delivery workers. Verify the old principal can no longer write.
2. Review the exact CI/GHCR digest. Run its explicit `schema` command as an
   operator: schema 2 -> 3 creates `installation_consent_epochs` and
   `installation_consent_requests`, then promotes metadata only after all DDL.
   Existing preferences and aliases are unchanged. Partial DDL is retryable.
3. Verify `schema -check`, readiness, unknown bootstrap (version 1, epoch 0,
   completed, null token), and the isolated consent integration tests. Enable
   the new runtime/workers only after downstream `/v2/consents` is available.
4. Exercise grant -> pending/no token -> matching completed acknowledgement ->
   epoch JWT; denial closes that epoch, a later grant increments it. Test exact
   retry, changed-body conflict, stale CAS, private/legacy denial, and deletion.

Schema-2 binaries reject schema 3 in readiness; schema-3 binaries reject schema
2 until operator migration. New code reads all existing data as unmanaged without
backfill. Do not roll back to a schema-2 writer after promotion. Recovery requires
maintenance/fencing and an explicitly reviewed backup restore, not a metadata
downgrade or deletion of additive tables. Restoring old Identity data does not
undo permanent downstream privacy suppression/deletion; never restore access by
creating another installation/account/alias.

## Wire protocol and authority

The existing denial-only PUT body and response remain unchanged. Supplying either
`request_id` or `expected_version` selects the strict versioned protocol and
requires both, plus allowed/denied, the credential policy and RFC3339 milliseconds.
Recorded time accepts durable offline decisions in [2020, 2100), at most 5 minutes
ahead; CAS, not client time, orders versioned decisions. Exact request replay
returns current state, never an obsolete grant. GET uses refresh bearer and no
body/query. Pending, processing and manual DLQ never authorize collection.

All managed writers atomically write evidence, shared preference version, epoch
snapshot and `telemetry.consent.changed` outbox. Legacy unmanaged denials retain
permanent opt-out behavior; a later grant cannot bypass that suppression. Person,
global and deletion authority is never cleared. Erasure removes epoch/request
rows and disables the original installation.

Consent delivery derives `https://<configured-host>/v2/consents` from the existing
HTTPS `/v2/privacy/requests` target, without redirects/new secrets. Service JWTs
use the exact product/audience/installation alias and only `consent:write`;
privacy delivery retains `privacy:write`. Only matching request_id/status completed
acks mark delivery. Managed Metrics JWTs contain the positive `consent_epoch`;
legacy JWTs omit it. No root IDs leave YDB.
