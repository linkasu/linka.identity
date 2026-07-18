# Production controls

## Runtime and IAM

Production must set `DEPLOYMENT_ENVIRONMENT=production`, `EMAIL_KEY_PROVIDER=yandex-kms`, and `REQUIRE_OUTBOX_DELIVERY=true`. The process refuses to start with a local KEK or optional outbox delivery.

The runtime service account needs only:

- `lockbox.payloadViewer` for the referenced runtime secret version;
- `kms.keys.encrypterDecrypter` for every active or retiring email KMS key;
- `container-registry.images.puller` for the immutable image.

Lockbox stores `DATABASE_URL`, workload credentials, product registry, pairwise HMAC key, blind-index keyring, signing keyring, and the KMS alias-to-key-ID map. Secret payloads are never Terraform variables or image build arguments.

## Gateway limits

Do not expose the Serverless Container invocation endpoint publicly. Route the Identity domain through API Gateway or Smart Web Security and configure, at minimum:

- global sustained limit: 20 requests/second, burst 40;
- `/v1/email-verifications`: 5 requests/minute per source and workload;
- `/v1/tokens`: 30 requests/minute per workload;
- request body limit: 64 KiB and header limit: 1 MiB;
- upstream timeout: 30 seconds.

YC API Gateway quota ceilings are folder controls and are not managed by the current Terraform provider. The production environment owner must record the quota request and rate-limit policy as an environment approval before enabling the deploy workflow. Alert on sustained `429`, rejected body size, and quota utilization above 80%.

## PostgreSQL backup and PITR

Use PostgreSQL 17 with TLS verification, encrypted storage, automated backups, and point-in-time recovery. Production startup rejects `DATABASE_URL` unless it uses `sslmode=verify-full`. Minimum production policy:

- backup at least every six hours;
- retain backups and WAL/PITR coverage for 35 days unless legal policy requires less;
- run a restore into an isolated project monthly;
- verify migration marker, row counts, privacy-step consistency, and `/readyz` against the restored database;
- document how live erasure and backup expiry satisfy the approved deletion policy.

`/readyz` is successful only when PostgreSQL is reachable, migration `0005_privacy_fanout_cancellation.sql` is applied, and required outbox delivery has no stale or manual-DLQ rows. Deployment runs the immutable migration image before replacing the application revision, then checks readiness and JWKS.

## Release and staging smoke

`.github/workflows/publish.yml` publishes only `sha-<commit>` images from the exact CI-tested commit. `.github/workflows/deploy-yc.yml` checks out the same commit/ref, runs its migration binary, deploys Lockbox references, and performs readiness/JWKS smoke checks.

Before production promotion, run `.github/workflows/staging-preflight.yml`. It verifies JWKS, creates and verifies an email identity, checks that an account JWT contains both account subject and pairwise person keys, ingests a Metric batch, requests linked account/installation deletion, and waits for terminal PostgreSQL completion.
