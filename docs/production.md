# Production controls

## Serverless YDB

Use a Serverless YDB database with the free-tier-oriented limits explicitly recorded in infrastructure review:

- provisioned capacity: `0 provisioned RCU`;
- storage limit: `5 GB`;
- request throttling limit: `10 RCU`;
- system backup retention: `7 days`.

The 7-day system backup is not PITR. Capacity and storage alerts must fire before limits affect identity, outbox, or deletion work. If usage no longer fits these limits, obtain product approval before changing the cost profile.

Set `YDB_ENDPOINT` to the public `grpcs` Serverless YDB endpoint and `YDB_DATABASE` to its absolute path. The Serverless Container uses metadata IAM credentials (`YDB_METADATA_CREDENTIALS=1`). No VPC connector or managed PostgreSQL network is required or configured.

## IAM and secrets

Production sets `DEPLOYMENT_ENVIRONMENT=production`, `EMAIL_KEY_PROVIDER=yandex-kms`, and `REQUIRE_OUTBOX_DELIVERY=true`.

Runtime service account permissions:

- least-privilege read/write access to the Identity YDB tables;
- `lockbox.payloadViewer` for referenced runtime secret versions;
- `kms.keys.encrypterDecrypter` for active and retiring email KMS keys;
- `container-registry.images.puller` for the exact image digest.

The deploy service account additionally applies YDB schema. Its key JSON is allowed only in GitHub Actions/local schema jobs, is mounted read-only, and is never injected into the runtime revision.

Lockbox stores workload credentials, product registry, pairwise HMAC key, blind-index keyring, signing keyring, and KMS alias map. `YDB_ENDPOINT` and `YDB_DATABASE` are non-secret environment values. Production KMS key material never enters Lockbox or the application.

## Release ordering

`.github/workflows/publish.yml` publishes `sha-<commit>` from the exact CI-tested commit. Deployment mirrors that image, resolves its `sha256:` registry digest, and uses the digest for both steps:

1. Run `/usr/local/bin/schema` against Serverless YDB with the deploy service-account key.
2. Only after schema succeeds, create the runtime revision with metadata auth and Lockbox references.
3. Verify `/readyz` and JWKS.

No `DATABASE_URL`, PostgreSQL migration, mutable deployment tag, VPC connector, or service-account-key JSON exists in the runtime revision.

## Serverless worker scheduling

Background goroutines are best-effort only in a Serverless Container and are not the guarantee for outbox delivery, privacy erasure, or expired-verification cleanup. Configure a Yandex Cloud timer trigger to invoke `POST /internal/workers/tick` on the direct container endpoint every minute. Use a separate service account with only the `serverless-containers.containerInvoker` role; do not use an application token for this endpoint.

The API Gateway exact path `/internal/workers/tick` must remain a dummy `404` integration so that the public greedy route cannot reach the worker tick. Direct container IAM invocation is the endpoint's authentication boundary.

## Gateway limits

Do not expose the raw Serverless Container invocation endpoint. Route through the approved gateway/SWS control and enforce at minimum:

- global sustained 20 requests/second, burst 40;
- `/v1/email-verifications`: 5 requests/minute per source and workload;
- `/v1/tokens`: 30 requests/minute per workload;
- request body 64 KiB, headers 1 MiB, upstream timeout 30 seconds.

Record gateway quota/rate-limit approval and alert on sustained `429`, rejected request size, and quota utilization above 80%.

## Staging

Run `.github/workflows/staging-preflight.yml` before promotion. It verifies JWKS, verified-account creation, pairwise account/person claims, Metric ingest, linked deletion fan-out, receipts, and final YDB erasure completion.
