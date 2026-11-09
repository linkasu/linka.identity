# Public product-scoped account deletion (v1)

Both endpoints use the existing public CORS policy, strict JSON bodies, Bearer
credentials and `Cache-Control: no-store`. They accept no query parameters.
They do not expose root account/person/privacy request IDs or offer all-product
deletion. No administrative credential belongs on the client.

Before transmitting anything, the client must durably save a fresh request UUID
and a cryptographically random 32-byte `status_secret` encoded as canonical,
unpadded base64url (43 characters). The UUID is not a secret. Keep the status
secret private and out of logs, URLs, analytics and crash reports.

## Create

`POST /v1/public/account-deletions`, authenticated with an account access JWT:

```json
{"request_id":"<client UUID>","status_secret":"<32 random bytes, base64url>"}
```

The signed JWT and authoritative active session select the account and product.
The server verifies the signed pairwise account subject, then rechecks the
session, product and expected account within the serializable privacy creation
transaction. Creation uses the existing person/product privacy fanout and outbox.
Pending deletion immediately fences ordinary account sessions.

HTTP 202 means requested, **not completed**. After a timeout or uncertain result,
use the status endpoint; do not blindly repeat the destructive POST. Replaying
creation may fail authentication once pending deletion fences the session.

## Read status

`POST /v1/public/account-deletions/status`, with `Authorization: Bearer <status_secret>`:

```json
{"request_id":"<same client UUID>","product_id":"<product>"}
```

This read-only capability cannot create a deletion. It remains usable after
session revocation and account/installation erasure. Only its domain-separated
SHA-256 digest is stored, in existing privacy idempotency records under a
namespace containing the product and client request UUID. No schema changes.

## Response (both endpoints)

```json
{"contract_version":1,"product":"plays","request_id":"<client UUID>","status":"requested","requested_at":"2026-11-09T12:00:00Z"}
```

Status is exactly `requested`, `processing`, `completed`, `rejected` or
`cancelled`; `completed_at` is optional. Status HTTP 200 reports the actual
orchestrator state; only `completed` means erasure finished. Other products
are outside this request's scope.

Malformed bodies/fields return 400, invalid credentials 401, conflicts 409.
Unknown status capability/request/product combinations return the same generic
404 (a malformed capability returns 401). Unknown outcomes must not be presented
as completed or trigger an automatic new deletion request.
