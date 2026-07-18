#!/bin/sh
set -eu

: "${IDENTITY_URL:?IDENTITY_URL is required}"
: "${METRIC_URL:?METRIC_URL is required}"
: "${PRODUCT_WORKLOAD_TOKEN:?PRODUCT_WORKLOAD_TOKEN is required}"
: "${EMAIL_VERIFIER_TOKEN:?EMAIL_VERIFIER_TOKEN is required}"
: "${PRIVACY_ADMIN_TOKEN:?PRIVACY_ADMIN_TOKEN is required}"
: "${PREFLIGHT_EMAIL:?PREFLIGHT_EMAIL is required}"

identity="${IDENTITY_URL%/}"
metric="${METRIC_URL%/}"
product="linka-plays"
now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
uuid() { python3 -c 'import uuid; print(uuid.uuid4())'; }

curl -fsS "$identity/readyz" >/dev/null
curl -fsS "$metric/healthz" >/dev/null
jwks="$(curl -fsS "$identity/.well-known/jwks.json")"
[ "$(printf '%s' "$jwks" | jq '.keys | length')" -ge 1 ]

installation="$(curl -fsS -X POST "$identity/v1/installations" \
  -H "Authorization: Bearer $PRODUCT_WORKLOAD_TOKEN" \
  -H 'Content-Type: application/json' \
  --data "{\"product_id\":\"$product\",\"platform\":\"staging-preflight\"}")"
installation_key="$(printf '%s' "$installation" | jq -er '.installation_key')"

verification="$(curl -fsS -X POST "$identity/v1/email-verifications" \
  -H "Authorization: Bearer $PRODUCT_WORKLOAD_TOKEN" \
  -H 'Content-Type: application/json' \
  --data "{\"product_id\":\"$product\",\"email\":\"$PREFLIGHT_EMAIL\",\"identity_namespace\":\"account\",\"age_category\":\"adult\",\"installation_key\":\"$installation_key\"}")"
verification_id="$(printf '%s' "$verification" | jq -er '.verification_id')"

curl -fsS -X POST "$identity/v1/internal/email-verifications/$verification_id/verify" \
  -H "Authorization: Bearer $EMAIL_VERIFIER_TOKEN" \
  -H 'Content-Type: application/json' \
  --data "{\"product_id\":\"$product\",\"evidence_id\":\"staging-preflight-$verification_id\"}" >/dev/null

account="$(curl -fsS -X POST "$identity/v1/email-identities" \
  -H "Authorization: Bearer $PRODUCT_WORKLOAD_TOKEN" \
  -H 'Content-Type: application/json' \
  --data "{\"product_id\":\"$product\",\"verification_id\":\"$verification_id\",\"create_account\":true}")"
account_key="$(printf '%s' "$account" | jq -er 'select(.subject_type == "account") | .subject_key')"

token_response="$(curl -fsS -X POST "$identity/v1/tokens" \
  -H "Authorization: Bearer $PRODUCT_WORKLOAD_TOKEN" \
  -H 'Content-Type: application/json' \
  --data "{\"product_id\":\"$product\",\"subject_type\":\"account\",\"subject_key\":\"$account_key\"}")"
access_token="$(printf '%s' "$token_response" | jq -er '.access_token')"
person_key="$(python3 -c 'import base64,json,sys; p=sys.argv[1].split(".")[1]; p += "="*((4-len(p)%4)%4); print(json.loads(base64.urlsafe_b64decode(p))["person_key"])' "$access_token")"

batch_id="$(uuid)"
record_id="$(uuid)"
session_id="$(uuid)"
curl -fsS -X POST "$metric/v2/batches" \
  -H "Authorization: Bearer $access_token" \
  -H "Idempotency-Key: $batch_id" \
  -H 'Content-Type: application/json' \
  --data "{\"schema_version\":2,\"batch_id\":\"$batch_id\",\"scope\":{\"product\":\"$product\",\"subject_key\":\"$account_key\",\"person_key\":\"$person_key\"},\"stream\":\"common\",\"sent_at\":\"$now\",\"records\":[{\"record_id\":\"$record_id\",\"occurred_at\":\"$now\",\"kind\":\"app_started\",\"app_session_id\":\"$session_id\",\"app\":{\"version\":\"preflight\",\"build\":\"1\",\"platform\":\"linux\",\"os_version\":\"test\",\"locale\":\"ru\"}}]}" >/dev/null

privacy_key="$(uuid)"
privacy="$(curl -fsS -X POST "$identity/v1/privacy-requests" \
  -H "Authorization: Bearer $PRODUCT_WORKLOAD_TOKEN" \
  -H "Idempotency-Key: $privacy_key" \
  -H 'Content-Type: application/json' \
  --data "{\"subject_type\":\"account\",\"subject_key\":\"$account_key\",\"request_type\":\"deletion\",\"scope\":\"product\",\"product_id\":\"$product\"}")"
privacy_id="$(printf '%s' "$privacy" | jq -er '.id')"

attempt=0
while [ "$attempt" -lt 60 ]; do
  status="$(curl -fsS "$identity/v1/privacy-requests/$privacy_id" -H "Authorization: Bearer $PRIVACY_ADMIN_TOKEN" | jq -er '.status')"
  [ "$status" = "completed" ] && exit 0
  case "$status" in requested|processing) ;; *) exit 1 ;; esac
  attempt=$((attempt + 1))
  sleep 2
done
exit 1
