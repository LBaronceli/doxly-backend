#!/usr/bin/env bash
set -euo pipefail

AUTH_BASE="http://localhost:8081"
CUSTOMER_BASE="http://localhost:8082"
ATTACH_BASE="http://localhost:8083"
S3_CONSOLE="http://localhost:9001"
MINIO_HINT="(MinIO console is at $S3_CONSOLE)"

email1="admin+e04e8921@acme.test"
pass1="changeme123"
org1="Acme E2E Inc"

email2="admin+e2e2@beta.test"
pass2="changeme123"
org2="Beta E2E LLC"

say() { printf "\n\033[1m▶ %s\033[0m\n" "$*"; }
ok()  { printf "\033[32m✔ %s\033[0m\n" "$*"; }
warn(){ printf "\033[33m! %s\033[0m\n" "$*"; }
die(){ printf "\033[31m✘ %s\033[0m\n" "$*"; exit 1; }

jqbin="jq"
command -v jq >/dev/null 2>&1 || jqbin="python3 -c 'import sys,json; print(json.dumps(json.load(sys.stdin)))'"

wait_ready () {
  local url=$1 name=$2 tries=60
  say "Waiting for $name to be ready at $url ..."
  for i in $(seq 1 $tries); do
    if curl -fsS "$url" >/dev/null; then ok "$name ready"; return 0; fi
    sleep 1
  done
  die "$name not ready after $tries seconds"
}

# 0) Health / readiness
wait_ready "$AUTH_BASE/healthz"       "auth"
wait_ready "$CUSTOMER_BASE/healthz"   "customer"
wait_ready "$ATTACH_BASE/healthz"     "attachments"

say "Check auth JWKS"
curl -fsS "$AUTH_BASE/.well-known/jwks.json" | $jqbin >/dev/null && ok "JWKS served"

# 1) Sign up org #1 (admin)
say "Signup org #1 admin"
TOKEN1=$(
  curl -fsS -X POST "$AUTH_BASE/v1/signup" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$email1\",\"password\":\"$pass1\",\"org_name\":\"$org1\"}" \
  | jq -r .token
)
test -n "$TOKEN1" || die "signup token empty"
ok "Signed up & received token (org #1)"

say "GET /v1/me with TOKEN1"
curl -fsS -H "Authorization: Bearer $TOKEN1" "$AUTH_BASE/v1/me" | jq .
ok "/v1/me ok"

# 2) Login (org #1)
say "Login org #1"
LOGIN1=$(
  curl -fsS -X POST "$AUTH_BASE/v1/login" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$email1\",\"password\":\"$pass1\"}"
)
TOKEN1B=$(echo "$LOGIN1" | jq -r .token)
test -n "$TOKEN1B" || die "login token empty"
ok "Login token acquired (org #1)"

# 3) Customer CRUD in org #1
say "Create customer in org #1"
CID=$(
  curl -fsS -X POST "$CUSTOMER_BASE/v1/customers" \
    -H "Authorization: Bearer $TOKEN1B" \
    -H "Content-Type: application/json" \
    -d '{"name":"Bruce Wayne","email":"bruce@wayne.enterprises","phone":"+1-555-1234","notes":"VIP"}' \
  | jq -r .id
)
test -n "$CID" || die "customer id empty"
ok "Customer created id=$CID"

say "List customers (limit=10)"
curl -fsS -H "Authorization: Bearer $TOKEN1B" "$CUSTOMER_BASE/v1/customers?limit=10" | jq .
ok "List customers ok"

say "Get customer"
curl -fsS -H "Authorization: Bearer $TOKEN1B" "$CUSTOMER_BASE/v1/customers/$CID" | jq .
ok "Get customer ok"

say "Update customer"
curl -fsS -X PUT "$CUSTOMER_BASE/v1/customers/$CID" \
  -H "Authorization: Bearer $TOKEN1B" -H "Content-Type: application/json" \
  -d '{"name":"Bruce W.","notes":"updated"}' | jq .
ok "Update customer ok"

# 4) Attachments flow in org #1
say "Presign upload URL ($MINIO_HINT)"
PRESIGN=$(
  curl -fsS -X POST "$ATTACH_BASE/v1/customers/$CID/attachments/presign" \
    -H "Authorization: Bearer $TOKEN1B" -H "Content-Type: application/json" \
    -d '{"filename":"hello.txt","content_type":"text/plain","size":12}'
)
echo "$PRESIGN" | jq .
URL=$(echo "$PRESIGN" | jq -r .url)
OBJ=$(echo "$PRESIGN" | jq -r .object_key)
test -n "$URL" || die "presign url empty"

say "Upload to MinIO via presigned PUT"
echo "hello world!" > hello.txt
curl -fsS -i -X PUT --data-binary @hello.txt "$URL" | sed -n '1,10p'
ok "PUT to MinIO ok"

say "Confirm upload"
CONFIRM=$(
  curl -fsS -X POST "$ATTACH_BASE/v1/customers/$CID/attachments/confirm" \
    -H "Authorization: Bearer $TOKEN1B" -H "Content-Type: application/json" \
    -d "{\"object_key\":\"$OBJ\",\"filename\":\"hello.txt\",\"content_type\":\"text/plain\"}"
)
echo "$CONFIRM" | jq .
ok "Confirm ok"

say "List attachments"
curl -fsS -H "Authorization: Bearer $TOKEN1B" "$ATTACH_BASE/v1/customers/$CID/attachments?limit=10" | jq .
ok "List attachments ok"

# 5) Negative: no token → 401
say "Negative: /v1/customers without token (expect 401)"
code=$(curl -s -o /dev/null -w "%{http_code}" "$CUSTOMER_BASE/v1/customers?limit=1")
test "$code" = "401" || die "expected 401, got $code"
ok "401 enforced without token"

# 6) Cross-tenant isolation
say "Create org #2 and try to read org #1 customer"
TOKEN2=$(
  curl -fsS -X POST "$AUTH_BASE/v1/signup" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$email2\",\"password\":\"$pass2\",\"org_name\":\"$org2\"}" \
  | jq -r .token
)
test -n "$TOKEN2" || die "org2 signup token empty"
code=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN2" "$CUSTOMER_BASE/v1/customers/$CID")
# Depending on your handler it can be 404 or 403; both prove isolation.
if [[ "$code" == "404" || "$code" == "403" ]]; then
  ok "Cross-tenant isolation enforced ($code)"
else
  die "expected 403/404 for cross-tenant, got $code"
fi

# 7) Delete customer (org #1) and verify gone
say "Delete customer"
code=$(curl -s -o /dev/null -w "%{http_code}" \
  -X DELETE -H "Authorization: Bearer $TOKEN1B" "$CUSTOMER_BASE/v1/customers/$CID")
test "$code" = "204" || die "expected 204 delete, got $code"
ok "Customer deleted"

say "Verify deleted"
code=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN1B" "$CUSTOMER_BASE/v1/customers/$CID")
test "$code" = "404" || die "expected 404 after delete, got $code"
ok "Verified delete"

say "E2E ✅  All good!"
