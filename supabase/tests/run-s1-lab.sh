#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '[s1-lab] %s\n' "$*"
}

pass() {
  TESTS_PASSED=$((TESTS_PASSED + 1))
  log "PASS: $1"
}

fail() {
  printf '[s1-lab] FAIL: %s\n' "$1" >&2
  exit 1
}

assert_success() {
  local name="$1"
  local status="$2"
  [[ "$status" =~ ^20[01]$ ]] || fail "$name (HTTP $status)"
  pass "$name"
}

assert_denied() {
  local name="$1"
  local status="$2"
  [[ ! "$status" =~ ^2 ]] || fail "$name (unexpected HTTP $status)"
  pass "$name"
}

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"

export SUPABASE_DISABLE_TELEMETRY=1

TESTS_PASSED=0
TMP_DIR="$(mktemp -d /tmp/supabase-s1-lab.XXXXXX)"
NETWORK_NAME="${S1_DOCKER_NETWORK:-supabase-s1-loopback}"
NETWORK_BINDING_OPTION="com.docker.network.bridge.host_binding_ipv4"

cleanup() {
  supabase stop --workdir "$PROJECT_ROOT" --no-backup >/dev/null 2>&1 || true
  rm -R "$TMP_DIR"
}
trap cleanup EXIT

if docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
  NETWORK_BINDING="$(docker network inspect --format "{{ index .Options \"${NETWORK_BINDING_OPTION}\" }}" "$NETWORK_NAME")"
  [[ "$NETWORK_BINDING" == "127.0.0.1" ]] \
    || fail "Docker network ${NETWORK_NAME} is not loopback-only"
else
  log "Creating loopback-only Docker network ${NETWORK_NAME}."
  docker network create \
    --driver bridge \
    --opt "${NETWORK_BINDING_OPTION}=127.0.0.1" \
    "$NETWORK_NAME" >/dev/null
fi

supabase stop --workdir "$PROJECT_ROOT" --no-backup >/dev/null 2>&1 || true

log "Starting the minimal local Supabase stack."
supabase start \
  --workdir "$PROJECT_ROOT" \
  --network-id "$NETWORK_NAME" \
  --exclude "realtime,imgproxy,studio,mailpit,edge-runtime,logflare,vector,supavisor" \
  >/dev/null

log "Resetting and seeding synthetic Prompt 1 fixtures."
supabase db reset \
  --workdir "$PROJECT_ROOT" \
  --yes \
  --network-id "$NETWORK_NAME" \
  >/dev/null

log "Running the policy-lab pgTAP matrix."
supabase test db \
  --workdir "$PROJECT_ROOT" \
  --local \
  --network-id "$NETWORK_NAME"

if docker inspect \
  supabase_kong_supabase-user-mcp-s1 \
  supabase_db_supabase-user-mcp-s1 \
  | node -e '
      const containers = JSON.parse(require("fs").readFileSync(0, "utf8"));
      const bindings = containers.flatMap((container) =>
        Object.values(container.NetworkSettings.Ports || {}).flatMap((entries) => entries || [])
      );
      const hostPorts = new Set(bindings.map((entry) => entry.HostPort));
      if (
        bindings.some((entry) => entry.HostIp !== "127.0.0.1")
        || !hostPorts.has("62421")
        || !hostPorts.has("62422")
      ) {
        process.exit(1);
      }
    '
then
  pass "local services bind only to 127.0.0.1"
else
  fail "local services bind only to 127.0.0.1"
fi

STATUS_PROJECTION="$(
  supabase status --workdir "$PROJECT_ROOT" -o json \
    | node -e '
        const status = JSON.parse(require("fs").readFileSync(0, "utf8"));
        const url = status.API_URL || status?.api?.url || "";
        const key = status.PUBLISHABLE_KEY || status.ANON_KEY || status?.api?.public_key || "";
        process.stdout.write(`${url}\t${key}`);
      '
)"
IFS=$'\t' read -r SUPABASE_URL SUPABASE_PUBLISHABLE_KEY <<<"$STATUS_PROJECTION"
[[ -n "$SUPABASE_URL" && -n "$SUPABASE_PUBLISHABLE_KEY" ]] \
  || fail "read local publishable API coordinates"

mint_token() {
  local email="$1"
  local label="$2"
  local response_file="$TMP_DIR/auth-${label}.json"
  local status

  status="$(curl -sS -o "$response_file" -w '%{http_code}' \
    -X POST "${SUPABASE_URL}/auth/v1/token?grant_type=password" \
    -H "apikey: ${SUPABASE_PUBLISHABLE_KEY}" \
    -H "Content-Type: application/json" \
    --data "{\"email\":\"${email}\",\"password\":\"SmpStrongPass!1\"}")"
  if [[ "$status" != "200" ]]; then
    local auth_error
    auth_error="$(node -e '
      const response = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
      process.stdout.write(response.error_description || response.msg || response.message || response.error || "unknown Auth error");
    ' "$response_file")"
    docker logs --tail 80 supabase_auth_supabase-user-mcp-s1 >&2 || true
    fail "mint ${label} authenticated session (HTTP ${status}: ${auth_error})"
  fi

  node -e '
    const response = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
    if (!response.access_token) process.exit(1);
    process.stdout.write(response.access_token);
  ' "$response_file"
}

ALICE_TOKEN="$(mint_token 'alice.fixture@example.test' 'alice')"
BOB_TOKEN="$(mint_token 'bob.fixture@example.test' 'bob')"
CHARLIE_TOKEN="$(mint_token 'charlie.fixture@example.test' 'charlie')"
DANA_TOKEN="$(mint_token 'dana.fixture@example.test' 'dana')"
LOADER_TOKEN="$(mint_token 'loader.fixture@example.test' 'loader')"
pass "real Supabase Auth sessions minted for synthetic users"

upload_fixture() {
  local bucket="$1"
  local object_key="$2"
  local body="$3"
  local label="$4"
  local status

  status="$(curl -sS -o "$TMP_DIR/upload-${label}.json" -w '%{http_code}' \
    -X POST "${SUPABASE_URL}/storage/v1/object/${bucket}/${object_key}" \
    -H "apikey: ${SUPABASE_PUBLISHABLE_KEY}" \
    -H "Authorization: Bearer ${LOADER_TOKEN}" \
    -H "Content-Type: text/plain" \
    --data-binary "$body")"
  assert_success "fixture upload: ${label}" "$status"
}

upload_fixture 'artifact-lab' 'authorized.txt' 'authorized synthetic fixture' 'authorized'
upload_fixture 'artifact-lab' 'wrong-principal.txt' 'bob artifact' 'wrong-principal'
upload_fixture 'artifact-lab' 'expired.txt' 'expired artifact' 'expired'
upload_fixture 'artifact-lab' 'present-unregistered.txt' 'unregistered object' 'unregistered'
upload_fixture 'artifact-lab' 'mutated-after-reg.txt' 'mutated-content!' 'mutated'
upload_fixture 'artifact-outside' 'outside.txt' 'outside bucket' 'outside-bucket'

storage_get() {
  local token="$1"
  local bucket="$2"
  local object_key="$3"
  local output_file="$4"

  curl -sS -o "$output_file" -w '%{http_code}' \
    "${SUPABASE_URL}/storage/v1/object/${bucket}/${object_key}" \
    -H "apikey: ${SUPABASE_PUBLISHABLE_KEY}" \
    -H "Authorization: Bearer ${token}"
}

AUTHORIZED_STATUS="$(storage_get "$ALICE_TOKEN" 'artifact-lab' 'authorized.txt' "$TMP_DIR/authorized.body")"
assert_success "authorized read succeeds" "$AUTHORIZED_STATUS"
[[ "$(<"$TMP_DIR/authorized.body")" == 'authorized synthetic fixture' ]] \
  || fail "authorized read returns exact bytes"
pass "authorized read returns exact bytes"

STORAGE_FIXTURE_COUNT="$(psql 'postgresql://postgres:postgres@127.0.0.1:62422/postgres' -X -Atc "
  select count(*)
  from storage.objects
  where bucket_id in ('artifact-lab', 'artifact-outside');
")"
[[ "$STORAGE_FIXTURE_COUNT" == "6" ]] || fail "Storage fixtures exist before list non-enumeration probe"
pass "Storage fixtures exist before list non-enumeration probe"

WRONG_PRINCIPAL_STATUS="$(storage_get "$ALICE_TOKEN" 'artifact-lab' 'wrong-principal.txt' "$TMP_DIR/wrong-principal.body")"
assert_denied "wrong principal denied" "$WRONG_PRINCIPAL_STATUS"

EXPIRED_STATUS="$(storage_get "$ALICE_TOKEN" 'artifact-lab' 'expired.txt' "$TMP_DIR/expired.body")"
assert_denied "expired row denied" "$EXPIRED_STATUS"

UNREGISTERED_STATUS="$(storage_get "$ALICE_TOKEN" 'artifact-lab' 'present-unregistered.txt' "$TMP_DIR/unregistered.body")"
assert_denied "object with no registry row denied" "$UNREGISTERED_STATUS"

OUTSIDE_STATUS="$(storage_get "$ALICE_TOKEN" 'artifact-outside' 'outside.txt' "$TMP_DIR/outside.body")"
assert_denied "object outside fixed bucket denied" "$OUTSIDE_STATUS"

LIST_STATUS="$(curl -sS -o "$TMP_DIR/list.body" -w '%{http_code}' \
  -X POST "${SUPABASE_URL}/storage/v1/object/list/artifact-lab" \
  -H "apikey: ${SUPABASE_PUBLISHABLE_KEY}" \
  -H "Authorization: Bearer ${ALICE_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{"prefix":"","limit":100,"offset":0}')"
LIST_COUNT="$(node -e '
  const rows = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
  process.stdout.write(String(Array.isArray(rows) ? rows.length : -1));
' "$TMP_DIR/list.body")"
[[ "$LIST_STATUS" == "200" && "$LIST_COUNT" == "0" ]] \
  || fail "list enumeration exposes no objects while get succeeds"
pass "list enumeration exposes no objects while get succeeds"

WRONG_CLIENT_STATUS="$(storage_get "$CHARLIE_TOKEN" 'artifact-lab' 'authorized.txt' "$TMP_DIR/wrong-client.body")"
assert_denied "wrong client capability claim denied" "$WRONG_CLIENT_STATUS"

ABSENT_CLIENT_STATUS="$(storage_get "$DANA_TOKEN" 'artifact-lab' 'authorized.txt' "$TMP_DIR/absent-client.body")"
assert_denied "absent client capability claim denied" "$ABSENT_CLIENT_STATUS"
pass "direct Storage access with valid non-inspector user JWT denied"

MISSING_STATUS="$(storage_get "$ALICE_TOKEN" 'artifact-lab' 'registered-missing.txt' "$TMP_DIR/missing.body")"
[[ "$MISSING_STATUS" == "$WRONG_PRINCIPAL_STATUS" ]] \
  || fail "missing and unauthorized status codes are identical"
cmp -s "$TMP_DIR/missing.body" "$TMP_DIR/wrong-principal.body" \
  || fail "missing and unauthorized response bodies are byte-identical"
pass "missing and unauthorized errors are byte-identical"

BOB_STATUS="$(storage_get "$BOB_TOKEN" 'artifact-lab' 'wrong-principal.txt' "$TMP_DIR/bob.body")"
assert_success "second approved principal reads only own object" "$BOB_STATUS"

DERIVATION_RESPONSE="$(curl -sS \
  "${SUPABASE_URL}/rest/v1/derivation_inputs?select=source_artifact_id&derivation_id=eq.12345678-1234-4123-8123-1234567890ab" \
  -H "apikey: ${SUPABASE_PUBLISHABLE_KEY}" \
  -H "Authorization: Bearer ${ALICE_TOKEN}")"
DERIVATION_COUNT="$(node -e 'const rows=JSON.parse(process.argv[1]); process.stdout.write(String(rows.length));' "$DERIVATION_RESPONSE")"
[[ "$DERIVATION_COUNT" == "2" ]] || fail "many-source derivation exposes both authorized inputs"
pass "many-source derivation supports two inputs"

EXPECTED_HASH_RESPONSE="$(curl -sS \
  "${SUPABASE_URL}/rest/v1/artifact_registry?select=sha256_full&artifact_id=eq.ffffffff-ffff-4fff-8fff-ffffffffffff" \
  -H "apikey: ${SUPABASE_PUBLISHABLE_KEY}" \
  -H "Authorization: Bearer ${ALICE_TOKEN}")"
EXPECTED_HASH="$(node -e '
  const rows = JSON.parse(process.argv[1]);
  const value = rows[0]?.sha256_full || "";
  process.stdout.write(value.replace(/^\\x/, ""));
' "$EXPECTED_HASH_RESPONSE")"
MUTATED_STATUS="$(storage_get "$ALICE_TOKEN" 'artifact-lab' 'mutated-after-reg.txt' "$TMP_DIR/mutated.body")"
assert_success "mutated object reaches verifier under authorized RLS" "$MUTATED_STATUS"
ACTUAL_HASH="$(shasum -a 256 "$TMP_DIR/mutated.body" | awk '{print $1}')"
[[ -n "$EXPECTED_HASH" && "$ACTUAL_HASH" != "$EXPECTED_HASH" ]] \
  || fail "mutated object hash mismatch detected"
rm "$TMP_DIR/mutated.body"
[[ ! -e "$TMP_DIR/mutated.body" ]] || fail "mutated payload withheld"
pass "object mutated after registration fails hash verification closed"

ACTUAL_API_GRANTS="$(psql 'postgresql://postgres:postgres@127.0.0.1:62422/postgres' -X -Atc "
  select coalesce(
    string_agg(
      grantee || ':' || table_name || ':' || privilege_type,
      E'\\n' order by grantee, table_name, privilege_type
    ),
    ''
  )
  from information_schema.role_table_grants
  where table_schema = 'public'
    and table_name in (
      'approved_inspector_clients',
      'artifact_registry',
      'artifact_chunks',
      'artifact_derivations',
      'derivation_inputs'
    )
    and grantee in ('anon', 'authenticated', 'service_role');
")"
EXPECTED_API_GRANTS=$'authenticated:approved_inspector_clients:SELECT\nauthenticated:artifact_chunks:SELECT\nauthenticated:artifact_derivations:SELECT\nauthenticated:artifact_registry:SELECT\nauthenticated:derivation_inputs:SELECT'
[[ "$ACTUAL_API_GRANTS" == "$EXPECTED_API_GRANTS" ]] \
  || fail "API-role table privileges match the exact SELECT-only allowlist"
pass "API-role table privileges match the exact SELECT-only allowlist"

if psql 'postgresql://postgres:postgres@127.0.0.1:62422/postgres' \
  -X -v ON_ERROR_STOP=1 \
  -c "begin; set local role authenticated; truncate table public.artifact_registry cascade; rollback;" \
  >"$TMP_DIR/truncate-probe.log" 2>&1
then
  fail "authenticated TRUNCATE is denied"
else
  pass "authenticated TRUNCATE is denied"
fi

CLIENT_TABLE_RLS="$(psql 'postgresql://postgres:postgres@127.0.0.1:62422/postgres' -X -Atc "
  select relrowsecurity::int
  from pg_class
  where oid = 'public.approved_inspector_clients'::regclass;
")"
[[ "$CLIENT_TABLE_RLS" == "1" ]] || fail "approved inspector clients table has RLS enabled"
pass "approved inspector clients table has RLS enabled"

if supabase db advisors \
  --workdir "$PROJECT_ROOT" \
  --local \
  --type security \
  --level warn \
  --fail-on warn \
  >"$TMP_DIR/security-advisor.json"
then
  pass "Supabase security advisor reports no warnings or errors"
else
  fail "Supabase security advisor reports no warnings or errors"
fi

log "S1 lab complete: ${TESTS_PASSED} named assertions passed; local stack will now stop."
