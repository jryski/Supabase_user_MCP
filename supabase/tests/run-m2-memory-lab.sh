#!/usr/bin/env bash
set -euo pipefail

log() { printf '[m2-memory] %s\n' "$*"; }
fail() { printf '[m2-memory] FAIL: %s\n' "$1" >&2; exit 1; }

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"
export SUPABASE_DISABLE_TELEMETRY=1

TMP_DIR="$(mktemp -d /tmp/supabase-user-mcp-m2.XXXXXX)"
NETWORK_NAME="${M2_DOCKER_NETWORK:-supabase-user-mcp-m2-loopback}"
NETWORK_BINDING_OPTION="com.docker.network.bridge.host_binding_ipv4"

cleanup() {
  supabase stop --workdir "$PROJECT_ROOT" --no-backup >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

if docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
  binding="$(docker network inspect --format "{{ index .Options \"${NETWORK_BINDING_OPTION}\" }}" "$NETWORK_NAME")"
  [[ "$binding" == "127.0.0.1" ]] || fail "existing Docker network is not loopback-only"
else
  docker network create --driver bridge \
    --opt "${NETWORK_BINDING_OPTION}=127.0.0.1" "$NETWORK_NAME" >/dev/null
fi

supabase stop --workdir "$PROJECT_ROOT" --no-backup >/dev/null 2>&1 || true
log "Starting pinned synthetic Supabase lifecycle."
supabase start \
  --workdir "$PROJECT_ROOT" \
  --network-id "$NETWORK_NAME" \
  --exclude "realtime,imgproxy,studio,mailpit,edge-runtime,logflare,vector,supavisor" \
  >/dev/null

log "Resetting migrations and synthetic fixtures."
supabase db reset --workdir "$PROJECT_ROOT" --yes --network-id "$NETWORK_NAME" >/dev/null

log "Running database authorization, ACL, mutation, and catalog matrices."
node scripts/run-policy-lab-catalog-test.mjs

STATUS_PROJECTION="$(
  supabase status --workdir "$PROJECT_ROOT" -o json \
    | node -e '
        const s = JSON.parse(require("fs").readFileSync(0, "utf8"));
        const url = s.API_URL || s?.api?.url || "";
        const key = s.PUBLISHABLE_KEY || s?.api?.publishable_key || "";
        if (!url || !key || key.split(".").length === 3) process.exit(2);
        process.stdout.write(`${url}\t${key}`);
      '
)" || fail "local Supabase must expose a non-JWT publishable key"
IFS=$'\t' read -r M2_SUPABASE_URL M2_PUBLISHABLE_KEY <<<"$STATUS_PROJECTION"
export M2_SUPABASE_URL M2_PUBLISHABLE_KEY

mint_token() {
  local email="$1"
  local label="$2"
  local response_file="$TMP_DIR/${label}.json"
  local status
  status="$(curl -sS -o "$response_file" -w '%{http_code}' \
    -X POST "${M2_SUPABASE_URL}/auth/v1/token?grant_type=password" \
    -H "apikey: ${M2_PUBLISHABLE_KEY}" \
    -H "Content-Type: application/json" \
    --data "{\"email\":\"${email}\",\"password\":\"SmpStrongPass!1\"}")"
  [[ "$status" == "200" ]] || fail "mint ${label} session (HTTP ${status})"
  node -e '
    const r = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
    if (typeof r.access_token !== "string") process.exit(1);
    process.stdout.write(r.access_token);
  ' "$response_file"
}

export M2_ALICE_TOKEN="$(mint_token 'alice.fixture@example.test' 'alice')"
export M2_BOB_TOKEN="$(mint_token 'bob.fixture@example.test' 'bob')"
export M2_CHARLIE_TOKEN="$(mint_token 'charlie.fixture@example.test' 'charlie')"
export M2_DANA_TOKEN="$(mint_token 'dana.fixture@example.test' 'dana')"
log "Minted real local Auth sessions without printing bearer material."

log "Running MCP client -> fixed Data API -> SECURITY INVOKER RPC -> PostgreSQL RLS tests."
npx vitest run packages/server/src/m2-local-e2e.test.ts

log "Checking malformed bearer fails before any governed record is returned."
malformed_status="$(curl -sS -o "$TMP_DIR/malformed.json" -w '%{http_code}' \
  -X POST "${M2_SUPABASE_URL}/rest/v1/rpc/authorized_memory_get_v1" \
  -H "apikey: ${M2_PUBLISHABLE_KEY}" \
  -H "Authorization: Bearer definitely.not.a-valid-jwt" \
  -H "Content-Type: application/json" \
  -H "Accept-Profile: memory" \
  -H "Content-Profile: memory" \
  --data '{"id":"mem_01JTESTALPHA000000000001"}')"
[[ ! "$malformed_status" =~ ^2 ]] || fail "malformed bearer unexpectedly reached the RPC"

HEAD_SHA="$(git rev-parse HEAD)"
NODE_VERSION="$(node --version)"
NPM_VERSION="$(npm --version)"
SUPABASE_VERSION="$(supabase --version)"
printf '{"schema":"supabase-user-mcp.m2-acceptance.v1","repositorySha":"%s","node":"%s","npm":"%s","supabase":"%s","cases":["db-rls-matrix","rpc-acl-census","principal-positive","cross-principal-denial","revoked-client-denial","missing-client-denial","hostile-content-boundary","malformed-bearer-denial"],"result":"pass"}\n' \
  "$HEAD_SHA" "$NODE_VERSION" "$NPM_VERSION" "$SUPABASE_VERSION" \
  > "$TMP_DIR/m2-acceptance-receipt.json"
cat "$TMP_DIR/m2-acceptance-receipt.json"
log "PASS: M2 synthetic acceptance complete."
