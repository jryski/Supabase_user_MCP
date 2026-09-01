#!/usr/bin/env bash
set -euo pipefail

log() { printf '[m2-memory] %s\n' "$*"; }
fail() { printf '[m2-memory] FAIL: %s\n' "$1" >&2; exit 1; }

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"
export SUPABASE_DISABLE_TELEMETRY=1

HEAD_SHA="$(git rev-parse HEAD)"
TREE_SHA="$(git rev-parse 'HEAD^{tree}')"
[[ -z "$(git status --porcelain --untracked-files=all)" ]] \
  || fail "acceptance worktree must be clean before execution"
if [[ -n "${M2_EXPECTED_HEAD_SHA:-}" && "$HEAD_SHA" != "$M2_EXPECTED_HEAD_SHA" ]]; then
  fail "repository head does not match the requested acceptance head"
fi
BASE_SHA="${M2_EXPECTED_BASE_SHA:-}"
if [[ -n "$BASE_SHA" && ! "$BASE_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  fail "requested acceptance base is not a full Git SHA"
fi
BASE_JSON="null"
if [[ -n "$BASE_SHA" ]]; then
  git cat-file -e "${BASE_SHA}^{commit}" 2>/dev/null || fail "acceptance base commit is unavailable"
  git merge-base --is-ancestor "$BASE_SHA" "$HEAD_SHA" \
    || fail "acceptance base is not an ancestor of the acceptance head"
  BASE_JSON="\"${BASE_SHA}\""
fi

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
S1_DOCKER_NETWORK="$NETWORK_NAME" node scripts/run-policy-lab-catalog-test.mjs

log "Building workspace packages for focused M2 imports."
npm run build

log "Verifying protected startup credentials reject malformed and expired tokens."
npx vitest run packages/server/src/local-credential-loader.test.ts

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
  npx tsx test/support/mint-m2-token.ts "${M2_SUPABASE_URL}/auth/v1" "$email" \
    || fail "mint ${label} session through official Auth client"
}

M2_ALICE_TOKEN="$(mint_token 'alice.fixture@example.test' 'alice')"
export M2_ALICE_TOKEN
M2_BOB_TOKEN="$(mint_token 'bob.fixture@example.test' 'bob')"
export M2_BOB_TOKEN
M2_CHARLIE_TOKEN="$(mint_token 'charlie.fixture@example.test' 'charlie')"
export M2_CHARLIE_TOKEN
M2_DANA_TOKEN="$(mint_token 'dana.fixture@example.test' 'dana')"
export M2_DANA_TOKEN
for token_name in M2_ALICE_TOKEN M2_BOB_TOKEN M2_CHARLIE_TOKEN M2_DANA_TOKEN; do
  [[ -n "${!token_name:-}" ]] || fail "required local Auth token was not minted"
done
log "Minted real local Auth sessions through official auth-js without printing bearer material."

log "Censusing the authenticated PostgREST OpenAPI surface outside the model-visible tool surface."
npx tsx test/support/check-m2-postgrest-surface.ts \
  > "$TMP_DIR/postgrest-surface-census.json"

log "Running MCP client -> fixed Data API -> SECURITY INVOKER RPC -> PostgreSQL RLS and complete-frame tests."
npx vitest run packages/server/src/m2-local-e2e.test.ts packages/server/src/read-only-server.test.ts

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

NODE_VERSION="$(node --version)"
NPM_VERSION="$(npm --version)"
SUPABASE_VERSION="$(supabase --version)"
[[ "$(git rev-parse HEAD)" == "$HEAD_SHA" ]] || fail "repository head changed during acceptance"
[[ "$(git rev-parse 'HEAD^{tree}')" == "$TREE_SHA" ]] \
  || fail "repository tree changed during acceptance"
[[ -z "$(git status --porcelain --untracked-files=all)" ]] \
  || fail "acceptance worktree changed during execution"
printf '{"schema":"supabase-user-mcp.m2-acceptance.v1","repositorySha":"%s","treeSha":"%s","baseSha":%s,"node":"%s","npm":"%s","supabase":"%s","cases":["db-rls-matrix","rpc-acl-census","official-auth-js-sign-in","postgrest-openapi-surface-census","auth-user-verification","principal-positive","principal-limiter-scope","cross-principal-denial","revoked-client-denial","missing-client-denial","expired-credential-denial","malformed-credential-file-denial","hostile-content-boundary","complete-frame-budget","malformed-bearer-denial"],"result":"pass"}\n' \
  "$HEAD_SHA" "$TREE_SHA" "$BASE_JSON" "$NODE_VERSION" "$NPM_VERSION" "$SUPABASE_VERSION" \
  > "$TMP_DIR/m2-acceptance-receipt.json"
cat "$TMP_DIR/m2-acceptance-receipt.json"
log "PASS: M2 synthetic acceptance complete."
