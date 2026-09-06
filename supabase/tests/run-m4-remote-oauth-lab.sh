#!/usr/bin/env bash
set -euo pipefail

log() { printf '[m4-remote-oauth] %s\n' "$*"; }
fail() { printf '[m4-remote-oauth] FAIL: %s\n' "$1" >&2; exit 1; }

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"
export SUPABASE_DISABLE_TELEMETRY=1
export PATH="${PROJECT_ROOT}/node_modules/.bin:${PATH}"

HEAD_SHA="$(git rev-parse HEAD)"
TREE_SHA="$(git rev-parse 'HEAD^{tree}')"
[[ -z "$(git status --porcelain --untracked-files=all)" ]] \
  || fail "acceptance worktree must be clean before execution"

TMP_DIR="$(mktemp -d /tmp/supabase-user-mcp-m4.XXXXXX)"
NETWORK_NAME="${M4_DOCKER_NETWORK:-supabase-user-mcp-m4-loopback}"
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
log "Starting pinned synthetic Supabase lifecycle with local OAuth server enabled."
supabase start \
  --workdir "$PROJECT_ROOT" \
  --network-id "$NETWORK_NAME" \
  --exclude "realtime,imgproxy,studio,mailpit,edge-runtime,logflare,vector,supavisor" \
  >/dev/null

log "Resetting migrations and synthetic fixtures."
supabase db reset --workdir "$PROJECT_ROOT" --yes --network-id "$NETWORK_NAME" >/dev/null

log "Running database authorization matrices including OAuth client-claim tests."
S1_DOCKER_NETWORK="$NETWORK_NAME" node scripts/run-policy-lab-catalog-test.mjs

log "Building workspace packages."
npm run build

STATUS_JSON="$(supabase status --workdir "$PROJECT_ROOT" -o json)"
STATUS_PROJECTION="$(
  printf '%s' "$STATUS_JSON" | node -e '
        const s = JSON.parse(require("fs").readFileSync(0, "utf8"));
        const url = s.API_URL || s?.api?.url || "";
        const key = s.PUBLISHABLE_KEY || s?.api?.publishable_key || "";
        const service = s.SERVICE_ROLE_KEY || s?.api?.service_role_key || "";
        const secret = s.JWT_SECRET || s?.auth?.jwt_secret || "";
        const db = s.DB_URL || s?.db?.url || "";
        if (!url || !key || !service || !secret || !db || key.split(".").length === 3) process.exit(2);
        process.stdout.write([url, key, service, secret, db].join("\t"));
      '
)" || fail "local Supabase must expose loopback API, publishable key, service role, JWT secret, and DB URL"
IFS=$'\t' read -r M4_SUPABASE_URL M4_PUBLISHABLE_KEY M4_SERVICE_ROLE_KEY M4_JWT_SECRET M4_DB_URL <<<"$STATUS_PROJECTION"
export M4_SUPABASE_URL M4_PUBLISHABLE_KEY M4_SERVICE_ROLE_KEY M4_JWT_SECRET M4_DB_URL

mint_token() {
  local email="$1"
  local label="$2"
  M2_PUBLISHABLE_KEY="$M4_PUBLISHABLE_KEY" npx tsx test/support/mint-m2-token.ts "${M4_SUPABASE_URL}/auth/v1" "$email" \
    || fail "mint ${label} session through official Auth client"
}

M4_ALICE_TOKEN="$(mint_token 'alice.fixture@example.test' 'alice')"
export M4_ALICE_TOKEN
M4_BOB_TOKEN="$(mint_token 'bob.fixture@example.test' 'bob')"
export M4_BOB_TOKEN
log "Minted synthetic local Auth sessions for consent without printing bearer material."

log "Running real local GoTrue PKCE/consent + remote MCP HTTP tests."
npx vitest run packages/server/src/local-oauth-pkce.e2e.test.ts packages/server/src/remote-http-profile.test.ts

NODE_VERSION="$(node --version)"
NPM_VERSION="$(npm --version)"
SUPABASE_VERSION="$(supabase --version)"
[[ "$(git rev-parse HEAD)" == "$HEAD_SHA" ]] || fail "repository head changed during acceptance"
[[ "$(git rev-parse 'HEAD^{tree}')" == "$TREE_SHA" ]] \
  || fail "repository tree changed during execution"
[[ -z "$(git status --porcelain --untracked-files=all)" ]] \
  || fail "acceptance worktree changed during execution"
printf '{"schema":"supabase-user-mcp.m4-remote-oauth.v1","repositorySha":"%s","treeSha":"%s","node":"%s","npm":"%s","supabase":"%s","oauthServer":"local-cli","dynamicClientRegistration":false,"hostedLiveOAuth":"unmet","downstreamCredential":"unresolved","dataDispatch":"fail-closed","cases":["local-oauth-server-enabled","pkce-s256-consent-approve","pkce-deny","pkce-wrong-verifier","dual-aud-resource-binding","es256-jwks-verify","wrong-client-pre-dispatch","access-token-logout-revocation","inbound-bearer-not-forwarded-to-data-api"],"result":"pass"}\n' \
  "$HEAD_SHA" "$TREE_SHA" "$NODE_VERSION" "$NPM_VERSION" "$SUPABASE_VERSION" \
  > "$TMP_DIR/m4-remote-oauth-receipt.json"
cat "$TMP_DIR/m4-remote-oauth-receipt.json"
log "PASS: local PKCE/JWKS lab complete. Downstream Data API credential remains unresolved; remote dispatch is fail-closed. Hosted live OAuth remains unmet."
