#!/usr/bin/env bash
# Disposable loopback dual-grant evidence. Requires Docker and local Supabase.
# Does not open ordinary remote dispatch, does not merge, and does not complete
# issue #62. A missing Docker daemon skips the live run and does not record a pass.
set -euo pipefail

log() { printf '[lab-dual-grant-m4] %s\n' "$*"; }
fail() { printf '[lab-dual-grant-m4] FAIL: %s\n' "$1" >&2; exit 1; }

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"
export SUPABASE_DISABLE_TELEMETRY=1
export PATH="${PROJECT_ROOT}/node_modules/.bin:${PATH}"

if ! docker info >/dev/null 2>&1; then
  log "SKIP: Docker daemon is not available. Live dual-grant M4 was not run."
  exit 2
fi

HEAD_SHA="$(git rev-parse HEAD)"
TREE_SHA="$(git rev-parse 'HEAD^{tree}')"
[[ -z "$(git status --porcelain --untracked-files=all)" ]] \
  || fail "acceptance worktree must be clean before execution"

TMP_DIR="$(mktemp -d /tmp/supabase-user-mcp-lab-dual-grant-m4.XXXXXX)"
NETWORK_NAME="${LAB_DUAL_GRANT_M4_DOCKER_NETWORK:-supabase-user-mcp-lab-dual-grant-m4}"
NETWORK_BINDING_OPTION="com.docker.network.bridge.host_binding_ipv4"
RECEIPT_PATH="$TMP_DIR/lab-dual-grant-m4-receipt.json"

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
log "Starting pinned local Supabase on the loopback Docker network."
supabase start \
  --workdir "$PROJECT_ROOT" \
  --network-id "$NETWORK_NAME" \
  --exclude "realtime,imgproxy,studio,mailpit,edge-runtime,logflare,vector,supavisor" \
  >/dev/null

log "Resetting migrations and synthetic fixtures."
supabase db reset --workdir "$PROJECT_ROOT" --yes --network-id "$NETWORK_NAME" >/dev/null

log "Building workspace packages."
npm run build

STATUS_JSON="$(supabase status --workdir "$PROJECT_ROOT" -o json)"
STATUS_PROJECTION="$(
  printf '%s' "$STATUS_JSON" | node -e '
        const s = JSON.parse(require("fs").readFileSync(0, "utf8"));
        const url = s.API_URL || s?.api?.url || "";
        const key = s.PUBLISHABLE_KEY || s?.api?.publishable_key || "";
        const service = s.SERVICE_ROLE_KEY || s?.api?.service_role_key || "";
        const db = s.DB_URL || s?.db?.url || "";
        if (!url || !key || !service || !db || key.split(".").length === 3) process.exit(2);
        for (const value of [url, db]) {
          const parsed = new URL(value);
          if (parsed.hostname !== "127.0.0.1") process.exit(3);
        }
        process.stdout.write([url, key, service, db].join("\t"));
      '
)" || fail "local Supabase must expose loopback API, publishable key, service role, and DB URL"
IFS=$'\t' read -r M4_SUPABASE_URL M4_PUBLISHABLE_KEY M4_SERVICE_ROLE_KEY M4_DB_URL <<<"$STATUS_PROJECTION"
export M4_SUPABASE_URL M4_PUBLISHABLE_KEY M4_SERVICE_ROLE_KEY M4_DB_URL
export LAB_DUAL_GRANT_M4_RECEIPT_PATH="$RECEIPT_PATH"

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

log "Running live dual-grant loopback evidence. Ordinary remote dispatch stays fail-closed."
npx vitest run packages/server/src/lab-dual-grant-m4.e2e.test.ts

[[ "$(git rev-parse HEAD)" == "$HEAD_SHA" ]] || fail "repository head changed during acceptance"
[[ "$(git rev-parse 'HEAD^{tree}')" == "$TREE_SHA" ]] \
  || fail "repository tree changed during execution"
[[ -z "$(git status --porcelain --untracked-files=all)" ]] \
  || fail "acceptance worktree changed during execution"
[[ -f "$RECEIPT_PATH" ]] || fail "secret-free receipt was not written"
node -e '
  const fs = require("fs");
  const receipt = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  if (receipt.result !== "pass") process.exit(2);
  if (receipt.ordinaryRemoteProfile?.dataDispatch !== "fail-closed") process.exit(3);
  if (receipt.labDualGrantProfile?.dataDispatch !== "loopback-lab-only") process.exit(4);
  if (receipt.externalMcpBinary !== false || receipt.hostedLiveOAuth !== "unmet") process.exit(5);
  if (JSON.stringify(receipt).includes("eyJ")) process.exit(6);
' "$RECEIPT_PATH" || fail "receipt did not match the secret-free loopback contract"
cat "$RECEIPT_PATH"
log "PASS: loopback dual-grant evidence receipt written. Ordinary remote dispatch stayed fail-closed."
