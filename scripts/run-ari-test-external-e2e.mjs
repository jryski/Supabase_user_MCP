/**
 * Parent orchestration for the TEST-only external client.
 * Default command is `plan`. It does not open a socket and does not contact
 * hosted TEST. `run` stays closed unless the controller sets the G5 gates
 * and ARI_LANE_B_EXECUTE=1. The child receives no bearer, refresh token,
 * password, or admin credential. The parent performs first-party consent
 * for external A and downstream B. Stdin accepts only the line `continue`.
 */
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { createInterface } from 'node:readline';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { performLoopbackConsent } from '../docs/evidence/ari-test-probe/consent-harness.mjs';
import { SYNTHETIC_EMAIL } from '../docs/evidence/ari-test-probe/decisions.mjs';
import { assertIpcHasNoSecrets } from './ari-test-external-client.mjs';

const FORBIDDEN = [
  'SUPABASE_SERVICE_ROLE_KEY',
  'SUPABASE_SECRET_KEY',
  'SERVICE_ROLE_KEY',
  'SUPABASE_SERVICE_KEY',
];

const CHILD_CONTEXT = ['PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'TZ'];
const CHILD_ARI = [
  'ARI_EXTERNAL_MCP_URL',
  'ARI_EXTERNAL_A_CLIENT_ID',
  'ARI_EXTERNAL_A_REDIRECT_URI',
  'ARI_LANE_B_TIMEOUT_MS',
];
const SAFE_CODE = /^[a-z0-9_]{1,64}$/;
const JWT_SHAPE = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\./;
const SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const SHA40 = /^[0-9a-f]{40}$/;
const PARENT_SECRET_ENV = [
  'ARI_TEST_SYNTHETIC_PASSWORD',
  'ARI_USER_PASSWORD',
  'ARI_FIRST_PARTY_ACCESS_TOKEN',
  'ARI_TEST_PUBLISHABLE_KEY',
  'ARI_TEST_JWKS_JSON',
  'ARI_TEST_SUPABASE_URL',
];
const CLIENT_SCRIPT = fileURLToPath(new URL('./ari-test-external-client.mjs', import.meta.url));

function coded(code) {
  return Object.assign(new Error(code), { code });
}

function safeCode(value) {
  return typeof value === 'string' && SAFE_CODE.test(value) ? value : 'child_failed';
}

export function controllerPlan() {
  return {
    packet: 'lane-b-external-client',
    profile: 'TEST_ONLY_PUBLIC_PKCE',
    executedByWriter: false,
    hostedContact: false,
    hookInstalled: false,
    acceptance: false,
    laneAClosedAt: '6e142ed510bab5c6b15312e0d25530f5840d0424',
    steps: [
      'Confirm Warden G5 on the exact Lane B commit before any hosted write.',
      'Do not apply sql/02. Do not edit sql/03. Keep the baseline A row.',
      'Apply sql/07, then sql/05, then sql/06 on odbcejsuuqdzhabjmozi only.',
      'If sql/05 raises STOP AND REPORT because auth.sessions is not readable, stop. Do not grant schema auth.',
      'Register external A and TEST-only public PKCE B out of band. No client secret. No openid. No DCR.',
      'N4 is A source-session revocation on a fresh A/B pair. N5 is B-session revocation on a different fresh A/B pair and uses a first-party session. Never run N5 after N4 on the same source session.',
      'After P1–P5 and N1 on the positive pair, start one fresh pair for N4 only, then another fresh pair for N5 only.',
      'Each fresh pair records passwordSessionId, sourceSessionId, and bSessionId on sessionLedger when it reaches P5. Cleanup deletes every id on that ledger.',
      'Keep B live during N4. Keep the A source live during N5. Opposite-state contamination fails that row.',
      'N2, N3, N6, N7, and N8 are not executed by this run.',
      'F1 in sql/06 covers public.ari_probe_marker only. That case is N6 and is not executed here.',
      'node scripts/run-ari-test-external-e2e.mjs plan',
      'Confirm git HEAD equals ARI_LANE_B_G5_HEAD and the tracked worktree is clean, then npm run build immediately before launch.',
      'After that build, set ARI_LANE_B_EXECUTE=1 and run node scripts/run-ari-test-external-e2e.mjs run.',
      'The parent consents for external_a and downstream_b. Do not paste a bearer into the child or stdin.',
      'Answer each fresh-pair revoke controller_action with a stdin line that is exactly continue, only after the target readback is zero and the opposite session is still live.',
    ],
    rollback: [
      'drop function if exists public.ari_probe_source_session_live_v1(uuid, text)',
      'drop policy if exists ari_probe_marker_reject_a_client on public.ari_probe_marker',
      "delete from ari_probe.mcp_client where probe_label = 'ari-test-external-a'",
      'drop table if exists ari_probe.downstream_client',
      're-apply sql/04 function body if the baseline hook must be restored',
    ],
  };
}

export function readActualGitHead(cwd = process.cwd()) {
  try {
    const head = execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    return SHA40.test(head) ? head : undefined;
  } catch {
    return undefined;
  }
}

export function trackedWorktreeDirty(cwd = process.cwd()) {
  try {
    const out = execFileSync('git', ['status', '--porcelain=v1', '--untracked-files=no'], {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    return out.split('\n').some((line) => line.trim().length > 0);
  } catch {
    return true;
  }
}

export function controllerGate(env, git = undefined) {
  for (const name of FORBIDDEN) {
    if (typeof env[name] === 'string' && env[name].length > 0) {
      return { ok: false, reason: 'service_role_refused' };
    }
  }
  if (env.ARI_LANE_B_LIVE !== 'controller-g5') return { ok: false, reason: 'live_gate_closed' };
  if (env.ARI_TEST_PROJECT_REF !== 'odbcejsuuqdzhabjmozi') {
    return { ok: false, reason: 'project_ref_refused' };
  }
  const reviewedHead = env.ARI_LANE_B_G5_HEAD;
  if (typeof reviewedHead !== 'string' || !SHA40.test(reviewedHead)) {
    return { ok: false, reason: 'g5_head_required' };
  }
  const actualHead = git?.actualHead ?? readActualGitHead(git?.cwd);
  if (typeof actualHead !== 'string' || !SHA40.test(actualHead)) {
    return { ok: false, reason: 'g5_head_unreadable' };
  }
  if (actualHead !== reviewedHead) return { ok: false, reason: 'g5_head_mismatch' };
  const trackedDirty = git?.trackedDirty ?? trackedWorktreeDirty(git?.cwd);
  if (trackedDirty) return { ok: false, reason: 'g5_worktree_dirty' };
  return { ok: true, actualHead, reviewedHead };
}

function required(env, name) {
  const value = env[name];
  if (typeof value !== 'string' || value.length === 0) {
    throw coded('live_configuration_incomplete');
  }
  return value;
}

function timeoutMsOf(env) {
  const raw = env.ARI_LANE_B_TIMEOUT_MS;
  if (raw === undefined || raw.length === 0) return 120_000;
  if (!/^\d+$/u.test(raw)) throw coded('live_configuration_incomplete');
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 1000 || value > 180_000) {
    throw coded('live_configuration_incomplete');
  }
  return value;
}

function loopbackUrl(value, pathname, code) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw coded('live_configuration_incomplete');
  }
  if (url.username !== '' || url.password !== '' || url.search !== '' || url.hash !== '') {
    throw coded('live_configuration_incomplete');
  }
  if (url.protocol !== 'http:' || (url.hostname !== '127.0.0.1' && url.hostname !== 'localhost')) {
    throw coded(code);
  }
  if (pathname !== undefined && url.pathname !== pathname) {
    throw coded('live_configuration_incomplete');
  }
  const port = Number(url.port);
  if (!Number.isSafeInteger(port) || port < 1) throw coded('live_configuration_incomplete');
  return url;
}

function copyPlain(env, name, target, max) {
  const value = env[name];
  if (typeof value !== 'string' || value.length === 0 || value.length > max) return;
  if (JWT_SHAPE.test(value) || /\s/u.test(value)) return;
  target[name] = value;
}

export function childEnvironment(env) {
  const next = {};
  for (const name of CHILD_CONTEXT) copyPlain(env, name, next, 4096);
  for (const name of ['NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE']) {
    const value = env[name];
    if (typeof value !== 'string' || !value.startsWith('/') || value.length > 512) continue;
    if (JWT_SHAPE.test(value) || /\s/u.test(value)) continue;
    next[name] = value;
  }
  for (const name of CHILD_ARI) copyPlain(env, name, next, 2048);
  next.ARI_LANE_B_LIVE = 'controller-g5';
  next.ARI_LANE_B_EXECUTE = '1';
  for (const name of FORBIDDEN) delete next[name];
  for (const name of PARENT_SECRET_ENV) delete next[name];
  return next;
}

export function isContinueLine(line) {
  return line === 'continue';
}

function sessionLive(row, now = Date.now()) {
  return row !== undefined && (row.notAfter == null || row.notAfter > now);
}

/**
 * Delete only the requested synthetic-user session, then read it back.
 * N4 keeps the B session. N5 keeps the A source session.
 * Continue is allowed only when the target session and its refresh rows
 * are zero and the opposite session is still present and live.
 * The receipt is UUIDs and counts. It does not carry a bearer.
 */
export function applyControllerRevocation(store, action) {
  const sessions = Array.isArray(store?.sessions) ? store.sessions.map((row) => ({ ...row })) : [];
  const refreshTokens = Array.isArray(store?.refreshTokens)
    ? store.refreshTokens.map((row) => ({ ...row }))
    : sessions.flatMap((row) =>
        Array.from({ length: Number.isInteger(row.refreshRows) ? row.refreshRows : 0 }, () => ({
          sessionId: row.id,
        })),
      );
  const kind = action?.action;
  const sourceSessionId = action?.source_session_id;
  const bSessionId = action?.b_session_id;
  const targetSessionId =
    kind === 'revoke_a_source_session'
      ? sourceSessionId
      : kind === 'revoke_b_session'
        ? bSessionId
        : undefined;
  const oppositeSessionId = kind === 'revoke_a_source_session' ? bSessionId : sourceSessionId;
  const snapshot = (rows, refreshRows) => {
    const opposite = rows.find((row) => row.id === oppositeSessionId);
    return {
      action: kind,
      targetSessionId,
      oppositeSessionId,
      targetSessionRows: rows.filter((row) => row.id === targetSessionId).length,
      targetRefreshRows: refreshRows.filter((row) => row.sessionId === targetSessionId).length,
      oppositeSessionRows: opposite === undefined ? 0 : 1,
      oppositeLive: sessionLive(opposite),
    };
  };
  const unread = snapshot(sessions, refreshTokens);
  if (
    (kind !== 'revoke_a_source_session' && kind !== 'revoke_b_session') ||
    typeof targetSessionId !== 'string' ||
    !SESSION_ID.test(targetSessionId) ||
    typeof oppositeSessionId !== 'string' ||
    !SESSION_ID.test(oppositeSessionId) ||
    targetSessionId === oppositeSessionId
  ) {
    return {
      ok: false,
      continue: false,
      reason: 'session_id_unreadable',
      receipt: unread,
      sessions,
    };
  }
  const target = sessions.find((row) => row.id === targetSessionId);
  if (target === undefined || target.userEmail !== SYNTHETIC_EMAIL) {
    return {
      ok: false,
      continue: false,
      reason: 'synthetic_user_guard',
      receipt: unread,
      sessions,
    };
  }
  if (!sessionLive(sessions.find((row) => row.id === oppositeSessionId))) {
    return {
      ok: false,
      continue: false,
      reason: 'opposite_not_live',
      receipt: unread,
      sessions,
    };
  }
  const next = sessions.filter((row) => row.id !== targetSessionId);
  const nextRefresh = refreshTokens.filter((row) => row.sessionId !== targetSessionId);
  const receipt = snapshot(next, nextRefresh);
  const continueOk =
    receipt.targetSessionRows === 0 &&
    receipt.targetRefreshRows === 0 &&
    receipt.oppositeSessionRows === 1 &&
    receipt.oppositeLive === true;
  return {
    ok: continueOk,
    continue: continueOk,
    reason: continueOk ? 'readback_ok' : 'opposite_not_live',
    receipt,
    sessions: next,
  };
}

/**
 * N4 passes only when this pair's A source is dead and its B session is live.
 * N5 passes only when this pair's B session is dead and its A source is live.
 * A denial caused by the opposite session, or by an A source already revoked
 * for another row, fails the row.
 */
export function revocationRowPass(input) {
  const prior = Array.isArray(input?.priorSourceSessionIds) ? input.priorSourceSessionIds : [];
  const sourceSessionId = input?.sourceSessionId;
  const bSessionId = input?.bSessionId;
  if (typeof sourceSessionId !== 'string' || typeof bSessionId !== 'string') return false;
  if (!SESSION_ID.test(sourceSessionId) || !SESSION_ID.test(bSessionId)) return false;
  if (sourceSessionId === bSessionId) return false;
  if (prior.includes(sourceSessionId)) return false;
  if (input.livenessDenied !== true || input.markerUnchanged !== true) return false;
  if (input.row === 'N4') return input.sourceLive === false && input.bLive === true;
  if (input.row === 'N5') return input.sourceLive === true && input.bLive === false;
  return false;
}

function lineReader(stream) {
  const rl = createInterface({ input: stream, crlfDelay: Infinity });
  const queue = [];
  let waiter;
  let ended = false;
  const deliver = (value) => {
    if (waiter === undefined) {
      if (value !== null) queue.push(value);
      return;
    }
    const resolve = waiter;
    waiter = undefined;
    resolve(value);
  };
  rl.on('line', (line) => {
    deliver(line.length > 8192 ? null : line);
  });
  const finish = () => {
    if (ended) return;
    ended = true;
    deliver(null);
  };
  rl.on('close', finish);
  stream.on('end', finish);
  return {
    next() {
      if (queue.length > 0) return Promise.resolve(queue.shift() ?? null);
      if (ended) return Promise.resolve(null);
      return new Promise((resolve) => {
        waiter = resolve;
      });
    },
    close() {
      rl.close();
    },
  };
}

function withTimeout(promise, timeoutMs) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(coded('orchestration_timeout')), timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function writeJson(stream, value) {
  stream.write(`${assertIpcHasNoSecrets(value)}\n`);
}

function hostedTest(supabaseUrl) {
  try {
    return new URL(supabaseUrl).hostname === 'odbcejsuuqdzhabjmozi.supabase.co';
  } catch {
    return false;
  }
}

function loopbackSupabase(supabaseUrl) {
  try {
    const host = new URL(supabaseUrl).hostname;
    return host === '127.0.0.1' || host === 'localhost' || host === '::1';
  } catch {
    return false;
  }
}

function notExecuted(id, name) {
  return { id, name, executed: false, pass: false, label: 'not_executed' };
}

function executedRow(id, name, pass, pair) {
  const row = { id, name, executed: true, pass: pass === true };
  if (pair !== undefined) {
    row.sourceSessionId = pair.sourceSessionId;
    row.bSessionId = pair.bSessionId;
  }
  return row;
}

function acceptanceRows(input) {
  const positive = input.positivePair;
  return [
    executedRow('P1', 'canary_shape', input.canaryShape, positive),
    executedRow('P2', 'b_via_second_consent', input.secondConsent, positive),
    executedRow('P3', 'discovery_initialize', input.discoveryInitialize, positive),
    executedRow('P4', 'list_tools', input.listTools, positive),
    executedRow('P5', 'marker_read', input.markerRead, positive),
    executedRow('N1', 'a_as_b', input.tokenARejectedAsB, positive),
    notExecuted('N2', 'wrong_user'),
    notExecuted('N3', 'wrong_agent_client_resource'),
    executedRow('N4', 'a_source_session_revocation', input.aSourceRevoked, input.n4Pair),
    executedRow('N5', 'b_session_revocation', input.bSessionRevoked, input.n5Pair),
    notExecuted('N6', 'hook_bypass_f1'),
    notExecuted('N7', 'openid'),
    notExecuted('N8', 'unbound_mismatched_b'),
  ];
}

function rowsPass(rows) {
  return rows.every((row) => (row.executed === true ? row.pass === true : row.pass === false));
}

function safeSha(value) {
  return typeof value === 'string' && SHA40.test(value) ? value : undefined;
}

const PAIR_LABEL = /^(positive|n4|n5)$/u;

function safeSessionId(value) {
  return typeof value === 'string' && SESSION_ID.test(value) ? value : undefined;
}

function ledgerIds(ids) {
  const entry = {};
  const passwordSessionId = safeSessionId(ids?.passwordSessionId);
  const sourceSessionId = safeSessionId(ids?.sourceSessionId);
  const bSessionId = safeSessionId(ids?.bSessionId);
  if (passwordSessionId !== undefined) entry.passwordSessionId = passwordSessionId;
  if (sourceSessionId !== undefined) entry.sourceSessionId = sourceSessionId;
  if (bSessionId !== undefined) entry.bSessionId = bSessionId;
  return entry;
}

function recordPairLedger(ledger, label, ids) {
  if (!Array.isArray(ledger) || typeof label !== 'string' || !PAIR_LABEL.test(label)) return;
  const safe = ledgerIds(ids);
  if (Object.keys(safe).length === 0) return;
  const existing = ledger.find((row) => row.pair === label);
  if (existing === undefined) {
    ledger.push({ pair: label, ...safe });
    return;
  }
  Object.assign(existing, safe);
}

function knownPairIds(runtime) {
  return {
    passwordSessionId: runtime?.secrets?.passwordSessionId,
    sourceSessionId: runtime?.observation?.sourceSessionId,
    bSessionId: runtime?.observation?.bSessionId,
  };
}

function sanitizeLedger(value) {
  if (!Array.isArray(value)) return [];
  const out = [];
  for (const row of value) {
    if (row === null || typeof row !== 'object') continue;
    const pair = row.pair;
    if (typeof pair !== 'string' || !PAIR_LABEL.test(pair)) continue;
    const safe = ledgerIds(row);
    if (Object.keys(safe).length === 0) continue;
    out.push({ pair, ...safe });
  }
  return out;
}

function ledgerReady(ledger) {
  const labels = ['positive', 'n4', 'n5'];
  if (ledger.length !== labels.length) return false;
  return labels.every((label, index) => {
    const row = ledger[index];
    if (row?.pair !== label) return false;
    const ids = [row.passwordSessionId, row.sourceSessionId, row.bSessionId];
    return ids.every((id) => safeSessionId(id) !== undefined) && new Set(ids).size === ids.length;
  });
}

function distinctAcrossPairs(ledger, key) {
  const ids = ledger.map((row) => row[key]);
  return ids.every((id) => safeSessionId(id) !== undefined) && new Set(ids).size === ids.length;
}

function parentReceipt(env, details) {
  const toolNames = Array.isArray(details.toolNames)
    ? details.toolNames.filter(
        (name) => typeof name === 'string' && /^[a-z0-9_-]{1,80}$/u.test(name),
      )
    : [];
  const childEnvNames = Array.isArray(details.childEnvNames)
    ? details.childEnvNames.filter((name) => typeof name === 'string' && /^[A-Z0-9_]+$/u.test(name))
    : [];
  const rows = acceptanceRows(details);
  return {
    type: 'receipt',
    packet: 'lane-b-external-client',
    profile: 'TEST_ONLY_PUBLIC_PKCE',
    acceptance: false,
    hostedContact: hostedTest(env.ARI_TEST_SUPABASE_URL),
    hookInstalled: false,
    executedByWriter: false,
    syntheticLoopback: loopbackSupabase(env.ARI_TEST_SUPABASE_URL),
    g5Head: safeSha(details.reviewedHead),
    actualHead: safeSha(details.actualHead),
    reviewedHead: safeSha(details.reviewedHead),
    projectRef: env.ARI_TEST_PROJECT_REF,
    passwordSessionId: safeSessionId(details.passwordSessionId),
    sessionLedger: sanitizeLedger(details.sessionLedger),
    markerReads: details.markerReads,
    initialized: details.discoveryInitialize === true,
    toolsListed: details.listTools === true,
    markerCalled: details.markerRead === true,
    downstreamBound: details.secondConsent === true,
    externalAuthorizationCompleted: details.externalConsent === true,
    rowsPass: rowsPass(rows),
    rows,
    toolNames,
    childEnvNames,
  };
}

function rejectJson(res) {
  res.writeHead(400, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(JSON.stringify({ error: 'invalid_request' }));
}

export async function startExternalRuntime(env) {
  const gate = controllerGate(env);
  if (!gate.ok) throw coded(gate.reason);
  if (env.ARI_LANE_B_EXECUTE !== '1') throw coded('live_runtime_not_started');
  const timeoutMs = timeoutMsOf(env);
  const mcpUrl = loopbackUrl(
    required(env, 'ARI_EXTERNAL_MCP_URL'),
    '/mcp',
    'mcp_resource_not_loopback',
  );
  const supabaseUrl = required(env, 'ARI_TEST_SUPABASE_URL');
  let supabase;
  try {
    supabase = new URL(supabaseUrl);
  } catch {
    throw coded('live_configuration_incomplete');
  }
  if (supabase.protocol !== 'https:' || supabase.username !== '' || supabase.password !== '') {
    throw coded('live_configuration_incomplete');
  }
  const aRedirect = loopbackUrl(
    env.ARI_EXTERNAL_A_REDIRECT_URI ?? new URL('/oauth/callback', mcpUrl.origin).toString(),
    '/oauth/callback',
    'mcp_resource_not_loopback',
  );
  if (aRedirect.origin !== mcpUrl.origin) throw coded('live_configuration_incomplete');
  const bRedirect = loopbackUrl(
    required(env, 'ARI_DOWNSTREAM_REDIRECT_URI'),
    '/oauth/downstream/callback',
    'mcp_resource_not_loopback',
  );
  if (bRedirect.origin !== mcpUrl.origin) throw coded('live_configuration_incomplete');
  if (
    typeof env.ARI_TEST_SYNTHETIC_PASSWORD !== 'string' ||
    env.ARI_TEST_SYNTHETIC_PASSWORD.length === 0
  ) {
    throw coded('synthetic_password_required');
  }
  let jwks;
  try {
    jwks = JSON.parse(required(env, 'ARI_TEST_JWKS_JSON'));
  } catch {
    throw coded('live_configuration_incomplete');
  }
  const childEnv = childEnvironment({
    ...env,
    ARI_EXTERNAL_A_REDIRECT_URI: aRedirect.toString(),
    ARI_LANE_B_TIMEOUT_MS: String(timeoutMs),
  });
  const { createNativeUserMcpReadHandler } = await import(
    '../packages/server/dist/native-user-mcp-read-handler.js'
  );
  const observation = {
    livenessChecks: 0,
    livenessDenials: 0,
    markerReads: 0,
    tokenAOfferedAsB: false,
    tokenARejectedAsB: false,
    sourceSessionId: null,
    bSessionId: null,
  };
  let handler;
  try {
    handler = createNativeUserMcpReadHandler({
      resourceServer: mcpUrl.origin + mcpUrl.pathname,
      supabaseUrl,
      expectedClientId: required(env, 'ARI_EXTERNAL_A_CLIENT_ID'),
      expectedAgentId: required(env, 'ARI_AGENT_ID'),
      ingressRole: 'mcp_ingress',
      publishableKey: required(env, 'ARI_TEST_PUBLISHABLE_KEY'),
      jwks,
      downstreamClientId: required(env, 'ARI_DOWNSTREAM_CLIENT_ID'),
      downstreamRedirectUri: bRedirect.toString(),
      enableAriTestMarker: true,
      observation,
    });
  } catch {
    throw coded('live_configuration_incomplete');
  }
  const session = {
    child: undefined,
    expectedAState: undefined,
    expectedBState: undefined,
    aSent: false,
    stderr: '',
  };
  const writeChild = (value) => {
    if (session.child === undefined || session.child.stdin.destroyed) return;
    writeJson(session.child.stdin, value);
  };
  const server = createServer((req, res) => {
    const host = req.headers.host;
    if (typeof host !== 'string' || host !== mcpUrl.host) {
      rejectJson(res);
      return;
    }
    let requestUrl;
    try {
      requestUrl = new URL(req.url ?? '/', `http://${host}`);
    } catch {
      rejectJson(res);
      return;
    }
    if (req.method === 'GET' && requestUrl.pathname === aRedirect.pathname) {
      const keys = [...requestUrl.searchParams.keys()];
      const code = requestUrl.searchParams.get('code') ?? '';
      const state = requestUrl.searchParams.get('state') ?? '';
      const keysOk = keys.length === 2 && keys.every((key) => key === 'code' || key === 'state');
      if (
        !keysOk ||
        session.aSent ||
        state !== session.expectedAState ||
        code.length < 1 ||
        code.length > 512 ||
        /\s/u.test(code) ||
        JWT_SHAPE.test(code)
      ) {
        rejectJson(res);
        return;
      }
      session.aSent = true;
      res.writeHead(200, { 'content-type': 'text/plain', 'cache-control': 'no-store' });
      res.end('callback_received');
      writeChild({ type: 'authorization_code', code, state });
      return;
    }
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const request = new Request(`http://${host}${req.url}`, {
        method: req.method,
        headers: req.headers,
        ...(body.length === 0 || req.method === 'GET' || req.method === 'HEAD' ? {} : { body }),
      });
      const downstream = req.method === 'GET' && requestUrl.pathname === bRedirect.pathname;
      const state = requestUrl.searchParams.get('state') ?? '';
      void handler(request).then(
        async (response) => {
          const headers = {};
          response.headers.forEach((value, key) => {
            headers[key] = value;
          });
          const payload = Buffer.from(await response.arrayBuffer());
          if (!res.headersSent) res.writeHead(response.status, headers);
          res.end(payload);
          if (!downstream || state.length === 0 || state !== session.expectedBState) return;
          if (response.status === 200) writeChild({ type: 'downstream_bound', state });
          else writeChild({ type: 'error', code: 'downstream_callback_failed' });
        },
        () => {
          if (!res.headersSent) {
            res.writeHead(500, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ error: 'server_error' }));
          }
        },
      );
    });
  });
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(Number(mcpUrl.port), '127.0.0.1', () => resolve());
    });
  } catch {
    server.close();
    throw coded('mcp_listen_failed');
  }
  const child = spawn(process.execPath, [CLIENT_SCRIPT], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: childEnv,
  });
  child.stdin.on('error', () => undefined);
  child.stderr.on('data', (chunk) => {
    session.stderr = `${session.stderr}${chunk.toString('utf8')}`.slice(-4000);
  });
  session.child = child;
  return {
    server,
    child,
    session,
    timeoutMs,
    childEnv,
    writeChild,
    authOrigin: supabase.origin,
    observation,
    secrets: { syntheticAccessToken: undefined, passwordSessionId: undefined },
    consentFlows: [],
  };
}

function sessionIdOrThrow(value, code) {
  if (typeof value !== 'string' || !SESSION_ID.test(value)) throw coded(code);
  return value;
}

async function performParentConsent(runtime, env, authorizationUrl) {
  const retained = runtime.secrets.syntheticAccessToken;
  const receipt = await performLoopbackConsent({
    fetch: globalThis.fetch,
    authOrigin: runtime.authOrigin,
    authorizationUrl,
    publishableKey: env.ARI_TEST_PUBLISHABLE_KEY,
    password: typeof retained === 'string' ? undefined : env.ARI_TEST_SYNTHETIC_PASSWORD,
    userAccessToken: retained,
    retainSession(token) {
      runtime.secrets.syntheticAccessToken = token;
    },
  });
  if (typeof receipt.passwordSessionId === 'string') {
    runtime.secrets.passwordSessionId = receipt.passwordSessionId;
  }
  if (receipt.ok !== true) throw coded(safeCode(receipt.reason));
}

function livenessFailClosed(before, after, childFailed) {
  return (
    childFailed === true &&
    after.livenessChecks > before.livenessChecks &&
    after.livenessDenials > before.livenessDenials &&
    after.markerReads === before.markerReads
  );
}

function observeCounts(observation) {
  return {
    livenessChecks: observation.livenessChecks,
    livenessDenials: observation.livenessDenials,
    markerReads: observation.markerReads,
  };
}

function currentPair(observation) {
  return {
    sourceSessionId: sessionIdOrThrow(observation.sourceSessionId, 'session_id_unreadable'),
    bSessionId: sessionIdOrThrow(observation.bSessionId, 'session_id_unreadable'),
  };
}

async function driveExternalSession(runtime, env, stdinReader, probe) {
  const deadline = Date.now() + runtime.timeoutMs;
  const reader = lineReader(runtime.child.stdout);
  const priorSourceSessionIds = probe.priorSourceSessionIds ?? [];
  try {
    const remaining = () => {
      const left = deadline - Date.now();
      if (left <= 0) throw coded('orchestration_timeout');
      return left;
    };
    const readChild = async () => {
      const line = await withTimeout(reader.next(), remaining());
      if (line === null) throw coded('child_failed');
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        throw coded('child_failed');
      }
      assertIpcHasNoSecrets(message);
      if (message.type === 'error') throw coded(safeCode(message.code));
      return message;
    };
    let checkpoint;
    while (checkpoint === undefined) {
      const message = await readChild();
      if (message.type === 'authorization_request') {
        runtime.session.expectedAState = message.state;
        await performParentConsent(runtime, env, message.authorizationUrl);
        runtime.consentFlows.push('external_a');
      } else if (message.type === 'downstream_authorization_required') {
        runtime.session.expectedBState = message.state;
        await performParentConsent(runtime, env, message.authorizationUrl);
        runtime.consentFlows.push('downstream_b');
      } else if (message.type === 'checkpoint' && message.id === 'P5') {
        checkpoint = message;
      } else {
        throw coded('child_failed');
      }
    }
    const pair = currentPair(runtime.observation);
    if (pair.sourceSessionId === pair.bSessionId) throw coded('session_id_unreadable');
    if (priorSourceSessionIds.includes(pair.sourceSessionId)) {
      throw coded('negative_pair_reused');
    }
    recordPairLedger(probe.ledger, probe.pairLabel, {
      passwordSessionId: runtime.secrets.passwordSessionId,
      sourceSessionId: pair.sourceSessionId,
      bSessionId: pair.bSessionId,
    });
    const probeRevocation = async (id, action) => {
      writeJson(process.stdout, {
        type: 'controller_action',
        action,
        pair: id === 'N4' ? 'n4' : 'n5',
        source_session_id: pair.sourceSessionId,
        b_session_id: pair.bSessionId,
      });
      const line = await withTimeout(stdinReader.next(), remaining());
      if (!isContinueLine(line)) throw coded('stdin_refused');
      const before = observeCounts(runtime.observation);
      runtime.writeChild({ type: 'call_tool_once', id });
      const result = await readChild();
      if (result.type !== 'tool_call_result' || result.id !== id) throw coded('child_failed');
      const after = observeCounts(runtime.observation);
      const denied = livenessFailClosed(before, after, result.failed === true);
      // Continue already required the controller readback: N4 keeps B live
      // and N5 keeps the A source live. This process does not read
      // auth.sessions. A reused A source still fails the row.
      const pass = revocationRowPass({
        row: id,
        sourceSessionId: pair.sourceSessionId,
        bSessionId: pair.bSessionId,
        livenessDenied: denied,
        markerUnchanged: after.markerReads === before.markerReads,
        sourceLive: id !== 'N4',
        bLive: id === 'N4',
        priorSourceSessionIds,
      });
      return { pass, pair };
    };
    let revocation = { pass: true, pair };
    if (probe.negative === 'N4') {
      revocation = await probeRevocation('N4', 'revoke_a_source_session');
    } else if (probe.negative === 'N5') {
      revocation = await probeRevocation('N5', 'revoke_b_session');
    } else if (probe.negative !== null && probe.negative !== undefined) {
      throw coded('child_failed');
    }
    runtime.writeChild({ type: 'finish' });
    const finalMessage = await readChild();
    if (finalMessage.type !== 'receipt') throw coded('child_failed');
    if (JWT_SHAPE.test(runtime.session.stderr) || /refresh_token/i.test(runtime.session.stderr)) {
      throw coded('ipc_refused_secret');
    }
    const toolNames = Array.isArray(checkpoint.toolNames) ? checkpoint.toolNames : [];
    const passwordSessionId = sessionIdOrThrow(
      runtime.secrets.passwordSessionId,
      'password_session_id_missing',
    );
    return {
      pass: revocation.pass === true,
      pair,
      passwordSessionId,
      markerReads: runtime.observation.markerReads,
      toolNames,
      childEnvNames: finalMessage.childEnvNames,
      details: {
        canaryShape: checkpoint.canaryShapeOk === true && checkpoint.markerCalled === true,
        secondConsent:
          runtime.consentFlows[0] === 'external_a' &&
          runtime.consentFlows[1] === 'downstream_b' &&
          checkpoint.downstreamBound === true,
        discoveryInitialize: checkpoint.discovered === true && checkpoint.initialized === true,
        listTools: checkpoint.toolsListed === true && toolNames.includes('ari_test_marker_get'),
        markerRead: checkpoint.markerCalled === true && runtime.observation.markerReads >= 1,
        tokenARejectedAsB:
          runtime.observation.tokenAOfferedAsB === true &&
          runtime.observation.tokenARejectedAsB === true,
        externalConsent: runtime.consentFlows.includes('external_a'),
      },
    };
  } finally {
    reader.close();
  }
}

async function runFreshPair(env, stdinReader, probe) {
  const runtime = await startExternalRuntime(env);
  try {
    return await driveExternalSession(runtime, env, stdinReader, probe);
  } catch (error) {
    recordPairLedger(probe.ledger, probe.pairLabel, knownPairIds(runtime));
    const sessionId = safeSessionId(runtime?.secrets?.passwordSessionId);
    if (
      sessionId !== undefined &&
      error !== null &&
      typeof error === 'object' &&
      error.passwordSessionId === undefined
    ) {
      error.passwordSessionId = sessionId;
    }
    throw error;
  } finally {
    await stopExternalRuntime(runtime);
  }
}

function distinctPairs(positive, n4, n5) {
  const sources = [positive.sourceSessionId, n4.sourceSessionId, n5.sourceSessionId];
  const sessions = [positive.bSessionId, n4.bSessionId, n5.bSessionId];
  return new Set(sources).size === 3 && new Set(sessions).size === 3;
}

async function runLaneB(env, stdin) {
  const gate = controllerGate(env);
  if (!gate.ok) throw coded(gate.reason);
  const stdinReader = lineReader(stdin);
  const sessionLedger = [];
  try {
    const positive = await runFreshPair(env, stdinReader, {
      negative: null,
      priorSourceSessionIds: [],
      pairLabel: 'positive',
      ledger: sessionLedger,
    });
    const n4 = await runFreshPair(env, stdinReader, {
      negative: 'N4',
      priorSourceSessionIds: [],
      pairLabel: 'n4',
      ledger: sessionLedger,
    });
    const n5 = await runFreshPair(env, stdinReader, {
      negative: 'N5',
      priorSourceSessionIds: [n4.pair.sourceSessionId],
      pairLabel: 'n5',
      ledger: sessionLedger,
    });
    if (!distinctPairs(positive.pair, n4.pair, n5.pair)) throw coded('negative_pair_reused');
    const ledger = sanitizeLedger(sessionLedger);
    if (
      !ledgerReady(ledger) ||
      !distinctAcrossPairs(ledger, 'passwordSessionId') ||
      !distinctAcrossPairs(ledger, 'sourceSessionId') ||
      !distinctAcrossPairs(ledger, 'bSessionId')
    ) {
      throw coded('session_ledger_incomplete');
    }
    const receipt = parentReceipt(env, {
      ...positive.details,
      aSourceRevoked: n4.pass,
      bSessionRevoked: n5.pass,
      positivePair: positive.pair,
      n4Pair: n4.pair,
      n5Pair: n5.pair,
      passwordSessionId: positive.passwordSessionId,
      sessionLedger: ledger,
      markerReads: positive.markerReads,
      toolNames: positive.toolNames,
      childEnvNames: positive.childEnvNames,
      actualHead: gate.actualHead,
      reviewedHead: gate.reviewedHead,
    });
    assertIpcHasNoSecrets(receipt);
    if (receipt.actualHead !== receipt.reviewedHead) throw coded('g5_head_mismatch');
    if (receipt.rowsPass !== true) throw coded('lane_b_row_failed');
    if (receipt.sessionLedger.length !== 3) throw coded('session_ledger_incomplete');
    return receipt;
  } catch (error) {
    if (error !== null && typeof error === 'object') {
      const ledger = sanitizeLedger(sessionLedger);
      error.sessionLedger = ledger;
      if (safeSessionId(error.passwordSessionId) === undefined) {
        const retained = ledger.find((row) => row.passwordSessionId !== undefined);
        if (retained !== undefined) error.passwordSessionId = retained.passwordSessionId;
      }
    }
    throw error;
  } finally {
    stdinReader.close();
  }
}

export async function stopExternalRuntime(runtime) {
  if (runtime === undefined) return;
  const { child, server } = runtime;
  if (child !== undefined && child.exitCode === null && child.signalCode === null) {
    child.kill('SIGTERM');
    await Promise.race([
      once(child, 'exit').then(() => undefined),
      new Promise((resolve) => setTimeout(resolve, 500)),
    ]);
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  }
  if (server !== undefined) {
    server.closeAllConnections?.();
    if (server.listening) await new Promise((resolve) => server.close(() => resolve()));
  }
}

async function main() {
  const command = process.argv[2] ?? 'plan';
  if (command === 'plan') {
    process.stdout.write(`${JSON.stringify(controllerPlan(), null, 2)}\n`);
    return;
  }
  if (command !== 'run') {
    process.stderr.write('usage: node scripts/run-ari-test-external-e2e.mjs [plan|run]\n');
    process.exitCode = 2;
    return;
  }
  const gate = controllerGate(process.env);
  if (!gate.ok) {
    process.stderr.write(`${gate.reason}\n`);
    process.exitCode = 2;
    return;
  }
  if (process.env.ARI_LANE_B_EXECUTE !== '1') {
    process.stderr.write('live_runtime_not_started\n');
    process.exitCode = 2;
    return;
  }
  try {
    const receipt = await runLaneB(process.env, process.stdin);
    process.stdout.write(`${JSON.stringify(receipt)}\n`);
  } catch (error) {
    const ledger = sanitizeLedger(error?.sessionLedger);
    const sessionId =
      safeSessionId(error?.passwordSessionId) ??
      ledger.find((row) => row.passwordSessionId !== undefined)?.passwordSessionId;
    if (ledger.length > 0 || sessionId !== undefined) {
      const failure = {
        type: 'receipt',
        packet: 'lane-b-external-client',
        acceptance: false,
        hookInstalled: false,
        executedByWriter: false,
        ...(sessionId !== undefined ? { passwordSessionId: sessionId } : {}),
        sessionLedger: ledger,
        rowsPass: false,
        reason: safeCode(error?.code),
      };
      assertIpcHasNoSecrets(failure);
      process.stdout.write(`${JSON.stringify(failure)}\n`);
    }
    process.stderr.write(`${safeCode(error?.code)}\n`);
    process.exitCode = 2;
  }
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(invokedPath).href) {
  await main();
}
