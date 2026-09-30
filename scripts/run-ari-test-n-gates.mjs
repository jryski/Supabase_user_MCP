/**
 * Remaining TEST gates N3, N7, N8, N2, and N6.
 * Default command is `plan`. It does not open a socket and does not contact
 * hosted TEST. `run` stays closed unless the controller opens the G5 gates
 * and sets ARI_N_GATES_EXECUTE=1. This packet does not apply SQL, install a
 * hook, register a client, or put an admin credential in the MCP child.
 * acceptance stays false. Historical H1 rows stay on the Lane B runner.
 */
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mkdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';
import { createLocalJWKSet, jwtVerify } from 'jose';

import {
  buildAuthorizeUrl,
  CALLBACK_PROFILES,
  createPkce,
  exchangeNativeCode,
  performLoopbackConsent,
  runOpenIdNegative,
} from '../docs/evidence/ari-test-probe/consent-harness.mjs';
import { SYNTHETIC_EMAIL } from '../docs/evidence/ari-test-probe/decisions.mjs';
import { assertIpcHasNoSecrets } from './ari-test-external-client.mjs';
import {
  controllerGate,
  isContinueLine,
  startExternalRuntime,
  stopExternalRuntime,
} from './run-ari-test-external-e2e.mjs';

const GATE_ORDER = Object.freeze(['N3', 'N7', 'N8', 'N2', 'N6']);
const GATE_NAMES = Object.freeze({
  N3: 'wrong_agent_client_resource',
  N7: 'openid',
  N8: 'unbound_mismatched_b',
  N2: 'wrong_user',
  N6: 'hook_bypass_f1',
});
const SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const SHA256 = /^[0-9a-f]{64}$/;
const SAFE_CODE = /^[a-z0-9_]{1,64}$/;
const PROJECT_REF = /^[a-z0-9]{20}$/u;
const HOOK_FUNCTION = 'ari_probe.custom_access_token_hook';
const F1_NAME = 'ari_probe_marker_reject_a_client';
const HOOK_URI = /^(?:pg-functions|https):\/\/[A-Za-z0-9._~:/?#-]{1,180}$/u;
const HOOK_FIELDS = Object.freeze([
  'agentId',
  'baselineClientId',
  'enabled',
  'externalClientId',
  'function',
  'projectRef',
  'resource',
  'settings',
  'uri',
]);
const LEDGER_KEYS = Object.freeze([
  'passwordSessionId',
  'sourceSessionId',
  'bSessionId',
  'authSessionId',
]);

function coded(code) {
  return Object.assign(new Error(code), { code });
}

function safeCode(value) {
  return typeof value === 'string' && SAFE_CODE.test(value) ? value : 'child_failed';
}

function safeUuid(value) {
  return typeof value === 'string' && SESSION_ID.test(value) ? value : undefined;
}

export function selectNGates(raw) {
  const text = raw === undefined || raw === null || raw === '' ? GATE_ORDER.join(',') : raw;
  if (typeof text !== 'string') throw coded('live_configuration_incomplete');
  const seen = new Set();
  for (const part of text.split(',')) {
    const id = part.trim();
    if (id.length === 0) continue;
    if (!GATE_ORDER.includes(id)) throw coded('live_configuration_incomplete');
    seen.add(id);
  }
  if (seen.size === 0) throw coded('live_configuration_incomplete');
  return GATE_ORDER.filter((id) => seen.has(id));
}

export function freshBuildReady(cwd = process.cwd()) {
  const pairs = [
    [
      'packages/server/src/native-user-mcp-read-handler.ts',
      'packages/server/dist/native-user-mcp-read-handler.js',
    ],
    [
      'packages/server/src/downstream-oauth-grant.ts',
      'packages/server/dist/downstream-oauth-grant.js',
    ],
  ];
  try {
    return pairs.every(([src, dist]) => {
      const source = statSync(`${cwd}/${src}`);
      const built = statSync(`${cwd}/${dist}`);
      return built.mtimeMs + 1000 >= source.mtimeMs;
    });
  } catch {
    return false;
  }
}

export function refuseLocalMint(env) {
  if (typeof env.ARI_N3_LOCAL_MINT === 'string' && env.ARI_N3_LOCAL_MINT.length > 0) {
    throw coded('hosted_mint_refused');
  }
}

function plainSettings(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const encoded = JSON.stringify(value);
  if (encoded === undefined || encoded.length > 2000 || encoded.includes('eyJ')) return undefined;
  return JSON.parse(encoded);
}

export function hookManifestHash(manifest, bound) {
  if (manifest === null || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw coded('hook_manifest_unreadable');
  }
  if (bound === null || typeof bound !== 'object' || Array.isArray(bound)) {
    throw coded('hook_manifest_unreadable');
  }
  const keys = Object.keys(manifest);
  if (keys.length !== HOOK_FIELDS.length || HOOK_FIELDS.some((key) => !keys.includes(key))) {
    throw coded('hook_manifest_unreadable');
  }
  if (manifest.enabled !== true || manifest.function !== HOOK_FUNCTION) {
    throw coded('hook_manifest_unreadable');
  }
  if (typeof manifest.uri !== 'string' || !HOOK_URI.test(manifest.uri)) {
    throw coded('hook_manifest_unreadable');
  }
  const settings = plainSettings(manifest.settings);
  if (settings === undefined) throw coded('hook_manifest_unreadable');
  if (
    manifest.projectRef !== bound.projectRef ||
    manifest.resource !== bound.resource ||
    manifest.agentId !== bound.agentId ||
    manifest.externalClientId !== bound.externalClientId ||
    typeof manifest.baselineClientId !== 'string' ||
    manifest.baselineClientId.length === 0 ||
    manifest.baselineClientId.length > 128
  ) {
    throw coded('hook_manifest_unreadable');
  }
  const canonical = JSON.stringify({
    agentId: manifest.agentId,
    baselineClientId: manifest.baselineClientId,
    enabled: true,
    externalClientId: manifest.externalClientId,
    function: manifest.function,
    projectRef: manifest.projectRef,
    resource: manifest.resource,
    settings,
    uri: manifest.uri,
  });
  return createHash('sha256').update(canonical).digest('hex');
}

export function classifyMarkerProbe(status, bodyText) {
  if (typeof bodyText === 'string' && /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\./u.test(bodyText)) {
    return {
      ok: false,
      denial: false,
      rows: null,
      httpStatus: status,
      reason: 'token_in_marker_body',
    };
  }
  let parsed;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    return { ok: false, denial: false, rows: null, httpStatus: status, reason: 'malformed_marker' };
  }
  if (status === 200 && Array.isArray(parsed)) {
    if (parsed.length === 0) {
      return { ok: true, denial: true, rows: 0, httpStatus: 200, category: 'rls_empty' };
    }
    const row = parsed.length === 1 ? parsed[0] : undefined;
    const marker = typeof row?.marker === 'string' ? row.marker : null;
    return {
      ok: true,
      denial: false,
      rows: parsed.length,
      httpStatus: 200,
      category: 'rows',
      marker,
      ownerId: safeUuid(row?.owner_id) ?? null,
    };
  }
  return { ok: false, denial: false, rows: null, httpStatus: status, reason: 'inconclusive' };
}

export function openIdSubcasePass(receipt, expected) {
  if (receipt?.ok !== true || receipt.reason !== 'openid_rejected') return false;
  if (receipt.policyMarker !== 'openid_scope_refused') return false;
  if (receipt.rejectionStage !== 'exchange' || receipt.exchangeStatus !== 403) return false;
  if (receipt.accessTokenPresent === true || receipt.idTokenPresent === true) return false;
  if (receipt.refreshTokenPresent === true) return false;
  const flow = receipt.consentFlow;
  if (flow !== 'approval_post' && flow !== 'already_consented_get') return false;
  if (expected.omitResource === true) {
    return receipt.resourceOnAuthorize === false && receipt.resourceOnExchange === false;
  }
  return receipt.resourceOnAuthorize === true && receipt.resourceOnExchange === true;
}

export function crossUserPass(fact) {
  if (fact?.event !== 'exchange_rejected' || fact?.subjectMismatch !== true) return false;
  if (fact?.bound === true || fact?.failureClass !== undefined) return false;
  if (fact?.exchangeError === 'invalid_grant') return false;
  if (safeUuid(fact?.sessionId) === undefined || safeUuid(fact?.sub) === undefined) return false;
  if (fact.livenessChecks !== 0 || fact.markerReads !== 0) return false;
  if (fact.user1Resolved === true) return false;
  if (fact.secondUserId !== undefined && fact.sub !== fact.secondUserId) return false;
  return fact.user1Sub !== fact.sub;
}

export function callbackUriMismatchPass(result) {
  if (result?.status === 500 || result?.error === 'malformed' || result?.error === 'unreadable') {
    return false;
  }
  if (result?.error === 'bound' || result?.grantEvent !== undefined) return false;
  return (
    result?.status === 401 && result?.error === 'invalid_token' && result?.exchangesDelta === 0
  );
}

export function n6Pass(input) {
  return (
    input?.verified === true &&
    input?.denial === true &&
    input?.category === 'rls_empty' &&
    input?.httpStatus === 200 &&
    input?.rows === 0 &&
    input?.ownerMarker === true &&
    input?.liveSession === true &&
    input?.policyUnchanged === true &&
    input?.cleanup === 'confirmed' &&
    input?.restore === 'confirmed' &&
    input?.canary === true &&
    typeof input?.hookHash === 'string' &&
    SHA256.test(input.hookHash)
  );
}

export function nGatesPlan() {
  return {
    packet: 'lane-b-n-gates',
    profile: 'TEST_ONLY_PUBLIC_PKCE',
    executedByWriter: false,
    hostedContact: false,
    hookInstalled: false,
    acceptance: false,
    order: [...GATE_ORDER],
    n6: 'last_and_exclusive',
    steps: [
      'node scripts/run-ari-test-n-gates.mjs plan opens no socket.',
      'Do not apply sql/03 through sql/07. Do not edit deployed mappings, roles, policies, or clients.',
      'Do not install the hook, register a client, run DCR, or widen a callback from this packet.',
      'Confirm the reviewed head equals the actual clean head, then npm run build immediately before launch.',
      'Set ARI_N_GATES_EXECUTE=1. Select gates with ARI_N_GATES. Default order is N3, N7, N8, N2, N6.',
      'N6 runs last on its own runtime. A failure before N6 does not disable the hook.',
      'External A uses /oauth/callback and its mapped resource. B uses /oauth/downstream/callback and omits resource on authorize and on token exchange.',
      'Baseline A /callback remains the consent-harness profile where that profile is used.',
      'N3 presents one genuine signed A, unmodified, under one local verifier mismatch at a time. Reauthorization stays off.',
      'N7 sends openid for external A and mapped B, both consent branches. Only exchange HTTP 403 openid_scope_refused with no token is a hook-policy pass.',
      'N8 keeps callback transport cases, and passes only with a legitimate signed B that the grant store refuses to bind. Transport evidence alone is incomplete.',
      'N2: create one run-owned second synthetic user distinct from the verified baseline, then delete that user only after cleanup. The child never receives the password.',
      'Cleanup readbacks must be a bijection of the requested session ids. A duplicate or omitted id is not confirmation.',
      'N6: read back the enabled hook and the effective restrictive F1, prove the exact owner marker for the verified owner, arm restoration, then disable only that hook.',
      'Hook-off A is verified with issuer and JWKS before the marker read. HTTP 401, HTTP 403, and HTTP 500 are inconclusive.',
      'Hook-off GET /auth/v1/user and the N6 marker read include their response bodies in the run timeout and in SIGINT or SIGTERM. A stall after disable still reaches exact restore or a pending or failed recovery receipt, and it is not an F1 pass.',
      'Clean every minted auth session, with sessions and refresh rows at zero, then restore the saved configuration and canary.',
      'cleanupStatus is confirmed when every recorded session id was cleaned. It is not_required only when the run recorded no session id. failed and unresolved take priority. Per-action cleanup readbacks stay mandatory.',
      'Restore stays armed until the readback hash matches the saved configuration. A failed readback is pending or failed, never not_required.',
      'Stdin JSON carries runId and action. A stale or wrong-action line cannot satisfy cleanup or restore.',
    ],
  };
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
  rl.on('line', (line) => deliver(line.length > 8192 ? null : line));
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

function withTimeout(promise, timeoutMs, signal) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(coded('orchestration_timeout')), timeoutMs);
  });
  const racers = [promise, timeout];
  if (signal !== undefined) racers.push(signal.interrupt());
  return Promise.race(racers).finally(() => clearTimeout(timer));
}

async function callBounded(timeoutMs, signal, work) {
  const controller = new AbortController();
  let reason = 'orchestration_timeout';
  let settled = false;
  const cancel = () => {
    reason = 'signal_received';
    controller.abort();
  };
  if (signal !== undefined) signal.onAbort(cancel);
  const attempt = (async () => {
    try {
      const value = await work(controller.signal);
      if (controller.signal.aborted) throw coded(reason);
      settled = true;
      return value;
    } catch (error) {
      if (controller.signal.aborted) throw coded(reason);
      throw error;
    }
  })();
  try {
    return await withTimeout(attempt, timeoutMs, signal);
  } finally {
    if (!settled) controller.abort();
    if (signal !== undefined) signal.offAbort(cancel);
  }
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

function writeJson(value) {
  process.stdout.write(`${assertIpcHasNoSecrets(value)}\n`);
}

function loopbackSupabase(supabaseUrl) {
  try {
    const host = new URL(supabaseUrl).hostname;
    return host === '127.0.0.1' || host === 'localhost' || host === '::1';
  } catch {
    return false;
  }
}

function hostedTest(supabaseUrl) {
  try {
    return new URL(supabaseUrl).hostname === 'odbcejsuuqdzhabjmozi.supabase.co';
  } catch {
    return false;
  }
}

function claimShape(token) {
  const parts = typeof token === 'string' ? token.split('.') : [];
  if (parts.length !== 3 || parts[1] === undefined) return null;
  try {
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (claims === null || typeof claims !== 'object' || Array.isArray(claims)) return null;
    const aud = Array.isArray(claims.aud) ? claims.aud[0] : claims.aud;
    return {
      role: typeof claims.role === 'string' ? claims.role : null,
      aud: typeof aud === 'string' ? aud : null,
      clientId: typeof claims.client_id === 'string' ? claims.client_id : null,
      agentId: typeof claims.agent_id === 'string' ? claims.agent_id : null,
      sessionId: safeUuid(claims.session_id),
      sourceSessionId: safeUuid(claims.source_session_id),
      sub: safeUuid(claims.sub),
    };
  } catch {
    return null;
  }
}

function ledgerIds(row) {
  const ids = [];
  for (const key of LEDGER_KEYS) {
    const id = safeUuid(row?.[key]);
    if (id !== undefined) ids.push(id);
  }
  return ids;
}

function noteSession(ledger, entry) {
  const row = { gate: entry.gate };
  for (const key of LEDGER_KEYS) {
    const id = safeUuid(entry[key]);
    if (id !== undefined) row[key] = id;
  }
  const sub = safeUuid(entry.sub);
  if (sub !== undefined) row.sub = sub;
  if (entry.rejected === true) row.rejected = true;
  const ids = ledgerIds(row);
  if (ids.length === 0) return;
  if (ledger.some((existing) => ledgerIds(existing).some((id) => ids.includes(id)))) {
    const existing = ledger.find((item) => ledgerIds(item).some((id) => ids.includes(id)));
    if (existing !== undefined && entry.rejected === true) existing.rejected = true;
    if (existing !== undefined && sub !== undefined && existing.sub === undefined)
      existing.sub = sub;
    return;
  }
  ledger.push(row);
}

function ledgerHas(ledger, id) {
  return id !== undefined && ledger.some((row) => ledgerIds(row).includes(id));
}

function noteAccessToken(ledger, gate, token, requestUrl) {
  const claims = claimShape(token);
  if (claims === null || claims.sessionId === undefined) return false;
  const url = String(requestUrl);
  if (url.includes('grant_type=password')) {
    noteSession(ledger, { gate, passwordSessionId: claims.sessionId, sub: claims.sub });
    return ledgerHas(ledger, claims.sessionId);
  }
  if (claims.sourceSessionId !== undefined) {
    noteSession(ledger, { gate, sourceSessionId: claims.sourceSessionId, sub: claims.sub });
    return ledgerHas(ledger, claims.sourceSessionId);
  }
  if (claims.clientId !== null) {
    const field =
      claims.role === 'authenticated' && claims.agentId !== null ? 'bSessionId' : 'authSessionId';
    noteSession(ledger, { gate, [field]: claims.sessionId, sub: claims.sub });
    return ledgerHas(ledger, claims.sessionId);
  }
  return false;
}

const PRE_ISSUANCE_DENIAL = new Set([
  'access_denied',
  'invalid_client',
  'invalid_grant',
  'invalid_request',
  'invalid_scope',
  'unauthorized_client',
  'unsupported_grant_type',
]);

function definitivePreIssuanceDenial(status, body) {
  if (status !== 400 && status !== 401 && status !== 403) return false;
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return false;
  if (typeof body.access_token === 'string') return false;
  return typeof body.error === 'string' && PRE_ISSUANCE_DENIAL.has(body.error);
}

async function issuanceAttemptResolved(response, ledger, gate, requestUrl) {
  const text = await response.clone().text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = undefined;
  }
  const status = response.status;
  if (status >= 200 && status < 300) {
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return false;
    if (typeof parsed.access_token !== 'string') return false;
    return noteAccessToken(ledger, gate, parsed.access_token, requestUrl);
  }
  return definitivePreIssuanceDenial(status, parsed);
}

function markRejected(ledger, sessionId) {
  const id = safeUuid(sessionId);
  if (id === undefined) return;
  const row = ledger.find((item) => item.bSessionId === id || item.authSessionId === id);
  if (row !== undefined) row.rejected = true;
}

export function exactIdBijection(left, right) {
  const unique = (values) => {
    if (!Array.isArray(values)) return null;
    const ids = [];
    const seen = new Set();
    for (const value of values) {
      const id = safeUuid(value);
      if (id === undefined || seen.has(id)) return null;
      seen.add(id);
      ids.push(id);
    }
    return ids;
  };
  const first = unique(left);
  const second = unique(right);
  if (first === null || second === null || first.length !== second.length) return false;
  const members = new Set(second);
  return first.every((id) => members.has(id));
}

function createIssuanceTracker(ledger, cursor, signal) {
  const pending = new Set();
  const controllers = new Set();
  const attempts = [];
  const abort = () => {
    for (const controller of controllers) controller.abort();
  };
  signal.onAbort(abort);
  return {
    abort,
    wrap(inner = globalThis.fetch) {
      return async (input, init) => {
        const gate = cursor.gate;
        const controller = new AbortController();
        controllers.add(controller);
        const parent = init?.signal;
        const onParent = () => controller.abort();
        if (parent !== undefined) {
          if (parent.aborted) controller.abort();
          else parent.addEventListener('abort', onParent, { once: true });
        }
        const url = String(input);
        const method = init?.method ?? 'GET';
        const issuance =
          method === 'POST' &&
          (url.includes('/oauth/token') || url.includes('grant_type=password'));
        const attempt = {
          gate,
          requestId: freshRequestId(),
          issuance,
          resolved: false,
        };
        if (issuance) attempts.push(attempt);
        const run = (async () => {
          try {
            const response = await inner(input, { ...init, signal: controller.signal });
            if (issuance) {
              try {
                attempt.resolved = await issuanceAttemptResolved(response, ledger, gate, url);
              } catch {
                attempt.resolved = false;
              }
            }
            return response;
          } finally {
            controllers.delete(controller);
            if (parent !== undefined) parent.removeEventListener('abort', onParent);
          }
        })();
        pending.add(run);
        void run.finally(() => pending.delete(run)).catch(() => undefined);
        return run;
      };
    },
    async settle(graceMs) {
      const deadline = Date.now() + graceMs;
      while (pending.size > 0 && Date.now() < deadline) {
        const current = [...pending];
        await Promise.race([
          Promise.allSettled(current),
          new Promise((resolve) => {
            setTimeout(resolve, Math.max(0, deadline - Date.now()));
          }),
        ]);
      }
      if (pending.size > 0) abort();
      await Promise.allSettled([...pending]);
    },
    attempted() {
      return attempts.length > 0;
    },
    ambiguous() {
      return attempts.some((row) => row.issuance && row.resolved !== true);
    },
    unresolvedGates() {
      return [
        ...new Set(
          attempts.filter((row) => row.issuance && row.resolved !== true).map((row) => row.gate),
        ),
      ];
    },
    unresolvedAttemptIds() {
      return attempts
        .filter((row) => row.issuance && row.resolved !== true)
        .map((row) => row.requestId)
        .filter((id) => safeUuid(id) !== undefined);
    },
  };
}

function recoveryFile(runId) {
  return join(tmpdir(), 'ari-n-gates-recovery', `${runId}.json`);
}

function armRecovery(state) {
  const path = recoveryFile(state.runId);
  mkdirSync(join(tmpdir(), 'ari-n-gates-recovery'), { recursive: true, mode: 0o700 });
  writeFileSync(
    path,
    JSON.stringify({
      packet: 'lane-b-n-gates',
      runId: state.runId,
      phase: 'disable_armed',
      hookHash: state.hash,
      hookManifest: state.manifest,
      projectRef: state.projectRef,
    }),
    { mode: 0o600 },
  );
  state.needed = true;
  state.locator = `${state.runId}.json`;
}

function clearRecovery(state) {
  try {
    rmSync(recoveryFile(state.runId), { force: true });
  } catch {
    // The locator remains on the receipt when removal fails.
  }
}

function createSignal() {
  let signaled = false;
  let waiter;
  const aborters = new Set();
  const onSignal = () => {
    for (const abort of aborters) abort();
    if (waiter !== undefined) {
      const current = waiter;
      waiter = undefined;
      signaled = false;
      current();
      return;
    }
    signaled = true;
  };
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);
  return {
    interrupt() {
      if (signaled) {
        signaled = false;
        return Promise.reject(coded('signal_received'));
      }
      return new Promise((_, reject) => {
        waiter = () => reject(coded('signal_received'));
      });
    },
    onAbort(abort) {
      aborters.add(abort);
    },
    offAbort(abort) {
      aborters.delete(abort);
    },
    dispose() {
      process.off('SIGINT', onSignal);
      process.off('SIGTERM', onSignal);
      waiter = undefined;
      aborters.clear();
    },
  };
}

function freshRequestId() {
  const id = randomUUID();
  if (safeUuid(id) === undefined) throw coded('live_configuration_incomplete');
  return id;
}

function assertCorrelated(parsed, action) {
  if (parsed?.runId !== action.runId || parsed?.action !== action.action) {
    throw coded('readback_stale');
  }
  if (parsed.requestId !== action.requestId || safeUuid(parsed.requestId) === undefined) {
    throw coded('readback_stale');
  }
  if (action.gate !== undefined && parsed.gate !== action.gate) throw coded('readback_stale');
}

async function pauseForContinue(reader, action, timeoutMs, signal) {
  const message = { ...action, requestId: freshRequestId() };
  writeJson({ type: 'controller_action', ...message });
  const line = await withTimeout(reader.next(), timeoutMs, signal);
  let parsed;
  try {
    parsed = JSON.parse(line);
  } catch {
    if (isContinueLine(line)) throw coded('readback_stale');
    throw coded('readback_malformed');
  }
  assertIpcHasNoSecrets(parsed);
  if (parsed?.type !== 'continue') throw coded('readback_stale');
  assertCorrelated(parsed, message);
  return parsed;
}

async function pauseForReadback(reader, action, timeoutMs, signal) {
  const message = { ...action, requestId: freshRequestId() };
  writeJson({ type: 'controller_action', ...message });
  const line = await withTimeout(reader.next(), timeoutMs, signal);
  if (typeof line !== 'string' || line.length === 0) throw coded('readback_required');
  let parsed;
  try {
    parsed = JSON.parse(line);
  } catch {
    throw coded('readback_malformed');
  }
  assertIpcHasNoSecrets(parsed);
  if (parsed?.type !== 'readback') throw coded('readback_required');
  assertCorrelated(parsed, message);
  return parsed;
}

function profileOf(env, kind) {
  const redirectUri =
    kind === 'downstream_b' ? env.ARI_DOWNSTREAM_REDIRECT_URI : env.ARI_EXTERNAL_A_REDIRECT_URI;
  const clientId =
    kind === 'downstream_b' ? env.ARI_DOWNSTREAM_CLIENT_ID : env.ARI_EXTERNAL_A_CLIENT_ID;
  const callbackProfile = kind === 'downstream_b' ? 'downstream_b' : 'external_a';
  const url = new URL(redirectUri);
  if (url.pathname !== CALLBACK_PROFILES[callbackProfile]) throw coded('redirect_not_exact');
  if (url.username !== '' || url.password !== '' || url.search !== '' || url.hash !== '') {
    throw coded('redirect_not_exact');
  }
  if (!url.port) throw coded('redirect_not_exact');
  return { redirectUri, clientId, callbackProfile, origin: url.origin };
}

async function obtainGrant(runtime, env, kind, login = {}, fetchImpl = globalThis.fetch) {
  const profile = profileOf(env, kind);
  const pkce = createPkce();
  const state = randomBytes(16).toString('base64url');
  const resource = kind === 'downstream_b' ? undefined : env.ARI_EXTERNAL_MCP_URL;
  const built = buildAuthorizeUrl({
    authorizeEndpoint: new URL('/auth/v1/oauth/authorize', runtime.authOrigin).toString(),
    clientId: profile.clientId,
    redirectUri: profile.redirectUri,
    scopes: ['email'],
    callbackProfile: profile.callbackProfile,
    expectedOrigin: profile.origin,
    requirePort: true,
    codeChallenge: pkce.codeChallenge,
    state,
    ...(kind === 'downstream_b' ? { omitResource: true } : { resource }),
  });
  if (!built.ok) throw coded(safeCode(built.reason));
  if (kind === 'downstream_b' && built.resourceOmitted !== true)
    throw coded('resource_not_omitted');
  runtime.session.expectedAState = state;
  runtime.session.aSent = false;
  runtime.session.retainedCode = undefined;
  const consent = await performLoopbackConsent({
    fetch: fetchImpl,
    authOrigin: runtime.authOrigin,
    authorizationUrl: built.url,
    publishableKey: env.ARI_TEST_PUBLISHABLE_KEY,
    password: login.password ?? env.ARI_TEST_SYNTHETIC_PASSWORD,
    email: login.email,
  });
  const code = runtime.session.retainedCode;
  runtime.session.retainedCode = undefined;
  if (typeof code !== 'string' || code.length === 0 || consent.ok !== true) {
    throw coded(safeCode(consent.reason ?? 'authorization_code_missing'));
  }
  const exchanged = await exchangeNativeCode({
    fetch: fetchImpl,
    authOrigin: runtime.authOrigin,
    publishableKey: env.ARI_TEST_PUBLISHABLE_KEY,
    clientId: profile.clientId,
    redirectUri: profile.redirectUri,
    code,
    codeVerifier: pkce.codeVerifier,
    codeChallenge: pkce.codeChallenge,
    callbackProfile: profile.callbackProfile,
    expectedOrigin: profile.origin,
    requirePort: true,
    ...(kind === 'downstream_b' ? { omitResource: true } : { resource }),
  });
  if (exchanged.accessToken === null) throw coded(safeCode(exchanged.receipt.reason));
  if (kind === 'downstream_b' && exchanged.receipt.resourceSent === true) {
    throw coded('resource_not_omitted');
  }
  return {
    accessToken: exchanged.accessToken,
    claims: claimShape(exchanged.accessToken),
    passwordSessionId: safeUuid(consent.passwordSessionId),
    resourceOmitted: built.resourceOmitted === true,
  };
}

async function presentOnce(url, token) {
  const response = await fetch(url, {
    method: 'POST',
    redirect: 'manual',
    headers: {
      accept: 'application/json, text/event-stream',
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'n-gates', version: '0.0.0' },
      },
    }),
  });
  const text = await response.text();
  let error = 'unreadable';
  let authorizationUrl;
  let state;
  try {
    const parsed = JSON.parse(text);
    if (typeof parsed.error === 'string' && SAFE_CODE.test(parsed.error)) error = parsed.error;
    if (typeof parsed.authorization_url === 'string') authorizationUrl = parsed.authorization_url;
    if (typeof parsed.state === 'string' && parsed.state.length <= 80) state = parsed.state;
  } catch {
    error = 'malformed';
  }
  return {
    status: response.status,
    error,
    redirected: response.status >= 300 && response.status < 400,
    authorizationUrl,
    state,
  };
}

function zeroCounts(observation) {
  return (
    observation.livenessChecks === 0 &&
    observation.livenessDenials === 0 &&
    observation.markerReads === 0 &&
    observation.bSessionId === null
  );
}

function subcaseRow(id, subcases, label) {
  return {
    id,
    name: GATE_NAMES[id],
    executed: true,
    pass: subcases.every((row) => row.pass === true),
    label,
    subcases,
  };
}

async function runN3(env, _ledger, timeoutMs, ctx) {
  ctx.cursor.gate = 'N3';
  const evidenceLabel = loopbackSupabase(env.ARI_TEST_SUPABASE_URL)
    ? 'loopback_issuer_local_verifier_expectation'
    : 'genuine_hosted_a';
  const runtimeEnv = { ...env, ARI_LANE_B_EXECUTE: '1' };
  const control = await startExternalRuntime(runtimeEnv, { spawnChild: false });
  let token;
  try {
    const issued = await withTimeout(
      obtainGrant(control, env, 'external_a', {}, ctx.fetch),
      timeoutMs,
      ctx.signal,
    );
    token = issued.accessToken;
    const presented = await presentOnce(env.ARI_EXTERNAL_MCP_URL, token);
    const controlOk =
      presented.status === 403 &&
      presented.error === 'downstream_authorization_required' &&
      presented.redirected === false &&
      zeroCounts(control.observation);
    if (!controlOk) {
      return subcaseRow(
        'N3',
        [{ id: 'control', executed: true, pass: false, reason: 'control_failed' }],
        evidenceLabel,
      );
    }
  } finally {
    await stopExternalRuntime(control);
  }
  const mismatches = [
    [
      'wrong_client',
      { expectedClientId: `${env.ARI_EXTERNAL_A_CLIENT_ID}-mismatch` },
      env.ARI_EXTERNAL_MCP_URL,
    ],
    ['wrong_agent', { expectedAgentId: `${env.ARI_AGENT_ID}-mismatch` }, env.ARI_EXTERNAL_MCP_URL],
    [
      'wrong_resource',
      { resourceServer: new URL('/mcp-mismatch', env.ARI_EXTERNAL_MCP_URL).toString() },
      new URL('/mcp-mismatch', env.ARI_EXTERNAL_MCP_URL).toString(),
    ],
  ];
  const subcases = [
    { id: 'control', executed: true, pass: true, reason: 'downstream_authorization_required' },
  ];
  for (const [id, options, target] of mismatches) {
    const runtime = await startExternalRuntime(runtimeEnv, { spawnChild: false, ...options });
    try {
      const presented = await presentOnce(target, token);
      const pass =
        presented.status === 401 &&
        presented.error === 'invalid_token' &&
        presented.redirected === false &&
        zeroCounts(runtime.observation);
      subcases.push({
        id,
        executed: true,
        pass,
        reason: pass ? 'auth_denied' : safeCode(presented.error),
      });
    } finally {
      await stopExternalRuntime(runtime);
    }
  }
  token = undefined;
  return subcaseRow('N3', subcases, evidenceLabel);
}

async function runN7(env, ledger, timeoutMs, ctx) {
  ctx.cursor.gate = 'N7';
  const profiles = [
    [
      'external_a',
      false,
      env.ARI_EXTERNAL_A_CLIENT_ID,
      env.ARI_EXTERNAL_A_REDIRECT_URI,
      env.ARI_EXTERNAL_MCP_URL,
    ],
    [
      'downstream_b',
      true,
      env.ARI_DOWNSTREAM_CLIENT_ID,
      env.ARI_DOWNSTREAM_REDIRECT_URI,
      undefined,
    ],
  ];
  const subcases = [];
  for (const [profile, omitResource, clientId, redirectUri, resource] of profiles) {
    const redirect = new URL(redirectUri);
    if (redirect.pathname !== CALLBACK_PROFILES[profile]) throw coded('redirect_not_exact');
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const receipt = await withTimeout(
        runOpenIdNegative({
          fetch: ctx.fetch,
          authOrigin: new URL(env.ARI_TEST_SUPABASE_URL).origin,
          publishableKey: env.ARI_TEST_PUBLISHABLE_KEY,
          clientId,
          redirectUri,
          scopes: ['openid', 'email'],
          callbackProfile: profile,
          expectedOrigin: redirect.origin,
          requirePort: true,
          password: env.ARI_TEST_SYNTHETIC_PASSWORD,
          ...(omitResource ? {} : { resource }),
        }),
        timeoutMs,
        ctx.signal,
      );
      if (safeUuid(receipt.passwordSessionId) !== undefined) {
        noteSession(ledger, { gate: 'N7', passwordSessionId: receipt.passwordSessionId });
      }
      const observed = receipt.consentFlow;
      const pass = openIdSubcasePass(receipt, { omitResource });
      subcases.push({
        id: `${profile}_${typeof observed === 'string' ? observed : 'unobserved'}`,
        executed: true,
        pass,
        observedFlow: typeof observed === 'string' ? observed : 'unobserved',
        reason: pass ? 'openid_scope_refused' : safeCode(receipt.reason),
      });
    }
  }
  return subcaseRow('N7', subcases, 'hook_policy');
}

function countFetch(counter, inner) {
  return async (input, init) => {
    const url = String(input);
    if ((init?.method ?? 'GET') === 'POST' && url.includes('/oauth/token')) counter.exchanges += 1;
    return inner(input, init);
  };
}

async function callbackGet(url) {
  const response = await fetch(url, { method: 'GET', redirect: 'manual' });
  const text = await response.text();
  let error = 'unreadable';
  try {
    const parsed = JSON.parse(text);
    if (typeof parsed.error === 'string' && SAFE_CODE.test(parsed.error)) error = parsed.error;
    if (parsed.bound === true) error = 'bound';
  } catch {
    error = response.status === 200 ? 'captured' : 'malformed';
  }
  return { status: response.status, error };
}

async function consentUrl(
  env,
  authorizationUrl,
  login = {},
  fetchImpl = globalThis.fetch,
  retain = {},
) {
  return performLoopbackConsent({
    fetch: async (input, init) => {
      const target = String(input);
      if (retain.holdCallback === true && target.startsWith(retain.redirectUri ?? '')) {
        try {
          retain.code = new URL(target).searchParams.get('code') ?? retain.code;
        } catch {
          // The callback URL is unreadable. retainCode still holds the code.
        }
        return new Response('held', { status: 200 });
      }
      return fetchImpl(input, init);
    },
    authOrigin: new URL(env.ARI_TEST_SUPABASE_URL).origin,
    authorizationUrl,
    publishableKey: env.ARI_TEST_PUBLISHABLE_KEY,
    password: login.password ?? env.ARI_TEST_SYNTHETIC_PASSWORD,
    ...(typeof login.email === 'string' ? { email: login.email } : {}),
    retainCode(code) {
      retain.code = code;
    },
  });
}

function downstreamAuthorize(env, runtime, state, pkce) {
  const profile = profileOf(env, 'downstream_b');
  return buildAuthorizeUrl({
    authorizeEndpoint: new URL('/auth/v1/oauth/authorize', runtime.authOrigin).toString(),
    clientId: profile.clientId,
    redirectUri: profile.redirectUri,
    scopes: ['email'],
    callbackProfile: 'downstream_b',
    expectedOrigin: profile.origin,
    requirePort: true,
    omitResource: true,
    codeChallenge: pkce.codeChallenge,
    state,
  });
}

async function runN8(env, _ledger, timeoutMs, ctx) {
  ctx.cursor.gate = 'N8';
  const runtimeEnv = { ...env, ARI_LANE_B_EXECUTE: '1' };
  const subcases = [];
  const profile = profileOf(env, 'downstream_b');

  const unboundCounter = { exchanges: 0 };
  const unboundFacts = [];
  const unbound = await startExternalRuntime(runtimeEnv, {
    spawnChild: false,
    fetch: countFetch(unboundCounter, ctx.fetch),
    onGrantFact(fact) {
      unboundFacts.push(fact);
    },
  });
  try {
    const issued = await withTimeout(
      obtainGrant(unbound, env, 'external_a', {}, ctx.fetch),
      timeoutMs,
      ctx.signal,
    );
    const opened = await presentOnce(env.ARI_EXTERNAL_MCP_URL, issued.accessToken);
    const built = downstreamAuthorize(
      env,
      unbound,
      randomBytes(16).toString('base64url'),
      createPkce(),
    );
    if (!built.ok || built.resourceOmitted !== true) throw coded('resource_not_omitted');
    const consent = await withTimeout(
      consentUrl(env, built.url, {}, ctx.fetch),
      timeoutMs,
      ctx.signal,
    );
    const again = await presentOnce(env.ARI_EXTERNAL_MCP_URL, issued.accessToken);
    const fact = unboundFacts.at(-1);
    const pass =
      opened.error === 'downstream_authorization_required' &&
      consent.consentPerformed === true &&
      fact?.event === 'unknown_state' &&
      fact.failureClass === undefined &&
      unboundFacts.every((row) => row.event !== 'bound') &&
      unboundCounter.exchanges === 0 &&
      again.error === 'downstream_authorization_required' &&
      again.authorizationUrl !== undefined &&
      unbound.observation.bSessionId === null &&
      unbound.observation.markerReads === 0;
    subcases.push({
      id: 'unbound',
      executed: true,
      pass,
      reason: pass ? 'never_bound' : 'unbound_missed',
    });
  } finally {
    await stopExternalRuntime(unbound);
  }

  const wrongCounter = { exchanges: 0 };
  const wrongFacts = [];
  const wrong = await startExternalRuntime(runtimeEnv, {
    spawnChild: false,
    fetch: countFetch(wrongCounter, ctx.fetch),
    onGrantFact(fact) {
      wrongFacts.push(fact);
    },
  });
  try {
    const issued = await withTimeout(
      obtainGrant(wrong, env, 'external_a', {}, ctx.fetch),
      timeoutMs,
      ctx.signal,
    );
    const opened = await presentOnce(env.ARI_EXTERNAL_MCP_URL, issued.accessToken);
    if (opened.authorizationUrl === undefined) throw coded('handshake_missing');
    const retain = { holdCallback: true, redirectUri: profile.redirectUri };
    const consent = await withTimeout(
      consentUrl(env, opened.authorizationUrl, {}, ctx.fetch, retain),
      timeoutMs,
      ctx.signal,
    );
    const wrongState = randomBytes(16).toString('base64url');
    const delivered = await callbackGet(
      `${profile.redirectUri}?code=${encodeURIComponent(retain.code ?? '')}&state=${wrongState}`,
    );
    const fact = wrongFacts.at(-1);
    const pass =
      consent.consentPerformed === true &&
      typeof retain.code === 'string' &&
      retain.code.length > 0 &&
      delivered.status === 403 &&
      delivered.error === 'downstream_credential_unresolved' &&
      fact?.event === 'unknown_state' &&
      fact.failureClass === undefined &&
      wrongCounter.exchanges === 0 &&
      wrong.observation.bSessionId === null;
    subcases.push({
      id: 'wrong_state',
      executed: true,
      pass,
      reason: pass ? 'unknown_state' : 'wrong_state_missed',
    });
  } finally {
    await stopExternalRuntime(wrong);
  }

  const pkceCounter = { exchanges: 0 };
  const pkceFacts = [];
  const pkceRuntime = await startExternalRuntime(runtimeEnv, {
    spawnChild: false,
    fetch: countFetch(pkceCounter, ctx.fetch),
    onGrantFact(fact) {
      pkceFacts.push(fact);
    },
  });
  try {
    const issued = await withTimeout(
      obtainGrant(pkceRuntime, env, 'external_a', {}, ctx.fetch),
      timeoutMs,
      ctx.signal,
    );
    const opened = await presentOnce(env.ARI_EXTERNAL_MCP_URL, issued.accessToken);
    if (opened.authorizationUrl === undefined) {
      subcases.push({
        id: 'pkce_invalid_grant',
        executed: true,
        pass: false,
        reason: 'handshake_missing',
      });
    } else {
      const state = new URL(opened.authorizationUrl).searchParams.get('state');
      const built = downstreamAuthorize(env, pkceRuntime, state ?? '', createPkce());
      if (!built.ok || built.resourceOmitted !== true) throw coded('resource_not_omitted');
      const before = pkceCounter.exchanges;
      await withTimeout(consentUrl(env, built.url, {}, ctx.fetch), timeoutMs, ctx.signal);
      const fact = pkceFacts.at(-1);
      const pass =
        opened.error === 'downstream_authorization_required' &&
        fact?.event === 'exchange_failed' &&
        fact.failureClass === 'invalid_grant' &&
        fact.subjectMismatch !== true &&
        pkceFacts.every((row) => row.event !== 'bound') &&
        pkceCounter.exchanges === before + 1 &&
        pkceRuntime.observation.bSessionId === null &&
        pkceRuntime.observation.markerReads === 0;
      subcases.push({
        id: 'pkce_invalid_grant',
        executed: true,
        pass,
        reason: pass ? 'pkce_invalid_grant' : safeCode(fact?.failureClass ?? 'binding_missed'),
      });
    }
  } finally {
    await stopExternalRuntime(pkceRuntime);
  }

  const replayCounter = { exchanges: 0 };
  const facts = [];
  const replay = await startExternalRuntime(runtimeEnv, {
    spawnChild: false,
    fetch: countFetch(replayCounter, ctx.fetch),
    onGrantFact(fact) {
      facts.push(fact);
    },
  });
  try {
    const issued = await withTimeout(
      obtainGrant(replay, env, 'external_a', {}, ctx.fetch),
      timeoutMs,
      ctx.signal,
    );
    const opened = await presentOnce(env.ARI_EXTERNAL_MCP_URL, issued.accessToken);
    if (opened.authorizationUrl === undefined) {
      subcases.push({
        id: 'accepted_then_replay',
        executed: true,
        pass: false,
        reason: 'handshake_missing',
      });
    } else {
      const state = new URL(opened.authorizationUrl).searchParams.get('state');
      const before = replayCounter.exchanges;
      const consent = await withTimeout(
        consentUrl(env, opened.authorizationUrl, {}, ctx.fetch),
        timeoutMs,
        ctx.signal,
      );
      const bound = facts.find((fact) => fact.event === 'bound');
      const afterBind = replayCounter.exchanges;
      const replayed = await callbackGet(
        `${profile.redirectUri}?code=${encodeURIComponent(randomBytes(16).toString('base64url'))}&state=${state}`,
      );
      const replayFact = facts.at(-1);
      const persisted = await presentOnce(env.ARI_EXTERNAL_MCP_URL, issued.accessToken);
      const pass =
        consent.ok === true &&
        bound !== undefined &&
        safeUuid(bound.sessionId) !== undefined &&
        bound.subjectMismatch === false &&
        replayed.status === 403 &&
        replayed.error === 'downstream_credential_unresolved' &&
        replayFact?.event === 'replay' &&
        replayCounter.exchanges === afterBind &&
        afterBind === before + 1 &&
        persisted.authorizationUrl === undefined &&
        replay.observation.bSessionId === bound.sessionId &&
        replay.observation.markerReads === 0;
      subcases.push({
        id: 'accepted_then_replay',
        executed: true,
        pass,
        reason: pass
          ? 'replay_rejected'
          : safeCode(
              facts.find((fact) => fact.event === 'exchange_failed')?.failureClass ??
                'replay_missed',
            ),
      });
    }
    const beforeUri = replayCounter.exchanges;
    const factsBeforeUri = facts.length;
    const uri = await callbackGet(
      `${new URL(env.ARI_EXTERNAL_MCP_URL).origin}/oauth/downstream/cb?code=x&state=y`,
    );
    const uriFact = facts.length > factsBeforeUri ? facts.at(-1) : undefined;
    const uriPass = callbackUriMismatchPass({
      status: uri.status,
      error: uri.error,
      exchangesDelta: replayCounter.exchanges - beforeUri,
      grantEvent: uriFact?.event,
    });
    subcases.push({
      id: 'callback_uri_mismatch',
      executed: true,
      pass: uriPass,
      reason: uriPass ? 'redirect_not_exact' : 'uri_inconclusive',
    });
  } finally {
    await stopExternalRuntime(replay);
  }

  if (!loopbackSupabase(env.ARI_TEST_SUPABASE_URL)) {
    subcases.push(
      { id: 'signed_b_unbound', executed: false, pass: false, reason: 'not_executed' },
      { id: 'signed_b_mismatch', executed: false, pass: false, reason: 'not_executed' },
    );
  } else {
    const unboundCounter = { exchanges: 0 };
    const counting = countFetch(unboundCounter, ctx.fetch);
    const unboundSigned = await startExternalRuntime(runtimeEnv, {
      spawnChild: false,
      captureDownstreamCode: true,
      fetch: ctx.fetch,
    });
    try {
      const issuedA = await withTimeout(
        obtainGrant(unboundSigned, env, 'external_a', {}, counting),
        timeoutMs,
        ctx.signal,
      );
      const verifiedA = await verifyJwt(issuedA.accessToken, env, {
        audience: env.ARI_EXTERNAL_MCP_URL,
        role: 'mcp_ingress',
        clientId: env.ARI_EXTERNAL_A_CLIENT_ID,
        agentId: env.ARI_AGENT_ID,
        requireSource: true,
      });
      const opened = await presentOnce(env.ARI_EXTERNAL_MCP_URL, issuedA.accessToken);
      const before = unboundCounter.exchanges;
      const issuedB = await withTimeout(
        obtainGrant(unboundSigned, env, 'downstream_b', {}, counting),
        timeoutMs,
        ctx.signal,
      );
      const verifiedB = await verifyJwt(issuedB.accessToken, env, {
        audience: 'authenticated',
        role: 'authenticated',
        clientId: env.ARI_DOWNSTREAM_CLIENT_ID,
        agentId: env.ARI_AGENT_ID,
      });
      const again = await presentOnce(env.ARI_EXTERNAL_MCP_URL, issuedA.accessToken);
      const pass =
        opened.error === 'downstream_authorization_required' &&
        unboundCounter.exchanges === before + 1 &&
        verifiedB.sub === verifiedA.sub &&
        verifiedB.sessionId !== verifiedA.sessionId &&
        again.error === 'downstream_authorization_required' &&
        again.authorizationUrl !== undefined &&
        unboundSigned.observation.bSessionId === null &&
        unboundSigned.observation.markerReads === 0;
      subcases.push({
        id: 'signed_b_unbound',
        executed: true,
        pass,
        reason: pass ? 'signed_b_not_stored' : 'inconclusive',
      });
    } catch (error) {
      subcases.push({
        id: 'signed_b_unbound',
        executed: true,
        pass: false,
        reason: safeCode(error?.code ?? 'inconclusive'),
      });
    } finally {
      await stopExternalRuntime(unboundSigned);
    }

    const mismatchCounter = { exchanges: 0 };
    const mismatchFacts = [];
    const mismatchFetch = countFetch(mismatchCounter, async (input, init) => {
      const url = String(input);
      if (!url.includes('/oauth/token')) return ctx.fetch(input, init);
      const headers = new Headers(init?.headers ?? {});
      headers.set('x-ari-probe-b-claim', 'agent-mismatch');
      return ctx.fetch(input, { ...init, headers });
    });
    const mismatched = await startExternalRuntime(runtimeEnv, {
      spawnChild: false,
      fetch: mismatchFetch,
      onGrantFact(fact) {
        mismatchFacts.push(fact);
      },
    });
    try {
      const issued = await withTimeout(
        obtainGrant(mismatched, env, 'external_a', {}, ctx.fetch),
        timeoutMs,
        ctx.signal,
      );
      const opened = await presentOnce(env.ARI_EXTERNAL_MCP_URL, issued.accessToken);
      if (opened.authorizationUrl === undefined) {
        subcases.push({
          id: 'signed_b_mismatch',
          executed: true,
          pass: false,
          reason: 'inconclusive',
        });
      } else {
        const before = mismatchCounter.exchanges;
        await withTimeout(
          consentUrl(env, opened.authorizationUrl, {}, ctx.fetch),
          timeoutMs,
          ctx.signal,
        );
        const fact = mismatchFacts.find((row) => row.event === 'exchange_rejected');
        const pass =
          fact !== undefined &&
          fact.subjectMismatch === false &&
          fact.failureClass === undefined &&
          safeUuid(fact.sessionId) !== undefined &&
          mismatchCounter.exchanges === before + 1 &&
          mismatchFacts.every((row) => row.event !== 'bound') &&
          mismatched.observation.bSessionId === null &&
          mismatched.observation.markerReads === 0;
        subcases.push({
          id: 'signed_b_mismatch',
          executed: true,
          pass,
          reason: pass ? 'binding_rejected' : 'inconclusive',
        });
      }
    } catch (error) {
      subcases.push({
        id: 'signed_b_mismatch',
        executed: true,
        pass: false,
        reason: safeCode(error?.code ?? 'inconclusive'),
      });
    } finally {
      await stopExternalRuntime(mismatched);
    }
  }
  const signed = subcases.filter(
    (row) => row.id === 'signed_b_unbound' || row.id === 'signed_b_mismatch',
  );
  const signedHeld =
    signed.length === 2 && signed.every((row) => row.executed === true && row.pass === true);
  const pass = signedHeld && subcases.every((row) => row.pass === true);
  return {
    id: 'N8',
    name: GATE_NAMES.N8,
    executed: true,
    pass,
    label: pass ? 'signed_b_refused' : 'n8_incomplete',
    subcases,
  };
}

function gateIds(ledger, cleared, gate) {
  const ids = [];
  for (const row of ledger) {
    if (gate !== undefined && row.gate !== gate) continue;
    for (const id of ledgerIds(row)) {
      if (!cleared.has(id) && !ids.includes(id)) ids.push(id);
    }
  }
  return ids;
}

async function confirmCleanup(reader, ctx, timeoutMs, gate) {
  const ids = gateIds(ctx.ledger, ctx.cleared, gate);
  if (ids.length === 0) return 'not_required';
  const readback = await pauseForReadback(
    reader,
    {
      runId: ctx.runId,
      action: 'cleanup_sessions',
      gate: gate ?? ctx.cursor.gate,
      sessionIds: ids,
      expectedSessions: ids.length,
    },
    timeoutMs,
    ctx.signal,
  );
  if (readback.sessionsRows !== 0 || readback.refreshRows !== 0) {
    throw coded('cleanup_unconfirmed');
  }
  if (!exactIdBijection(readback.sessionIds, ids)) throw coded('cleanup_unconfirmed');
  for (const id of ids) {
    if (!readback.sessionIds.includes(id)) throw coded('cleanup_unconfirmed');
    ctx.cleared.add(id);
  }
  return 'confirmed';
}

async function runN2(env, ledger, reader, timeoutMs, ctx) {
  ctx.cursor.gate = 'N2';
  if (
    typeof env.ARI_N2_SECOND_EMAIL !== 'string' ||
    env.ARI_N2_SECOND_EMAIL.length === 0 ||
    typeof env.ARI_N2_SECOND_PASSWORD !== 'string' ||
    env.ARI_N2_SECOND_PASSWORD.length === 0
  ) {
    throw coded('second_user_required');
  }
  const prepared = await pauseForReadback(
    reader,
    { runId: ctx.runId, action: 'prepare_second_synthetic_user', gate: 'N2' },
    timeoutMs,
    ctx.signal,
  );
  const secondUserId = safeUuid(prepared.secondUserId);
  if (
    secondUserId === undefined ||
    prepared.createdForRun !== true ||
    prepared.email !== env.ARI_N2_SECOND_EMAIL ||
    prepared.email === SYNTHETIC_EMAIL
  ) {
    throw coded('second_user_unverified');
  }
  const runtimeEnv = { ...env, ARI_LANE_B_EXECUTE: '1' };
  const facts = [];
  const runtime = await startExternalRuntime(runtimeEnv, {
    spawnChild: false,
    fetch: ctx.fetch,
    onGrantFact(fact) {
      facts.push(fact);
    },
  });
  let crossPass = false;
  let baselineSub;
  let crossSubject;
  try {
    const issued = await withTimeout(
      obtainGrant(runtime, env, 'external_a', {}, ctx.fetch),
      timeoutMs,
      ctx.signal,
    );
    const baseline = await verifyJwt(issued.accessToken, env, {
      audience: env.ARI_EXTERNAL_MCP_URL,
      role: 'mcp_ingress',
      clientId: env.ARI_EXTERNAL_A_CLIENT_ID,
      agentId: env.ARI_AGENT_ID,
      requireSource: true,
    });
    const opened = await presentOnce(env.ARI_EXTERNAL_MCP_URL, issued.accessToken);
    if (opened.authorizationUrl === undefined) throw coded('handshake_missing');
    if (new URL(opened.authorizationUrl).searchParams.get('resource') !== null) {
      throw coded('resource_not_omitted');
    }
    const consent = await withTimeout(
      consentUrl(
        env,
        opened.authorizationUrl,
        {
          email: env.ARI_N2_SECOND_EMAIL,
          password: env.ARI_N2_SECOND_PASSWORD,
        },
        ctx.fetch,
      ),
      timeoutMs,
      ctx.signal,
    );
    const fact = facts.find((row) => row.subjectMismatch === true);
    baselineSub = baseline.sub;
    crossSubject = safeUuid(fact?.sub);
    markRejected(ledger, fact?.sessionId);
    const again = await presentOnce(env.ARI_EXTERNAL_MCP_URL, issued.accessToken);
    const user1Resolved = again.error !== 'downstream_authorization_required';
    crossPass = crossUserPass({
      event: fact?.event,
      failureClass: fact?.failureClass,
      subjectMismatch: fact?.subjectMismatch === true,
      bound: false,
      sessionId: fact?.sessionId,
      sub: fact?.sub,
      livenessChecks: runtime.observation.livenessChecks,
      markerReads: runtime.observation.markerReads,
      user1Resolved,
      user1Sub: baseline.sub,
      secondUserId,
      exchangeError: fact?.failureClass === 'invalid_grant' ? 'invalid_grant' : undefined,
    });
    if (consent.ok === true) crossPass = false;
  } finally {
    await stopExternalRuntime(runtime);
  }
  const positiveFacts = [];
  const positive = await startExternalRuntime(runtimeEnv, {
    spawnChild: false,
    fetch: ctx.fetch,
    onGrantFact(fact) {
      positiveFacts.push(fact);
    },
  });
  let positivePass = false;
  try {
    const issued = await withTimeout(
      obtainGrant(positive, env, 'external_a', {}, ctx.fetch),
      timeoutMs,
      ctx.signal,
    );
    const opened = await presentOnce(env.ARI_EXTERNAL_MCP_URL, issued.accessToken);
    const consent = await withTimeout(
      consentUrl(env, opened.authorizationUrl, {}, ctx.fetch),
      timeoutMs,
      ctx.signal,
    );
    const bound = positiveFacts.find(
      (fact) => fact.event === 'bound' && fact.sub === issued.claims?.sub,
    );
    positivePass =
      consent.ok === true &&
      bound !== undefined &&
      bound.subjectMismatch === false &&
      bound.sub === issued.claims?.sub;
  } finally {
    await stopExternalRuntime(positive);
  }
  if (baselineSub !== undefined && secondUserId !== baselineSub && crossSubject === secondUserId) {
    ctx.deletionEligible = true;
    ctx.eligibleSecondUserId = secondUserId;
  }
  await confirmCleanup(reader, ctx, timeoutMs, 'N2');
  if (ctx.deletionEligible === true && ctx.eligibleSecondUserId !== undefined) {
    const deleted = await pauseForContinue(
      reader,
      {
        runId: ctx.runId,
        action: 'delete_second_synthetic_user',
        gate: 'N2',
        secondUserId: ctx.eligibleSecondUserId,
      },
      timeoutMs,
      ctx.signal,
    );
    if (deleted.secondUserId !== ctx.eligibleSecondUserId) throw coded('readback_stale');
    ctx.secondDeleted = true;
  }
  return subcaseRow(
    'N2',
    [
      {
        id: 'cross_user',
        executed: true,
        pass: crossPass,
        reason: crossPass ? 'subject_rejected' : 'cross_user_missed',
      },
      {
        id: 'matching_subject',
        executed: true,
        pass: positivePass,
        reason: positivePass ? 'subject_bound' : 'control_failed',
      },
    ],
    'controller_second_user',
  );
}

async function probeMarker(env, token, timeoutMs, signal) {
  const target = new URL(MARKER_PATH, new URL(env.ARI_TEST_SUPABASE_URL).origin);
  if (
    target.pathname !== '/rest/v1/ari_probe_marker' ||
    target.search !== '?select=marker,owner_id'
  ) {
    throw coded('marker_path_refused');
  }
  return callBounded(timeoutMs, signal, async (abortSignal) => {
    let response;
    try {
      response = await fetch(target, {
        method: 'GET',
        redirect: 'error',
        signal: abortSignal,
        headers: {
          accept: 'application/json',
          authorization: `Bearer ${token}`,
          apikey: env.ARI_TEST_PUBLISHABLE_KEY,
        },
      });
    } catch (error) {
      if (abortSignal.aborted) throw error;
      throw coded('orchestration_timeout');
    }
    const text = await response.text();
    return classifyMarkerProbe(response.status, text);
  });
}

const MARKER_PATH = '/rest/v1/ari_probe_marker?select=marker,owner_id';

function expectedOwnerMarker(projectRef) {
  if (typeof projectRef !== 'string' || !PROJECT_REF.test(projectRef)) return null;
  return `ari-probe-marker-${projectRef}`;
}

function ownerMarkerHeld(probe, projectRef, ownerId) {
  const marker = expectedOwnerMarker(projectRef);
  return (
    marker !== null &&
    probe?.rows === 1 &&
    probe?.httpStatus === 200 &&
    probe?.marker === marker &&
    ownerId !== undefined &&
    probe?.ownerId === ownerId
  );
}

function grantRecord(row) {
  if (row === null || typeof row !== 'object' || Array.isArray(row)) return null;
  if (typeof row.role !== 'string' || typeof row.privilege !== 'string') return null;
  if (typeof row.table !== 'string' || typeof row.allowed !== 'boolean') return null;
  return {
    allowed: row.allowed,
    privilege: row.privilege,
    role: row.role,
    table: row.table,
  };
}

function mappingRecord(row) {
  if (row === null || typeof row !== 'object' || Array.isArray(row)) return null;
  if (typeof row.clientId !== 'string' || row.clientId.length === 0) return null;
  if (typeof row.resource !== 'string' || row.resource.length === 0) return null;
  if (typeof row.agentId !== 'string' || typeof row.probeLabel !== 'string') return null;
  return {
    agentId: row.agentId,
    clientId: row.clientId,
    probeLabel: row.probeLabel,
    resource: row.resource,
  };
}

const CLIENT_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const OWNER_QUAL = '(( SELECT auth.uid() AS uid) = owner_id)';

function sqlQuote(value) {
  return `'${value.replaceAll("'", "''")}'`;
}

export function canonicalOwnerQual() {
  return OWNER_QUAL;
}

export function canonicalF1Qual(baselineClientId, externalClientId) {
  if (typeof baselineClientId !== 'string' || typeof externalClientId !== 'string') return null;
  if (!CLIENT_ID.test(baselineClientId) || !CLIENT_ID.test(externalClientId)) return null;
  if (baselineClientId === externalClientId) return null;
  const comparison = (clientId) => {
    const literal = sqlQuote(clientId);
    return `(COALESCE((auth.jwt() ->> 'client_id'::text), ''::text) IS DISTINCT FROM ${literal}::text)`;
  };
  return `(${comparison(baselineClientId)} AND ${comparison(externalClientId)})`;
}

function policySnapshot(readback, env, baselineClientId) {
  const external = env.ARI_EXTERNAL_A_CLIENT_ID;
  const agentId = env.ARI_AGENT_ID;
  const resource = env.ARI_EXTERNAL_MCP_URL;
  if (typeof baselineClientId !== 'string' || baselineClientId.length === 0) return null;
  if (typeof external !== 'string' || external.length === 0 || external === baselineClientId) {
    return null;
  }
  if (typeof agentId !== 'string' || typeof resource !== 'string' || resource.length === 0) {
    return null;
  }
  const f1 = readback?.f1;
  if (f1 === null || typeof f1 !== 'object' || Array.isArray(f1)) return null;
  if (f1.name !== F1_NAME || f1.schema !== 'public' || f1.table !== 'ari_probe_marker') return null;
  if (f1.command !== 'select' || f1.kind !== 'restrictive') return null;
  if (!Array.isArray(f1.roles) || f1.roles.length !== 1 || f1.roles[0] !== 'authenticated') {
    return null;
  }
  const expectedQual = canonicalF1Qual(baselineClientId, external);
  if (expectedQual === null || typeof f1.qual !== 'string' || f1.qual !== expectedQual) return null;
  const rls = readback.rls;
  if (
    rls?.schema !== 'public' ||
    rls?.table !== 'ari_probe_marker' ||
    rls?.enabled !== true ||
    rls?.forced !== true
  ) {
    return null;
  }
  const owner = readback.ownerPolicy;
  if (
    owner?.name !== 'ari_probe_marker_owner_read' ||
    owner?.kind !== 'permissive' ||
    owner?.command !== 'select' ||
    owner?.qual !== canonicalOwnerQual() ||
    !Array.isArray(owner?.roles) ||
    owner.roles.length !== 1 ||
    owner.roles[0] !== 'authenticated'
  ) {
    return null;
  }
  if (!Array.isArray(readback.grants)) return null;
  const grants = readback.grants.map(grantRecord);
  if (grants.some((row) => row === null)) return null;
  grants.sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
  const expectedGrants = [
    { allowed: false, privilege: 'SELECT', role: 'anon', table: 'public.ari_probe_marker' },
    { allowed: true, privilege: 'SELECT', role: 'authenticated', table: 'public.ari_probe_marker' },
    { allowed: false, privilege: 'SELECT', role: 'mcp_ingress', table: 'public.ari_probe_marker' },
    { allowed: false, privilege: 'SELECT', role: 'public', table: 'public.ari_probe_marker' },
  ];
  expectedGrants.sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
  if (JSON.stringify(grants) !== JSON.stringify(expectedGrants)) return null;
  if (!Array.isArray(readback.mappings) || readback.mappings.length !== 2) return null;
  const mappings = readback.mappings.map(mappingRecord);
  if (mappings.some((row) => row === null)) return null;
  const baseline = mappings.find((row) => row.probeLabel === 'ari-test-synthetic');
  const externalRow = mappings.find((row) => row.probeLabel === 'ari-test-external-a');
  if (baseline === undefined || externalRow === undefined) return null;
  if (baseline.clientId !== baselineClientId || baseline.agentId !== agentId) return null;
  if (externalRow.clientId !== external || externalRow.agentId !== agentId) return null;
  if (externalRow.resource !== resource || baseline.resource === externalRow.resource) return null;
  return JSON.stringify({
    baselineResource: baseline.resource,
    externalResource: externalRow.resource,
    f1Qual: f1.qual,
    grants,
    ownerQual: owner.qual,
  });
}

function hookBound(env) {
  return {
    projectRef: env.ARI_TEST_PROJECT_REF,
    resource: env.ARI_EXTERNAL_MCP_URL,
    agentId: env.ARI_AGENT_ID,
    externalClientId: env.ARI_EXTERNAL_A_CLIENT_ID,
  };
}

async function verifyJwt(token, env, checks) {
  let keys;
  try {
    keys = createLocalJWKSet(JSON.parse(env.ARI_TEST_JWKS_JSON));
  } catch {
    throw coded('hook_off_unverified');
  }
  const issuer = new URL('/auth/v1', new URL(env.ARI_TEST_SUPABASE_URL).origin).toString();
  const requiredClaims = ['exp', 'iat', 'sub', 'role', 'client_id', 'session_id'];
  if (checks.agentId !== null) requiredClaims.push('agent_id');
  if (checks.requireSource === true) requiredClaims.push('source_session_id');
  let payload;
  try {
    const verified = await jwtVerify(token, keys, {
      issuer,
      audience: checks.audience,
      algorithms: ['ES256', 'RS256', 'EdDSA'],
      requiredClaims,
    });
    payload = verified.payload;
  } catch {
    throw coded('hook_off_unverified');
  }
  if (typeof payload.exp !== 'number' || !Number.isSafeInteger(payload.exp)) {
    throw coded('hook_off_unverified');
  }
  if (typeof payload.iat !== 'number' || !Number.isSafeInteger(payload.iat)) {
    throw coded('hook_off_unverified');
  }
  if (payload.exp <= payload.iat) throw coded('hook_off_unverified');
  if (payload.iat * 1000 > Date.now() + 60_000) throw coded('hook_off_unverified');
  if (payload.role !== checks.role) throw coded('hook_off_unverified');
  if (payload.client_id !== checks.clientId) throw coded('hook_off_unverified');
  if (checks.agentId === null) {
    if (payload.agent_id !== undefined && payload.agent_id !== null)
      throw coded('hook_off_unverified');
    if (payload.source_session_id !== undefined) throw coded('hook_off_unverified');
  } else if (payload.agent_id !== checks.agentId) {
    throw coded('hook_off_unverified');
  }
  const sessionId = safeUuid(payload.session_id);
  const sourceSessionId = safeUuid(payload.source_session_id);
  if (sessionId === undefined) throw coded('hook_off_unverified');
  if (checks.requireSource === true) {
    if (sourceSessionId === undefined || sourceSessionId === sessionId) {
      throw coded('hook_off_unverified');
    }
  }
  const sub = safeUuid(payload.sub);
  if (sub === undefined) throw coded('hook_off_unverified');
  return { sessionId, sourceSessionId, sub };
}

async function liveOwner(env, token, sub, timeoutMs, signal) {
  return callBounded(timeoutMs, signal, async (abortSignal) => {
    const response = await fetch(
      new URL('/auth/v1/user', new URL(env.ARI_TEST_SUPABASE_URL).origin),
      {
        method: 'GET',
        signal: abortSignal,
        headers: {
          accept: 'application/json',
          authorization: `Bearer ${token}`,
          apikey: env.ARI_TEST_PUBLISHABLE_KEY,
        },
      },
    );
    let body = null;
    try {
      body = await response.json();
    } catch (error) {
      if (abortSignal.aborted) throw error;
      body = null;
    }
    return response.status === 200 && body?.id === sub;
  });
}

async function restoreHook(reader, state, timeoutMs, signal, bound, env) {
  const readback = await pauseForReadback(
    reader,
    {
      runId: state.runId,
      action: 'restore_hook_configuration',
      gate: 'N6',
      hookHash: state.hash,
      hookManifest: state.manifest,
    },
    timeoutMs,
    signal,
  );
  let restored;
  try {
    restored = hookManifestHash(readback.hookManifest, bound);
  } catch (error) {
    state.mismatch = true;
    throw error;
  }
  if (
    readback.hookEnabled !== true ||
    restored !== state.hash ||
    readback.function !== HOOK_FUNCTION ||
    policySnapshot(readback, env, state.baselineClientId) !== state.policy
  ) {
    state.mismatch = true;
    throw coded('hook_restore_mismatch');
  }
  clearRecovery(state);
  state.confirmed = true;
  state.locator = undefined;
}

function restoreStatusOf(state) {
  if (state.confirmed) return 'confirmed';
  if (!state.needed) return 'not_required';
  if (state.mismatch === true) return 'failed';
  return 'pending';
}

async function runN6(env, _ledger, reader, timeoutMs, restoreState, ctx) {
  ctx.cursor.gate = 'N6';
  const bound = hookBound(env);
  const captured = await pauseForReadback(
    reader,
    { runId: ctx.runId, action: 'capture_hook_manifest', gate: 'N6' },
    timeoutMs,
    ctx.signal,
  );
  const hash = hookManifestHash(captured.hookManifest, bound);
  const baselineClientId = captured.hookManifest?.baselineClientId;
  const policy = policySnapshot(captured, env, baselineClientId);
  if (policy === null) throw coded('f1_readback_missing');
  restoreState.hash = hash;
  restoreState.manifest = captured.hookManifest;
  restoreState.policy = policy;
  restoreState.baselineClientId = baselineClientId;
  restoreState.projectRef = env.ARI_TEST_PROJECT_REF;
  restoreState.runId = ctx.runId;
  const runtimeEnv = { ...env, ARI_LANE_B_EXECUTE: '1' };
  const capture = await startExternalRuntime(runtimeEnv, {
    spawnChild: false,
    captureDownstreamCode: true,
    fetch: ctx.fetch,
  });
  let owner = null;
  let ownerMarker = false;
  try {
    const issued = await withTimeout(
      obtainGrant(capture, env, 'downstream_b', {}, ctx.fetch),
      timeoutMs,
      ctx.signal,
    );
    let verified;
    try {
      verified = await verifyJwt(issued.accessToken, env, {
        audience: 'authenticated',
        role: 'authenticated',
        clientId: env.ARI_DOWNSTREAM_CLIENT_ID,
        agentId: env.ARI_AGENT_ID,
      });
    } catch (error) {
      if (error?.code !== 'hook_off_unverified') throw error;
      verified = undefined;
    }
    const probe = await probeMarker(env, issued.accessToken, timeoutMs, ctx.signal);
    ownerMarker = ownerMarkerHeld(probe, env.ARI_TEST_PROJECT_REF, verified?.sub);
    if (verified !== undefined) owner = { sub: verified.sub, bSessionId: verified.sessionId };
  } finally {
    await stopExternalRuntime(capture);
  }
  if (!ownerMarker || owner === null) {
    await confirmCleanup(reader, ctx, timeoutMs, 'N6');
    return subcaseRow(
      'N6',
      [{ id: 'owner_read', executed: true, pass: false, reason: 'owner_missing' }],
      'f1',
    );
  }
  armRecovery(restoreState);
  const disabled = await pauseForReadback(
    reader,
    {
      runId: ctx.runId,
      action: 'disable_current_hook',
      gate: 'N6',
      hookHash: hash,
      hookManifest: restoreState.manifest,
    },
    timeoutMs,
    ctx.signal,
  );
  if (
    disabled.hookEnabled !== false ||
    disabled.hookHash !== hash ||
    disabled.function !== HOOK_FUNCTION ||
    policySnapshot(disabled, env, restoreState.baselineClientId) !== restoreState.policy
  ) {
    throw coded('hook_disable_mismatch');
  }
  const hookOffRuntime = await startExternalRuntime(runtimeEnv, {
    spawnChild: false,
    captureDownstreamCode: true,
    fetch: ctx.fetch,
  });
  let denial = false;
  let rows = null;
  let verified = false;
  let liveSession = false;
  let category;
  let httpStatus;
  try {
    const issued = await withTimeout(
      obtainGrant(hookOffRuntime, env, 'external_a', {}, ctx.fetch),
      timeoutMs,
      ctx.signal,
    );
    const hookOff = await verifyJwt(issued.accessToken, env, {
      audience: 'authenticated',
      role: 'authenticated',
      clientId: env.ARI_EXTERNAL_A_CLIENT_ID,
      agentId: null,
    });
    if (hookOff.sub !== owner.sub || hookOff.sessionId === owner.bSessionId) {
      throw coded('hook_off_unverified');
    }
    liveSession = await liveOwner(env, issued.accessToken, owner.sub, timeoutMs, ctx.signal);
    if (!liveSession) throw coded('hook_off_unverified');
    verified = true;
    const probe = await probeMarker(env, issued.accessToken, timeoutMs, ctx.signal);
    denial = probe.denial === true && probe.category === 'rls_empty' && probe.httpStatus === 200;
    rows = probe.rows;
    category = probe.category;
    httpStatus = probe.httpStatus;
  } finally {
    await stopExternalRuntime(hookOffRuntime);
  }
  const cleaned = await confirmCleanup(reader, ctx, timeoutMs, 'N6');
  await restoreHook(reader, restoreState, timeoutMs, ctx.signal, bound, env);
  const canaryRuntime = await startExternalRuntime(runtimeEnv, {
    spawnChild: false,
    fetch: ctx.fetch,
  });
  let canary = false;
  try {
    const issued = await withTimeout(
      obtainGrant(canaryRuntime, env, 'external_a', {}, ctx.fetch),
      timeoutMs,
      ctx.signal,
    );
    const checked = await verifyJwt(issued.accessToken, env, {
      audience: env.ARI_EXTERNAL_MCP_URL,
      role: 'mcp_ingress',
      clientId: env.ARI_EXTERNAL_A_CLIENT_ID,
      agentId: env.ARI_AGENT_ID,
      requireSource: true,
    });
    const presented = await presentOnce(env.ARI_EXTERNAL_MCP_URL, issued.accessToken);
    canary =
      checked.sub === owner.sub &&
      presented.status === 403 &&
      presented.error === 'downstream_authorization_required';
    await confirmCleanup(reader, ctx, timeoutMs, 'N6');
  } finally {
    await stopExternalRuntime(canaryRuntime);
  }
  const pass = n6Pass({
    verified,
    denial,
    category,
    httpStatus,
    rows,
    ownerMarker,
    liveSession,
    policyUnchanged: true,
    cleanup: cleaned,
    restore: 'confirmed',
    canary,
    hookHash: hash,
  });
  return subcaseRow(
    'N6',
    [
      {
        id: 'f1_denial',
        executed: true,
        pass: denial && verified && liveSession,
        reason: denial && verified && liveSession ? 'marker_denied' : 'denial_missed',
      },
      {
        id: 'restore_canary',
        executed: true,
        pass: canary && restoreState.confirmed === true,
        reason: canary ? 'canary_ok' : 'canary_missed',
      },
    ],
    pass ? 'hook_restored' : 'n6_incomplete',
  );
}

function notExecuted(id) {
  return { id, name: GATE_NAMES[id], executed: false, pass: false, label: 'not_executed' };
}

function rowsPass(selected, rows) {
  return rows.every((row) =>
    selected.includes(row.id)
      ? row.executed === true && row.pass === true
      : row.executed === false && row.pass === false,
  );
}

function parentReceipt(env, gate, selected, results, ledger, runId, outcome) {
  const rows = GATE_ORDER.map((id) => results.get(id) ?? notExecuted(id));
  let pass = rowsPass(selected, rows);
  if (
    outcome.issuanceStatus === 'unresolved' ||
    outcome.cleanupStatus === 'unresolved' ||
    outcome.cleanupStatus === 'failed' ||
    outcome.restoreStatus === 'failed' ||
    outcome.restoreStatus === 'pending'
  ) {
    pass = false;
  }
  return {
    type: 'receipt',
    packet: 'lane-b-n-gates',
    profile: 'TEST_ONLY_PUBLIC_PKCE',
    acceptance: false,
    hostedContact: hostedTest(env.ARI_TEST_SUPABASE_URL),
    hookInstalled: false,
    executedByWriter: false,
    syntheticLoopback: loopbackSupabase(env.ARI_TEST_SUPABASE_URL),
    actualHead: gate.actualHead,
    reviewedHead: gate.reviewedHead,
    projectRef: env.ARI_TEST_PROJECT_REF,
    runId,
    selectedGates: selected,
    rowsPass: pass,
    issuanceStatus: outcome.issuanceStatus,
    cleanupStatus: outcome.cleanupStatus,
    restoreStatus: outcome.restoreStatus,
    unresolvedAttemptIds: outcome.unresolvedAttemptIds,
    ...(typeof outcome.recoveryLocator === 'string'
      ? { recoveryLocator: outcome.recoveryLocator }
      : {}),
    rows,
    sessionLedger: ledger,
  };
}

export async function runNGates(env, stdin) {
  const gate = controllerGate(env);
  if (!gate.ok) throw coded(gate.reason);
  if (env.ARI_N_GATES_EXECUTE !== '1') throw coded('live_runtime_not_started');
  if (!freshBuildReady()) throw coded('stale_build');
  refuseLocalMint(env);
  const selected = selectNGates(env.ARI_N_GATES);
  const timeoutMs = timeoutMsOf(env);
  const ledger = [];
  const results = new Map();
  const reader = lineReader(stdin);
  const cursor = { gate: 'N3' };
  const signal = createSignal();
  const issuance = createIssuanceTracker(ledger, cursor, signal);
  const ctx = {
    runId: randomUUID(),
    cursor,
    ledger,
    cleared: new Set(),
    fetch: issuance.wrap(globalThis.fetch),
    signal,
    issuance,
    deletionEligible: false,
    eligibleSecondUserId: undefined,
    secondDeleted: false,
  };
  const restoreState = {
    needed: false,
    confirmed: false,
    mismatch: false,
    hash: undefined,
    manifest: undefined,
    runId: ctx.runId,
    projectRef: env.ARI_TEST_PROJECT_REF,
    locator: undefined,
  };
  let thrown;
  let cleanupStatus = 'not_required';
  let issuanceStatus = 'not_required';
  try {
    for (const id of selected) {
      let row;
      if (id === 'N3') row = await runN3(env, ledger, timeoutMs, ctx);
      else if (id === 'N7') row = await runN7(env, ledger, timeoutMs, ctx);
      else if (id === 'N8') row = await runN8(env, ledger, timeoutMs, ctx);
      else if (id === 'N2') row = await runN2(env, ledger, reader, timeoutMs, ctx);
      else if (id === 'N6') row = await runN6(env, ledger, reader, timeoutMs, restoreState, ctx);
      else throw coded('live_configuration_incomplete');
      results.set(id, row);
      if (id !== 'N2' && id !== 'N6') await confirmCleanup(reader, ctx, timeoutMs, id);
      if (row.pass !== true) break;
    }
  } catch (error) {
    thrown = error;
    if (error !== null && typeof error === 'object') error.sessionLedger = ledger;
  } finally {
    try {
      await ctx.issuance.settle(Math.min(Math.max(timeoutMs, 3_000), 5_000));
      const ambiguous = ctx.issuance.ambiguous();
      if (ambiguous) {
        issuanceStatus = 'unresolved';
        // This readback does not settle the attempt, and ids in it are not deletable.
        await pauseForReadback(
          reader,
          {
            runId: ctx.runId,
            action: 'reconcile_unresolved_issuance',
            gate: ctx.cursor.gate,
            gates: ctx.issuance.unresolvedGates(),
            attemptIds: ctx.issuance.unresolvedAttemptIds(),
          },
          timeoutMs,
          signal,
        );
        const known = gateIds(ledger, ctx.cleared);
        if (known.length > 0) await confirmCleanup(reader, ctx, timeoutMs);
        cleanupStatus = 'unresolved';
      } else {
        if (ctx.issuance.attempted()) issuanceStatus = 'resolved';
        const recorded = gateIds(ledger, new Set());
        const leftover = gateIds(ledger, ctx.cleared);
        if (leftover.length > 0) {
          await confirmCleanup(reader, ctx, timeoutMs);
          cleanupStatus = gateIds(ledger, ctx.cleared).length === 0 ? 'confirmed' : 'failed';
        } else if (recorded.length > 0) {
          cleanupStatus = 'confirmed';
        }
      }
    } catch {
      if (ctx.issuance.ambiguous()) {
        issuanceStatus = 'unresolved';
        cleanupStatus = 'unresolved';
      } else {
        cleanupStatus = 'failed';
      }
    }
    const unresolvedAttemptIds = ctx.issuance.unresolvedAttemptIds();
    if (unresolvedAttemptIds.length > 0) {
      issuanceStatus = 'unresolved';
      if (cleanupStatus !== 'failed') cleanupStatus = 'unresolved';
    }
    if (
      ctx.deletionEligible === true &&
      ctx.eligibleSecondUserId !== undefined &&
      ctx.secondDeleted !== true &&
      cleanupStatus !== 'failed' &&
      cleanupStatus !== 'unresolved'
    ) {
      try {
        const deleted = await pauseForContinue(
          reader,
          {
            runId: ctx.runId,
            action: 'delete_second_synthetic_user',
            gate: 'N2',
            secondUserId: ctx.eligibleSecondUserId,
          },
          timeoutMs,
          signal,
        );
        if (deleted.secondUserId === ctx.eligibleSecondUserId) ctx.secondDeleted = true;
      } catch {
        ctx.secondDeleted = false;
      }
    }
    if (restoreState.needed && !restoreState.confirmed) {
      try {
        await restoreHook(reader, restoreState, timeoutMs, signal, hookBound(env), env);
      } catch (restoreError) {
        if (restoreState.mismatch !== true) restoreState.error = safeCode(restoreError?.code);
      }
    }
    if (thrown !== undefined && thrown !== null && typeof thrown === 'object') {
      thrown.restoreStatus = restoreStatusOf(restoreState);
      thrown.cleanupStatus = cleanupStatus;
      thrown.issuanceStatus = issuanceStatus;
      thrown.unresolvedAttemptIds = unresolvedAttemptIds;
      if (restoreState.locator !== undefined) thrown.recoveryLocator = restoreState.locator;
      thrown.runId = ctx.runId;
    }
    signal.dispose();
    reader.close();
  }
  if (thrown !== undefined) throw thrown;
  const receipt = parentReceipt(env, gate, selected, results, ledger, ctx.runId, {
    issuanceStatus,
    cleanupStatus,
    restoreStatus: restoreStatusOf(restoreState),
    unresolvedAttemptIds: ctx.issuance.unresolvedAttemptIds(),
    recoveryLocator: restoreState.locator,
  });
  assertIpcHasNoSecrets(receipt);
  return receipt;
}

async function main() {
  const command = process.argv[2] ?? 'plan';
  if (command === 'plan') {
    process.stdout.write(`${JSON.stringify(nGatesPlan(), null, 2)}\n`);
    return;
  }
  if (command !== 'run') {
    process.stderr.write('usage: node scripts/run-ari-test-n-gates.mjs [plan|run]\n');
    process.exitCode = 2;
    return;
  }
  const gate = controllerGate(process.env);
  if (!gate.ok) {
    process.stderr.write(`${gate.reason}\n`);
    process.exitCode = 2;
    return;
  }
  if (process.env.ARI_N_GATES_EXECUTE !== '1') {
    process.stderr.write('live_runtime_not_started\n');
    process.exitCode = 2;
    return;
  }
  try {
    const receipt = await runNGates(process.env, process.stdin);
    if (receipt.rowsPass !== true) {
      process.stdout.write(`${JSON.stringify(receipt)}\n`);
      process.stderr.write('n_gates_row_failed\n');
      process.exitCode = 2;
      return;
    }
    process.stdout.write(`${JSON.stringify(receipt)}\n`);
  } catch (error) {
    const failure = {
      type: 'receipt',
      packet: 'lane-b-n-gates',
      acceptance: false,
      hookInstalled: false,
      executedByWriter: false,
      rowsPass: false,
      reason: safeCode(error?.code),
      restoreStatus: safeCode(error?.restoreStatus ?? 'not_required'),
      cleanupStatus: safeCode(error?.cleanupStatus ?? 'not_required'),
      issuanceStatus: safeCode(error?.issuanceStatus ?? 'not_required'),
      unresolvedAttemptIds: Array.isArray(error?.unresolvedAttemptIds)
        ? error.unresolvedAttemptIds.filter((id) => safeUuid(id) !== undefined)
        : [],
      ...(typeof error?.runId === 'string' ? { runId: error.runId } : {}),
      ...(typeof error?.recoveryLocator === 'string'
        ? { recoveryLocator: error.recoveryLocator }
        : {}),
      sessionLedger: Array.isArray(error?.sessionLedger) ? error.sessionLedger : [],
    };
    try {
      assertIpcHasNoSecrets(failure);
      process.stdout.write(`${JSON.stringify(failure)}\n`);
    } catch {
      process.stdout.write(
        '{"type":"receipt","packet":"lane-b-n-gates","acceptance":false,"rowsPass":false}\n',
      );
    }
    process.stderr.write(`${safeCode(error?.code)}\n`);
    process.exitCode = 2;
  }
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(invokedPath).href) {
  await main();
}
