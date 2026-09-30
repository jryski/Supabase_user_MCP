/**
 * Remaining TEST gates N3, N7, N8, N2, and N6.
 * Default command is `plan`. It does not open a socket and does not contact
 * hosted TEST. `run` stays closed unless the controller opens the G5 gates
 * and sets ARI_N_GATES_EXECUTE=1. This packet does not apply SQL, install a
 * hook, register a client, or put an admin credential in the MCP child.
 * acceptance stays false. Historical H1 rows stay on the Lane B runner.
 */
import { createHash, randomBytes } from 'node:crypto';
import { statSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';

import {
  buildAuthorizeUrl,
  CALLBACK_PROFILES,
  createPkce,
  exchangeNativeCode,
  performLoopbackConsent,
  runOpenIdNegative,
} from '../docs/evidence/ari-test-probe/consent-harness.mjs';
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
const CANARY = /^ari-probe-marker-[a-z0-9]{20}$/u;
const HOOK_FUNCTION = 'ari_probe.custom_access_token_hook';

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

export function hookManifestHash(manifest) {
  if (manifest === null || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw coded('hook_manifest_unreadable');
  }
  const allowed = [
    'enabled',
    'function',
    'projectRef',
    'resource',
    'agentId',
    'externalClientId',
    'baselineClientId',
  ];
  const keys = Object.keys(manifest);
  if (keys.some((key) => !allowed.includes(key))) throw coded('hook_manifest_unreadable');
  if (manifest.enabled !== true || manifest.function !== HOOK_FUNCTION) {
    throw coded('hook_manifest_unreadable');
  }
  const canonical = JSON.stringify(
    Object.fromEntries(keys.sort().map((key) => [key, manifest[key]])),
  );
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
    const marker = parsed.length === 1 ? parsed[0]?.marker : undefined;
    return {
      ok: true,
      denial: false,
      rows: parsed.length,
      httpStatus: 200,
      category: 'rows',
      markerMatched: typeof marker === 'string' && CANARY.test(marker),
    };
  }
  if (status === 401 || status === 403) {
    return { ok: true, denial: true, rows: 0, httpStatus: status, category: 'http_denied' };
  }
  return { ok: false, denial: false, rows: null, httpStatus: status, reason: 'inconclusive' };
}

export function openIdSubcasePass(receipt, expected) {
  if (receipt?.ok !== true || receipt.reason !== 'openid_rejected') return false;
  if (receipt.policyMarker !== 'openid_scope_refused') return false;
  if (receipt.rejectionStage !== 'exchange' || receipt.exchangeStatus !== 403) return false;
  if (receipt.accessTokenPresent === true || receipt.idTokenPresent === true) return false;
  if (receipt.refreshTokenPresent === true) return false;
  if (receipt.consentFlow !== expected.consentFlow) return false;
  if (expected.omitResource === true) {
    return receipt.resourceOnAuthorize === false && receipt.resourceOnExchange === false;
  }
  return receipt.resourceOnAuthorize === true && receipt.resourceOnExchange === true;
}

export function crossUserPass(fact) {
  if (fact?.subjectMismatch !== true || fact?.bound === true) return false;
  if (fact?.exchangeError === 'invalid_grant') return false;
  if (safeUuid(fact?.sessionId) === undefined || safeUuid(fact?.sub) === undefined) return false;
  if (fact.livenessChecks !== 0 || fact.markerReads !== 0) return false;
  if (fact.user1Resolved === true) return false;
  return fact.user1Sub !== fact.sub;
}

export function n6Pass(input) {
  return (
    input?.denial === true &&
    input?.cleanup === 'confirmed' &&
    input?.restore === 'confirmed' &&
    input?.canary === true &&
    typeof input?.hookHash === 'string' &&
    SHA256.test(input.hookHash) &&
    input?.rows === 0
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
      'N8 uses the real callback. Unbound, unknown state, replay, mismatched binding, and redirect mismatch are denials. Cross-user B is N2.',
      'N2: create one run-owned second synthetic user, type continue, then delete that user after cleanup. The child never receives the password.',
      'N6: read back the enabled hook manifest, prove B can read the marker, disable only that hook, probe the marker with hook-off A, clean sessions, restore the same manifest, then canary.',
      'Restore the hook on failure, timeout, and abort. N6 passes only when denial, cleanup, restore, and canary all hold.',
      'Stdin is the line continue, or one readback JSON line with no credential.',
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

function withTimeout(promise, timeoutMs) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(coded('orchestration_timeout')), timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
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

function rememberLedger(ledger, entry) {
  const row = { gate: entry.gate };
  for (const key of [
    'passwordSessionId',
    'sourceSessionId',
    'bSessionId',
    'canarySessionId',
    'sub',
  ]) {
    const id = safeUuid(entry[key]);
    if (id !== undefined) row[key] = id;
  }
  if (entry.rejected === true) row.rejected = true;
  if (Object.keys(row).length === 1) return;
  ledger.push(row);
}

async function pauseForContinue(reader, action, timeoutMs) {
  writeJson({ type: 'controller_action', ...action });
  const line = await withTimeout(reader.next(), timeoutMs);
  if (!isContinueLine(line)) throw coded('stdin_refused');
}

async function pauseForReadback(reader, action, timeoutMs) {
  writeJson({ type: 'controller_action', ...action });
  const line = await withTimeout(reader.next(), timeoutMs);
  if (typeof line !== 'string' || line.length === 0) throw coded('readback_required');
  let parsed;
  try {
    parsed = JSON.parse(line);
  } catch {
    throw coded('readback_malformed');
  }
  assertIpcHasNoSecrets(parsed);
  if (parsed?.type !== 'readback') throw coded('readback_required');
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

async function obtainGrant(runtime, env, kind, login = {}) {
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
    fetch: globalThis.fetch,
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
    fetch: globalThis.fetch,
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

async function runN3(env, ledger, timeoutMs) {
  const evidenceLabel = loopbackSupabase(env.ARI_TEST_SUPABASE_URL)
    ? 'loopback_issuer_local_verifier_expectation'
    : 'genuine_hosted_a';
  const runtimeEnv = { ...env, ARI_LANE_B_EXECUTE: '1' };
  const control = await startExternalRuntime(runtimeEnv, { spawnChild: false });
  let token;
  try {
    const issued = await withTimeout(obtainGrant(control, env, 'external_a'), timeoutMs);
    token = issued.accessToken;
    rememberLedger(ledger, {
      gate: 'N3',
      passwordSessionId: issued.passwordSessionId,
      sourceSessionId: issued.claims?.sourceSessionId,
    });
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

async function runN7(env, ledger, timeoutMs) {
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
    for (const consentFlow of ['approval_post', 'already_consented_get']) {
      const receipt = await withTimeout(
        runOpenIdNegative({
          fetch: globalThis.fetch,
          authOrigin: new URL(env.ARI_TEST_SUPABASE_URL).origin,
          publishableKey: env.ARI_TEST_PUBLISHABLE_KEY,
          clientId,
          redirectUri,
          scopes: ['openid', 'email'],
          callbackProfile: profile,
          expectedOrigin: new URL(redirectUri).origin,
          requirePort: true,
          password: env.ARI_TEST_SYNTHETIC_PASSWORD,
          ...(omitResource ? {} : { resource }),
        }),
        timeoutMs,
      );
      rememberLedger(ledger, { gate: 'N7', passwordSessionId: receipt.passwordSessionId });
      const pass = openIdSubcasePass(receipt, { consentFlow, omitResource });
      subcases.push({
        id: `${profile}_${consentFlow}`,
        executed: true,
        pass,
        reason: pass ? 'openid_scope_refused' : safeCode(receipt.reason),
      });
    }
  }
  return subcaseRow('N7', subcases, 'hook_policy');
}

function countFetch(counter) {
  return async (input, init) => {
    const url = String(input);
    if ((init?.method ?? 'GET') === 'POST' && url.includes('/oauth/token')) counter.exchanges += 1;
    return globalThis.fetch(input, init);
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

async function consentUrl(env, authorizationUrl, login = {}) {
  return performLoopbackConsent({
    fetch: globalThis.fetch,
    authOrigin: new URL(env.ARI_TEST_SUPABASE_URL).origin,
    authorizationUrl,
    publishableKey: env.ARI_TEST_PUBLISHABLE_KEY,
    password: login.password ?? env.ARI_TEST_SYNTHETIC_PASSWORD,
    ...(typeof login.email === 'string' ? { email: login.email } : {}),
  });
}

async function runN8(env, ledger, timeoutMs) {
  const runtimeEnv = { ...env, ARI_LANE_B_EXECUTE: '1' };
  const subcases = [];
  const unboundCounter = { exchanges: 0 };
  const unbound = await startExternalRuntime(runtimeEnv, {
    spawnChild: false,
    fetch: countFetch(unboundCounter),
  });
  try {
    const stray = await callbackGet(
      `${env.ARI_DOWNSTREAM_REDIRECT_URI}?code=unbound-code&state=${randomBytes(8).toString('hex')}`,
    );
    const issued = await withTimeout(obtainGrant(unbound, env, 'external_a'), timeoutMs);
    const again = await presentOnce(env.ARI_EXTERNAL_MCP_URL, issued.accessToken);
    const pass =
      stray.status === 403 &&
      stray.error === 'downstream_credential_unresolved' &&
      unboundCounter.exchanges === 0 &&
      again.error === 'downstream_authorization_required' &&
      zeroCounts(unbound.observation);
    subcases.push({
      id: 'unbound',
      executed: true,
      pass,
      reason: pass ? 'never_bound' : 'unbound_missed',
    });
    rememberLedger(ledger, {
      gate: 'N8',
      passwordSessionId: issued.passwordSessionId,
      sourceSessionId: issued.claims?.sourceSessionId,
    });
  } finally {
    await stopExternalRuntime(unbound);
  }

  const mismatchCounter = { exchanges: 0 };
  const mismatchFacts = [];
  const mismatch = await startExternalRuntime(runtimeEnv, {
    spawnChild: false,
    fetch: countFetch(mismatchCounter),
    onGrantFact(fact) {
      mismatchFacts.push(fact);
    },
  });
  try {
    const issued = await withTimeout(obtainGrant(mismatch, env, 'external_a'), timeoutMs);
    const opened = await presentOnce(env.ARI_EXTERNAL_MCP_URL, issued.accessToken);
    const handshake =
      opened.authorizationUrl === undefined ? undefined : new URL(opened.authorizationUrl);
    const state = handshake?.searchParams.get('state') ?? '';
    const pkce = createPkce();
    const profile = profileOf(env, 'downstream_b');
    const built = buildAuthorizeUrl({
      authorizeEndpoint: new URL('/auth/v1/oauth/authorize', mismatch.authOrigin).toString(),
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
    if (!built.ok || built.resourceOmitted !== true) throw coded('resource_not_omitted');
    if (new URL(built.url).searchParams.get('resource') !== null)
      throw coded('resource_not_omitted');
    const consent = await withTimeout(consentUrl(env, built.url), timeoutMs);
    const fact = mismatchFacts.at(-1);
    const pass =
      opened.error === 'downstream_authorization_required' &&
      consent.ok !== true &&
      fact?.event === 'exchange_failed' &&
      fact?.subjectMismatch !== true &&
      crossUserPass({ ...fact, exchangeError: 'invalid_grant', user1Sub: 'x', sub: 'y' }) ===
        false &&
      mismatchCounter.exchanges >= 1 &&
      mismatch.observation.markerReads === 0 &&
      mismatch.observation.bSessionId === null;
    subcases.push({
      id: 'mismatched_binding',
      executed: true,
      pass,
      reason: pass ? 'binding_rejected' : 'binding_missed',
    });
  } finally {
    await stopExternalRuntime(mismatch);
  }

  const replayCounter = { exchanges: 0 };
  const facts = [];
  const replay = await startExternalRuntime(runtimeEnv, {
    spawnChild: false,
    fetch: countFetch(replayCounter),
    onGrantFact(fact) {
      facts.push(fact);
    },
  });
  try {
    const issued = await withTimeout(obtainGrant(replay, env, 'external_a'), timeoutMs);
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
      const consent = await withTimeout(consentUrl(env, opened.authorizationUrl), timeoutMs);
      const bound = facts.find((fact) => fact.event === 'bound');
      const afterBind = replayCounter.exchanges;
      const replayed = await callbackGet(
        `${env.ARI_DOWNSTREAM_REDIRECT_URI}?code=replay-code&state=${state}`,
      );
      const pass =
        consent.ok === true &&
        bound !== undefined &&
        safeUuid(bound.sessionId) !== undefined &&
        replayed.status === 403 &&
        replayCounter.exchanges === afterBind &&
        afterBind === before + 1 &&
        replay.observation.markerReads === 0;
      subcases.push({
        id: 'accepted_then_replay',
        executed: true,
        pass,
        reason: pass ? 'replay_rejected' : 'replay_missed',
      });
      rememberLedger(ledger, { gate: 'N8', bSessionId: bound?.sessionId });
    }
    const beforeUri = replayCounter.exchanges;
    const origin = new URL(env.ARI_EXTERNAL_MCP_URL).origin;
    const uri = await callbackGet(`${origin}/oauth/downstream/cb?code=x&state=y`);
    const uriPass = uri.error !== 'bound' && replayCounter.exchanges === beforeUri;
    subcases.push({
      id: 'callback_uri_mismatch',
      executed: true,
      pass: uriPass,
      reason: uriPass ? 'redirect_not_exact' : 'uri_accepted',
    });
  } finally {
    await stopExternalRuntime(replay);
  }
  return subcaseRow('N8', subcases, 'callback_transport');
}

async function runN2(env, ledger, reader, timeoutMs) {
  if (
    typeof env.ARI_N2_SECOND_EMAIL !== 'string' ||
    env.ARI_N2_SECOND_EMAIL.length === 0 ||
    typeof env.ARI_N2_SECOND_PASSWORD !== 'string' ||
    env.ARI_N2_SECOND_PASSWORD.length === 0
  ) {
    throw coded('second_user_required');
  }
  await pauseForContinue(
    reader,
    { action: 'prepare_second_synthetic_user', gate: 'N2' },
    timeoutMs,
  );
  const runtimeEnv = { ...env, ARI_LANE_B_EXECUTE: '1' };
  const facts = [];
  const runtime = await startExternalRuntime(runtimeEnv, {
    spawnChild: false,
    onGrantFact(fact) {
      facts.push(fact);
    },
  });
  let crossPass = false;
  let secondSub;
  try {
    const issued = await withTimeout(obtainGrant(runtime, env, 'external_a'), timeoutMs);
    const opened = await presentOnce(env.ARI_EXTERNAL_MCP_URL, issued.accessToken);
    if (opened.authorizationUrl === undefined) throw coded('handshake_missing');
    if (new URL(opened.authorizationUrl).searchParams.get('resource') !== null) {
      throw coded('resource_not_omitted');
    }
    const consent = await withTimeout(
      consentUrl(env, opened.authorizationUrl, {
        email: env.ARI_N2_SECOND_EMAIL,
        password: env.ARI_N2_SECOND_PASSWORD,
      }),
      timeoutMs,
    );
    const fact = facts.find((row) => row.subjectMismatch === true);
    const again = await presentOnce(env.ARI_EXTERNAL_MCP_URL, issued.accessToken);
    const user1Resolved = again.error !== 'downstream_authorization_required';
    crossPass = crossUserPass({
      subjectMismatch: fact?.subjectMismatch === true,
      bound: false,
      sessionId: fact?.sessionId,
      sub: fact?.sub,
      livenessChecks: runtime.observation.livenessChecks,
      markerReads: runtime.observation.markerReads,
      user1Resolved,
      user1Sub: issued.claims?.sub,
      exchangeError: fact?.event === 'exchange_failed' ? 'invalid_grant' : undefined,
    });
    secondSub = fact?.sub;
    rememberLedger(ledger, {
      gate: 'N2',
      passwordSessionId: consent.passwordSessionId ?? issued.passwordSessionId,
      sourceSessionId: issued.claims?.sourceSessionId,
      bSessionId: fact?.sessionId,
      sub: fact?.sub,
      rejected: true,
    });
    if (consent.ok === true) crossPass = false;
  } finally {
    await stopExternalRuntime(runtime);
  }
  const positive = await startExternalRuntime(runtimeEnv, {
    spawnChild: false,
    onGrantFact(fact) {
      facts.push(fact);
    },
  });
  let positivePass = false;
  try {
    const issued = await withTimeout(obtainGrant(positive, env, 'external_a'), timeoutMs);
    const opened = await presentOnce(env.ARI_EXTERNAL_MCP_URL, issued.accessToken);
    const consent = await withTimeout(consentUrl(env, opened.authorizationUrl), timeoutMs);
    const bound = facts.find((fact) => fact.event === 'bound' && fact.sub === issued.claims?.sub);
    positivePass = consent.ok === true && bound !== undefined && bound.subjectMismatch === false;
    rememberLedger(ledger, {
      gate: 'N2',
      passwordSessionId: issued.passwordSessionId,
      sourceSessionId: issued.claims?.sourceSessionId,
      bSessionId: bound?.sessionId,
    });
  } finally {
    await stopExternalRuntime(positive);
  }
  await pauseForContinue(
    reader,
    { action: 'delete_second_synthetic_user', gate: 'N2', secondUserId: secondSub },
    timeoutMs,
  );
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

async function probeMarker(env, token, timeoutMs) {
  const target = new URL(MARKER_PATH, new URL(env.ARI_TEST_SUPABASE_URL).origin);
  if (target.pathname !== '/rest/v1/ari_probe_marker' || target.search !== '?select=marker') {
    throw coded('marker_path_refused');
  }
  let response;
  try {
    response = await fetch(target, {
      method: 'GET',
      redirect: 'error',
      signal: AbortSignal.timeout(timeoutMs),
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${token}`,
        apikey: env.ARI_TEST_PUBLISHABLE_KEY,
      },
    });
  } catch {
    throw coded('orchestration_timeout');
  }
  return classifyMarkerProbe(response.status, await response.text());
}

const MARKER_PATH = '/rest/v1/ari_probe_marker?select=marker';

function hookOffOk(claims, env) {
  return (
    claims?.role === 'authenticated' &&
    claims.aud === 'authenticated' &&
    claims.clientId === env.ARI_EXTERNAL_A_CLIENT_ID &&
    claims.agentId === null &&
    claims.sourceSessionId === undefined &&
    claims.sessionId !== undefined
  );
}

function canaryOk(claims, env) {
  return (
    claims?.role === 'mcp_ingress' &&
    claims.aud === env.ARI_EXTERNAL_MCP_URL &&
    claims.clientId === env.ARI_EXTERNAL_A_CLIENT_ID &&
    claims.agentId === env.ARI_AGENT_ID &&
    claims.sessionId !== undefined &&
    claims.sourceSessionId !== undefined &&
    claims.sessionId !== claims.sourceSessionId
  );
}

async function restoreHook(reader, hash, timeoutMs) {
  const readback = await pauseForReadback(
    reader,
    { action: 'restore_hook_configuration', gate: 'N6', hookHash: hash },
    timeoutMs,
  );
  if (
    readback.hookEnabled !== true ||
    readback.hookHash !== hash ||
    readback.function !== HOOK_FUNCTION
  ) {
    throw coded('hook_restore_mismatch');
  }
}

async function runN6(env, ledger, reader, timeoutMs, restoreState) {
  const captured = await pauseForReadback(
    reader,
    { action: 'capture_hook_manifest', gate: 'N6' },
    timeoutMs,
  );
  if (captured.f1Policy !== 'ari_probe_marker_reject_a_client' || captured.mappingReady !== true) {
    throw coded('f1_readback_missing');
  }
  const hash = hookManifestHash(captured.hookManifest);
  restoreState.hash = hash;
  const runtimeEnv = { ...env, ARI_LANE_B_EXECUTE: '1' };
  const capture = await startExternalRuntime(runtimeEnv, {
    spawnChild: false,
    captureDownstreamCode: true,
  });
  let ownerMatched = false;
  try {
    const issued = await withTimeout(obtainGrant(capture, env, 'downstream_b'), timeoutMs);
    const probe = await probeMarker(env, issued.accessToken, timeoutMs);
    ownerMatched = probe.markerMatched === true && probe.rows === 1;
    rememberLedger(ledger, {
      gate: 'N6',
      passwordSessionId: issued.passwordSessionId,
      bSessionId: issued.claims?.sessionId,
    });
  } finally {
    await stopExternalRuntime(capture);
  }
  if (!ownerMatched) {
    return subcaseRow(
      'N6',
      [{ id: 'owner_read', executed: true, pass: false, reason: 'owner_missing' }],
      'f1',
    );
  }
  const disabled = await pauseForReadback(
    reader,
    { action: 'disable_current_hook', gate: 'N6', hookHash: hash },
    timeoutMs,
  );
  if (
    disabled.hookEnabled !== false ||
    disabled.hookHash !== hash ||
    disabled.function !== HOOK_FUNCTION
  ) {
    throw coded('hook_disable_mismatch');
  }
  restoreState.needed = true;
  const hookOffRuntime = await startExternalRuntime(runtimeEnv, {
    spawnChild: false,
    captureDownstreamCode: true,
  });
  let denial = false;
  let rows = null;
  try {
    const issued = await withTimeout(obtainGrant(hookOffRuntime, env, 'external_a'), timeoutMs);
    if (!hookOffOk(issued.claims, env)) throw coded('hook_off_shape_mismatch');
    const probe = await probeMarker(env, issued.accessToken, timeoutMs);
    denial = probe.denial === true && probe.rows === 0;
    rows = probe.rows;
    rememberLedger(ledger, {
      gate: 'N6',
      sourceSessionId: issued.claims?.sessionId,
      rejected: true,
    });
  } finally {
    await stopExternalRuntime(hookOffRuntime);
  }
  await pauseForContinue(
    reader,
    {
      action: 'cleanup_sessions',
      gate: 'N6',
      sessionIds: ledger
        .filter((row) => row.gate === 'N6')
        .flatMap((row) =>
          ['passwordSessionId', 'sourceSessionId', 'bSessionId']
            .map((key) => row[key])
            .filter((id) => safeUuid(id) !== undefined),
        ),
    },
    timeoutMs,
  );
  await restoreHook(reader, hash, timeoutMs);
  restoreState.confirmed = true;
  const canaryRuntime = await startExternalRuntime(runtimeEnv, { spawnChild: false });
  let canary = false;
  try {
    const issued = await withTimeout(obtainGrant(canaryRuntime, env, 'external_a'), timeoutMs);
    const presented = await presentOnce(env.ARI_EXTERNAL_MCP_URL, issued.accessToken);
    canary =
      canaryOk(issued.claims, env) &&
      presented.status === 403 &&
      presented.error === 'downstream_authorization_required';
    rememberLedger(ledger, { gate: 'N6', canarySessionId: issued.claims?.sourceSessionId });
    await pauseForContinue(
      reader,
      {
        action: 'cleanup_sessions',
        gate: 'N6',
        sessionIds: [issued.claims?.sourceSessionId, issued.claims?.sessionId].filter(
          (id) => safeUuid(id) !== undefined,
        ),
      },
      timeoutMs,
    );
  } finally {
    await stopExternalRuntime(canaryRuntime);
  }
  const pass = n6Pass({
    denial,
    cleanup: 'confirmed',
    restore: 'confirmed',
    canary,
    hookHash: hash,
    rows,
  });
  return subcaseRow(
    'N6',
    [
      {
        id: 'f1_denial',
        executed: true,
        pass: denial,
        reason: denial ? 'marker_denied' : 'denial_missed',
      },
      {
        id: 'restore_canary',
        executed: true,
        pass: canary,
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

function parentReceipt(env, gate, selected, results, ledger) {
  const rows = GATE_ORDER.map((id) => results.get(id) ?? notExecuted(id));
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
    selectedGates: selected,
    rowsPass: rowsPass(selected, rows),
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
  const restoreState = { needed: false, confirmed: false, hash: undefined };
  let thrown;
  try {
    for (const id of selected) {
      let row;
      if (id === 'N3') row = await runN3(env, ledger, timeoutMs);
      else if (id === 'N7') row = await runN7(env, ledger, timeoutMs);
      else if (id === 'N8') row = await runN8(env, ledger, timeoutMs);
      else if (id === 'N2') row = await runN2(env, ledger, reader, timeoutMs);
      else if (id === 'N6') row = await runN6(env, ledger, reader, timeoutMs, restoreState);
      else throw coded('live_configuration_incomplete');
      results.set(id, row);
      if (row.pass !== true) break;
    }
    const receipt = parentReceipt(env, gate, selected, results, ledger);
    assertIpcHasNoSecrets(receipt);
    return receipt;
  } catch (error) {
    thrown = error;
    if (error !== null && typeof error === 'object') error.sessionLedger = ledger;
    throw error;
  } finally {
    if (restoreState.needed && !restoreState.confirmed && restoreState.hash !== undefined) {
      try {
        await restoreHook(reader, restoreState.hash, timeoutMs);
        restoreState.confirmed = true;
      } catch (restoreError) {
        restoreState.error = safeCode(restoreError?.code);
      }
    }
    if (thrown !== undefined && thrown !== null && typeof thrown === 'object') {
      thrown.restoreStatus = restoreState.confirmed
        ? 'confirmed'
        : (restoreState.error ?? 'not_required');
    }
    reader.close();
  }
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
