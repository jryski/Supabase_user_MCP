/**
 * Parent orchestration for the TEST-only external client.
 * Default command is `plan`. It does not open a socket and does not contact
 * hosted TEST. `run` stays closed unless the controller sets the G5 gates
 * and ARI_LANE_B_EXECUTE=1. The child receives no bearer, refresh token,
 * password, or admin credential. First-party consent stays in the browser.
 */
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { createInterface } from 'node:readline';
import { fileURLToPath, pathToFileURL } from 'node:url';

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
      'N4 is A-session revocation. B-session revocation is a separate case and uses a first-party session.',
      'F1 in sql/06 covers public.ari_probe_marker only.',
      'node scripts/run-ari-test-external-e2e.mjs plan',
      'After G5, set ARI_LANE_B_EXECUTE=1 and run node scripts/run-ari-test-external-e2e.mjs run.',
      'Open each controller_action authorizationUrl in a browser. Do not paste a bearer into the child.',
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

export function controllerGate(env) {
  for (const name of FORBIDDEN) {
    if (typeof env[name] === 'string' && env[name].length > 0) {
      return { ok: false, reason: 'service_role_refused' };
    }
  }
  if (env.ARI_LANE_B_LIVE !== 'controller-g5') return { ok: false, reason: 'live_gate_closed' };
  if (env.ARI_TEST_PROJECT_REF !== 'odbcejsuuqdzhabjmozi') {
    return { ok: false, reason: 'project_ref_refused' };
  }
  if (
    typeof env.ARI_LANE_B_G5_HEAD !== 'string' ||
    !/^[0-9a-f]{40}$/.test(env.ARI_LANE_B_G5_HEAD)
  ) {
    return { ok: false, reason: 'g5_head_required' };
  }
  return { ok: true };
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
  return next;
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

function parentReceipt(message, env) {
  const toolNames = Array.isArray(message.toolNames)
    ? message.toolNames.filter(
        (name) => typeof name === 'string' && /^[a-z0-9_-]{1,80}$/u.test(name),
      )
    : [];
  const childEnvNames = Array.isArray(message.childEnvNames)
    ? message.childEnvNames.filter((name) => typeof name === 'string' && /^[A-Z0-9_]+$/u.test(name))
    : [];
  return {
    type: 'receipt',
    packet: 'lane-b-external-client',
    profile: 'TEST_ONLY_PUBLIC_PKCE',
    acceptance: false,
    hostedContact: hostedTest(env.ARI_TEST_SUPABASE_URL),
    hookInstalled: false,
    executedByWriter: false,
    syntheticLoopback: loopbackSupabase(env.ARI_TEST_SUPABASE_URL),
    g5Head: env.ARI_LANE_B_G5_HEAD,
    projectRef: env.ARI_TEST_PROJECT_REF,
    initialized: message.initialized === true,
    toolsListed: message.toolsListed === true,
    markerCalled: message.markerCalled === true,
    downstreamBound: message.downstreamBound === true,
    externalAuthorizationCompleted: message.externalAuthorizationCompleted === true,
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
  return { server, child, session, timeoutMs, childEnv };
}

async function driveExternalSession(runtime, env) {
  const deadline = Date.now() + runtime.timeoutMs;
  const reader = lineReader(runtime.child.stdout);
  let receipt;
  while (receipt === undefined) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw coded('orchestration_timeout');
    const line = await withTimeout(reader.next(), remaining);
    if (line === null) throw coded('child_failed');
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      throw coded('child_failed');
    }
    assertIpcHasNoSecrets(message);
    if (message.type === 'authorization_request') {
      runtime.session.expectedAState = message.state;
      writeJson(process.stdout, {
        type: 'controller_action',
        action: 'open_authorization',
        flow: 'external_a',
        authorizationUrl: message.authorizationUrl,
        state: message.state,
      });
    } else if (message.type === 'downstream_authorization_required') {
      runtime.session.expectedBState = message.state;
      writeJson(process.stdout, {
        type: 'controller_action',
        action: 'open_authorization',
        flow: 'downstream_b',
        authorizationUrl: message.authorizationUrl,
        state: message.state,
        handshakeId: message.handshakeId,
      });
    } else if (message.type === 'receipt') {
      receipt = parentReceipt(message, env);
    } else if (message.type === 'error') {
      throw coded(safeCode(message.code));
    }
  }
  if (JWT_SHAPE.test(runtime.session.stderr) || /refresh_token/i.test(runtime.session.stderr)) {
    throw coded('ipc_refused_secret');
  }
  assertIpcHasNoSecrets(receipt);
  return receipt;
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
  let runtime;
  try {
    runtime = await startExternalRuntime(process.env);
    const receipt = await driveExternalSession(runtime, process.env);
    process.stdout.write(`${JSON.stringify(receipt)}\n`);
  } catch (error) {
    process.stderr.write(`${safeCode(error?.code)}\n`);
    process.exitCode = 2;
  } finally {
    await stopExternalRuntime(runtime);
  }
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(invokedPath).href) {
  await main();
}
