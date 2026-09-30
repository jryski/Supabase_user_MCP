import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import test from 'node:test';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

import { SYNTHETIC_EMAIL } from '../docs/evidence/ari-test-probe/decisions.mjs';
import {
  callbackUriMismatchPass,
  classifyMarkerProbe,
  crossUserPass,
  exactIdBijection,
  hookManifestHash,
  n6Pass,
  nGatesPlan,
  openIdSubcasePass,
  refuseLocalMint,
  selectNGates,
} from './run-ari-test-n-gates.mjs';

const USER1 = '11111111-1111-4111-8111-111111111111';
const USER2 = '22222222-2222-4222-8222-222222222222';
const EMAIL2 = 'ari-probe-second@loopback.invalid';
const A_CLIENT = 'external-a-client';
const B_CLIENT = 'downstream-b-client';
const AGENT = 'hook-only-agent';
const PASSWORD = 'synthetic-password-sentinel';
const PASSWORD2 = 'second-user-password-sentinel';
const REFRESH = 'refresh-sentinel-must-not-leak';
const PUBLISHABLE = 'sb_publishable_parent_only_sentinel';

test('plan stays closed and false passes stay false', () => {
  const plan = nGatesPlan();
  assert.equal(plan.acceptance, false);
  assert.equal(plan.hostedContact, false);
  assert.equal(plan.executedByWriter, false);
  assert.deepEqual(plan.order, ['N3', 'N7', 'N8', 'N2', 'N6']);
  assert.equal(selectNGates('N6,N3').join(','), 'N3,N6');
  assert.throws(() => selectNGates('N1'), /live_configuration_incomplete/);
  assert.throws(() => refuseLocalMint({ ARI_N3_LOCAL_MINT: '1' }), /hosted_mint_refused/);
  assert.equal(
    openIdSubcasePass(
      { ok: true, reason: 'openid_refused_client_scope' },
      { omitResource: false, consentFlow: 'approval_post' },
    ),
    false,
  );
  assert.equal(
    openIdSubcasePass(
      {
        ok: false,
        reason: 'exchange_inconclusive',
        policyMarker: null,
        rejectionStage: 'exchange',
        exchangeStatus: 400,
      },
      { omitResource: true, consentFlow: 'approval_post' },
    ),
    false,
  );
  assert.equal(
    crossUserPass({
      subjectMismatch: false,
      exchangeError: 'invalid_grant',
      sessionId: USER2,
      sub: USER2,
      livenessChecks: 0,
      markerReads: 0,
      user1Resolved: false,
      user1Sub: USER1,
    }),
    false,
  );
  assert.equal(
    n6Pass({
      denial: true,
      cleanup: 'confirmed',
      restore: 'aborted_unconfirmed',
      canary: true,
      hookHash: 'a'.repeat(64),
      rows: 0,
    }),
    false,
  );
  assert.equal(classifyMarkerProbe(200, '[]').denial, true);
  assert.equal(
    classifyMarkerProbe(200, '[{"marker":"ari-probe-marker-odbcejsuuqdzhabjmozi"}]').denial,
    false,
  );
  assert.equal(classifyMarkerProbe(500, '{}').reason, 'inconclusive');
  const bound = {
    projectRef: 'odbcejsuuqdzhabjmozi',
    resource: 'http://127.0.0.1:9/mcp',
    agentId: AGENT,
    externalClientId: A_CLIENT,
  };
  const hash = hookManifestHash(
    {
      enabled: true,
      function: 'ari_probe.custom_access_token_hook',
      uri: 'pg-functions://postgres/ari_probe/custom_access_token_hook',
      settings: { schema: 'ari_probe' },
      projectRef: 'odbcejsuuqdzhabjmozi',
      resource: 'http://127.0.0.1:9/mcp',
      agentId: AGENT,
      externalClientId: A_CLIENT,
      baselineClientId: 'baseline-a-client',
    },
    bound,
  );
  assert.equal(hash.length, 64);
  assert.throws(
    () =>
      hookManifestHash({ enabled: true, function: 'ari_probe.custom_access_token_hook' }, bound),
    /hook_manifest_unreadable/,
  );
  assert.throws(
    () =>
      hookManifestHash(
        {
          enabled: true,
          function: 'ari_probe.custom_access_token_hook',
          uri: 'pg-functions://postgres/ari_probe/custom_access_token_hook',
          settings: {},
          projectRef: 'other-project-ref',
          resource: 'http://127.0.0.1:9/mcp',
          agentId: AGENT,
          externalClientId: A_CLIENT,
          baselineClientId: 'baseline-a-client',
        },
        bound,
      ),
    /hook_manifest_unreadable/,
  );
  assert.equal(exactIdBijection([USER1, USER1], [USER1, USER2]), false);
  assert.equal(exactIdBijection([USER2, USER1], [USER1, USER2]), true);
  assert.equal(classifyMarkerProbe(401, '{}').reason, 'inconclusive');
  assert.equal(classifyMarkerProbe(403, '{}').denial, false);
  assert.equal(
    callbackUriMismatchPass({ status: 500, error: 'malformed', exchangesDelta: 0 }),
    false,
  );
});

test('plan command opens no runtime and run stays closed', async () => {
  const planRun = spawn(process.execPath, ['scripts/run-ari-test-n-gates.mjs', 'plan'], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const out = [];
  planRun.stdout.on('data', (chunk) => out.push(chunk));
  const [code] = await once(planRun, 'exit');
  assert.equal(code, 0);
  const printed = JSON.parse(Buffer.concat(out).toString('utf8'));
  assert.equal(printed.hostedContact, false);
  assert.equal(printed.acceptance, false);
  const run = spawn(process.execPath, ['scripts/run-ari-test-n-gates.mjs', 'run'], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const err = [];
  run.stderr.on('data', (chunk) => err.push(chunk));
  const [runCode] = await once(run, 'exit');
  assert.equal(runCode, 2);
  assert.match(Buffer.concat(err).toString('utf8'), /live_gate_closed/);
});

function stdoutLines(stream) {
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
  rl.on('line', (line) => deliver(line));
  rl.on('close', () => {
    if (ended) return;
    ended = true;
    deliver(null);
  });
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

async function freePort() {
  const probe = createHttpServer();
  await new Promise((resolve) => probe.listen(0, '127.0.0.1', () => resolve()));
  const address = probe.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  await new Promise((resolve) => probe.close(() => resolve()));
  return port;
}

async function startIssuer(mode) {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  const jwks = { keys: [{ ...jwk, kid: 'g2-test', alg: 'ES256', use: 'sig' }] };
  const dir = mkdtempSync(`${tmpdir()}/ari-n-gates-`);
  const certPath = `${dir}/cert.pem`;
  const keyPath = `${dir}/key.pem`;
  execFileSync(
    'openssl',
    [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-keyout',
      keyPath,
      '-out',
      certPath,
      '-days',
      '1',
      '-nodes',
      '-subj',
      '/CN=127.0.0.1',
      '-addext',
      'subjectAltName=IP:127.0.0.1',
    ],
    { stdio: 'ignore' },
  );
  const seen = {
    authorize: [],
    exchange: [],
    marker: [],
    emails: [],
    forbidden: 0,
    decoySessionIds: [],
    codes: 0,
  };
  const authorizations = new Map();
  const pending = new Map();
  const sessions = new Map();
  const remembered = new Set();
  if (mode === 'preconsented') {
    remembered.add(`${USER1}:${A_CLIENT}:openid email`);
    remembered.add(`${USER1}:${B_CLIENT}:openid email`);
  }
  let hookEnabled = true;
  let passwordSerial = 0;
  const https = createHttpsServer(
    { cert: readFileSync(certPath), key: readFileSync(keyPath) },
    (req, res) => {
      const url = new URL(req.url ?? '/', 'https://127.0.0.1');
      const origin = `https://127.0.0.1:${https.address().port}`;
      const issuer = `${origin}/auth/v1`;
      const send = (status, body, type = 'application/json') => {
        if (res.writableEnded) return;
        res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store' });
        res.end(body);
      };
      const bearerUser = () => {
        const header = req.headers.authorization ?? '';
        return sessions.get(header.replace(/^Bearer\s+/u, ''));
      };
      if (req.method === 'GET' && url.pathname === '/auth/v1/oauth/authorize') {
        const redirect = url.searchParams.get('redirect_uri') ?? '';
        const challenge = url.searchParams.get('code_challenge') ?? '';
        const resource = url.searchParams.get('resource');
        seen.authorize.push({
          clientId: url.searchParams.get('client_id'),
          redirect,
          scope: url.searchParams.get('scope') ?? '',
          resource,
          method: url.searchParams.get('code_challenge_method'),
        });
        if (url.searchParams.get('code_challenge_method') !== 'S256' || challenge.length < 20) {
          send(400, JSON.stringify({ error: 'invalid_request' }));
          return;
        }
        const authorizationId = randomBytes(16).toString('base64url');
        authorizations.set(authorizationId, {
          clientId: url.searchParams.get('client_id') ?? '',
          challenge,
          redirect,
          state: url.searchParams.get('state') ?? '',
          scope: url.searchParams.get('scope') ?? '',
          resource,
          sub: null,
        });
        res.writeHead(302, {
          location: `${origin}/oauth/consent?authorization_id=${authorizationId}`,
          'cache-control': 'no-store',
        });
        res.end();
        return;
      }
      const issueCode = (record) => {
        const code = randomBytes(16).toString('base64url');
        seen.codes += 1;
        pending.set(code, record);
        const redirectUrl = new URL(record.redirect);
        redirectUrl.searchParams.set('code', code);
        redirectUrl.searchParams.set('state', record.state);
        return redirectUrl;
      };
      const authorizationPath = url.pathname.match(
        /^\/auth\/v1\/oauth\/authorizations\/([^/]+)(\/consent)?$/u,
      );
      if (authorizationPath) {
        const authorizationId = decodeURIComponent(authorizationPath[1] ?? '');
        const user = bearerUser();
        const record = authorizations.get(authorizationId);
        if (user === undefined) {
          send(401, JSON.stringify({ error: 'unauthorized' }));
          return;
        }
        if (record === undefined) {
          send(404, JSON.stringify({ error: 'not_found' }));
          return;
        }
        const consentKey = `${user.sub}:${record.clientId}:${record.scope}`;
        if (req.method === 'GET' && authorizationPath[2] === undefined) {
          if (remembered.has(consentKey)) {
            record.sub = user.sub;
            send(200, JSON.stringify({ redirect_url: issueCode(record).toString() }));
            return;
          }
          send(200, JSON.stringify({ authorization_id: authorizationId }));
          return;
        }
        if (req.method === 'POST' && authorizationPath[2] === '/consent') {
          const chunks = [];
          req.on('data', (chunk) => chunks.push(chunk));
          req.on('end', () => {
            remembered.add(consentKey);
            record.sub = user.sub;
            send(200, JSON.stringify({ redirect_url: issueCode(record).toString() }));
          });
          return;
        }
      }
      if (
        req.method === 'POST' &&
        url.pathname === '/auth/v1/token' &&
        url.searchParams.get('grant_type') === 'password'
      ) {
        const chunks = [];
        req.on('data', (chunk) => chunks.push(chunk));
        req.on('end', () => {
          void (async () => {
            let body = {};
            try {
              body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            } catch {
              body = {};
            }
            seen.emails.push(body.email);
            const user =
              body.email === SYNTHETIC_EMAIL && body.password === PASSWORD
                ? { sub: USER1 }
                : body.email === EMAIL2 && body.password === PASSWORD2
                  ? { sub: mode === 'wrong_subject' ? USER1 : USER2 }
                  : undefined;
            if (user === undefined) {
              send(400, JSON.stringify({ error: 'invalid_grant' }));
              return;
            }
            if (mode === 'hang_issuance') return;
            if (mode === 'delay_password')
              await new Promise((resolve) => setTimeout(resolve, 1300));
            passwordSerial += 1;
            const sessionId = `77777777-7777-4777-8777-${passwordSerial.toString(16).padStart(12, '0')}`;
            const access = await new SignJWT({ role: 'authenticated', session_id: sessionId })
              .setProtectedHeader({ alg: 'ES256', kid: 'g2-test', typ: 'JWT' })
              .setSubject(user.sub)
              .setIssuer(issuer)
              .setAudience('authenticated')
              .setIssuedAt()
              .setExpirationTime('5m')
              .sign(privateKey);
            sessions.set(access, user);
            send(200, JSON.stringify({ access_token: access, token_type: 'bearer' }));
          })();
        });
        return;
      }
      if (req.method === 'POST' && url.pathname === '/auth/v1/oauth/token') {
        const chunks = [];
        req.on('data', (chunk) => chunks.push(chunk));
        req.on('end', () => {
          void (async () => {
            const form = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
            const record = pending.get(form.get('code') ?? '');
            pending.delete(form.get('code') ?? '');
            const digest = createHash('sha256')
              .update(form.get('code_verifier') ?? '')
              .digest('base64url');
            seen.exchange.push({
              clientId: form.get('client_id'),
              redirect: form.get('redirect_uri'),
              resource: form.get('resource'),
              scope: record?.scope ?? '',
            });
            if (
              record === undefined ||
              digest !== record.challenge ||
              form.get('client_id') !== record.clientId ||
              form.get('redirect_uri') !== record.redirect
            ) {
              send(400, JSON.stringify({ error: 'invalid_grant' }));
              return;
            }
            if ((record.scope ?? '').includes('openid') && mode !== 'openid_issued') {
              if (mode === 'invalid_scope') {
                send(400, JSON.stringify({ error: 'invalid_scope' }));
                return;
              }
              send(
                403,
                JSON.stringify({
                  error: 'invalid_request',
                  error_description: 'openid_scope_refused',
                }),
              );
              return;
            }
            if (mode === 'b_exchange_503' && record.clientId === B_CLIENT) {
              send(503, JSON.stringify({ error: 'server_error' }));
              return;
            }
            const mismatch = req.headers['x-ari-probe-b-claim'] === 'agent-mismatch';
            const tokenA = record.clientId === A_CLIENT;
            if (mode === 'delay_oauth' && tokenA) {
              await new Promise((resolve) => setTimeout(resolve, 1300));
            }
            if (mode === 'delay_rejected_b' && !tokenA && (record.sub ?? USER1) !== USER1) {
              await new Promise((resolve) => setTimeout(resolve, 1300));
            }
            const mintedSession = randomUUID();
            const sourceSession = randomUUID();
            const claims = tokenA
              ? hookEnabled
                ? {
                    role: 'mcp_ingress',
                    client_id: A_CLIENT,
                    session_id: mintedSession,
                    source_session_id: sourceSession,
                    agent_id: AGENT,
                  }
                : { role: 'authenticated', client_id: A_CLIENT, session_id: mintedSession }
              : {
                  role: 'authenticated',
                  client_id: B_CLIENT,
                  session_id: mintedSession,
                  agent_id: mismatch && !tokenA ? 'other-agent' : AGENT,
                };
            if (tokenA && hookEnabled) seen.decoySessionIds.push(mintedSession);
            const access = await new SignJWT(claims)
              .setProtectedHeader({ alg: 'ES256', kid: 'g2-test', typ: 'JWT' })
              .setSubject(record.sub ?? USER1)
              .setIssuer(issuer)
              .setAudience(tokenA && hookEnabled ? (record.resource ?? '') : 'authenticated')
              .setIssuedAt()
              .setExpirationTime(
                mode === 'expired_hook_off' && tokenA && !hookEnabled ? '-10s' : '5m',
              )
              .sign(privateKey);
            sessions.set(access, { sub: record.sub ?? USER1 });
            send(
              200,
              JSON.stringify({
                access_token: access,
                token_type: 'Bearer',
                expires_in: 300,
                refresh_token: REFRESH,
              }),
            );
          })();
        });
        return;
      }
      if (req.method === 'GET' && url.pathname === '/rest/v1/ari_probe_marker') {
        seen.marker.push(url.search);
        if (url.search !== '?select=marker,owner_id') {
          seen.forbidden += 1;
          send(404, JSON.stringify({ error: 'not_found' }));
          return;
        }
        const payload = (req.headers.authorization ?? '').split('.')[1];
        let clientId = '';
        try {
          clientId =
            JSON.parse(Buffer.from(payload ?? '', 'base64url').toString('utf8')).client_id ?? '';
        } catch {
          clientId = '';
        }
        if (mode === 'hang-a-marker' && clientId === A_CLIENT) return;
        if (mode === 'marker_401' && clientId === A_CLIENT) {
          send(401, JSON.stringify({ error: 'unauthorized' }));
          return;
        }
        if (mode === 'marker_403' && clientId === A_CLIENT) {
          send(403, JSON.stringify({ error: 'permission_denied' }));
          return;
        }
        if (clientId === A_CLIENT) {
          send(200, '[]');
          return;
        }
        if (clientId === B_CLIENT) {
          let subject = USER1;
          try {
            subject =
              JSON.parse(Buffer.from(payload ?? '', 'base64url').toString('utf8')).sub ?? USER1;
          } catch {
            subject = USER1;
          }
          const marker =
            mode === 'wrong_marker'
              ? 'ari-probe-marker-zzzzzzzzzzzzzzzzzzzz'
              : 'ari-probe-marker-odbcejsuuqdzhabjmozi';
          const ownerId = mode === 'wrong_owner' ? USER2 : subject;
          send(200, JSON.stringify([{ marker, owner_id: ownerId }]));
          return;
        }
        send(401, JSON.stringify({ error: 'unauthorized' }));
        return;
      }
      if (req.method === 'GET' && url.pathname === '/auth/v1/user') {
        const user = bearerUser();
        if (user === undefined) {
          send(401, JSON.stringify({ error: 'unauthorized' }));
          return;
        }
        send(200, JSON.stringify({ id: user.sub }));
        return;
      }
      if (
        req.method === 'POST' &&
        url.pathname === '/rest/v1/rpc/ari_probe_source_session_live_v1'
      ) {
        send(200, 'true');
        return;
      }
      if (url.pathname.startsWith('/auth/v1/admin') || url.pathname.startsWith('/rest/v1/')) {
        seen.forbidden += 1;
      }
      send(404, JSON.stringify({ error: 'not_found' }));
    },
  );
  await new Promise((resolve) => https.listen(0, '127.0.0.1', () => resolve()));
  return {
    https,
    jwks,
    certPath,
    seen,
    origin: `https://127.0.0.1:${https.address().port}`,
    setHook(enabled) {
      hookEnabled = enabled;
    },
  };
}

async function drive(mode, gates, fault = 'none') {
  const issuer = await startIssuer(mode);
  const mcpPort = await freePort();
  const mcpResource = `http://127.0.0.1:${mcpPort}/mcp`;
  const head = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  const manifest = {
    enabled: true,
    function: 'ari_probe.custom_access_token_hook',
    uri: 'pg-functions://postgres/ari_probe/custom_access_token_hook',
    settings: { schema: 'ari_probe' },
    projectRef: 'odbcejsuuqdzhabjmozi',
    resource: mcpResource,
    agentId: AGENT,
    externalClientId: A_CLIENT,
    baselineClientId: 'baseline-a-client',
  };
  const hash = hookManifestHash(manifest, {
    projectRef: 'odbcejsuuqdzhabjmozi',
    resource: mcpResource,
    agentId: AGENT,
    externalClientId: A_CLIENT,
  });
  const proc = spawn(process.execPath, ['scripts/run-ari-test-n-gates.mjs', 'run'], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME ?? '/tmp',
      NODE_EXTRA_CA_CERTS: issuer.certPath,
      ARI_LANE_B_LIVE: 'controller-g5',
      ARI_N_GATES_EXECUTE: '1',
      ARI_N_GATES: gates,
      ARI_LANE_B_G5_HEAD: head,
      ARI_LANE_B_TIMEOUT_MS:
        mode === 'hang-a-marker' ||
        mode === 'delay_password' ||
        mode === 'delay_oauth' ||
        mode === 'delay_rejected_b' ||
        mode === 'hang_issuance' ||
        fault === 'timeout_disable'
          ? '1000'
          : '20000',
      ...(fault === 'callback_500' ? { ARI_N_GATES_SYNTHETIC_HTTP_STATUS: '500' } : {}),
      ARI_TEST_PROJECT_REF: 'odbcejsuuqdzhabjmozi',
      ARI_TEST_SUPABASE_URL: issuer.origin,
      ARI_TEST_PUBLISHABLE_KEY: PUBLISHABLE,
      ARI_TEST_JWKS_JSON: JSON.stringify(issuer.jwks),
      ARI_EXTERNAL_MCP_URL: mcpResource,
      ARI_EXTERNAL_A_CLIENT_ID: A_CLIENT,
      ARI_EXTERNAL_A_REDIRECT_URI: `http://127.0.0.1:${mcpPort}/oauth/callback`,
      ARI_DOWNSTREAM_CLIENT_ID: B_CLIENT,
      ARI_DOWNSTREAM_REDIRECT_URI: `http://127.0.0.1:${mcpPort}/oauth/downstream/callback`,
      ARI_AGENT_ID: AGENT,
      ARI_TEST_SYNTHETIC_PASSWORD: PASSWORD,
      ARI_N2_SECOND_EMAIL: EMAIL2,
      ARI_N2_SECOND_PASSWORD: PASSWORD2,
    },
  });
  const stderr = [];
  proc.stderr.on('data', (chunk) => stderr.push(chunk));
  const reader = stdoutLines(proc.stdout);
  const stdoutText = [];
  let receipt;
  const actions = [];
  const messages = [];
  const evidence = () => ({
    f1: {
      name: 'ari_probe_marker_reject_a_client',
      schema: 'public',
      table: 'ari_probe_marker',
      command: 'select',
      kind: 'restrictive',
      roles: ['authenticated'],
      distinctClientIds: ['baseline-a-client', A_CLIENT].sort(),
    },
    rls: { schema: 'public', table: 'ari_probe_marker', enabled: true, forced: true },
    ownerPolicy: {
      name: 'ari_probe_marker_owner_read',
      kind: 'permissive',
      command: 'select',
      roles: ['authenticated'],
      using: 'auth.uid() = owner_id',
    },
    grants: [
      { role: 'anon', privilege: 'SELECT', table: 'public.ari_probe_marker', allowed: false },
      {
        role: 'authenticated',
        privilege: 'SELECT',
        table: 'public.ari_probe_marker',
        allowed: true,
      },
      {
        role: 'mcp_ingress',
        privilege: 'SELECT',
        table: 'public.ari_probe_marker',
        allowed: false,
      },
      { role: 'public', privilege: 'SELECT', table: 'public.ari_probe_marker', allowed: false },
    ],
    mappings: [
      {
        clientId: 'baseline-a-client',
        resource: 'https://odbcejsuuqdzhabjmozi.supabase.co/mcp',
        agentId: AGENT,
        probeLabel: 'ari-test-synthetic',
      },
      {
        clientId: A_CLIENT,
        resource: mcpResource,
        agentId: AGENT,
        probeLabel: 'ari-test-external-a',
      },
    ],
  });
  const write = (value) => {
    proc.stdin.write(`${JSON.stringify(value)}\n`);
  };
  const correlated = (message, fields) => {
    write({
      runId: message.runId,
      action: message.action,
      requestId: message.requestId,
      ...(message.gate === undefined ? {} : { gate: message.gate }),
      ...fields,
    });
  };
  try {
    while (receipt === undefined) {
      let timer;
      const line = await Promise.race([
        reader.next(),
        new Promise((resolve) => {
          timer = setTimeout(
            () => resolve(null),
            mode === 'hang-a-marker' || fault === 'timeout_disable' ? 20_000 : 60_000,
          );
        }),
      ]);
      clearTimeout(timer);
      if (line === null) break;
      stdoutText.push(line);
      const message = JSON.parse(line);
      if (message.type === 'controller_action') {
        actions.push(message.action);
        messages.push(message);
        assert.equal(JSON.stringify(message).includes(PASSWORD), false);
        assert.equal(JSON.stringify(message).includes(PASSWORD2), false);
        assert.equal(JSON.stringify(message).includes(REFRESH), false);
        if (message.action === 'capture_hook_manifest') {
          if (fault === 'minimal_manifest') {
            correlated(message, {
              type: 'readback',
              hookManifest: { enabled: true, function: manifest.function },
              ...evidence(),
            });
          } else if (fault === 'foreign_manifest') {
            correlated(message, {
              type: 'readback',
              hookManifest: { ...manifest, projectRef: 'other-project-ref' },
              ...evidence(),
            });
          } else if (fault === 'boolean_policy') {
            correlated(message, {
              type: 'readback',
              hookManifest: manifest,
              f1Policy: 'ari_probe_marker_reject_a_client',
              mappingReady: true,
              grantsUnchanged: true,
            });
          } else if (fault === 'altered_f1') {
            correlated(message, {
              type: 'readback',
              hookManifest: manifest,
              ...evidence(),
              f1: { ...evidence().f1, kind: 'permissive' },
            });
          } else {
            correlated(message, {
              type: 'readback',
              hookManifest: manifest,
              ...evidence(),
            });
          }
        } else if (message.action === 'disable_current_hook') {
          assert.equal(message.hookHash, hash);
          issuer.setHook(false);
          if (fault === 'malformed_disable') {
            proc.stdin.write('not-json\n');
          } else if (fault === 'eof_disable') {
            proc.stdin.end();
          } else if (fault === 'stale_disable') {
            write({
              type: 'readback',
              runId: 'stale-run',
              action: 'restore_hook_configuration',
              hookEnabled: true,
              hookHash: hash,
              function: manifest.function,
              hookManifest: manifest,
              ...evidence(),
            });
          } else if (fault === 'sigint') {
            proc.kill('SIGINT');
          } else if (fault === 'timeout_disable') {
            // Leave the disable readback unanswered so the runner times out armed.
          } else {
            correlated(message, {
              type: 'readback',
              hookEnabled: false,
              hookHash: hash,
              function: manifest.function,
              ...evidence(),
            });
          }
        } else if (message.action === 'restore_hook_configuration') {
          assert.equal(message.hookHash, hash);
          assert.equal(message.hookManifest.function, manifest.function);
          assert.equal(message.hookManifest.uri, manifest.uri);
          issuer.setHook(true);
          const restored = evidence();
          if (fault === 'altered_f1_restore') {
            restored.grants = restored.grants.map((row) =>
              row.role === 'anon' ? { ...row, allowed: true } : row,
            );
          }
          correlated(message, {
            type: 'readback',
            hookEnabled: true,
            hookHash: hash,
            function: manifest.function,
            hookManifest: manifest,
            ...restored,
          });
        } else if (message.action === 'cleanup_sessions') {
          const ids = Array.isArray(message.sessionIds) ? message.sessionIds : [];
          correlated(message, {
            type: 'readback',
            sessionsRows: 0,
            refreshRows: 0,
            sessionIds:
              fault === 'duplicate_cleanup' && ids.length > 1
                ? Array(ids.length).fill(ids[0])
                : ids,
          });
        } else if (message.action === 'prepare_second_synthetic_user') {
          correlated(message, {
            type: 'readback',
            secondUserId: fault === 'baseline_id' || fault === 'early_failure' ? USER1 : USER2,
            ...(fault === 'early_failure' ? {} : { createdForRun: true }),
            email: fault === 'same_email' ? SYNTHETIC_EMAIL : EMAIL2,
          });
        } else if (message.action === 'delete_second_synthetic_user') {
          correlated(message, {
            type: 'continue',
            secondUserId: message.secondUserId,
          });
        } else if (message.action === 'reconcile_unresolved_issuance') {
          correlated(message, { type: 'readback', reconciled: false });
        } else {
          assert.fail(`unhandled ${message.action}`);
        }
      } else if (message.type === 'receipt') {
        receipt = message;
      } else {
        assert.fail(`unexpected ${message.type}`);
      }
    }
    const [code] = await once(proc, 'exit');
    return {
      code,
      receipt,
      errText: Buffer.concat(stderr).toString('utf8'),
      outText: stdoutText.join('\n'),
      seen: issuer.seen,
      actions,
      messages,
      head,
    };
  } finally {
    issuer.https.closeAllConnections?.();
    issuer.https.close();
  }
}

test('synthetic packet executes the remaining gates without hosted contact', async () => {
  const result = await drive('policy', 'N3,N7,N8,N2,N6');
  assert.equal(result.code, 0, `${result.errText}\n${result.outText}`);
  const receipt = result.receipt;
  assert.equal(receipt.acceptance, false);
  assert.equal(receipt.hostedContact, false);
  assert.equal(receipt.hookInstalled, false);
  assert.equal(receipt.executedByWriter, false);
  assert.equal(receipt.syntheticLoopback, true);
  assert.equal(receipt.rowsPass, true);
  assert.equal(receipt.actualHead, result.head);
  assert.equal(receipt.reviewedHead, result.head);
  const byId = Object.fromEntries(receipt.rows.map((row) => [row.id, row]));
  for (const id of ['N3', 'N7', 'N8', 'N2', 'N6']) {
    assert.equal(byId[id].executed, true, id);
    assert.equal(byId[id].pass, true, JSON.stringify(byId[id]));
  }
  assert.deepEqual(
    byId.N3.subcases.map((row) => row.id),
    ['control', 'wrong_client', 'wrong_agent', 'wrong_resource'],
  );
  assert.equal(byId.N3.label, 'loopback_issuer_local_verifier_expectation');
  assert.deepEqual(
    byId.N7.subcases.map((row) => row.id),
    [
      'external_a_approval_post',
      'external_a_already_consented_get',
      'downstream_b_approval_post',
      'downstream_b_already_consented_get',
    ],
  );
  assert.equal(
    byId.N7.subcases.every((row) => row.reason === 'openid_scope_refused'),
    true,
  );
  const bAuthorize = result.seen.authorize.filter((row) => row.clientId === B_CLIENT);
  const bExchange = result.seen.exchange.filter((row) => row.clientId === B_CLIENT);
  assert.equal(bAuthorize.length > 0, true);
  assert.equal(bExchange.length > 0, true);
  assert.equal(
    bAuthorize.every((row) => row.resource === null),
    true,
  );
  assert.equal(
    bExchange.every((row) => row.resource === null),
    true,
  );
  const aOpenId = result.seen.authorize.filter(
    (row) => row.clientId === A_CLIENT && row.scope.includes('openid'),
  );
  assert.equal(
    aOpenId.every(
      (row) =>
        row.redirect.endsWith('/oauth/callback') &&
        row.resource ===
          result.seen.authorize.find((item) => item.clientId === A_CLIENT && item.resource)
            ?.resource,
    ),
    true,
  );
  assert.equal(result.seen.emails.includes(EMAIL2), true);
  assert.equal(
    receipt.sessionLedger.some(
      (row) => row.gate === 'N2' && row.rejected === true && row.bSessionId,
    ),
    true,
  );
  assert.equal(result.seen.forbidden, 0);
  assert.equal(
    result.seen.marker.every((search) => search === '?select=marker,owner_id'),
    true,
  );
  assert.deepEqual(result.actions, [
    'cleanup_sessions',
    'cleanup_sessions',
    'cleanup_sessions',
    'prepare_second_synthetic_user',
    'cleanup_sessions',
    'delete_second_synthetic_user',
    'capture_hook_manifest',
    'disable_current_hook',
    'cleanup_sessions',
    'restore_hook_configuration',
    'cleanup_sessions',
  ]);
  const cleanup = result.messages.filter((row) => row.action === 'cleanup_sessions');
  const n2Cleanup = cleanup.find((row) => row.gate === 'N2');
  const deleteAt = result.messages.findIndex(
    (row) => row.action === 'delete_second_synthetic_user',
  );
  const n2CleanupAt = result.messages.findIndex(
    (row) => row.action === 'cleanup_sessions' && row.gate === 'N2',
  );
  assert.equal(n2CleanupAt < deleteAt, true);
  assert.equal(n2Cleanup.sessionIds.length, 8);
  assert.equal(result.messages[deleteAt].secondUserId, USER2);
  const n2Ids = new Set();
  for (const row of receipt.sessionLedger.filter((item) => item.gate === 'N2')) {
    for (const key of ['passwordSessionId', 'sourceSessionId', 'bSessionId', 'authSessionId']) {
      if (row[key]) n2Ids.add(row[key]);
    }
  }
  assert.equal(n2Ids.size, 8);
  assert.equal(
    receipt.sessionLedger.some(
      (row) => row.gate === 'N2' && row.rejected === true && row.sub === USER2,
    ),
    true,
  );
  assert.equal(
    receipt.sessionLedger.some((row) => row.gate === 'N8' && row.passwordSessionId),
    true,
  );
  assert.equal(
    receipt.sessionLedger.some((row) => row.gate === 'N8' && row.bSessionId),
    true,
  );
  assert.equal(
    receipt.sessionLedger.some((row) => row.gate === 'N6' && row.passwordSessionId),
    true,
  );
  assert.equal(
    receipt.sessionLedger.some((row) => row.gate === 'N6' && row.authSessionId),
    true,
  );
  const cleaned = new Set(cleanup.flatMap((row) => row.sessionIds));
  for (const decoy of result.seen.decoySessionIds) {
    assert.equal(cleaned.has(decoy), false, decoy);
  }
  assert.equal(result.seen.decoySessionIds.length > 0, true);
  assert.equal(result.seen.codes > result.seen.exchange.length, true);
  for (const secret of [PASSWORD, PASSWORD2, REFRESH, PUBLISHABLE, 'eyJ']) {
    assert.equal(result.outText.includes(secret), false, secret);
    assert.equal(result.errText.includes(secret), false, secret);
  }
});

test('generic invalid_scope is not an N7 hook-policy pass', async () => {
  const result = await drive('invalid_scope', 'N7');
  assert.equal(result.code, 2);
  assert.equal(result.receipt.acceptance, false);
  assert.equal(result.receipt.rowsPass, false);
  const n7 = result.receipt.rows.find((row) => row.id === 'N7');
  assert.equal(n7.executed, true);
  assert.equal(n7.pass, false);
  assert.equal(
    n7.subcases.some((row) => row.pass === true),
    false,
  );
});

test('N6 restores the saved hook when the marker probe times out', async () => {
  const result = await drive('hang-a-marker', 'N6');
  assert.equal(result.code, 2);
  assert.equal(result.receipt.acceptance, false);
  assert.equal(result.receipt.rowsPass, false);
  assert.equal(result.receipt.reason, 'orchestration_timeout');
  assert.equal(result.receipt.restoreStatus, 'confirmed');
  assert.equal(result.actions.includes('disable_current_hook'), true);
  assert.equal(result.actions.includes('restore_hook_configuration'), true);
  assert.equal(result.outText.includes(PASSWORD), false);
  assert.equal(result.outText.includes(REFRESH), false);
  assert.equal(result.receipt.cleanupStatus, 'confirmed');
});

test('retained consent still proves N7 policy without a forced approval', async () => {
  const result = await drive('preconsented', 'N7');
  assert.equal(result.code, 0, `${result.errText}\n${result.outText}`);
  const n7 = result.receipt.rows.find((row) => row.id === 'N7');
  assert.equal(n7.pass, true);
  assert.equal(
    n7.subcases.every((row) => row.observedFlow === 'already_consented_get'),
    true,
  );
  assert.equal(
    n7.subcases.every((row) => row.reason === 'openid_scope_refused'),
    true,
  );
});

test('unrelated marker 401 and 403 cannot pass F1', async () => {
  for (const mode of ['marker_401', 'marker_403']) {
    const result = await drive(mode, 'N6');
    assert.equal(result.code, 2, mode);
    assert.equal(result.receipt.acceptance, false);
    assert.equal(result.receipt.rowsPass, false);
    const n6 = result.receipt.rows.find((row) => row.id === 'N6');
    assert.equal(n6.pass, false, mode);
    assert.equal(n6.subcases.find((row) => row.id === 'f1_denial').pass, false, mode);
    assert.equal(result.receipt.restoreStatus, undefined);
    assert.equal(result.actions.includes('restore_hook_configuration'), true, mode);
  }
});

test('expired hook-off token cannot pass F1 and still restores', async () => {
  const result = await drive('expired_hook_off', 'N6');
  assert.equal(result.code, 2);
  assert.equal(result.receipt.rowsPass, false);
  assert.equal(result.receipt.reason, 'hook_off_unverified');
  assert.equal(result.receipt.restoreStatus, 'confirmed');
  assert.notEqual(result.receipt.restoreStatus, 'not_required');
});

test('malformed disable readback still restores and is not not_required', async () => {
  const result = await drive('policy', 'N6', 'malformed_disable');
  assert.equal(result.code, 2);
  assert.equal(result.receipt.reason, 'readback_malformed');
  assert.equal(result.receipt.restoreStatus, 'confirmed');
  assert.equal(result.actions.includes('disable_current_hook'), true);
  assert.equal(result.actions.includes('restore_hook_configuration'), true);
});

test('EOF after disable stays pending and keeps the recovery locator', async () => {
  const result = await drive('policy', 'N6', 'eof_disable');
  assert.equal(result.code, 2);
  assert.equal(result.receipt.restoreStatus, 'pending');
  assert.notEqual(result.receipt.restoreStatus, 'not_required');
  assert.equal(typeof result.receipt.recoveryLocator, 'string');
  const file = join(tmpdir(), 'ari-n-gates-recovery', result.receipt.recoveryLocator);
  assert.equal(existsSync(file), true);
  const saved = JSON.parse(readFileSync(file, 'utf8'));
  assert.equal(saved.phase, 'disable_armed');
  assert.equal(saved.hookManifest.function, 'ari_probe.custom_access_token_hook');
  assert.equal(JSON.stringify(saved).includes(PASSWORD), false);
  assert.equal(JSON.stringify(saved).includes('eyJ'), false);
});

test('disable timeout and SIGINT keep restoration armed', async () => {
  const timed = await drive('policy', 'N6', 'timeout_disable');
  assert.equal(timed.code, 2);
  assert.equal(timed.receipt.reason, 'orchestration_timeout');
  assert.equal(timed.receipt.restoreStatus, 'confirmed');
  const signaled = await drive('policy', 'N6', 'sigint');
  assert.equal(signaled.code, 2);
  assert.equal(signaled.receipt.reason, 'signal_received');
  assert.equal(signaled.receipt.restoreStatus, 'confirmed');
  assert.equal(signaled.actions.includes('restore_hook_configuration'), true);
});

test('stale readback cannot satisfy disable', async () => {
  const result = await drive('policy', 'N6', 'stale_disable');
  assert.equal(result.code, 2);
  assert.equal(result.receipt.reason, 'readback_stale');
  assert.equal(result.receipt.restoreStatus, 'confirmed');
  assert.notEqual(result.receipt.restoreStatus, 'not_required');
});

test('minimal and foreign hook manifests are rejected before disable', async () => {
  for (const fault of ['minimal_manifest', 'foreign_manifest']) {
    const result = await drive('policy', 'N6', fault);
    assert.equal(result.code, 2, fault);
    assert.equal(result.receipt.reason, 'hook_manifest_unreadable', fault);
    assert.equal(result.receipt.restoreStatus, 'not_required', fault);
    assert.equal(result.actions.includes('disable_current_hook'), false, fault);
  }
});

test('exchange service failure and callback HTTP 500 cannot pass binding or URI', async () => {
  const service = await drive('b_exchange_503', 'N8');
  assert.equal(service.code, 2);
  assert.equal(service.receipt.rowsPass, false);
  const n8 = service.receipt.rows.find((row) => row.id === 'N8');
  assert.equal(
    n8.subcases.some((row) => row.pass === true && row.reason === 'binding_rejected'),
    false,
  );
  assert.equal(n8.subcases.find((row) => row.id === 'accepted_then_replay').pass, false);
  assert.equal(
    n8.subcases.find((row) => row.id === 'accepted_then_replay').reason,
    'service_error',
  );
  assert.equal(
    n8.subcases.find((row) => row.id === 'pkce_invalid_grant').reason,
    'pkce_invalid_grant',
  );
  const uri = await drive('policy', 'N8', 'callback_500');
  assert.equal(uri.code, 2);
  const uriRow = uri.receipt.rows
    .find((row) => row.id === 'N8')
    .subcases.find((row) => row.id === 'callback_uri_mismatch');
  assert.equal(uriRow.pass, false);
  assert.equal(uriRow.reason, 'uri_inconclusive');
});

test('unexpected N7 issuance is not policy proof and stays on the ledger', async () => {
  const result = await drive('openid_issued', 'N7');
  assert.equal(result.code, 2);
  const n7 = result.receipt.rows.find((row) => row.id === 'N7');
  assert.equal(n7.pass, false);
  assert.equal(
    n7.subcases.some((row) => row.pass === true),
    false,
  );
  assert.equal(
    result.receipt.sessionLedger.some((row) => row.gate === 'N7' && row.passwordSessionId),
    true,
  );
  assert.equal(result.actions.includes('cleanup_sessions'), true);
});

test('duplicate cleanup ids are refused and do not delete a user', async () => {
  const result = await drive('policy', 'N2', 'duplicate_cleanup');
  assert.equal(result.code, 2);
  assert.equal(result.receipt.acceptance, false);
  assert.equal(result.receipt.reason, 'cleanup_unconfirmed');
  assert.equal(result.receipt.cleanupStatus, 'failed');
  assert.equal(result.actions.includes('cleanup_sessions'), true);
  assert.equal(result.actions.includes('delete_second_synthetic_user'), false);
  assert.equal(
    result.messages.some((row) => row.secondUserId === USER1),
    false,
  );
});

test('baseline, same email, wrong subject, and early failure do not delete the baseline', async () => {
  const baseline = await drive('policy', 'N2', 'baseline_id');
  assert.equal(baseline.code, 2, baseline.errText);
  assert.equal(baseline.receipt.acceptance, false);
  assert.equal(baseline.receipt.rowsPass, false);
  assert.equal(baseline.actions.includes('delete_second_synthetic_user'), false);
  assert.equal(
    baseline.messages.some((row) => row.secondUserId === USER1),
    false,
  );
  const sameEmail = await drive('policy', 'N2', 'same_email');
  assert.equal(sameEmail.code, 2);
  assert.equal(sameEmail.receipt.reason, 'second_user_unverified');
  assert.equal(sameEmail.actions.includes('delete_second_synthetic_user'), false);
  assert.equal(sameEmail.seen.emails.length, 0);
  const wrongSubject = await drive('wrong_subject', 'N2');
  assert.equal(wrongSubject.code, 2, wrongSubject.errText);
  assert.equal(wrongSubject.receipt.rowsPass, false);
  assert.equal(wrongSubject.actions.includes('delete_second_synthetic_user'), false);
  const early = await drive('policy', 'N2', 'early_failure');
  assert.equal(early.code, 2);
  assert.equal(early.receipt.reason, 'second_user_unverified');
  assert.equal(early.actions.includes('delete_second_synthetic_user'), false);
  assert.equal(early.seen.emails.length, 0);
  assert.equal(early.receipt.issuanceStatus, 'not_required');
});

function issuanceCleanedBeforeReceipt(result) {
  const cleanupAt = result.outText.indexOf('"action":"cleanup_sessions"');
  const receiptAt = result.outText.indexOf('"type":"receipt"');
  assert.equal(cleanupAt >= 0 && receiptAt > cleanupAt, true);
  assert.equal(result.receipt.cleanupStatus, 'confirmed');
  assert.notEqual(result.receipt.cleanupStatus, 'not_required');
  assert.equal(result.receipt.issuanceStatus, 'resolved');
  assert.equal(result.actions.includes('delete_second_synthetic_user'), false);
}

test('late password and oauth issuance are cleaned before the receipt', async () => {
  const password = await drive('delay_password', 'N3');
  assert.equal(password.code, 2, password.errText);
  assert.equal(password.receipt.reason, 'orchestration_timeout');
  issuanceCleanedBeforeReceipt(password);
  assert.equal(
    password.receipt.sessionLedger.some((row) => row.passwordSessionId),
    true,
  );
  const oauth = await drive('delay_oauth', 'N3');
  assert.equal(oauth.code, 2, oauth.errText);
  assert.equal(oauth.receipt.reason, 'orchestration_timeout');
  issuanceCleanedBeforeReceipt(oauth);
  assert.equal(
    oauth.receipt.sessionLedger.some((row) => row.sourceSessionId || row.authSessionId),
    true,
  );
});

test('aborted issuance stays unresolved and a late rejected B is cleaned', async () => {
  const aborted = await drive('hang_issuance', 'N3');
  assert.equal(aborted.code, 2, aborted.errText);
  assert.equal(aborted.receipt.issuanceStatus, 'unresolved');
  assert.equal(aborted.receipt.cleanupStatus, 'unresolved');
  assert.notEqual(aborted.receipt.cleanupStatus, 'confirmed');
  assert.notEqual(aborted.receipt.cleanupStatus, 'not_required');
  assert.equal(aborted.actions.includes('reconcile_unresolved_issuance'), true);
  assert.equal(aborted.actions.includes('delete_second_synthetic_user'), false);
  const rejected = await drive('delay_rejected_b', 'N2');
  assert.equal(rejected.code, 2, rejected.errText);
  issuanceCleanedBeforeReceipt(rejected);
  assert.equal(
    rejected.receipt.sessionLedger.some((row) => row.bSessionId && row.sub === USER2),
    true,
  );
  assert.equal(rejected.actions.includes('delete_second_synthetic_user'), false);
});

test('wrong marker, name-only policy, and altered F1 cannot pass N6', async () => {
  for (const mode of ['wrong_marker', 'wrong_owner']) {
    const result = await drive(mode, 'N6');
    assert.equal(result.code, 2, mode);
    assert.equal(result.receipt.acceptance, false);
    const n6 = result.receipt.rows.find((row) => row.id === 'N6');
    assert.equal(n6.pass, false, mode);
    assert.equal(n6.subcases.find((row) => row.id === 'owner_read').pass, false, mode);
    assert.equal(result.actions.includes('disable_current_hook'), false, mode);
  }
  for (const fault of ['boolean_policy', 'altered_f1']) {
    const result = await drive('policy', 'N6', fault);
    assert.equal(result.code, 2, fault);
    assert.equal(result.receipt.reason, 'f1_readback_missing', fault);
    assert.equal(result.actions.includes('disable_current_hook'), false, fault);
    assert.equal(result.receipt.restoreStatus, 'not_required', fault);
  }
  const restored = await drive('policy', 'N6', 'altered_f1_restore');
  assert.equal(restored.code, 2);
  assert.equal(restored.receipt.reason, 'hook_restore_mismatch');
  assert.equal(restored.receipt.restoreStatus, 'failed');
  assert.equal(restored.actions.includes('disable_current_hook'), true);
  assert.equal(restored.actions.includes('restore_hook_configuration'), true);
});
