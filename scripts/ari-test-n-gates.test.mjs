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
import { PGlite } from '@electric-sql/pglite';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

import { SYNTHETIC_EMAIL } from '../docs/evidence/ari-test-probe/decisions.mjs';

import {
  callbackUriMismatchPass,
  canonicalF1Qual,
  canonicalOwnerQual,
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
const DECOY_SESSION = '33333333-3333-4333-8333-333333333333';

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
  assert.equal(
    plan.steps.some(
      (step) => step.includes('GET /auth/v1/user') && step.includes('not an F1 pass'),
    ),
    true,
  );
  assert.equal(
    plan.steps.some((step) =>
      step.includes('not_required only when the run recorded no session id'),
    ),
    true,
  );
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

function laneTimeoutMs(mode, fault) {
  if (fault === 'sigint_user' || fault === 'sigterm_user') return '20000';
  if (
    mode === 'hang-a-marker' ||
    mode === 'delay_password' ||
    mode === 'delay_oauth' ||
    mode === 'delay_rejected_b' ||
    mode === 'hang_issuance' ||
    mode === 'stall_token_body' ||
    mode === 'stall_user_headers' ||
    mode === 'stall_user_body' ||
    mode === 'stall_marker_body' ||
    fault === 'timeout_disable'
  ) {
    return '1000';
  }
  return '20000';
}

async function startIssuer(mode, hooks = {}) {
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
    for (const user of [USER1, USER2]) {
      remembered.add(`${user}:${A_CLIENT}:openid email`);
      remembered.add(`${user}:${B_CLIENT}:openid email`);
    }
  }
  const { privateKey: decoyKey } = await generateKeyPair('ES256');
  let hookEnabled = true;
  let passwordSerial = 0;
  let downstreamTokenPosts = 0;
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
            if (mode === 'stall_token_body') {
              res.writeHead(200, {
                'content-type': 'application/json',
                'cache-control': 'no-store',
              });
              res.write('{"access_token":');
              return;
            }
            if (mode === 'malformed_token') {
              send(200, 'not-json');
              return;
            }
            if (mode === 'hang_issuance') return;
            if (mode === 'delay_password')
              await new Promise((resolve) => setTimeout(resolve, 1300));
            passwordSerial += 1;
            const sessionId = `77777777-7777-4777-8777-${passwordSerial.toString(16).padStart(12, '0')}`;
            const access = await new SignJWT(
              mode === 'missing_session'
                ? { role: 'authenticated' }
                : { role: 'authenticated', session_id: sessionId },
            )
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
            if (form.get('client_id') === B_CLIENT) {
              downstreamTokenPosts += 1;
              if (mode === 'ambiguous_n8' && downstreamTokenPosts >= 3) {
                send(200, 'not-json');
                return;
              }
            }
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
              if (mode === 'hook_marker_nested') {
                send(
                  403,
                  JSON.stringify({ error: { http_code: 403, message: 'openid_scope_refused' } }),
                );
                return;
              }
              if (mode === 'hook_marker_description') {
                send(403, JSON.stringify({ error_description: 'openid_scope_refused' }));
                return;
              }
              if (mode === 'hook_truncated') {
                send(403, '{"message":"openid_scope_refused"');
                return;
              }
              if (mode === 'hook_malformed') {
                send(403, 'not-json');
                return;
              }
              if (mode === 'hook_5xx') {
                send(503, JSON.stringify({ message: 'openid_scope_refused' }));
                return;
              }
              if (mode === 'hook_token') {
                send(
                  403,
                  JSON.stringify({
                    message: 'openid_scope_refused',
                    access_token: 'access-sentinel-must-not-leak',
                  }),
                );
                return;
              }
              if (mode === 'hook_refresh') {
                send(
                  403,
                  JSON.stringify({
                    error: 'invalid_request',
                    error_description: 'openid_scope_refused',
                    refresh_token: 'refresh-sentinel-must-not-leak',
                  }),
                );
                return;
              }
              if (mode === 'hook_ambiguous') {
                send(403, JSON.stringify(['openid_scope_refused']));
                return;
              }
              if (mode === 'generic_403') {
                send(403, JSON.stringify({ error: 'temporarily_unavailable' }));
                return;
              }
              if (mode === 'deny_refresh_token') {
                send(400, JSON.stringify({ error: 'invalid_request', refresh_token: 'synthetic' }));
                return;
              }
              if (mode === 'deny_id_token') {
                send(401, JSON.stringify({ error: 'invalid_grant', id_token: 'synthetic' }));
                return;
              }
              if (mode === 'deny_access_null') {
                send(403, JSON.stringify({ error: 'access_denied', access_token: null }));
                return;
              }
              if (mode === 'deny_access_nonstring') {
                send(400, JSON.stringify({ error: 'invalid_request', access_token: false }));
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
            if (mode === 'b_malformed' && record.clientId === B_CLIENT) {
              send(200, 'not-json');
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
            if (mode === 'missing_session') delete claims.session_id;
            const access = await new SignJWT(claims)
              .setProtectedHeader({ alg: 'ES256', kid: 'g2-test', typ: 'JWT' })
              .setSubject(record.sub ?? USER1)
              .setIssuer(issuer)
              .setAudience(tokenA && hookEnabled ? (record.resource ?? '') : 'authenticated')
              .setIssuedAt()
              .setExpirationTime(
                mode === 'expired_hook_off' && tokenA && !hookEnabled ? '-10s' : '5m',
              )
              .sign(mode === 'b_bad_signature' && !tokenA ? decoyKey : privateKey);
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
        const mcpMarker = url.search === '?select=marker';
        const ownerMarker = url.search === '?select=marker,owner_id';
        if (!mcpMarker && !ownerMarker) {
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
        if (mcpMarker && clientId === B_CLIENT) {
          if (mode === 'marker_tool_5xx') {
            send(500, JSON.stringify({ error: 'server_error' }));
            return;
          }
          if (mode === 'marker_tool_malformed') {
            send(200, 'not-json');
            return;
          }
          send(200, JSON.stringify([{ marker: 'ari-probe-marker-odbcejsuuqdzhabjmozi' }]));
          return;
        }
        if (mode === 'hang-a-marker' && clientId === A_CLIENT) return;
        if (mode === 'stall_marker_body' && clientId === A_CLIENT) {
          res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
          res.write('[');
          hooks.onStall?.();
          return;
        }
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
        if (mode === 'stall_user_headers' || mode === 'stall_user_body') {
          if (mode === 'stall_user_body') {
            res.writeHead(200, {
              'content-type': 'application/json',
              'cache-control': 'no-store',
            });
            res.write('{"id":');
          }
          hooks.onStall?.();
          return;
        }
        const user = bearerUser();
        if (user === undefined) {
          send(401, JSON.stringify({ error: 'unauthorized' }));
          return;
        }
        send(200, JSON.stringify({ id: user.sub, aud: 'authenticated' }));
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

async function drive(mode, gates, fault = 'none', options = {}) {
  const recoveryTmp = typeof options.tmpdir === 'string' ? options.tmpdir : tmpdir();
  const hooks = {};
  const issuer = await startIssuer(mode, hooks);
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
      ARI_LANE_B_TIMEOUT_MS: laneTimeoutMs(mode, fault),
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
      TMPDIR: recoveryTmp,
    },
  });
  const stderr = [];
  proc.stderr.on('data', (chunk) => stderr.push(chunk));
  hooks.onStall = () => {
    if (hooks.signaled === true) return;
    hooks.signaled = true;
    if (fault === 'sigint_user') proc.kill('SIGINT');
    else if (fault === 'sigterm_user') proc.kill('SIGTERM');
  };
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
      qual: canonicalF1Qual('baseline-a-client', A_CLIENT),
    },
    rls: { schema: 'public', table: 'ari_probe_marker', enabled: true, forced: true },
    ownerPolicy: {
      name: 'ari_probe_marker_owner_read',
      kind: 'permissive',
      command: 'select',
      roles: ['authenticated'],
      qual: canonicalOwnerQual(),
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
            mode === 'hang-a-marker' ||
              mode === 'stall_user_headers' ||
              mode === 'stall_user_body' ||
              mode === 'stall_marker_body' ||
              fault === 'timeout_disable' ||
              fault === 'sigint_user' ||
              fault === 'sigterm_user'
              ? 20_000
              : 60_000,
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
          } else if (fault === 'missing_f1_qual') {
            const body = evidence();
            delete body.f1.qual;
            correlated(message, { type: 'readback', hookManifest: manifest, ...body });
          } else if (fault === 'using_true' || fault === 'using_false') {
            const body = evidence();
            body.f1 = { ...body.f1, qual: fault === 'using_true' ? 'true' : 'false' };
            correlated(message, { type: 'readback', hookManifest: manifest, ...body });
          } else if (fault === 'or_not_and' || fault === 'one_comparison') {
            const body = evidence();
            const full = body.f1.qual;
            const andAt = full.indexOf(' AND ');
            body.f1 = {
              ...body.f1,
              qual: fault === 'or_not_and' ? full.replace(' AND ', ' OR ') : full.slice(1, andAt),
            };
            correlated(message, { type: 'readback', hookManifest: manifest, ...body });
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
          if (fault === 'altered_f1_expr_restore') {
            restored.f1 = {
              ...restored.f1,
              qual: restored.f1.qual.replace(' AND ', ' OR '),
            };
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
          correlated(message, {
            type: 'readback',
            reconciled: true,
            sessionIds: [DECOY_SESSION],
          });
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
      recoveryTmp,
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
  assert.equal(receipt.issuanceStatus, 'resolved');
  assert.equal(receipt.cleanupStatus, 'confirmed');
  assert.notEqual(receipt.cleanupStatus, 'not_required');
  assert.equal(receipt.restoreStatus, 'confirmed');
  assert.deepEqual(receipt.unresolvedAttemptIds, []);
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
  assert.equal(
    byId.N7.subcases.every(
      (row) =>
        row.exchangeStatus === 403 &&
        row.policyMarker === 'openid_scope_refused' &&
        row.accessTokenPresent === false &&
        row.idTokenPresent === false &&
        row.refreshTokenPresent === false,
    ),
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
  assert.equal(result.seen.marker.includes('?select=marker,owner_id'), true);
  assert.equal(result.seen.marker.includes('?select=marker'), true);
  assert.equal(
    result.seen.marker.every(
      (search) => search === '?select=marker,owner_id' || search === '?select=marker',
    ),
    true,
  );
  const n8 = byId.N8;
  const unbound = n8.subcases.find((row) => row.id === 'signed_b_unbound');
  const subject = n8.subcases.find((row) => row.id === 'signed_b_mismatch');
  const synthetic = n8.subcases.find((row) => row.id === 'synthetic_agent_mismatch');
  const replay = n8.subcases.find((row) => row.id === 'accepted_then_replay');
  assert.equal(unbound.pass, true);
  assert.equal(unbound.reason, 'signed_b_not_stored');
  assert.equal(unbound.negativeStatus, 401);
  assert.equal(unbound.negativeError, 'invalid_token');
  assert.equal(unbound.bLive, true);
  assert.equal(unbound.storedGrant, false);
  assert.equal(subject.pass, true);
  assert.equal(subject.reason, 'SUBJECT');
  assert.equal(subject.mismatchClass, 'SUBJECT');
  assert.equal(subject.subject, USER2);
  assert.equal(synthetic.pass, true);
  assert.equal(synthetic.reason, 'synthetic_agent');
  assert.equal(synthetic.mismatchClass, 'synthetic_agent');
  assert.equal(replay.pass, true);
  assert.equal(replay.reason, 'replay_rejected');
  assert.equal(replay.exchangesAfterBind, 1);
  assert.equal(replay.exchangesAfterReplay, 0);
  assert.equal(replay.markerReads, 2);
  assert.equal(replay.livenessDenials, 0);
  assert.deepEqual(result.actions, [
    'cleanup_sessions',
    'prepare_second_synthetic_user',
    'cleanup_sessions',
    'cleanup_sessions',
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
  assert.equal(
    n7.subcases.every((row) => row.exchangeStatus === 400 && row.policyMarker === null),
    true,
  );
  assert.equal(result.receipt.issuanceStatus, 'resolved');
  assert.deepEqual(result.receipt.unresolvedAttemptIds, []);
  assert.equal(result.actions.includes('reconcile_unresolved_issuance'), false);
});

function assertNoIssuanceSecrets(result, label) {
  for (const secret of [
    PASSWORD,
    PASSWORD2,
    REFRESH,
    'access-sentinel-must-not-leak',
    'refresh-sentinel-must-not-leak',
    'eyJ',
  ]) {
    assert.equal(result.outText.includes(secret), false, `${label}:${secret}`);
    assert.equal(result.errText.includes(secret), false, `${label}:${secret}`);
  }
}

function assertStoppedBeforeN2(result, label) {
  assert.equal(
    result.messages.some(
      (row) => row.action === 'prepare_second_synthetic_user' && row.gate === 'N2',
    ),
    false,
    label,
  );
  assert.equal(result.actions.includes('delete_second_synthetic_user'), false, label);
  const n2 = result.receipt.rows.find((row) => row.id === 'N2');
  assert.equal(n2.executed, false, label);
  assert.equal(n2.pass, false, label);
  assert.equal(n2.label, 'not_executed', label);
}

test('complete hook-policy denials resolve issuance without an OAuth error name', async () => {
  for (const mode of ['hook_marker_description', 'hook_marker_nested']) {
    const result = await drive(mode, 'N7');
    assert.equal(result.code, 0, `${mode}\n${result.errText}\n${result.outText}`);
    assert.equal(result.receipt.acceptance, false, mode);
    assert.equal(result.receipt.rowsPass, true, mode);
    assert.equal(result.receipt.issuanceStatus, 'resolved', mode);
    assert.deepEqual(result.receipt.unresolvedAttemptIds, [], mode);
    assert.equal(result.actions.includes('reconcile_unresolved_issuance'), false, mode);
    const n7 = result.receipt.rows.find((row) => row.id === 'N7');
    assert.equal(n7.pass, true, mode);
    for (const row of n7.subcases) {
      assert.equal(row.exchangeStatus, 403, mode);
      assert.equal(row.policyMarker, 'openid_scope_refused', mode);
      assert.equal(row.accessTokenPresent, false, mode);
      assert.equal(row.idTokenPresent, false, mode);
      assert.equal(row.refreshTokenPresent, false, mode);
      assert.equal(row.reason, 'openid_scope_refused', mode);
      assert.equal(JSON.stringify(row).includes('access_token'), false, mode);
    }
    assertNoIssuanceSecrets(result, mode);
  }
  const continued = await drive('hook_marker_description', 'N7,N2');
  assert.equal(continued.code, 0, `${continued.errText}\n${continued.outText}`);
  assert.equal(continued.receipt.acceptance, false);
  assert.equal(continued.receipt.issuanceStatus, 'resolved');
  assert.equal(continued.actions.includes('prepare_second_synthetic_user'), true);
  assert.equal(continued.actions.includes('delete_second_synthetic_user'), true);
  assert.equal(continued.receipt.rows.find((row) => row.id === 'N2').pass, true);
  assertNoIssuanceSecrets(continued, 'continued');
});

test('truncated malformed 5xx token-present and ambiguous bodies stay unresolved', async () => {
  const cases = [
    ['hook_truncated', false, 403, null, false, false, false],
    ['hook_malformed', false, 403, null, false, false, false],
    ['hook_5xx', false, 503, 'openid_scope_refused', false, false, false],
    ['hook_token', false, 403, 'openid_scope_refused', true, false, false],
    ['hook_refresh', false, 403, 'openid_scope_refused', false, false, true],
    ['hook_ambiguous', true, 403, 'openid_scope_refused', false, false, false],
    ['generic_403', false, 403, null, false, false, false],
  ];
  for (const [mode, n7Pass, status, marker, access, idToken, refresh] of cases) {
    const result = await drive(mode, 'N7,N2');
    assert.equal(result.code, 2, `${mode}\n${result.errText}\n${result.outText}`);
    assert.equal(result.receipt.acceptance, false, mode);
    assert.equal(result.receipt.rowsPass, false, mode);
    assert.equal(result.receipt.issuanceStatus, 'unresolved', mode);
    assert.notEqual(result.receipt.issuanceStatus, 'resolved', mode);
    assert.equal(result.receipt.cleanupStatus, 'unresolved', mode);
    assert.equal(result.receipt.unresolvedAttemptIds.length > 0, true, mode);
    assert.equal(result.actions.includes('reconcile_unresolved_issuance'), true, mode);
    assertStoppedBeforeN2(result, mode);
    const n7 = result.receipt.rows.find((row) => row.id === 'N7');
    assert.equal(n7.executed, true, mode);
    assert.equal(n7.pass, n7Pass, mode);
    assert.equal(
      n7.subcases.every(
        (row) =>
          row.exchangeStatus === status &&
          row.policyMarker === marker &&
          row.accessTokenPresent === access &&
          row.idTokenPresent === idToken &&
          row.refreshTokenPresent === refresh,
      ),
      true,
      `${mode}:${JSON.stringify(n7.subcases)}`,
    );
    const reconcileAt = result.outText.indexOf('"action":"reconcile_unresolved_issuance"');
    const receiptAt = result.outText.lastIndexOf('"type":"receipt"');
    assert.equal(reconcileAt >= 0 && receiptAt > reconcileAt, true, mode);
    assertNoIssuanceSecrets(result, mode);
  }
});

test('allowlisted denials that carry a token field stay unresolved and do not start N2', async () => {
  const cases = [
    ['deny_refresh_token', 400, false, false, true],
    ['deny_id_token', 401, false, true, false],
    ['deny_access_null', 403, false, false, false],
    ['deny_access_nonstring', 400, false, false, false],
  ];
  for (const [mode, status, access, idToken, refresh] of cases) {
    const result = await drive(mode, 'N7,N2');
    assert.equal(result.code, 2, `${mode}\n${result.errText}\n${result.outText}`);
    assert.equal(result.receipt.acceptance, false, mode);
    assert.equal(result.receipt.rowsPass, false, mode);
    assert.equal(result.receipt.issuanceStatus, 'unresolved', mode);
    assert.notEqual(result.receipt.issuanceStatus, 'resolved', mode);
    assert.equal(result.receipt.cleanupStatus, 'unresolved', mode);
    assert.equal(result.receipt.unresolvedAttemptIds.length > 0, true, mode);
    assert.equal(result.actions.includes('reconcile_unresolved_issuance'), true, mode);
    assertStoppedBeforeN2(result, mode);
    const n7 = result.receipt.rows.find((row) => row.id === 'N7');
    assert.equal(n7.executed, true, mode);
    assert.equal(n7.pass, false, mode);
    assert.equal(
      n7.subcases.every(
        (row) =>
          row.exchangeStatus === status &&
          row.policyMarker === null &&
          row.accessTokenPresent === access &&
          row.idTokenPresent === idToken &&
          row.refreshTokenPresent === refresh,
      ),
      true,
      `${mode}:${JSON.stringify(n7.subcases)}`,
    );
    const reconcileAt = result.outText.indexOf('"action":"reconcile_unresolved_issuance"');
    const receiptAt = result.outText.lastIndexOf('"type":"receipt"');
    assert.equal(reconcileAt >= 0 && receiptAt > reconcileAt, true, mode);
    assert.equal(result.outText.includes('"refresh_token"'), false, mode);
    assert.equal(result.outText.includes('"id_token"'), false, mode);
    assert.equal(result.outText.includes('"access_token"'), false, mode);
    assert.equal(result.outText.includes('"synthetic"'), false, mode);
    assertNoIssuanceSecrets(result, mode);
  }
});

test('unresolved issuance after a passing gate does not start N2', async () => {
  const result = await drive('missing_session', 'N7,N2');
  assert.equal(result.code, 2, `${result.errText}\n${result.outText}`);
  assert.equal(result.receipt.acceptance, false);
  assert.equal(result.receipt.rowsPass, false);
  assert.equal(result.receipt.issuanceStatus, 'unresolved');
  assert.equal(result.receipt.cleanupStatus, 'unresolved');
  const n7 = result.receipt.rows.find((row) => row.id === 'N7');
  assert.equal(n7.executed, true);
  assert.equal(n7.pass, true);
  assert.equal(
    n7.subcases.every(
      (row) =>
        row.pass === true &&
        row.exchangeStatus === 403 &&
        row.policyMarker === 'openid_scope_refused' &&
        row.accessTokenPresent === false &&
        row.idTokenPresent === false &&
        row.refreshTokenPresent === false,
    ),
    true,
  );
  assertStoppedBeforeN2(result, 'missing_session');
  assert.equal(result.actions.includes('reconcile_unresolved_issuance'), true);
  const reconcileAt = result.outText.indexOf('"action":"reconcile_unresolved_issuance"');
  const receiptAt = result.outText.lastIndexOf('"type":"receipt"');
  assert.equal(reconcileAt >= 0 && receiptAt > reconcileAt, true);
  assertNoIssuanceSecrets(result, 'missing_session');
});

function assertHookOffStall(result, label, reason) {
  assert.equal(result.code, 2, `${label}\n${result.errText}\n${result.outText}`);
  assert.equal(result.receipt.acceptance, false, label);
  assert.equal(result.receipt.rowsPass, false, label);
  assert.equal(result.receipt.reason, reason, label);
  assert.equal(result.actions.includes('disable_current_hook'), true, label);
  assert.equal(result.actions.includes('restore_hook_configuration'), true, label);
  const disableAt = result.actions.indexOf('disable_current_hook');
  const restoreAt = result.actions.indexOf('restore_hook_configuration');
  assert.equal(restoreAt > disableAt, true, label);
  assert.equal(result.receipt.restoreStatus, 'confirmed', label);
  assert.notEqual(result.receipt.restoreStatus, 'not_required', label);
  assert.equal(result.receipt.recoveryLocator, undefined, label);
  assert.equal(result.outText.includes('"id":"f1_denial"'), false, label);
  const restore = result.messages.find((row) => row.action === 'restore_hook_configuration');
  assert.equal(restore.hookManifest.function, 'ari_probe.custom_access_token_hook', label);
  assert.equal(restore.hookManifest.uri.includes('custom_access_token_hook'), true, label);
  const restoreOut = result.outText.indexOf('"action":"restore_hook_configuration"');
  const receiptAt = result.outText.indexOf('"type":"receipt"');
  assert.equal(restoreOut >= 0 && receiptAt > restoreOut, true, label);
  issuanceCleanedBeforeReceipt(result);
  const cleaned = new Set(
    result.messages
      .filter((row) => row.action === 'cleanup_sessions')
      .flatMap((row) => row.sessionIds),
  );
  assert.equal(result.receipt.sessionLedger.length > 0, true, label);
  for (const row of result.receipt.sessionLedger) {
    for (const key of ['passwordSessionId', 'sourceSessionId', 'bSessionId', 'authSessionId']) {
      if (row[key] !== undefined) assert.equal(cleaned.has(row[key]), true, `${label}:${row[key]}`);
    }
  }
  assert.equal(result.outText.includes(PASSWORD), false, label);
  assert.equal(result.outText.includes(REFRESH), false, label);
}

test('stalled hook-off user and marker reads restore without an F1 pass', async () => {
  const cases = [
    ['stall_user_headers', 'none', 'orchestration_timeout'],
    ['stall_user_body', 'none', 'orchestration_timeout'],
    ['stall_user_headers', 'sigint_user', 'signal_received'],
    ['stall_user_body', 'sigterm_user', 'signal_received'],
    ['stall_marker_body', 'none', 'orchestration_timeout'],
    ['stall_marker_body', 'sigint_user', 'signal_received'],
  ];
  for (const [mode, fault, reason] of cases) {
    const result = await drive(mode, 'N6', fault);
    assertHookOffStall(result, `${mode}:${fault}`, reason);
  }
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

test('repeated already-consented reads stay an incomplete N7 gate', async () => {
  const result = await drive('preconsented', 'N7');
  assert.equal(result.code, 2, `${result.errText}\n${result.outText}`);
  assert.equal(result.receipt.acceptance, false);
  assert.equal(result.receipt.rowsPass, false);
  const n7 = result.receipt.rows.find((row) => row.id === 'N7');
  assert.equal(n7.executed, true);
  assert.equal(n7.pass, false);
  assert.equal(n7.label, 'n7_incomplete');
  assert.equal(
    n7.subcases.every((row) => row.observedFlow === 'already_consented_get' && row.pass === true),
    true,
  );
  assert.equal(
    n7.subcases.every((row) => row.reason === 'openid_scope_refused'),
    true,
  );
  assert.equal(result.actions.includes('delete_second_synthetic_user'), false);
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
    assert.equal(result.receipt.restoreStatus, 'confirmed', mode);
    assert.notEqual(result.receipt.restoreStatus, 'not_required', mode);
    assert.equal(result.receipt.issuanceStatus !== undefined, true, mode);
    assert.equal(result.receipt.cleanupStatus !== undefined, true, mode);
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
  assert.equal(result.recoveryTmp, tmpdir());
  const file = join(tmpdir(), 'ari-n-gates-recovery', result.receipt.recoveryLocator);
  assert.equal(existsSync(file), true);
  const saved = JSON.parse(readFileSync(file, 'utf8'));
  assert.equal(saved.phase, 'disable_armed');
  assert.equal(saved.hookManifest.function, 'ari_probe.custom_access_token_hook');
  assert.equal(JSON.stringify(saved).includes(PASSWORD), false);
  assert.equal(JSON.stringify(saved).includes('eyJ'), false);
});

test('N6 EOF recovery locator follows a profile-scratch TMPDIR', async () => {
  const scratch = mkdtempSync(join(tmpdir(), 'ari-n-gates-profile-'));
  const result = await drive('policy', 'N6', 'eof_disable', { tmpdir: scratch });
  assert.equal(result.code, 2, `${result.errText}\n${result.outText}`);
  assert.equal(result.receipt.acceptance, false);
  assert.equal(result.receipt.restoreStatus, 'pending');
  assert.notEqual(result.receipt.restoreStatus, 'not_required');
  assert.equal(result.recoveryTmp, scratch);
  const file = join(scratch, 'ari-n-gates-recovery', result.receipt.recoveryLocator);
  assert.equal(existsSync(file), true);
  assert.equal(
    existsSync(join(tmpdir(), 'ari-n-gates-recovery', result.receipt.recoveryLocator)),
    false,
  );
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
    n8.subcases.some((row) => row.pass === true && row.reason === 'SUBJECT'),
    false,
  );
  assert.equal(n8.subcases.find((row) => row.id === 'signed_b_mismatch').pass, false);
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

test('N8 rejects marker 5xx, unreadable marker, bad signature, malformed B, and wrong subject', async () => {
  for (const [mode, replayReason] of [
    ['marker_tool_5xx', 'marker_unproven'],
    ['marker_tool_malformed', 'marker_unproven'],
  ]) {
    const result = await drive(mode, 'N8');
    assert.equal(result.code, 2, `${mode}\n${result.errText}\n${result.outText}`);
    assert.equal(result.receipt.acceptance, false, mode);
    assert.equal(result.receipt.rowsPass, false, mode);
    const replay = result.receipt.rows
      .find((row) => row.id === 'N8')
      .subcases.find((row) => row.id === 'accepted_then_replay');
    assert.equal(replay.pass, false, mode);
    assert.equal(replay.reason, replayReason, mode);
    assert.notEqual(replay.reason, 'replay_rejected', mode);
    assertNoIssuanceSecrets(result, mode);
  }
  const signature = await drive('b_bad_signature', 'N8');
  assert.equal(signature.code, 2, signature.errText);
  assert.equal(signature.receipt.acceptance, false);
  const signatureN8 = signature.receipt.rows.find((row) => row.id === 'N8');
  assert.equal(signatureN8.subcases.find((row) => row.id === 'signed_b_mismatch').pass, false);
  assert.notEqual(
    signatureN8.subcases.find((row) => row.id === 'signed_b_mismatch').reason,
    'SUBJECT',
  );
  assert.equal(
    signatureN8.subcases.find((row) => row.id === 'accepted_then_replay').reason,
    'signature_rejected',
  );
  assertNoIssuanceSecrets(signature, 'b_bad_signature');
  const malformed = await drive('b_malformed', 'N8');
  assert.equal(malformed.code, 2, malformed.errText);
  assert.equal(malformed.receipt.acceptance, false);
  assert.equal(malformed.receipt.issuanceStatus, 'unresolved');
  assert.equal(malformed.receipt.cleanupStatus, 'unresolved');
  const malformedSigned = malformed.receipt.rows
    .find((row) => row.id === 'N8')
    .subcases.find((row) => row.id === 'signed_b_unbound');
  assert.equal(malformedSigned.executed, true);
  assert.equal(malformedSigned.pass, false);
  assert.notEqual(malformedSigned.reason, 'signed_b_not_stored');
  assert.equal(malformed.actions.includes('delete_second_synthetic_user'), false);
  assert.equal(malformed.actions.includes('reconcile_unresolved_issuance'), true);
  assertNoIssuanceSecrets(malformed, 'b_malformed');
  const wrongSubject = await drive('wrong_subject', 'N8');
  assert.equal(wrongSubject.code, 2, wrongSubject.errText);
  assert.equal(wrongSubject.receipt.acceptance, false);
  const wrongRow = wrongSubject.receipt.rows
    .find((row) => row.id === 'N8')
    .subcases.find((row) => row.id === 'signed_b_mismatch');
  assert.equal(wrongRow.pass, false);
  assert.notEqual(wrongRow.reason, 'SUBJECT');
  assert.equal(wrongSubject.actions.includes('delete_second_synthetic_user'), false);
  assert.equal(
    wrongSubject.messages.some((row) => row.secondUserId === USER1),
    false,
  );
  assertNoIssuanceSecrets(wrongSubject, 'wrong_subject');
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
  assert.equal(early.receipt.cleanupStatus, 'not_required');
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
  for (const fault of [
    'boolean_policy',
    'altered_f1',
    'missing_f1_qual',
    'using_true',
    'using_false',
    'or_not_and',
    'one_comparison',
  ]) {
    const result = await drive('policy', 'N6', fault);
    assert.equal(result.code, 2, fault);
    assert.equal(result.receipt.reason, 'f1_readback_missing', fault);
    assert.equal(result.receipt.rowsPass, false, fault);
    assert.equal(result.actions.includes('disable_current_hook'), false, fault);
    assert.equal(result.receipt.restoreStatus, 'not_required', fault);
    assert.equal(result.receipt.issuanceStatus !== undefined, true, fault);
    assert.equal(result.receipt.cleanupStatus !== undefined, true, fault);
  }
  const restored = await drive('policy', 'N6', 'altered_f1_restore');
  assert.equal(restored.code, 2);
  assert.equal(restored.receipt.reason, 'hook_restore_mismatch');
  assert.equal(restored.receipt.restoreStatus, 'failed');
  assert.equal(restored.actions.includes('disable_current_hook'), true);
  assert.equal(restored.actions.includes('restore_hook_configuration'), true);
  const expr = await drive('policy', 'N6', 'altered_f1_expr_restore');
  assert.equal(expr.code, 2, expr.errText);
  assert.equal(expr.receipt.reason, 'hook_restore_mismatch');
  assert.equal(expr.receipt.restoreStatus, 'failed');
  assert.equal(expr.receipt.rowsPass, false);
  assert.equal(expr.actions.includes('disable_current_hook'), true);
  assert.equal(expr.actions.includes('restore_hook_configuration'), true);
});

function reconcileBeforeReceipt(result) {
  const reconcileAt = result.outText.indexOf('"action":"reconcile_unresolved_issuance"');
  const receiptAt = result.outText.lastIndexOf('"type":"receipt"');
  assert.equal(reconcileAt >= 0 && receiptAt > reconcileAt, true);
  const reconcile = result.messages.find((row) => row.action === 'reconcile_unresolved_issuance');
  assert.deepEqual(reconcile.attemptIds, result.receipt.unresolvedAttemptIds);
  assert.equal(result.receipt.unresolvedAttemptIds.length > 0, true);
  assert.equal(
    result.receipt.unresolvedAttemptIds.every((id) => id !== DECOY_SESSION),
    true,
  );
  assert.equal(
    result.messages.some(
      (row) =>
        row.action === 'cleanup_sessions' &&
        Array.isArray(row.sessionIds) &&
        row.sessionIds.includes(DECOY_SESSION),
    ),
    false,
  );
  assert.equal(result.actions.includes('delete_second_synthetic_user'), false);
}

test('headers then a stalled token body stay unresolved', async () => {
  const result = await drive('stall_token_body', 'N3');
  assert.equal(result.code, 2, `${result.errText}\n${result.outText}`);
  assert.equal(result.receipt.acceptance, false);
  assert.equal(result.receipt.rowsPass, false);
  assert.equal(result.receipt.issuanceStatus, 'unresolved');
  assert.notEqual(result.receipt.issuanceStatus, 'resolved');
  assert.equal(result.receipt.cleanupStatus, 'unresolved');
  assert.equal(result.receipt.restoreStatus, 'not_required');
  assert.equal(result.receipt.sessionLedger.length, 0);
  reconcileBeforeReceipt(result);
});

test('malformed 2xx and a missing session claim stay unresolved', async () => {
  const malformed = await drive('malformed_token', 'N3');
  assert.equal(malformed.code, 2, malformed.errText);
  assert.equal(malformed.receipt.acceptance, false);
  assert.equal(malformed.receipt.issuanceStatus, 'unresolved');
  assert.equal(malformed.receipt.cleanupStatus, 'unresolved');
  assert.equal(malformed.receipt.sessionLedger.length, 0);
  reconcileBeforeReceipt(malformed);
  const missing = await drive('missing_session', 'N3');
  assert.equal(missing.code, 2, missing.errText);
  assert.equal(missing.receipt.acceptance, false);
  assert.equal(missing.receipt.issuanceStatus, 'unresolved');
  assert.equal(missing.receipt.cleanupStatus, 'unresolved');
  assert.equal(
    missing.receipt.sessionLedger.some(
      (row) => row.passwordSessionId || row.sourceSessionId || row.bSessionId || row.authSessionId,
    ),
    false,
  );
  reconcileBeforeReceipt(missing);
});

test('a failed N8 row finalizes ambiguous issuance before the receipt', async () => {
  const result = await drive('ambiguous_n8', 'N8');
  assert.equal(result.code, 2, `${result.errText}\n${result.outText}`);
  assert.equal(result.receipt.acceptance, false);
  assert.equal(result.receipt.rowsPass, false);
  const n8 = result.receipt.rows.find((row) => row.id === 'N8');
  assert.equal(n8.executed, true);
  assert.equal(n8.pass, false);
  assert.equal(n8.label, 'n8_incomplete');
  const signed = n8.subcases.find((row) => row.id === 'signed_b_unbound');
  assert.equal(signed.executed, true);
  assert.equal(signed.pass, false);
  assert.notEqual(signed.reason, 'not_executed');
  assert.equal(result.receipt.issuanceStatus, 'unresolved');
  assert.equal(result.receipt.cleanupStatus, 'unresolved');
  assert.equal(result.receipt.restoreStatus, 'not_required');
  reconcileBeforeReceipt(result);
});

test('F1 qual matches local pg_policies.qual for the sql/06 expression', async () => {
  const baseline = 'baseline-a-client';
  const external = 'external-a-client';
  const sql06 = readFileSync(
    new URL('../docs/evidence/ari-test-probe/sql/06-ingress-client-rls.sql', import.meta.url),
    'utf8',
  );
  const sql01 = readFileSync(
    new URL('../docs/evidence/ari-test-probe/sql/01-synthetic-fixture.sql', import.meta.url),
    'utf8',
  );
  assert.equal(
    sql06.includes(
      "coalesce(auth.jwt() ->> 'client_id', '') is distinct from %L\n          and coalesce(auth.jwt() ->> 'client_id', '') is distinct from %L",
    ),
    true,
  );
  assert.equal(sql01.includes('using ((select auth.uid()) = owner_id);'), true);
  const db = new PGlite();
  await db.waitReady;
  await db.exec(`
    create schema auth;
    create function auth.jwt() returns jsonb language sql stable as $$
      select nullif(current_setting('request.jwt.claims', true), '')::jsonb
    $$;
    create function auth.uid() returns uuid language sql stable as $$
      select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid
    $$;
    create role authenticated nologin noinherit;
    create table public.ari_probe_marker (
      marker text primary key,
      owner_id uuid not null
    );
    create policy ari_probe_marker_owner_read
      on public.ari_probe_marker
      for select
      to authenticated
      using ((select auth.uid()) = owner_id);
    create policy ari_probe_marker_reject_a_client
      on public.ari_probe_marker
      as restrictive
      for select
      to authenticated
      using (
        coalesce(auth.jwt() ->> 'client_id', '') is distinct from '${baseline}'
        and coalesce(auth.jwt() ->> 'client_id', '') is distinct from '${external}'
      );
    create policy using_true
      on public.ari_probe_marker
      as restrictive
      for select
      to authenticated
      using (true);
    create policy using_false
      on public.ari_probe_marker
      as restrictive
      for select
      to authenticated
      using (false);
  `);
  const rows = await db.query(`
    select policyname, qual
    from pg_policies
    where schemaname = 'public' and tablename = 'ari_probe_marker'
  `);
  await db.close();
  const qual = Object.fromEntries(rows.rows.map((row) => [row.policyname, row.qual]));
  assert.equal(qual.ari_probe_marker_reject_a_client, canonicalF1Qual(baseline, external));
  assert.equal(qual.ari_probe_marker_owner_read, canonicalOwnerQual());
  assert.notEqual(qual.using_true, qual.using_false);
  assert.notEqual(qual.using_true, qual.ari_probe_marker_reject_a_client);
  assert.notEqual(qual.using_false, qual.ari_probe_marker_reject_a_client);
  assert.equal(
    canonicalF1Qual(external, baseline) === qual.ari_probe_marker_reject_a_client,
    false,
  );
});
