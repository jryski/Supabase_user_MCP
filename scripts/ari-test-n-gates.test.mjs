import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { mkdtempSync, readFileSync } from 'node:fs';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { tmpdir } from 'node:os';
import { createInterface } from 'node:readline';
import test from 'node:test';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

import { SYNTHETIC_EMAIL } from '../docs/evidence/ari-test-probe/decisions.mjs';
import {
  classifyMarkerProbe,
  crossUserPass,
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
  const hash = hookManifestHash({
    enabled: true,
    function: 'ari_probe.custom_access_token_hook',
    projectRef: 'odbcejsuuqdzhabjmozi',
    resource: 'http://127.0.0.1:9/mcp',
    agentId: AGENT,
    externalClientId: A_CLIENT,
    baselineClientId: 'baseline-a-client',
  });
  assert.equal(hash.length, 64);
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
  const seen = { authorize: [], exchange: [], marker: [], emails: [], forbidden: 0 };
  const authorizations = new Map();
  const pending = new Map();
  const sessions = new Map();
  const remembered = new Set();
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
        const consentKey = `${user.sub}:${record.clientId}`;
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
                  ? { sub: USER2 }
                  : undefined;
            if (user === undefined) {
              send(400, JSON.stringify({ error: 'invalid_grant' }));
              return;
            }
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
            if ((record.scope ?? '').includes('openid')) {
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
            const tokenA = record.clientId === A_CLIENT;
            const claims = tokenA
              ? hookEnabled
                ? {
                    role: 'mcp_ingress',
                    client_id: A_CLIENT,
                    session_id: randomUUID(),
                    source_session_id: randomUUID(),
                    agent_id: AGENT,
                  }
                : { role: 'authenticated', client_id: A_CLIENT, session_id: randomUUID() }
              : {
                  role: 'authenticated',
                  client_id: B_CLIENT,
                  session_id: randomUUID(),
                  agent_id: AGENT,
                };
            const access = await new SignJWT(claims)
              .setProtectedHeader({ alg: 'ES256', kid: 'g2-test', typ: 'JWT' })
              .setSubject(record.sub ?? USER1)
              .setIssuer(issuer)
              .setAudience(tokenA && hookEnabled ? (record.resource ?? '') : 'authenticated')
              .setIssuedAt()
              .setExpirationTime('5m')
              .sign(privateKey);
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
        if (url.search !== '?select=marker') {
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
        if (clientId === A_CLIENT) {
          send(200, '[]');
          return;
        }
        if (clientId === B_CLIENT) {
          send(200, JSON.stringify([{ marker: 'ari-probe-marker-odbcejsuuqdzhabjmozi' }]));
          return;
        }
        send(401, JSON.stringify({ error: 'unauthorized' }));
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

async function drive(mode, gates) {
  const issuer = await startIssuer(mode);
  const mcpPort = await freePort();
  const mcpResource = `http://127.0.0.1:${mcpPort}/mcp`;
  const head = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  const manifest = {
    enabled: true,
    function: 'ari_probe.custom_access_token_hook',
    projectRef: 'odbcejsuuqdzhabjmozi',
    resource: mcpResource,
    agentId: AGENT,
    externalClientId: A_CLIENT,
    baselineClientId: 'baseline-a-client',
  };
  const hash = hookManifestHash(manifest);
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
      ARI_LANE_B_TIMEOUT_MS: mode === 'hang-a-marker' ? '1000' : '20000',
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
  try {
    while (receipt === undefined) {
      let timer;
      const line = await Promise.race([
        reader.next(),
        new Promise((resolve) => {
          timer = setTimeout(() => resolve(null), mode === 'hang-a-marker' ? 20_000 : 60_000);
        }),
      ]);
      clearTimeout(timer);
      if (line === null) break;
      stdoutText.push(line);
      const message = JSON.parse(line);
      if (message.type === 'controller_action') {
        actions.push(message.action);
        assert.equal(JSON.stringify(message).includes(PASSWORD), false);
        assert.equal(JSON.stringify(message).includes(PASSWORD2), false);
        assert.equal(JSON.stringify(message).includes(REFRESH), false);
        if (message.action === 'capture_hook_manifest') {
          proc.stdin.write(
            `${JSON.stringify({
              type: 'readback',
              hookManifest: manifest,
              f1Policy: 'ari_probe_marker_reject_a_client',
              mappingReady: true,
            })}\n`,
          );
        } else if (message.action === 'disable_current_hook') {
          assert.equal(message.hookHash, hash);
          issuer.setHook(false);
          proc.stdin.write(
            `${JSON.stringify({ type: 'readback', hookEnabled: false, hookHash: hash, function: manifest.function })}\n`,
          );
        } else if (message.action === 'restore_hook_configuration') {
          assert.equal(message.hookHash, hash);
          issuer.setHook(true);
          proc.stdin.write(
            `${JSON.stringify({ type: 'readback', hookEnabled: true, hookHash: hash, function: manifest.function })}\n`,
          );
        } else {
          proc.stdin.write('continue\n');
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
      head,
    };
  } finally {
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
    result.seen.marker.every((search) => search === '?select=marker'),
    true,
  );
  assert.deepEqual(result.actions, [
    'prepare_second_synthetic_user',
    'delete_second_synthetic_user',
    'capture_hook_manifest',
    'disable_current_hook',
    'cleanup_sessions',
    'restore_hook_configuration',
    'cleanup_sessions',
  ]);
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
});
