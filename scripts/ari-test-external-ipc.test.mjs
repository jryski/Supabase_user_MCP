import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { tmpdir } from 'node:os';
import { createInterface } from 'node:readline';
import test from 'node:test';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { SYNTHETIC_EMAIL } from '../docs/evidence/ari-test-probe/decisions.mjs';
import {
  assertIpcHasNoSecrets,
  createExternalPublicPkceProvider,
  EXTERNAL_CLIENT_PROFILE,
  publishDownstreamAuthorization,
} from './ari-test-external-client.mjs';
import {
  childEnvironment,
  controllerGate,
  controllerPlan,
  isContinueLine,
} from './run-ari-test-external-e2e.mjs';

test('IPC refuses tokens and the provider does not register or keep refresh tokens', async () => {
  assert.throws(
    () => assertIpcHasNoSecrets({ access_token: 'header.payload.sig' }),
    /ipc_refused_secret/,
  );
  assert.throws(
    () => assertIpcHasNoSecrets({ note: 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.sig' }),
    /ipc_refused_secret/,
  );
  const lines = [];
  const provider = createExternalPublicPkceProvider({
    clientId: 'external-a-client',
    redirectUrl: 'http://127.0.0.1:8788/oauth/callback',
    writeIpc(line) {
      lines.push(line);
    },
    async readIpc() {
      throw new Error('redirect_must_not_consume_code');
    },
  });
  assert.equal('saveClientInformation' in provider, false);
  assert.equal(provider.clientInformation().client_id, 'external-a-client');
  assert.equal(provider.clientMetadata.token_endpoint_auth_method, 'none');
  assert.equal(provider.clientMetadata.scope, 'email');
  assert.equal(provider.clientMetadata.client_secret, undefined);
  assert.equal(provider.profile, EXTERNAL_CLIENT_PROFILE);
  provider.saveTokens({
    access_token: 'memory-access-token',
    refresh_token: 'refresh-must-drop',
    token_type: 'Bearer',
  });
  assert.deepEqual(provider.tokens(), {
    access_token: 'memory-access-token',
    token_type: 'Bearer',
  });
  assert.equal(JSON.stringify(provider.tokens()).includes('refresh-must-drop'), false);
  const url = new URL(`http://127.0.0.1:9999/authorize?state=${provider.state()}`);
  await provider.redirectToAuthorization(url);
  const message = JSON.parse(lines[0]);
  assert.equal(message.type, 'authorization_request');
  assert.equal(message.state, provider.state());
  assert.equal(message.authorizationUrl.includes('refresh'), false);
  const forwarded = [];
  assert.equal(
    publishDownstreamAuthorization(
      {
        error: 'downstream_authorization_required',
        authorization_url: 'http://127.0.0.1/auth?state=abc',
        state: 'abc',
        handshake_id: 'abc',
      },
      (line) => forwarded.push(line),
    ),
    true,
  );
  assert.equal(JSON.parse(forwarded[0]).handshakeId, 'abc');
  assert.equal(JSON.parse(forwarded[0]).access_token, undefined);
});

test('plan prints controller steps and run stays closed', async () => {
  const plan = controllerPlan();
  assert.equal(plan.executedByWriter, false);
  assert.equal(plan.hostedContact, false);
  assert.equal(plan.hookInstalled, false);
  assert.match(plan.steps.join('\n'), /STOP AND REPORT/);
  assert.match(plan.steps.join('\n'), /first-party session/);
  assert.match(plan.rollback.join('\n'), /ari-test-external-a/);
  assert.equal(controllerGate({}).ok, false);
  assert.equal(controllerGate({ ARI_LANE_B_LIVE: 'controller-g5' }).reason, 'project_ref_refused');
  assert.equal(
    controllerGate({
      ARI_LANE_B_LIVE: 'controller-g5',
      ARI_TEST_PROJECT_REF: 'odbcejsuuqdzhabjmozi',
      SUPABASE_SERVICE_ROLE_KEY: 'nope',
    }).reason,
    'service_role_refused',
  );

  const planRun = spawn(process.execPath, ['scripts/run-ari-test-external-e2e.mjs', 'plan'], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const planOut = [];
  planRun.stdout.on('data', (chunk) => planOut.push(chunk));
  const [planCode] = await once(planRun, 'exit');
  assert.equal(planCode, 0);
  const printed = JSON.parse(Buffer.concat(planOut).toString('utf8'));
  assert.equal(printed.hostedContact, false);

  const run = spawn(process.execPath, ['scripts/run-ari-test-external-e2e.mjs', 'run'], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const runErr = [];
  run.stderr.on('data', (chunk) => runErr.push(chunk));
  const [runCode] = await once(run, 'exit');
  assert.equal(runCode, 2);
  assert.match(Buffer.concat(runErr).toString('utf8'), /live_gate_closed/);
});

test('child environment drops bearers and execute stays closed without the opt-in', async () => {
  const filtered = childEnvironment({
    PATH: '/usr/bin',
    ARI_EXTERNAL_MCP_URL: 'http://127.0.0.1:9/mcp',
    ARI_LANE_B_EXECUTE: '0',
    ARI_FIRST_PARTY_ACCESS_TOKEN: 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.sig',
    ARI_USER_PASSWORD: 'synthetic-password-sentinel',
    ARI_TEST_SYNTHETIC_PASSWORD: 'synthetic-password-sentinel',
    ARI_TEST_PUBLISHABLE_KEY: 'sb_publishable_parent_only_sentinel',
    ARI_TEST_JWKS_JSON: '{"keys":[]}',
    SUPABASE_SERVICE_ROLE_KEY: 'nope',
  });
  assert.equal(filtered.ARI_LANE_B_EXECUTE, '1');
  assert.equal(filtered.ARI_LANE_B_LIVE, 'controller-g5');
  assert.equal(filtered.ARI_EXTERNAL_MCP_URL, 'http://127.0.0.1:9/mcp');
  assert.equal(filtered.ARI_FIRST_PARTY_ACCESS_TOKEN, undefined);
  assert.equal(filtered.ARI_USER_PASSWORD, undefined);
  assert.equal(filtered.ARI_TEST_SYNTHETIC_PASSWORD, undefined);
  assert.equal(filtered.ARI_TEST_PUBLISHABLE_KEY, undefined);
  assert.equal(filtered.ARI_TEST_JWKS_JSON, undefined);
  assert.equal(filtered.SUPABASE_SERVICE_ROLE_KEY, undefined);

  const closed = spawn(process.execPath, ['scripts/run-ari-test-external-e2e.mjs', 'run'], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      PATH: process.env.PATH,
      ARI_LANE_B_LIVE: 'controller-g5',
      ARI_TEST_PROJECT_REF: 'odbcejsuuqdzhabjmozi',
      ARI_LANE_B_G5_HEAD: 'a'.repeat(40),
      ARI_EXTERNAL_MCP_URL: 'http://127.0.0.1:9/mcp',
    },
  });
  const closedErr = [];
  closed.stderr.on('data', (chunk) => closedErr.push(chunk));
  const [closedCode] = await once(closed, 'exit');
  assert.equal(closedCode, 2);
  assert.match(Buffer.concat(closedErr).toString('utf8'), /live_runtime_not_started/);

  const child = spawn(process.execPath, ['scripts/ari-test-external-client.mjs'], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      PATH: process.env.PATH,
      ARI_LANE_B_LIVE: 'controller-g5',
    },
  });
  const childErr = [];
  child.stderr.on('data', (chunk) => childErr.push(chunk));
  const [childCode] = await once(child, 'exit');
  assert.equal(childCode, 2);
  assert.match(
    Buffer.concat(childErr).toString('utf8'),
    /external client live connect is a controller step after G5/,
  );
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

test('continue is the only stdin line the parent accepts', () => {
  assert.equal(isContinueLine('continue'), true);
  assert.equal(isContinueLine('continue\n'), false);
  assert.equal(isContinueLine(' continue'), false);
  assert.equal(isContinueLine('eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.sig'), false);
  assert.equal(isContinueLine('synthetic-password-sentinel'), false);
});

async function freePort() {
  const probe = createHttpServer();
  await new Promise((resolve) => probe.listen(0, '127.0.0.1', () => resolve()));
  const address = probe.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  await new Promise((resolve) => probe.close(() => resolve()));
  return port;
}

test('CLI run completes SDK OAuth, B bind, and the marker call', { timeout: 40_000 }, async () => {
  const plantedToken = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.sig';
  const plantedPassword = 'synthetic-password-sentinel';
  const refreshSentinel = 'refresh-sentinel-must-not-leak';
  const publishable = 'sb_publishable_parent_only_sentinel';
  const aClient = 'external-a-client';
  const bClient = 'downstream-b-client';
  const agent = 'hook-only-agent';
  const sub = '11111111-1111-4111-8111-111111111111';
  const source = '22222222-2222-4222-8222-222222222222';
  const decoy = '44444444-4444-4444-8444-444444444444';
  const bSession = '33333333-3333-4333-8333-333333333333';
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  const jwks = { keys: [{ ...jwk, kid: 'g2-test', alg: 'ES256', use: 'sig' }] };
  const dir = mkdtempSync(`${tmpdir()}/ari-lane-b-`);
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
  const ca = readFileSync(certPath);
  const counts = {
    aExchange: 0,
    bExchange: 0,
    liveness: 0,
    livenessDenied: 0,
    marker: 0,
    markerUsedA: false,
    consentPosts: 0,
    passwordLogins: 0,
    authorizeWithCode: 0,
  };
  const pending = new Map();
  const authorizations = new Map();
  const revokedSources = new Set();
  const revokedBSessions = new Set();
  let passwordToken = '';
  const passwordSessionId = '66666666-6666-4666-8666-666666666666';
  const mcpPort = await freePort();
  const mcpResource = `http://127.0.0.1:${mcpPort}/mcp`;
  const https = createHttpsServer({ cert: ca, key: readFileSync(keyPath) }, (req, res) => {
    const url = new URL(req.url ?? '/', 'https://127.0.0.1');
    const origin = `https://127.0.0.1:${https.address().port}`;
    const issuer = `${origin}/auth/v1`;
    const send = (status, body, type = 'application/json') => {
      res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store' });
      res.end(body);
    };
    if (
      req.method === 'GET' &&
      url.pathname === '/.well-known/oauth-authorization-server/auth/v1'
    ) {
      send(
        200,
        JSON.stringify({
          issuer,
          authorization_endpoint: `${origin}/auth/v1/oauth/authorize`,
          token_endpoint: `${origin}/auth/v1/oauth/token`,
          response_types_supported: ['code'],
          grant_types_supported: ['authorization_code'],
          code_challenge_methods_supported: ['S256'],
          token_endpoint_auth_methods_supported: ['none'],
          scopes_supported: ['email'],
        }),
      );
      return;
    }
    if (req.method === 'GET' && url.pathname === '/auth/v1/oauth/authorize') {
      let redirectUrl;
      try {
        redirectUrl = new URL(url.searchParams.get('redirect_uri') ?? '');
      } catch {
        send(400, JSON.stringify({ error: 'invalid_request' }));
        return;
      }
      const challenge = url.searchParams.get('code_challenge') ?? '';
      if (
        redirectUrl.hostname !== '127.0.0.1' ||
        url.searchParams.get('code_challenge_method') !== 'S256' ||
        challenge.length < 20
      ) {
        send(400, JSON.stringify({ error: 'invalid_request' }));
        return;
      }
      const authorizationId = randomBytes(16).toString('base64url');
      authorizations.set(authorizationId, {
        clientId: url.searchParams.get('client_id') ?? '',
        challenge,
        redirect: redirectUrl.toString(),
        state: url.searchParams.get('state') ?? '',
      });
      const location = `${origin}/oauth/consent?authorization_id=${authorizationId}`;
      if (location.includes('code=')) counts.authorizeWithCode += 1;
      res.writeHead(302, { location, 'cache-control': 'no-store' });
      res.end();
      return;
    }
    if (req.method === 'GET' && url.pathname === '/oauth/consent') {
      send(200, 'consent-ui-not-deployed', 'text/html');
      return;
    }
    const authorizationPath = url.pathname.match(
      /^\/auth\/v1\/oauth\/authorizations\/([^/]+)(\/consent)?$/u,
    );
    if (authorizationPath) {
      const authorizationId = decodeURIComponent(authorizationPath[1] ?? '');
      const bearer = req.headers.authorization ?? '';
      if (passwordToken.length === 0 || bearer !== `Bearer ${passwordToken}`) {
        send(401, JSON.stringify({ error: 'unauthorized' }));
        return;
      }
      if (req.method === 'GET' && authorizationPath[2] === undefined) {
        if (!authorizations.has(authorizationId)) {
          send(404, JSON.stringify({ error: 'not_found' }));
          return;
        }
        send(200, JSON.stringify({ authorization_id: authorizationId }));
        return;
      }
      if (req.method === 'POST' && authorizationPath[2] === '/consent') {
        const chunks = [];
        req.on('data', (chunk) => chunks.push(chunk));
        req.on('end', () => {
          const record = authorizations.get(authorizationId);
          let action = '';
          try {
            action = JSON.parse(Buffer.concat(chunks).toString('utf8')).action ?? '';
          } catch {
            action = '';
          }
          if (record === undefined || action !== 'approve') {
            send(400, JSON.stringify({ error: 'invalid_request' }));
            return;
          }
          const code = randomBytes(16).toString('base64url');
          pending.set(code, { clientId: record.clientId, challenge: record.challenge });
          counts.consentPosts += 1;
          const redirectUrl = new URL(record.redirect);
          redirectUrl.searchParams.set('code', code);
          redirectUrl.searchParams.set('state', record.state);
          send(200, JSON.stringify({ redirect_url: redirectUrl.toString() }));
        });
        return;
      }
      send(400, JSON.stringify({ error: 'invalid_request' }));
      return;
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
          if (body.email !== SYNTHETIC_EMAIL || body.password !== plantedPassword) {
            send(400, JSON.stringify({ error: 'invalid_grant' }));
            return;
          }
          passwordToken = await new SignJWT({
            role: 'authenticated',
            session_id: passwordSessionId,
          })
            .setProtectedHeader({ alg: 'ES256', kid: 'g2-test', typ: 'JWT' })
            .setSubject(sub)
            .setIssuer(issuer)
            .setAudience('authenticated')
            .setIssuedAt()
            .setExpirationTime('2m')
            .sign(privateKey);
          counts.passwordLogins += 1;
          send(200, JSON.stringify({ access_token: passwordToken, token_type: 'bearer' }));
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
          const code = form.get('code') ?? '';
          const record = pending.get(code);
          pending.delete(code);
          const digest = createHash('sha256')
            .update(form.get('code_verifier') ?? '')
            .digest('base64url');
          if (
            record === undefined ||
            digest !== record.challenge ||
            form.get('client_id') !== record.clientId
          ) {
            send(400, JSON.stringify({ error: 'invalid_grant' }));
            return;
          }
          const tokenA = record.clientId === aClient;
          if (tokenA) counts.aExchange += 1;
          if (record.clientId === bClient) counts.bExchange += 1;
          const access = await new SignJWT(
            tokenA
              ? {
                  role: 'mcp_ingress',
                  client_id: aClient,
                  session_id: decoy,
                  source_session_id: source,
                  agent_id: agent,
                }
              : {
                  role: 'authenticated',
                  client_id: bClient,
                  session_id: bSession,
                  agent_id: agent,
                },
          )
            .setProtectedHeader({ alg: 'ES256', kid: 'g2-test', typ: 'JWT' })
            .setSubject(sub)
            .setIssuer(issuer)
            .setAudience(tokenA ? mcpResource : 'authenticated')
            .setIssuedAt()
            .setExpirationTime('2m')
            .sign(privateKey);
          send(
            200,
            JSON.stringify({
              access_token: access,
              token_type: 'Bearer',
              expires_in: 120,
              refresh_token: refreshSentinel,
            }),
          );
        })();
      });
      return;
    }
    const bearer = req.headers.authorization ?? '';
    const payload = bearer.split('.')[1];
    let clientId = '';
    if (payload !== undefined) {
      try {
        clientId = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')).client_id ?? '';
      } catch {
        clientId = '';
      }
    }
    if (req.method === 'POST' && url.pathname === '/rest/v1/rpc/ari_probe_source_session_live_v1') {
      const chunks = [];
      req.on('data', (chunk) => chunks.push(chunk));
      req.on('end', () => {
        counts.liveness += 1;
        if (clientId === aClient) counts.markerUsedA = true;
        let sourceSessionId = '';
        try {
          sourceSessionId =
            JSON.parse(Buffer.concat(chunks).toString('utf8')).source_session_id ?? '';
        } catch {
          sourceSessionId = '';
        }
        let bSessionId = '';
        if (payload !== undefined) {
          try {
            bSessionId =
              JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')).session_id ?? '';
          } catch {
            bSessionId = '';
          }
        }
        if (revokedSources.has(sourceSessionId) || revokedBSessions.has(bSessionId)) {
          counts.livenessDenied += 1;
          send(200, 'false');
          return;
        }
        send(200, 'true');
      });
      return;
    }
    if (req.method === 'GET' && url.pathname === '/auth/v1/user') {
      send(200, JSON.stringify({ id: sub, aud: 'authenticated' }));
      return;
    }
    if (req.method === 'GET' && url.pathname === '/rest/v1/ari_probe_marker') {
      counts.marker += 1;
      if (clientId === aClient) counts.markerUsedA = true;
      send(200, JSON.stringify([{ marker: 'ari-probe-marker-odbcejsuuqdzhabjmozi' }]));
      return;
    }
    send(404, JSON.stringify({ error: 'not_found' }));
  });
  await new Promise((resolve) => https.listen(0, '127.0.0.1', () => resolve()));
  const httpsPort = https.address().port;
  const head = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  const proc = spawn(process.execPath, ['scripts/run-ari-test-external-e2e.mjs', 'run'], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME ?? '/tmp',
      NODE_EXTRA_CA_CERTS: certPath,
      ARI_LANE_B_LIVE: 'controller-g5',
      ARI_LANE_B_EXECUTE: '1',
      ARI_LANE_B_G5_HEAD: head,
      ARI_LANE_B_TIMEOUT_MS: '20000',
      ARI_TEST_PROJECT_REF: 'odbcejsuuqdzhabjmozi',
      ARI_TEST_SUPABASE_URL: `https://127.0.0.1:${httpsPort}`,
      ARI_TEST_PUBLISHABLE_KEY: publishable,
      ARI_TEST_JWKS_JSON: JSON.stringify(jwks),
      ARI_EXTERNAL_MCP_URL: mcpResource,
      ARI_EXTERNAL_A_CLIENT_ID: aClient,
      ARI_EXTERNAL_A_REDIRECT_URI: `http://127.0.0.1:${mcpPort}/oauth/callback`,
      ARI_DOWNSTREAM_CLIENT_ID: bClient,
      ARI_DOWNSTREAM_REDIRECT_URI: `http://127.0.0.1:${mcpPort}/oauth/downstream/callback`,
      ARI_AGENT_ID: agent,
      ARI_FIRST_PARTY_ACCESS_TOKEN: plantedToken,
      ARI_USER_PASSWORD: plantedPassword,
      ARI_TEST_SYNTHETIC_PASSWORD: plantedPassword,
    },
  });
  const stderr = [];
  proc.stderr.on('data', (chunk) => stderr.push(chunk));
  const exited = once(proc, 'exit');
  const reader = stdoutLines(proc.stdout);
  let receipt;
  try {
    while (receipt === undefined) {
      let timer;
      const line = await Promise.race([
        reader.next(),
        new Promise((resolve) => {
          timer = setTimeout(() => resolve(null), 20_000);
        }),
      ]);
      clearTimeout(timer);
      assert.notEqual(line, null, Buffer.concat(stderr).toString('utf8'));
      const message = JSON.parse(line);
      if (message.type === 'controller_action') {
        assert.equal(message.authorizationUrl, undefined);
        assert.equal(message.code, undefined);
        if (message.action === 'revoke_a_source_session') {
          assert.equal(message.source_session_id, source);
          revokedSources.add(message.source_session_id);
          proc.stdin.write('continue\n');
        } else if (message.action === 'revoke_b_session') {
          assert.equal(message.b_session_id, bSession);
          revokedBSessions.add(message.b_session_id);
          proc.stdin.write('continue\n');
        } else {
          assert.fail(`unexpected action ${message.action}`);
        }
      } else if (message.type === 'receipt') {
        receipt = message;
      } else {
        assert.fail(`unexpected stdout line ${message.type}`);
      }
    }
    const [code] = await exited;
    const errText = Buffer.concat(stderr).toString('utf8');
    const outText = JSON.stringify(receipt);
    assert.equal(code, 0, errText);
    assert.equal(receipt.acceptance, false);
    assert.equal(receipt.hostedContact, false);
    assert.equal(receipt.hookInstalled, false);
    assert.equal(receipt.executedByWriter, false);
    assert.equal(receipt.syntheticLoopback, true);
    assert.equal(receipt.initialized, true);
    assert.equal(receipt.toolsListed, true);
    assert.equal(receipt.markerCalled, true);
    assert.equal(receipt.downstreamBound, true);
    assert.equal(receipt.externalAuthorizationCompleted, true);
    assert.equal(receipt.toolNames.includes('ari_test_marker_get'), true);
    assert.equal(receipt.passwordSessionId, passwordSessionId);
    assert.equal(receipt.rowsPass, true);
    assert.equal(receipt.markerReads, 1);
    const byId = Object.fromEntries(receipt.rows.map((row) => [row.id, row]));
    for (const id of ['P1', 'P2', 'P3', 'P4', 'P5', 'N1', 'N4', 'N5']) {
      assert.equal(byId[id].executed, true, id);
      assert.equal(byId[id].pass, true, id);
    }
    assert.equal(byId.P1.name, 'canary_shape');
    assert.equal(byId.P2.name, 'b_via_second_consent');
    assert.equal(byId.P3.name, 'discovery_initialize');
    assert.equal(byId.P4.name, 'list_tools');
    assert.equal(byId.P5.name, 'marker_read');
    assert.equal(byId.N1.name, 'a_as_b');
    assert.equal(byId.N4.name, 'a_source_session_revocation');
    assert.equal(byId.N5.name, 'b_session_revocation');
    for (const id of ['N2', 'N3', 'N6', 'N7', 'N8']) {
      assert.equal(byId[id].executed, false, id);
      assert.equal(byId[id].pass, false, id);
      assert.equal(byId[id].label, 'not_executed', id);
    }
    assert.equal(byId.N2.name, 'wrong_user');
    assert.equal(byId.N3.name, 'wrong_agent_client_resource');
    assert.equal(byId.N6.name, 'hook_bypass_f1');
    assert.equal(byId.N7.name, 'openid');
    assert.equal(byId.N8.name, 'unbound_mismatched_b');
    for (const name of [
      'ARI_FIRST_PARTY_ACCESS_TOKEN',
      'ARI_USER_PASSWORD',
      'ARI_TEST_SYNTHETIC_PASSWORD',
      'ARI_TEST_PUBLISHABLE_KEY',
      'ARI_TEST_JWKS_JSON',
      'SUPABASE_SERVICE_ROLE_KEY',
    ]) {
      assert.equal(receipt.childEnvNames.includes(name), false);
    }
    assert.equal(outText.includes(plantedToken), false);
    assert.equal(outText.includes(plantedPassword), false);
    assert.equal(outText.includes(passwordToken), false);
    assert.equal(outText.includes(refreshSentinel), false);
    assert.equal(outText.includes(publishable), false);
    assert.equal(errText.includes(plantedToken), false);
    assert.equal(errText.includes(refreshSentinel), false);
    assert.equal(counts.aExchange, 1);
    assert.equal(counts.bExchange, 1);
    assert.equal(counts.passwordLogins, 1);
    assert.equal(counts.consentPosts, 2);
    assert.equal(counts.authorizeWithCode, 0);
    assert.equal(counts.livenessDenied >= 2, true);
    assert.equal(counts.marker, 1);
    assert.equal(counts.markerUsedA, false);
  } finally {
    if (proc.exitCode === null && proc.signalCode === null) proc.kill('SIGKILL');
    await exited.catch(() => undefined);
    https.closeAllConnections?.();
    await new Promise((resolve) => https.close(() => resolve()));
    rmSync(dir, { recursive: true, force: true });
  }
});
