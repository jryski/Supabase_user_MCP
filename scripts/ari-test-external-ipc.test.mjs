import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer as createHttpServer, request as httpRequest } from 'node:http';
import { createServer as createHttpsServer, request as httpsRequest } from 'node:https';
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
import { childEnvironment, controllerGate, controllerPlan } from './run-ari-test-external-e2e.mjs';

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
    ARI_TEST_SYNTHETIC_PASSWORD: 'synthetic-password-parent-only',
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

function requestText(target, ca, init = {}) {
  const lib = target.protocol === 'https:' ? httpsRequest : httpRequest;
  return new Promise((resolve, reject) => {
    const req = lib(
      target,
      {
        ca,
        method: init.method ?? 'GET',
        headers: init.headers,
        rejectUnauthorized: true,
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const location = res.headers.location;
          resolve({
            status: res.statusCode ?? 0,
            location: Array.isArray(location) ? location[0] : location,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      },
    );
    req.on('error', reject);
    if (init.body !== undefined) req.write(init.body);
    req.end();
  });
}

async function freePort() {
  const probe = createHttpServer();
  await new Promise((resolve) => probe.listen(0, '127.0.0.1', () => resolve()));
  const address = probe.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  await new Promise((resolve) => probe.close(() => resolve()));
  return port;
}

test('CLI run completes SDK OAuth, B bind, and the marker call', { timeout: 60_000 }, async () => {
  const plantedToken = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.sig';
  const plantedPassword = 'synthetic-password-sentinel';
  const unusedPassword = 'different-password-must-not-be-used';
  const passwordSession = '55555555-5555-4555-8555-555555555555';
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
    authorize: 0,
    authorizeWithCode: 0,
    consentPost: 0,
    consentRejected: 0,
    codeIssued: 0,
    aExchange: 0,
    bExchange: 0,
    liveness: 0,
    marker: 0,
    markerUsedA: false,
    passwordLogin: 0,
  };
  let aLive = true;
  let bLive = true;
  const authorizations = new Map();
  const codes = new Map();
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
    const readChunks = () =>
      new Promise((resolve) => {
        const chunks = [];
        req.on('data', (chunk) => chunks.push(chunk));
        req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      });
    const bearerSession = () => {
      const header = req.headers.authorization ?? '';
      if (!header.startsWith('Bearer ')) return '';
      const payload = header.slice('Bearer '.length).split('.')[1];
      if (payload === undefined) return '';
      try {
        return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')).session_id ?? '';
      } catch {
        return '';
      }
    };
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
      const consentUrl = new URL('/oauth/consent', origin);
      consentUrl.searchParams.set('authorization_id', authorizationId);
      counts.authorize += 1;
      if (consentUrl.searchParams.has('code')) counts.authorizeWithCode += 1;
      res.writeHead(302, { location: consentUrl.toString(), 'cache-control': 'no-store' });
      res.end();
      return;
    }
    if (req.method === 'GET' && url.pathname === '/oauth/consent') {
      send(200, 'consent_ui_not_deployed', 'text/plain');
      return;
    }
    if (req.method === 'POST' && url.pathname === '/auth/v1/token') {
      void readChunks().then(async (raw) => {
        let parsed = {};
        try {
          parsed = JSON.parse(raw);
        } catch {
          parsed = {};
        }
        if (parsed.email !== SYNTHETIC_EMAIL || parsed.password !== plantedPassword) {
          send(400, JSON.stringify({ error: 'invalid_grant' }));
          return;
        }
        counts.passwordLogin += 1;
        const access = await new SignJWT({
          role: 'authenticated',
          session_id: passwordSession,
        })
          .setProtectedHeader({ alg: 'ES256', kid: 'g2-test', typ: 'JWT' })
          .setSubject(sub)
          .setIssuer(issuer)
          .setAudience('authenticated')
          .setIssuedAt()
          .setExpirationTime('5m')
          .sign(privateKey);
        send(200, JSON.stringify({ access_token: access, token_type: 'bearer', expires_in: 300 }));
      });
      return;
    }
    const authorizationMatch = url.pathname.match(/^\/auth\/v1\/oauth\/authorizations\/([^/]+)$/u);
    if (req.method === 'GET' && authorizationMatch) {
      if (bearerSession() !== passwordSession) {
        send(401, JSON.stringify({ error: 'unauthorized' }));
        return;
      }
      const authorizationId = decodeURIComponent(authorizationMatch[1] ?? '');
      if (!authorizations.has(authorizationId)) {
        send(404, JSON.stringify({ error: 'not_found' }));
        return;
      }
      send(200, JSON.stringify({ authorization_id: authorizationId }));
      return;
    }
    const consentMatch = url.pathname.match(
      /^\/auth\/v1\/oauth\/authorizations\/([^/]+)\/consent$/u,
    );
    if (req.method === 'POST' && consentMatch) {
      void readChunks().then((raw) => {
        if (bearerSession() !== passwordSession) {
          counts.consentRejected += 1;
          send(401, JSON.stringify({ error: 'unauthorized' }));
          return;
        }
        const authorizationId = decodeURIComponent(consentMatch[1] ?? '');
        const record = authorizations.get(authorizationId);
        let action = '';
        try {
          action = JSON.parse(raw).action ?? '';
        } catch {
          action = '';
        }
        if (record === undefined || action !== 'approve') {
          send(400, JSON.stringify({ error: 'invalid_request' }));
          return;
        }
        const code = randomBytes(16).toString('base64url');
        codes.set(code, { clientId: record.clientId, challenge: record.challenge });
        const redirect = new URL(record.redirect);
        redirect.searchParams.set('code', code);
        redirect.searchParams.set('state', record.state);
        counts.consentPost += 1;
        counts.codeIssued += 1;
        send(200, JSON.stringify({ redirect_url: redirect.toString() }));
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
          const record = codes.get(code);
          codes.delete(code);
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
      counts.liveness += 1;
      if (clientId === aClient) counts.markerUsedA = true;
      if (!bLive) {
        send(401, JSON.stringify({ error: 'session_not_found' }));
        return;
      }
      send(200, aLive ? 'true' : 'false');
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
  const preflightChallenge = createHash('sha256')
    .update('preflight-verifier-preflight-verifier')
    .digest('base64url');
  const preflight = new URL(`https://127.0.0.1:${httpsPort}/auth/v1/oauth/authorize`);
  preflight.searchParams.set('response_type', 'code');
  preflight.searchParams.set('client_id', aClient);
  preflight.searchParams.set('redirect_uri', `http://127.0.0.1:${mcpPort}/oauth/callback`);
  preflight.searchParams.set('code_challenge', preflightChallenge);
  preflight.searchParams.set('code_challenge_method', 'S256');
  preflight.searchParams.set('state', 'preflight');
  const preAuthorize = await requestText(preflight, ca);
  assert.equal(preAuthorize.status, 302);
  const preLocation = new URL(preAuthorize.location ?? 'http://127.0.0.1/');
  assert.equal(preLocation.searchParams.get('code'), null);
  assert.equal(typeof preLocation.searchParams.get('authorization_id'), 'string');
  const prePage = await requestText(preLocation, ca);
  assert.equal(prePage.status, 200);
  assert.equal(prePage.body.includes('code='), false);
  const preConsent = await requestText(
    new URL(
      `/auth/v1/oauth/authorizations/${preLocation.searchParams.get('authorization_id')}/consent`,
      `https://127.0.0.1:${httpsPort}`,
    ),
    ca,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ action: 'approve' }),
    },
  );
  assert.equal(preConsent.status, 401);
  assert.equal(counts.codeIssued, 0);
  assert.equal(counts.consentRejected, 1);

  const proc = spawn(process.execPath, ['scripts/run-ari-test-external-e2e.mjs', 'run'], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME ?? '/tmp',
      NODE_EXTRA_CA_CERTS: certPath,
      ARI_LANE_B_LIVE: 'controller-g5',
      ARI_LANE_B_EXECUTE: '1',
      ARI_LANE_B_G5_HEAD: head,
      ARI_LANE_B_TIMEOUT_MS: '25000',
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
      ARI_USER_PASSWORD: unusedPassword,
      ARI_TEST_SYNTHETIC_PASSWORD: plantedPassword,
    },
  });
  proc.stdin.on('error', () => undefined);
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
          timer = setTimeout(() => resolve(null), 25_000);
        }),
      ]).finally(() => clearTimeout(timer));
      assert.notEqual(
        line,
        null,
        `${Buffer.concat(stderr).toString('utf8')} counts=${JSON.stringify(counts)}`,
      );
      const message = JSON.parse(line);
      if (message.type === 'controller_action' && message.action === 'revoke_a_source_session') {
        assert.equal(message.source_session_id, source);
        assert.equal(message.authorizationUrl, undefined);
        assert.equal(message.code, undefined);
        aLive = false;
        proc.stdin.write('continue\n');
      } else if (message.type === 'controller_action' && message.action === 'revoke_b_session') {
        assert.equal(message.b_session_id, bSession);
        assert.equal(message.authorizationUrl, undefined);
        bLive = false;
        proc.stdin.write('continue\n');
      } else if (message.type === 'receipt') {
        receipt = message;
      } else {
        assert.fail(`unexpected stdout line ${message.type ?? message.action}`);
      }
    }
    let exitTimer;
    const [code] = await Promise.race([
      exited,
      new Promise((resolve) => {
        exitTimer = setTimeout(() => resolve([-1]), 5_000);
      }),
    ]).finally(() => clearTimeout(exitTimer));
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
    assert.equal(outText.includes(unusedPassword), false);
    assert.equal(outText.includes(refreshSentinel), false);
    assert.equal(outText.includes(publishable), false);
    assert.equal(errText.includes(plantedToken), false);
    assert.equal(errText.includes(plantedPassword), false);
    assert.equal(errText.includes(refreshSentinel), false);
    assert.equal(receipt.passwordSessionId, passwordSession);
    assert.equal(counts.authorizeWithCode, 0);
    assert.equal(counts.passwordLogin, 1);
    assert.equal(counts.consentPost, 3);
    assert.equal(counts.codeIssued, 3);
    assert.equal(counts.consentRejected, 1);
    assert.equal(counts.aExchange, 2);
    assert.equal(counts.bExchange, 1);
    assert.equal(counts.liveness >= 3, true);
    assert.equal(counts.marker, 1);
    assert.equal(counts.markerUsedA, false);
    const byId = Object.fromEntries(receipt.cases.map((row) => [row.id, row]));
    for (const id of ['P1', 'P2', 'P3', 'P4', 'P5', 'N1', 'N4', 'N5']) {
      assert.equal(byId[id].executed, true, id);
      assert.equal(byId[id].passed, true, id);
    }
    assert.equal(byId.P1.label, 'canary_shape');
    assert.equal(byId.P2.label, 'b_via_second_consent');
    assert.equal(byId.P5.label, 'marker_read');
    assert.equal(byId.N1.label, 'a_as_b');
    assert.equal(byId.N4.label, 'a_source_session_revocation');
    assert.equal(byId.N5.label, 'b_session_revocation');
    assert.equal(byId.N6.label, 'hook_bypass_f1');
    assert.equal(byId.N7.label, 'openid');
    assert.equal(byId.N8.label, 'unbound_mismatched_b');
    for (const id of ['N2', 'N3', 'N6', 'N7', 'N8']) {
      assert.equal(byId[id].executed, false, id);
      assert.equal(byId[id].passed, false, id);
      assert.equal(byId[id].note, 'not_executed_by_this_run', id);
    }
  } finally {
    if (proc.exitCode === null && proc.signalCode === null) proc.kill('SIGKILL');
    await exited.catch(() => undefined);
    https.closeAllConnections?.();
    https.unref();
    https.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
