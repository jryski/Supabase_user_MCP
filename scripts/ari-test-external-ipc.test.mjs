import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { tmpdir } from 'node:os';
import { createInterface } from 'node:readline';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { SYNTHETIC_EMAIL } from '../docs/evidence/ari-test-probe/decisions.mjs';
import {
  assertIpcHasNoSecrets,
  createExternalPublicPkceProvider,
  EXTERNAL_CLIENT_PROFILE,
  projectChildFailure,
  publishDownstreamAuthorization,
} from './ari-test-external-client.mjs';
import {
  applyControllerRevocation,
  childEnvironment,
  controllerGate,
  controllerPlan,
  isContinueLine,
  revocationRowPass,
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
  assert.match(plan.steps.join('\n'), /fresh A\/B pair/);
  assert.match(plan.steps.join('\n'), /sessionLedger/);
  assert.match(plan.steps.join('\n'), /npm run build/);
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
      ARI_LANE_B_G5_HEAD: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
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

test('G5 gate requires the reviewed head to equal the actual clean head', () => {
  const reviewed = 'a'.repeat(40);
  const actual = 'b'.repeat(40);
  const env = {
    ARI_LANE_B_LIVE: 'controller-g5',
    ARI_TEST_PROJECT_REF: 'odbcejsuuqdzhabjmozi',
    ARI_LANE_B_G5_HEAD: reviewed,
  };
  assert.equal(
    controllerGate(env, { actualHead: actual, trackedDirty: false }).reason,
    'g5_head_mismatch',
  );
  assert.equal(
    controllerGate(env, { actualHead: reviewed, trackedDirty: true }).reason,
    'g5_worktree_dirty',
  );
  const open = controllerGate(
    { ...env, ARI_LANE_B_G5_HEAD: reviewed },
    { actualHead: reviewed, trackedDirty: false },
  );
  assert.equal(open.ok, true);
  assert.equal(open.actualHead, reviewed);
  assert.equal(open.reviewedHead, reviewed);
});

test('opposite-state contamination fails the wrong revocation row', () => {
  const a1 = '22222222-2222-4222-8222-222222222222';
  const b1 = '33333333-3333-4333-8333-333333333333';
  const a2 = '55555555-5555-4555-8555-555555555555';
  const b2 = '77777777-7777-4777-8777-777777777777';
  const stranger = '88888888-8888-4888-8888-888888888888';
  const store = {
    sessions: [
      { id: a1, userEmail: SYNTHETIC_EMAIL, refreshRows: 2, notAfter: null },
      { id: b1, userEmail: SYNTHETIC_EMAIL, refreshRows: 1, notAfter: null },
      { id: a2, userEmail: SYNTHETIC_EMAIL, refreshRows: 1, notAfter: null },
      { id: b2, userEmail: SYNTHETIC_EMAIL, refreshRows: 0, notAfter: null },
      { id: stranger, userEmail: 'other@example.com', refreshRows: 1, notAfter: null },
    ],
  };
  const n4 = applyControllerRevocation(store, {
    action: 'revoke_a_source_session',
    source_session_id: a1,
    b_session_id: b1,
  });
  assert.equal(n4.continue, true);
  assert.equal(n4.receipt.targetSessionId, a1);
  assert.equal(n4.receipt.targetSessionRows, 0);
  assert.equal(n4.receipt.targetRefreshRows, 0);
  assert.equal(n4.receipt.oppositeSessionId, b1);
  assert.equal(n4.receipt.oppositeSessionRows, 1);
  assert.equal(n4.receipt.oppositeLive, true);
  assert.equal(
    n4.sessions.some((row) => row.id === a1),
    false,
  );
  assert.equal(
    n4.sessions.some((row) => row.id === b1),
    true,
  );
  assert.equal(JSON.stringify(n4.receipt).includes('Bearer'), false);
  assert.equal(
    revocationRowPass({
      row: 'N4',
      sourceSessionId: a1,
      bSessionId: b1,
      livenessDenied: true,
      markerUnchanged: true,
      sourceLive: false,
      bLive: true,
      priorSourceSessionIds: [],
    }),
    true,
  );
  const n4Opposite = revocationRowPass({
    row: 'N4',
    sourceSessionId: a1,
    bSessionId: b1,
    livenessDenied: true,
    markerUnchanged: true,
    sourceLive: true,
    bLive: false,
    priorSourceSessionIds: [],
  });
  assert.equal(n4Opposite, false);
  const contaminated = {
    sessions: store.sessions.filter((row) => row.id !== b1),
  };
  const n4MissingB = applyControllerRevocation(contaminated, {
    action: 'revoke_a_source_session',
    source_session_id: a1,
    b_session_id: b1,
  });
  assert.equal(n4MissingB.continue, false);
  assert.equal(n4MissingB.receipt.oppositeLive, false);
  assert.equal(
    n4MissingB.sessions.some((row) => row.id === a1),
    true,
  );
  const n5SameSource = revocationRowPass({
    row: 'N5',
    sourceSessionId: a1,
    bSessionId: b1,
    livenessDenied: true,
    markerUnchanged: true,
    sourceLive: false,
    bLive: true,
    priorSourceSessionIds: [a1],
  });
  assert.equal(n5SameSource, false);
  const n5 = applyControllerRevocation(store, {
    action: 'revoke_b_session',
    source_session_id: a2,
    b_session_id: b2,
  });
  assert.equal(n5.continue, true);
  assert.equal(n5.receipt.targetSessionRows, 0);
  assert.equal(n5.receipt.targetRefreshRows, 0);
  assert.equal(n5.receipt.oppositeSessionId, a2);
  assert.equal(n5.receipt.oppositeLive, true);
  assert.equal(
    n5.sessions.some((row) => row.id === a2),
    true,
  );
  assert.equal(
    revocationRowPass({
      row: 'N5',
      sourceSessionId: a2,
      bSessionId: b2,
      livenessDenied: true,
      markerUnchanged: true,
      sourceLive: true,
      bLive: false,
      priorSourceSessionIds: [a1],
    }),
    true,
  );
  const n5Opposite = revocationRowPass({
    row: 'N5',
    sourceSessionId: a2,
    bSessionId: b2,
    livenessDenied: true,
    markerUnchanged: true,
    sourceLive: false,
    bLive: true,
    priorSourceSessionIds: [a1],
  });
  assert.equal(n5Opposite, false);
  const guarded = applyControllerRevocation(store, {
    action: 'revoke_a_source_session',
    source_session_id: stranger,
    b_session_id: b2,
  });
  assert.equal(guarded.continue, false);
  assert.equal(guarded.reason, 'synthetic_user_guard');
  assert.equal(
    guarded.sessions.some((row) => row.id === stranger),
    true,
  );
});

const PARENT_SCRIPT = fileURLToPath(new URL('./run-ari-test-external-e2e.mjs', import.meta.url));

function initTrackedRepo() {
  const repo = mkdtempSync(`${tmpdir()}/ari-g5-`);
  execFileSync('git', ['init'], { cwd: repo, stdio: 'ignore' });
  execFileSync('git', ['config', 'user.email', 'g5-fixture@example.com'], { cwd: repo });
  execFileSync('git', ['config', 'user.name', 'g5-fixture'], { cwd: repo });
  writeFileSync(`${repo}/integration.txt`, 'tracked\n');
  execFileSync('git', ['add', 'integration.txt'], { cwd: repo, stdio: 'ignore' });
  execFileSync('git', ['-c', 'commit.gpgsign=false', 'commit', '-m', 'tracked integration file'], {
    cwd: repo,
    stdio: 'ignore',
  });
  const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8' }).trim();
  return { repo, head };
}

async function refuseRun(repo, head) {
  const proc = spawn(process.execPath, [PARENT_SCRIPT, 'run'], {
    cwd: repo,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      PATH: process.env.PATH,
      ARI_LANE_B_LIVE: 'controller-g5',
      ARI_LANE_B_EXECUTE: '1',
      ARI_TEST_PROJECT_REF: 'odbcejsuuqdzhabjmozi',
      ARI_LANE_B_G5_HEAD: head,
    },
  });
  const stderr = [];
  proc.stderr.on('data', (chunk) => stderr.push(chunk));
  const [code] = await once(proc, 'exit');
  return { code, stderr: Buffer.concat(stderr).toString('utf8') };
}

test('wrong G5 head and a dirty tracked integration file are refused', async () => {
  const { repo, head } = initTrackedRepo();
  try {
    const wrong = head.startsWith('a') ? 'b'.repeat(40) : 'a'.repeat(40);
    assert.match(wrong, /^[0-9a-f]{40}$/);
    assert.notEqual(wrong, head);
    const mismatched = await refuseRun(repo, wrong);
    assert.equal(mismatched.code, 2);
    assert.match(mismatched.stderr, /g5_head_mismatch/);
    writeFileSync(`${repo}/integration.txt`, 'tracked\ndirty\n');
    const dirty = await refuseRun(repo, head);
    assert.equal(dirty.code, 2);
    assert.match(dirty.stderr, /g5_worktree_dirty/);
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
});

async function freePort() {
  const probe = createHttpServer();
  await new Promise((resolve) => probe.listen(0, '127.0.0.1', () => resolve()));
  const address = probe.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  await new Promise((resolve) => probe.close(() => resolve()));
  return port;
}

async function runSyntheticLaneB(mode, inject) {
  const plantedToken = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.sig';
  const plantedPassword = 'synthetic-password-sentinel';
  const refreshSentinel = 'refresh-sentinel-must-not-leak';
  const publishable = 'sb_publishable_parent_only_sentinel';
  const aClient = 'external-a-client';
  const bClient = 'downstream-b-client';
  const agent = 'hook-only-agent';
  const sub = '11111111-1111-4111-8111-111111111111';
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
    alreadyConsentedGets: 0,
    passwordLogins: 0,
    authorizeWithCode: 0,
  };
  const pending = new Map();
  const authorizations = new Map();
  const rememberedConsent = new Set();
  const revokedSources = new Set();
  const revokedBSessions = new Set();
  let passwordToken = '';
  const passwordSessionIds = [
    '66666666-6666-4666-8666-666666666661',
    '66666666-6666-4666-8666-666666666662',
    '66666666-6666-4666-8666-666666666663',
  ];
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
    const issueApprovedRedirect = (record) => {
      const code = randomBytes(16).toString('base64url');
      pending.set(code, { clientId: record.clientId, challenge: record.challenge });
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
      const bearer = req.headers.authorization ?? '';
      if (passwordToken.length === 0 || bearer !== `Bearer ${passwordToken}`) {
        send(401, JSON.stringify({ error: 'unauthorized' }));
        return;
      }
      const record = authorizations.get(authorizationId);
      const consentKey = record === undefined ? '' : `${sub}:${record.clientId}`;
      if (req.method === 'GET' && authorizationPath[2] === undefined) {
        if (record === undefined) {
          send(404, JSON.stringify({ error: 'not_found' }));
          return;
        }
        if (rememberedConsent.has(consentKey)) {
          counts.alreadyConsentedGets += 1;
          send(200, JSON.stringify({ redirect_url: issueApprovedRedirect(record).toString() }));
          return;
        }
        send(200, JSON.stringify({ authorization_id: authorizationId }));
        return;
      }
      if (req.method === 'POST' && authorizationPath[2] === '/consent') {
        const chunks = [];
        req.on('data', (chunk) => chunks.push(chunk));
        req.on('end', () => {
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
          if (rememberedConsent.has(consentKey)) {
            send(400, JSON.stringify({ error: 'validation_failed' }));
            return;
          }
          rememberedConsent.add(consentKey);
          counts.consentPosts += 1;
          send(200, JSON.stringify({ redirect_url: issueApprovedRedirect(record).toString() }));
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
          const sessionId = passwordSessionIds[counts.passwordLogins];
          if (sessionId === undefined) {
            send(500, JSON.stringify({ error: 'too_many_logins' }));
            return;
          }
          passwordToken = await new SignJWT({
            role: 'authenticated',
            session_id: sessionId,
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
          const source = randomUUID();
          const decoy = randomUUID();
          const bSession = randomUUID();
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
        if (inject?.liveness === 'timeout') return;
        counts.liveness += 1;
        if (inject?.liveness === 'auth') {
          send(
            401,
            JSON.stringify({
              leak: refreshSentinel,
              url: 'https://user:pass@evil.example/hook?code=abc&state=xyz',
            }),
          );
          return;
        }
        if (inject?.liveness === 'service') {
          send(500, JSON.stringify({ leak: refreshSentinel, detail: 'raw-service-body' }));
          return;
        }
        if (inject?.liveness === 'malformed') {
          send(200, `not-json ${refreshSentinel}`);
          return;
        }
        if (inject?.liveness === 'rpc') {
          send(400, JSON.stringify({ leak: refreshSentinel, hint: 'raw-validation-body' }));
          return;
        }
        if (inject?.liveness === 'false') {
          send(200, 'false');
          return;
        }
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
      ...(inject?.fault === undefined ? {} : { ARI_LANE_B_DIAGNOSTIC_FAULT: inject.fault }),
      ...(inject?.liveness === 'timeout' ? { ARI_LANE_B_LIVENESS_TIMEOUT_MS: '300' } : {}),
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
  const stdoutText = [];
  let receipt;
  let abortedN5;
  try {
    while (receipt === undefined) {
      let timer;
      const line = await Promise.race([
        reader.next(),
        new Promise((resolve) => {
          timer = setTimeout(() => resolve(null), 40_000);
        }),
      ]);
      clearTimeout(timer);
      assert.notEqual(line, null, Buffer.concat(stderr).toString('utf8'));
      stdoutText.push(line);
      const message = JSON.parse(line);
      if (message.type === 'controller_action') {
        if (mode === 'abort-n5' && message.action === 'revoke_b_session') {
          assert.equal(message.pair, 'n5');
          abortedN5 = message;
          proc.stdin.end();
          continue;
        }
        assert.equal(message.authorizationUrl, undefined);
        assert.equal(message.code, undefined);
        assert.match(message.source_session_id, /^[0-9a-f-]{36}$/u);
        assert.match(message.b_session_id, /^[0-9a-f-]{36}$/u);
        assert.notEqual(message.source_session_id, message.b_session_id);
        const proof = applyControllerRevocation(
          {
            sessions: [
              {
                id: message.source_session_id,
                userEmail: SYNTHETIC_EMAIL,
                refreshRows: 1,
                notAfter: null,
              },
              {
                id: message.b_session_id,
                userEmail: SYNTHETIC_EMAIL,
                refreshRows: 1,
                notAfter: null,
              },
            ],
          },
          message,
        );
        assert.equal(proof.continue, true, proof.reason);
        assert.equal(proof.receipt.targetSessionRows, 0);
        assert.equal(proof.receipt.targetRefreshRows, 0);
        assert.equal(proof.receipt.oppositeLive, true);
        assert.equal(proof.receipt.oppositeSessionRows, 1);
        if (message.action === 'revoke_a_source_session') {
          assert.equal(message.pair, 'n4');
          assert.equal(proof.receipt.targetSessionId, message.source_session_id);
          assert.equal(revokedBSessions.has(message.b_session_id), false);
          revokedSources.add(message.source_session_id);
        } else if (message.action === 'revoke_b_session') {
          assert.equal(message.pair, 'n5');
          assert.equal(proof.receipt.targetSessionId, message.b_session_id);
          assert.equal(revokedSources.has(message.source_session_id), false);
          revokedBSessions.add(message.b_session_id);
        } else {
          assert.fail(`unexpected action ${message.action}`);
        }
        proc.stdin.write('continue\n');
      } else if (message.type === 'receipt') {
        receipt = message;
      } else {
        assert.fail(`unexpected stdout line ${message.type}`);
      }
    }
    const [code] = await exited;
    const errText = Buffer.concat(stderr).toString('utf8');
    const outText = stdoutText.join('\n');
    if (mode === 'inject') {
      assert.equal(code, 2, errText);
      assert.notEqual(receipt, undefined);
      return { receipt, errText, outText, passwordSessionIds };
    }
    if (mode === 'abort-n5') {
      assert.equal(code, 2, errText);
      assert.equal(receipt.acceptance, false);
      assert.equal(receipt.rowsPass, false);
      assert.equal(receipt.hookInstalled, false);
      assert.equal(receipt.executedByWriter, false);
      assert.equal(receipt.reason, 'stdin_refused');
      assert.deepEqual(
        receipt.sessionLedger.map((row) => row.pair),
        ['positive', 'n4', 'n5'],
      );
      const ledgerPasswordIds = receipt.sessionLedger.map((row) => row.passwordSessionId);
      const ledgerSourceIds = receipt.sessionLedger.map((row) => row.sourceSessionId);
      const ledgerBIds = receipt.sessionLedger.map((row) => row.bSessionId);
      assert.deepEqual(ledgerPasswordIds, passwordSessionIds);
      assert.equal(new Set(ledgerPasswordIds).size, 3);
      assert.equal(new Set(ledgerSourceIds).size, 3);
      assert.equal(new Set(ledgerBIds).size, 3);
      assert.equal(receipt.sessionLedger[2].sourceSessionId, abortedN5.source_session_id);
      assert.equal(receipt.sessionLedger[2].bSessionId, abortedN5.b_session_id);
      assert.notEqual(ledgerPasswordIds[0], ledgerPasswordIds[1]);
      assert.notEqual(ledgerSourceIds[0], ledgerSourceIds[1]);
      assert.notEqual(ledgerSourceIds[1], ledgerSourceIds[2]);
      assert.notEqual(ledgerBIds[0], ledgerBIds[1]);
      assert.notEqual(ledgerBIds[1], ledgerBIds[2]);
      assert.equal(outText.includes(plantedToken), false);
      assert.equal(outText.includes(plantedPassword), false);
      assert.equal(outText.includes(refreshSentinel), false);
      assert.equal(outText.includes(publishable), false);
      assert.equal(outText.includes('eyJ'), false);
      assert.equal(errText.includes(plantedToken), false);
      assert.equal(errText.includes(plantedPassword), false);
      assert.equal(errText.includes(refreshSentinel), false);
      assert.equal(JSON.stringify(receipt).includes('Bearer'), false);
      return;
    }
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
    assert.equal(receipt.passwordSessionId, passwordSessionIds[0]);
    assert.equal(outText.includes('eyJ'), false);
    assert.equal(receipt.rowsPass, true);
    assert.equal(receipt.markerReads, 1);
    assert.equal(receipt.actualHead, head);
    assert.equal(receipt.reviewedHead, head);
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
    assert.notEqual(byId.N4.sourceSessionId, byId.N5.sourceSessionId);
    assert.notEqual(byId.N4.bSessionId, byId.N5.bSessionId);
    assert.notEqual(byId.P5.sourceSessionId, byId.N4.sourceSessionId);
    assert.notEqual(byId.P5.sourceSessionId, byId.N5.sourceSessionId);
    assert.notEqual(byId.P5.bSessionId, byId.N4.bSessionId);
    assert.notEqual(byId.P5.bSessionId, byId.N5.bSessionId);
    assert.equal(byId.P1.sourceSessionId, byId.P5.sourceSessionId);
    assert.equal(byId.N1.sourceSessionId, byId.P5.sourceSessionId);
    assert.equal(byId.N1.bSessionId, byId.P5.bSessionId);
    assert.deepEqual(
      receipt.sessionLedger.map((row) => row.pair),
      ['positive', 'n4', 'n5'],
    );
    const ledgerPasswordIds = receipt.sessionLedger.map((row) => row.passwordSessionId);
    const ledgerSourceIds = receipt.sessionLedger.map((row) => row.sourceSessionId);
    const ledgerBIds = receipt.sessionLedger.map((row) => row.bSessionId);
    assert.deepEqual(ledgerPasswordIds, passwordSessionIds);
    assert.equal(new Set(ledgerPasswordIds).size, 3);
    assert.equal(new Set(ledgerSourceIds).size, 3);
    assert.equal(new Set(ledgerBIds).size, 3);
    assert.equal(receipt.sessionLedger[0].sourceSessionId, byId.P5.sourceSessionId);
    assert.equal(receipt.sessionLedger[0].bSessionId, byId.P5.bSessionId);
    assert.equal(receipt.sessionLedger[1].sourceSessionId, byId.N4.sourceSessionId);
    assert.equal(receipt.sessionLedger[1].bSessionId, byId.N4.bSessionId);
    assert.equal(receipt.sessionLedger[2].sourceSessionId, byId.N5.sourceSessionId);
    assert.equal(receipt.sessionLedger[2].bSessionId, byId.N5.bSessionId);
    for (const row of receipt.sessionLedger) {
      assert.notEqual(row.passwordSessionId, row.sourceSessionId);
      assert.notEqual(row.passwordSessionId, row.bSessionId);
      assert.notEqual(row.sourceSessionId, row.bSessionId);
    }
    assert.equal(revokedSources.has(byId.N4.sourceSessionId), true);
    assert.equal(revokedBSessions.has(byId.N4.bSessionId), false);
    assert.equal(revokedBSessions.has(byId.N5.bSessionId), true);
    assert.equal(revokedSources.has(byId.N5.sourceSessionId), false);
    assert.equal(
      revocationRowPass({
        row: 'N4',
        sourceSessionId: byId.N4.sourceSessionId,
        bSessionId: byId.N4.bSessionId,
        livenessDenied: true,
        markerUnchanged: true,
        sourceLive: false,
        bLive: !revokedBSessions.has(byId.N4.bSessionId),
        priorSourceSessionIds: [],
      }),
      true,
    );
    assert.equal(
      revocationRowPass({
        row: 'N5',
        sourceSessionId: byId.N5.sourceSessionId,
        bSessionId: byId.N5.bSessionId,
        livenessDenied: true,
        markerUnchanged: true,
        sourceLive: !revokedSources.has(byId.N5.sourceSessionId),
        bLive: false,
        priorSourceSessionIds: [byId.N4.sourceSessionId],
      }),
      true,
    );
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
    assert.equal(counts.aExchange, 3);
    assert.equal(counts.bExchange, 3);
    assert.equal(counts.passwordLogins, 3);
    assert.equal(counts.consentPosts, 2);
    assert.equal(counts.alreadyConsentedGets, 4);
    assert.equal(counts.authorizeWithCode, 0);
    assert.equal(counts.livenessDenied >= 2, true);
    assert.equal(counts.marker, 3);
    assert.equal(counts.markerUsedA, false);
  } finally {
    if (proc.exitCode === null && proc.signalCode === null) proc.kill('SIGKILL');
    await exited.catch(() => undefined);
    https.closeAllConnections?.();
    await new Promise((resolve) => https.close(() => resolve()));
    rmSync(dir, { recursive: true, force: true });
  }
}

test('CLI run completes SDK OAuth, B bind, and the marker call', { timeout: 90_000 }, async () => {
  await runSyntheticLaneB('success');
});

test('failure during N5 keeps positive, N4, and known N5 cleanup ids', {
  timeout: 90_000,
}, async () => {
  await runSyntheticLaneB('abort-n5');
});

test('child projection keeps distinct RPC codes and drops raw error text', () => {
  const invalid = projectChildFailure(
    Object.assign(new Error('raw-invalid-params-body'), { code: -32602 }),
    'initialize',
  );
  const internal = projectChildFailure(
    Object.assign(new Error('raw-internal-body'), { code: -32603 }),
    'list',
  );
  assert.equal(invalid.reason, 'child_failed');
  assert.equal(invalid.stage, 'initialize');
  assert.equal(invalid.category, 'rpc_validation');
  assert.equal(invalid.rpcCode, -32602);
  assert.equal(internal.stage, 'list');
  assert.equal(internal.category, 'service_error');
  assert.equal(internal.rpcCode, -32603);
  assert.notEqual(invalid.category, internal.category);
  assert.equal(JSON.stringify(invalid).includes('raw-invalid'), false);
  assert.equal(JSON.stringify(internal).includes('raw-internal'), false);
  const embedded = projectChildFailure(
    new Error(
      'Error POSTing to endpoint (HTTP 403): {"error":"downstream_credential_unresolved","stage":"liveness","category":"false","httpStatus":200,"access_token":"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.sig"}',
    ),
    'initialize',
  );
  assert.equal(embedded.stage, 'liveness');
  assert.equal(embedded.category, 'false');
  assert.equal(embedded.httpStatus, 200);
  assertIpcHasNoSecrets(embedded);
  assert.equal(JSON.stringify(embedded).includes('eyJ'), false);
});

test('controller runbook states the Primary Users retained-baseline hygiene rule', () => {
  const controller = readFileSync(
    fileURLToPath(new URL('../docs/evidence/ari-test-probe/lane-b-controller.md', import.meta.url)),
    'utf8',
  );
  assert.match(controller, /Primary Users keep the retained baseline/);
  assert.match(controller, /Each `run` is its own/);
  assert.match(controller, /Do not reuse a previous run's ledger/);
  assert.match(controller, /category/);
  assert.match(controller, /rpcCode/);
  assert.equal(controller.includes('Principal Users'), false);
});

function assertDiagnosticReceipt(result, expected, sentinels) {
  const { receipt, errText, outText } = result;
  assert.equal(receipt.acceptance, false);
  assert.equal(receipt.rowsPass, false);
  assert.equal(receipt.hookInstalled, false);
  assert.equal(receipt.executedByWriter, false);
  assert.equal(receipt.reason, 'child_failed');
  assert.equal(receipt.stage, expected.stage);
  assert.equal(receipt.category, expected.category);
  assert.equal(receipt.rpcCode, expected.rpcCode);
  assert.equal(receipt.httpStatus, expected.httpStatus);
  assert.equal(receipt.sessionLedger.length, 1);
  assert.equal(receipt.sessionLedger[0].pair, 'positive');
  assert.match(receipt.sessionLedger[0].passwordSessionId, /^[0-9a-f-]{36}$/u);
  assert.match(receipt.sessionLedger[0].sourceSessionId, /^[0-9a-f-]{36}$/u);
  assert.match(receipt.sessionLedger[0].bSessionId, /^[0-9a-f-]{36}$/u);
  assert.equal(receipt.passwordSessionId, receipt.sessionLedger[0].passwordSessionId);
  assert.notEqual(
    receipt.sessionLedger[0].passwordSessionId,
    receipt.sessionLedger[0].sourceSessionId,
  );
  assert.notEqual(receipt.sessionLedger[0].sourceSessionId, receipt.sessionLedger[0].bSessionId);
  assert.equal(Number.isInteger(receipt.livenessChecks), true);
  assert.equal(Number.isInteger(receipt.livenessDenials), true);
  assert.equal(Number.isInteger(receipt.markerReads), true);
  assert.equal(receipt.livenessChecks >= expected.minChecks, true);
  if (expected.denials === 0) assert.equal(receipt.livenessDenials, 0);
  else assert.equal(receipt.livenessDenials >= expected.denials, true);
  assert.equal(receipt.markerReads, 0);
  assert.equal(errText.includes('request_failed'), false);
  assert.equal(errText.includes('raw-service-body'), false);
  assert.equal(errText.includes('raw-validation-body'), false);
  assert.equal(errText.includes('evil.example'), false);
  const packed = `${outText}\n${errText}\n${JSON.stringify(receipt)}`;
  for (const sentinel of sentinels) assert.equal(packed.includes(sentinel), false, sentinel);
  assert.equal(packed.includes('eyJ'), false);
  assert.equal(JSON.stringify(receipt).includes('Bearer'), false);
}

test('actual child failures after B stay distinguishable on the parent receipt', {
  timeout: 240_000,
}, async () => {
  const sentinels = [
    'synthetic-password-sentinel',
    'refresh-sentinel-must-not-leak',
    'sb_publishable_parent_only_sentinel',
    'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.sig',
    'evil.example',
    'raw-service-body',
    'raw-validation-body',
    'request_failed',
  ];
  const cases = [
    {
      inject: { liveness: 'false' },
      expected: { stage: 'liveness', category: 'false', httpStatus: 200, minChecks: 1, denials: 1 },
    },
    {
      inject: { liveness: 'auth' },
      expected: {
        stage: 'liveness',
        category: 'auth_denial',
        httpStatus: 401,
        minChecks: 1,
        denials: 1,
      },
    },
    {
      inject: { liveness: 'service' },
      expected: {
        stage: 'liveness',
        category: 'service_error',
        httpStatus: 500,
        minChecks: 1,
        denials: 1,
      },
    },
    {
      inject: { liveness: 'malformed' },
      expected: {
        stage: 'liveness',
        category: 'malformed_response',
        httpStatus: 200,
        minChecks: 1,
        denials: 1,
      },
    },
    {
      inject: { liveness: 'rpc' },
      expected: {
        stage: 'liveness',
        category: 'rpc_validation',
        httpStatus: 400,
        minChecks: 1,
        denials: 1,
      },
    },
    {
      inject: { liveness: 'timeout' },
      expected: { stage: 'liveness', category: 'timeout', minChecks: 1, denials: 1 },
    },
    {
      inject: { fault: 'initialize:-32602' },
      expected: {
        stage: 'initialize',
        category: 'rpc_validation',
        rpcCode: -32602,
        minChecks: 1,
        denials: 0,
      },
    },
    {
      inject: { fault: 'initialize:-32603' },
      expected: {
        stage: 'initialize',
        category: 'service_error',
        rpcCode: -32603,
        minChecks: 1,
        denials: 0,
      },
    },
    {
      inject: { fault: 'list:-32602' },
      expected: {
        stage: 'list',
        category: 'rpc_validation',
        rpcCode: -32602,
        minChecks: 1,
        denials: 0,
      },
    },
    {
      inject: { fault: 'tool:-32603' },
      expected: {
        stage: 'tool',
        category: 'service_error',
        rpcCode: -32603,
        minChecks: 1,
        denials: 0,
      },
    },
  ];
  const seen = [];
  for (const item of cases) {
    const result = await runSyntheticLaneB('inject', item.inject);
    assertDiagnosticReceipt(result, item.expected, sentinels);
    seen.push(
      `${result.receipt.stage}:${result.receipt.category}:${result.receipt.rpcCode ?? ''}:${result.receipt.httpStatus ?? ''}`,
    );
  }
  assert.equal(new Set(seen).size, seen.length);
});

test('cleanup runbook deletes every receipt-linked session and keeps the user', () => {
  const cleanup = readFileSync(
    fileURLToPath(
      new URL('../docs/evidence/ari-test-probe/oauth-session-cleanup.md', import.meta.url),
    ),
    'utf8',
  );
  assert.match(cleanup, /sessionLedger/);
  assert.match(cleanup, /positive\.passwordSessionId/);
  assert.match(cleanup, /positive\.sourceSessionId/);
  assert.match(cleanup, /positive\.bSessionId/);
  assert.match(cleanup, /n4\.passwordSessionId/);
  assert.match(cleanup, /n4\.sourceSessionId/);
  assert.match(cleanup, /n4\.bSessionId/);
  assert.match(cleanup, /n5\.passwordSessionId/);
  assert.match(cleanup, /n5\.sourceSessionId/);
  assert.match(cleanup, /n5\.bSessionId/);
  assert.match(cleanup, /reads zero/);
  assert.match(cleanup, /baseline `auth\.sessions`/);
  assert.match(cleanup, /Not executed from this branch/);
  assert.match(cleanup, /not a revocation receipt/);
  assert.match(cleanup, /user_rows` must still be 1/);
});
