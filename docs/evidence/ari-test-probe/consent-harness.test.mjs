import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import {
  authSessionControl,
  buildAuthorizeUrl,
  buildOpenIdNegativeAuthorizeUrl,
  CONTROLS,
  createPkce,
  DISCOVERY,
  exchangeAuthorizationCode,
  listenOnce,
  performConsent,
  planConsent,
  redactCallback,
  redactResponseBody,
  redactTokenBody,
  runCli,
  runConsentExchange,
  runInProcessProbe,
  runOpenIdNegative,
} from './consent-harness.mjs';

const REDIRECT = 'http://127.0.0.1:8787/callback';
const CLIENT = 'registered-client-parameter';
const RESOURCE = 'https://odbcejsuuqdzhabjmozi.supabase.co/mcp';

test('plan does not execute and names the MC1488 controls', () => {
  const plan = planConsent();
  assert.equal(plan.executed, false);
  assert.equal(plan.hookInstalledByThisPacket, false);
  assert.equal(plan.acceptance, false);
  assert.equal(plan.revocationClaimed, false);
  assert.equal(plan.tokenBCustody, false);
  assert.deepEqual(plan.controls, CONTROLS);
  assert.equal(plan.discovery.fetchedByThisPacket, false);
  assert.equal(plan.discovery.oauthAuthorizationServer, DISCOVERY.oauthAuthorizationServer);
  assert.equal(plan.discovery.oidc, DISCOVERY.oidc);
  assert.equal(JSON.stringify(plan).includes('access_token'), false);
});

test('authorize URL is loopback PKCE and refuses openid', () => {
  const pkce = createPkce();
  const built = buildAuthorizeUrl({
    authorizeEndpoint: 'https://odbcejsuuqdzhabjmozi.supabase.co/auth/v1/oauth/authorize',
    clientId: CLIENT,
    redirectUri: REDIRECT,
    scopes: ['email'],
    resource: RESOURCE,
    codeChallenge: pkce.codeChallenge,
    state: 'loopback-state',
  });
  assert.equal(built.ok, true);
  const url = new URL(built.url);
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.get('code_challenge'), pkce.codeChallenge);
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(url.searchParams.get('redirect_uri'), REDIRECT);
  assert.equal(url.searchParams.get('scope'), 'email');
  assert.equal(url.searchParams.has('code_verifier'), false);
  assert.equal(built.url.includes(pkce.codeVerifier), false);
  assert.equal(
    buildAuthorizeUrl({
      authorizeEndpoint: 'https://odbcejsuuqdzhabjmozi.supabase.co/auth/v1/oauth/authorize',
      clientId: CLIENT,
      redirectUri: REDIRECT,
      scopes: ['openid'],
      resource: RESOURCE,
      codeChallenge: pkce.codeChallenge,
    }).reason,
    'openid_scope_refused',
  );
  assert.equal(
    buildAuthorizeUrl({
      authorizeEndpoint: 'https://lygftpbjgqgvuunkwnxf.supabase.co/auth/v1/oauth/authorize',
      clientId: CLIENT,
      redirectUri: 'https://example.test/callback',
      scopes: ['email'],
      resource: RESOURCE,
      codeChallenge: pkce.codeChallenge,
    }).reason,
    'forbidden_target',
  );
});

test('callback and token receipts drop token values', () => {
  const secret = 'access-token-value-must-not-leak';
  const callback = redactCallback(
    `http://127.0.0.1:8787/callback?code=auth-code&access_token=${secret}`,
  );
  assert.equal(callback.hasToken, true);
  assert.equal(JSON.stringify(callback).includes(secret), false);
  assert.equal(JSON.stringify(callback).includes('auth-code'), false);
  const redacted = redactTokenBody(
    JSON.stringify({ access_token: secret, refresh_token: 'refresh-secret', token_type: 'bearer' }),
  );
  assert.equal(redacted.ok, true);
  assert.deepEqual(redacted.secretKeyNames, ['access_token', 'refresh_token']);
  assert.equal(JSON.stringify(redacted).includes(secret), false);
  assert.equal(
    redactTokenBody(JSON.stringify({ id_token: secret, access_token: secret })).reason,
    'id_token_present',
  );
  assert.equal(
    JSON.stringify(redactTokenBody(JSON.stringify({ id_token: secret }))).includes(secret),
    false,
  );
});

test('Auth session control is 403 session_not_found and is not revocation', () => {
  const held = authSessionControl(403, JSON.stringify({ error: 'session_not_found' }));
  assert.equal(held.ok, true);
  assert.equal(held.revocationClaimed, false);
  assert.equal(authSessionControl(401, JSON.stringify({ error: 'session_not_found' })).ok, false);
  assert.equal(
    authSessionControl(403, JSON.stringify({ error: 'session_not_found', access_token: 'x' }))
      .reason,
    'credential_in_body',
  );
});

function jsonResponse(status, body, headers = {}) {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: {
      get(name) {
        return headers[name.toLowerCase()] ?? null;
      },
    },
    async text() {
      return text;
    },
  };
}

test('consent GET and POST plus S256 exchange stay redacted', async () => {
  const pkce = createPkce();
  const session = 'synthetic-session-must-not-leak';
  const code = 'auth-code-must-not-leak';
  const access = 'access-token-value-must-not-leak';
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url: `${url}`, init });
    const href = `${url}`;
    if (init?.method === 'GET' && href.endsWith('/auth/v1/oauth/authorizations/authz-1')) {
      return jsonResponse(200, { authorization_id: 'authz-1' });
    }
    if (init?.method === 'POST' && href.endsWith('/auth/v1/oauth/authorizations/authz-1/consent')) {
      return jsonResponse(200, {
        redirect_url: `http://127.0.0.1:8787/callback?code=${code}`,
      });
    }
    if (init?.method === 'POST' && href.endsWith('/auth/v1/oauth/token')) {
      return jsonResponse(200, {
        access_token: access,
        refresh_token: 'refresh-secret',
        token_type: 'bearer',
      });
    }
    throw new Error('unexpected request');
  };
  const input = {
    fetch: fetchImpl,
    authOrigin: 'https://odbcejsuuqdzhabjmozi.supabase.co',
    authorizationId: 'authz-1',
    userAccessToken: session,
    publishableKey: 'publishable-key',
    clientId: CLIENT,
    redirectUri: REDIRECT,
    resource: RESOURCE,
    codeVerifier: pkce.codeVerifier,
    codeChallenge: pkce.codeChallenge,
  };
  const consent = await performConsent(input);
  assert.equal(consent.performed, true);
  assert.equal(consent.getAuthorization, true);
  assert.equal(consent.postConsent, true);
  assert.equal(consent.hasCode, true);
  assert.equal(consent.label, 'synthetic_user_consent');
  assert.equal(calls[0].init.headers.Authorization, `Bearer ${session}`);
  assert.equal(calls[1].init.body, '{"action":"approve"}');
  const exchanged = await runConsentExchange(input);
  assert.equal(exchanged.consentPerformed, true);
  assert.equal(exchanged.exchangePerformed, true);
  assert.equal(exchanged.exchangeStatus, 200);
  assert.equal(exchanged.idTokenPresent, false);
  assert.equal(exchanged.codeChallengeMethod, 'S256');
  assert.equal(exchanged.acceptance, false);
  assert.equal(exchanged.hookInstalledByThisPacket, false);
  const tokenCall = calls.find((call) => call.url.endsWith('/auth/v1/oauth/token'));
  const params = new URLSearchParams(tokenCall.init.body);
  assert.equal(params.get('grant_type'), 'authorization_code');
  assert.equal(params.get('code'), code);
  assert.equal(params.get('code_verifier'), pkce.codeVerifier);
  assert.equal(
    createHash('sha256').update(params.get('code_verifier')).digest('base64url'),
    pkce.codeChallenge,
  );
  const receipt = JSON.stringify({ consent, exchanged });
  assert.equal(receipt.includes(session), false);
  assert.equal(receipt.includes(code), false);
  assert.equal(receipt.includes(pkce.codeVerifier), false);
  assert.equal(receipt.includes(access), false);
  const direct = await exchangeAuthorizationCode({ ...input, code });
  assert.equal(direct.exchanged, true);
  assert.equal(JSON.stringify(direct).includes(code), false);
  assert.equal(JSON.stringify(direct).includes(access), false);
});

test('openid_negative sends openid and records authorize or exchange rejection', async () => {
  const pkce = createPkce();
  const session = 'synthetic-session-must-not-leak';
  const code = 'openid-code-must-not-leak';
  const idToken = 'id-token-value-must-not-leak';
  const blocked = buildAuthorizeUrl({
    authorizeEndpoint: 'https://odbcejsuuqdzhabjmozi.supabase.co/auth/v1/oauth/authorize',
    clientId: CLIENT,
    redirectUri: REDIRECT,
    scopes: ['openid', 'email'],
    resource: RESOURCE,
    codeChallenge: pkce.codeChallenge,
  });
  assert.equal(blocked.reason, 'openid_scope_refused');
  const sent = buildOpenIdNegativeAuthorizeUrl({
    authorizeEndpoint: 'https://odbcejsuuqdzhabjmozi.supabase.co/auth/v1/oauth/authorize',
    clientId: CLIENT,
    redirectUri: REDIRECT,
    scopes: ['openid', 'email'],
    resource: RESOURCE,
    codeChallenge: pkce.codeChallenge,
    state: 'openid-negative',
  });
  assert.equal(sent.ok, true);
  assert.equal(sent.label, 'openid_negative');
  assert.equal(sent.openidSent, true);
  assert.equal(new URL(sent.url).searchParams.get('scope').includes('openid'), true);

  const base = {
    authOrigin: 'https://odbcejsuuqdzhabjmozi.supabase.co',
    userAccessToken: session,
    publishableKey: 'publishable-key',
    clientId: CLIENT,
    redirectUri: REDIRECT,
    resource: RESOURCE,
    codeVerifier: pkce.codeVerifier,
    codeChallenge: pkce.codeChallenge,
    scopes: ['openid', 'email'],
  };

  const authorizeCalls = [];
  const atAuthorize = await runOpenIdNegative({
    ...base,
    fetch: async (url, init) => {
      authorizeCalls.push({ url: `${url}`, init });
      return jsonResponse(400, { error: 'invalid_request', error_description: 'openid refused' });
    },
  });
  assert.equal(atAuthorize.ok, true);
  assert.equal(atAuthorize.label, 'openid_negative');
  assert.equal(atAuthorize.openidSent, true);
  assert.equal(atAuthorize.rejectionStage, 'authorize');
  assert.equal(atAuthorize.idTokenPresent, false);
  assert.equal(new URL(authorizeCalls[0].url).searchParams.get('scope').includes('openid'), true);
  assert.equal(authorizeCalls.length, 1);

  const exchangeCalls = [];
  const atExchange = await runOpenIdNegative({
    ...base,
    fetch: async (url, init) => {
      exchangeCalls.push({ url: `${url}`, method: init?.method });
      const href = `${url}`;
      if (href.includes('/oauth/authorize?')) {
        return jsonResponse(302, '', { location: '/oauth/consent?authorization_id=authz-openid' });
      }
      if (init?.method === 'GET') return jsonResponse(200, { authorization_id: 'authz-openid' });
      if (href.endsWith('/consent')) {
        return jsonResponse(200, { redirect_url: `http://127.0.0.1:8787/callback?code=${code}` });
      }
      return jsonResponse(400, { error: 'invalid_grant' });
    },
  });
  assert.equal(atExchange.ok, true);
  assert.equal(atExchange.rejectionStage, 'exchange');
  assert.equal(atExchange.idTokenPresent, false);
  assert.equal(atExchange.codeChallengeMethod, 'S256');
  assert.equal(
    exchangeCalls.some((call) => call.url.endsWith('/auth/v1/oauth/token')),
    true,
  );
  assert.equal(
    exchangeCalls.some(
      (call) => call.method === 'GET' && call.url.includes('/oauth/authorizations/'),
    ),
    true,
  );
  assert.equal(
    exchangeCalls.some((call) => call.method === 'POST' && call.url.endsWith('/consent')),
    true,
  );

  const leaked = await runOpenIdNegative({
    ...base,
    fetch: async (url, init) => {
      const href = `${url}`;
      if (href.includes('/oauth/authorize?')) {
        return jsonResponse(302, '', { location: '/oauth/consent?authorization_id=authz-openid' });
      }
      if (init?.method === 'GET') return jsonResponse(200, { authorization_id: 'authz-openid' });
      if (href.endsWith('/consent')) {
        return jsonResponse(200, { redirect_url: `http://127.0.0.1:8787/callback?code=${code}` });
      }
      return jsonResponse(200, { id_token: idToken, access_token: 'access-secret' });
    },
  });
  assert.equal(leaked.ok, false);
  assert.equal(leaked.reason, 'id_token_present');
  assert.equal(leaked.rejectionStage, 'exchange');
  assert.equal(leaked.idTokenPresent, true);
  const printed = JSON.stringify({ atAuthorize, atExchange, leaked });
  assert.equal(printed.includes(session), false);
  assert.equal(printed.includes(code), false);
  assert.equal(printed.includes(pkce.codeVerifier), false);
  assert.equal(printed.includes(idToken), false);
});

test('redact drops consent redirect codes and the README pipes the live commands', async () => {
  const code = 'readme-code-must-not-leak';
  const redacted = redactResponseBody(
    JSON.stringify({ redirect_url: `http://127.0.0.1:8787/callback?code=${code}` }),
  );
  assert.equal(redacted.hasCode, true);
  assert.equal(JSON.stringify(redacted).includes(code), false);
  const readme = await readFile(new URL('./README.md', import.meta.url), 'utf8');
  assert.match(readme, /GET \/auth\/v1\/oauth\/authorizations\/\{id\}/);
  assert.match(readme, /\/auth\/v1\/oauth\/authorizations\/\$ARI_TEST_AUTHORIZATION_ID\/consent/);
  assert.match(readme, /grant_type=authorization_code/);
  assert.match(readme, /code_verifier=\$ARI_TEST_CODE_VERIFIER/);
  assert.match(readme, /state=openid-negative/);
  assert.match(readme, /consent-harness\.mjs redact/g);
  assert.match(readme, /does not run on each MCP\s+call/);
  assert.match(readme, /adapter has no liveness check/);
  const cleanup = await readFile(new URL('./oauth-session-cleanup.md', import.meta.url), 'utf8');
  assert.match(cleanup, /source_session_id/);
  assert.match(cleanup, /not a revocation receipt/);
  assert.match(cleanup, /Not executed from this branch/);
  assert.match(cleanup, /user_rows` must still be 1/);
});

const CONSOLE_METHODS = ['log', 'info', 'warn', 'error', 'debug'];

function streamText(value) {
  if (typeof value === 'string') return value;
  if (Buffer.isBuffer(value)) return value.toString('utf8');
  if (value instanceof Uint8Array) return Buffer.from(value).toString('utf8');
  return String(value ?? '');
}

let streamCaptureTail = Promise.resolve();

async function captureProcessStreams(fn) {
  const previous = streamCaptureTail;
  let release;
  streamCaptureTail = new Promise((resolve) => {
    release = resolve;
  });
  await previous;
  const stdoutChunks = [];
  const stderrChunks = [];
  const consoleChunks = [];
  const stdoutWrite = process.stdout.write;
  const stderrWrite = process.stderr.write;
  const savedConsole = {};
  process.stdout.write = function captureStdout(chunk, encoding, callback) {
    stdoutChunks.push(streamText(chunk));
    return stdoutWrite.call(process.stdout, chunk, encoding, callback);
  };
  process.stderr.write = function captureStderr(chunk, encoding, callback) {
    stderrChunks.push(streamText(chunk));
    return stderrWrite.call(process.stderr, chunk, encoding, callback);
  };
  for (const method of CONSOLE_METHODS) {
    savedConsole[method] = console[method];
    console[method] = (...args) => {
      consoleChunks.push(
        args.map((item) => (typeof item === 'string' ? item : JSON.stringify(item))).join(' '),
      );
      return savedConsole[method].apply(console, args);
    };
  }
  try {
    const result = await fn();
    return {
      result,
      stdout: stdoutChunks.join(''),
      stderr: stderrChunks.join(''),
      console: consoleChunks.join('\n'),
    };
  } finally {
    process.stdout.write = stdoutWrite;
    process.stderr.write = stderrWrite;
    for (const method of CONSOLE_METHODS) console[method] = savedConsole[method];
    release();
  }
}

function assertStreamsClean(streams, sentinels) {
  const output = `${streams.stdout}\n${streams.stderr}\n${streams.console}`;
  const leaked = sentinels.filter(
    (secret) => typeof secret === 'string' && secret.length > 0 && output.includes(secret),
  );
  assert.deepEqual(leaked, []);
}

function jsonLine(stdout, marker) {
  const markerAt = stdout.indexOf(marker);
  assert.ok(markerAt !== -1, 'receipt missing from process stdout');
  const start = stdout.lastIndexOf('{', markerAt);
  assert.ok(start !== -1, 'receipt missing from process stdout');
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let index = start; index < stdout.length; index += 1) {
    const char = stdout[index];
    if (inString) {
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') inString = true;
    else if (char === '{') depth += 1;
    else if (char === '}') {
      depth -= 1;
      if (depth === 0) return JSON.parse(stdout.slice(start, index + 1));
    }
  }
  assert.fail('receipt missing from process stdout');
}

describe('process stream sentinels', { concurrency: false }, () => {
  test('Warden mutation: process.stdout.write of token A before runProbe fails the sentinel scan', async () => {
    const tokenA = 'token-a-value-must-not-leak-aaaa';
    const tokenB = 'token-b-value-must-not-leak-bbbb';
    const refreshA = 'refresh-a-must-not-leak-aaaa';
    const refreshB = 'refresh-b-must-not-leak-bbbb';
    const code = 'auth-code-must-not-leak-cccc';
    const password = 'synthetic-password-must-not-leak';
    const canary = 'env-token-must-not-leak-eeee';
    const env = {
      ARI_TEST_PROJECT_REF: 'odbcejsuuqdzhabjmozi',
      ARI_TEST_SUPABASE_URL: 'https://odbcejsuuqdzhabjmozi.supabase.co',
      ARI_TEST_PUBLISHABLE_KEY: 'publishable-key',
      ARI_TEST_EXPECTED_CLIENT_ID: CLIENT,
      ARI_TEST_JWKS_JSON: '{"keys":[]}',
      ARI_TEST_SYNTHETIC_PASSWORD: password,
      ARI_TEST_REDIRECT_URI: REDIRECT,
      ARI_TEST_TOKEN_A: canary,
    };
    const calls = [];
    const fetchImpl = async (url, init) => {
      calls.push({ url: `${url}`, init });
      const href = `${url}`;
      if (href.includes('grant_type=password')) {
        return jsonResponse(200, {
          access_token: tokenB,
          refresh_token: refreshB,
          token_type: 'bearer',
        });
      }
      if (href.includes('/oauth/authorize?')) {
        return jsonResponse(302, '', { location: '/oauth/consent?authorization_id=authz-run' });
      }
      if (init?.method === 'GET' && href.includes('/oauth/authorizations/')) {
        return jsonResponse(200, { authorization_id: 'authz-run' });
      }
      if (href.endsWith('/consent')) {
        return jsonResponse(200, { redirect_url: `${REDIRECT}?code=${code}` });
      }
      if (href.endsWith('/oauth/token')) {
        return jsonResponse(200, {
          access_token: tokenA,
          refresh_token: refreshA,
          token_type: 'bearer',
        });
      }
      throw new Error('unexpected request');
    };
    const seen = {};
    const captured = await captureProcessStreams(() =>
      runCli(['node', 'consent-harness.mjs', 'run'], {
        env,
        fetch: fetchImpl,
        runProbe: async (options) => {
          seen.tokenA = options.tokenA;
          seen.tokenB = options.tokenB;
          seen.exported = options.env.ARI_TEST_TOKEN_A;
          return { ok: false, exitCode: 3, reason: 'jwt_malformed', rows: [], requests: 0 };
        },
      }),
    );
    const exitCode = captured.result;
    assert.equal(seen.tokenA, tokenA);
    assert.equal(seen.tokenB, tokenB);
    assert.equal(seen.exported, canary);
    assert.equal(Object.hasOwn(env, 'ARI_TEST_TOKEN_B'), false);
    assert.equal(calls[0].url.includes('/oauth/authorize?'), true);
    assert.equal(new URL(calls[0].url).searchParams.get('scope').includes('openid'), false);
    assert.equal(calls[1].url.includes('grant_type=password'), true);
    assert.equal(
      calls.some(
        (call) => call.init?.method === 'GET' && call.url.includes('/oauth/authorizations/'),
      ),
      true,
    );
    assert.equal(
      calls.some((call) => call.init?.method === 'POST' && call.url.endsWith('/consent')),
      true,
    );
    const tokenCall = calls.find((call) => call.url.endsWith('/oauth/token'));
    const params = new URLSearchParams(tokenCall.init.body);
    assert.equal(params.get('grant_type'), 'authorization_code');
    assert.equal(params.get('code'), code);
    assert.equal(params.get('code_verifier')?.length > 0, true);
    const receipt = jsonLine(captured.stdout, '"packet":"ari-test-consent-probe"');
    assert.equal(exitCode, 3);
    assert.equal(receipt.probeRan, true);
    assert.equal(receipt.tokenAInMemory, true);
    assert.equal(receipt.tokenBInMemory, true);
    assert.equal(receipt.exportedToEnv, false);
    assert.equal(receipt.acceptance, false);
    assert.equal(receipt.hookInstalledByThisPacket, false);
    assert.deepEqual(receipt.order, [
      'authorize',
      'password_login',
      'consent',
      'exchange',
      'probe',
    ]);
    const sentinels = [
      tokenA,
      tokenB,
      refreshA,
      refreshB,
      code,
      password,
      canary,
      params.get('code_verifier'),
    ];
    assertStreamsClean(captured, sentinels);
    const direct = await captureProcessStreams(() =>
      runInProcessProbe({
        fetch: fetchImpl,
        authOrigin: env.ARI_TEST_SUPABASE_URL,
        publishableKey: env.ARI_TEST_PUBLISHABLE_KEY,
        clientId: CLIENT,
        redirectUri: REDIRECT,
        resource: 'https://odbcejsuuqdzhabjmozi.supabase.co/mcp',
        projectRef: env.ARI_TEST_PROJECT_REF,
        jwks: env.ARI_TEST_JWKS_JSON,
        password,
        env,
      }),
    );
    assert.equal(direct.result.probeRan, true);
    assert.equal(direct.result.probe.reason, 'jwt_malformed');
    assertStreamsClean(direct, sentinels);
  });

  test('failure paths keep sentinels off process stdout and stderr', async () => {
    const tokenB = 'token-b-value-must-not-leak-bbbb';
    const refreshB = 'refresh-b-must-not-leak-bbbb';
    const code = 'auth-code-must-not-leak-cccc';
    const password = 'synthetic-password-must-not-leak';
    const canary = 'env-token-must-not-leak-eeee';
    const env = {
      ARI_TEST_PROJECT_REF: 'odbcejsuuqdzhabjmozi',
      ARI_TEST_SUPABASE_URL: 'https://odbcejsuuqdzhabjmozi.supabase.co',
      ARI_TEST_PUBLISHABLE_KEY: 'publishable-key',
      ARI_TEST_EXPECTED_CLIENT_ID: CLIENT,
      ARI_TEST_JWKS_JSON: '{"keys":[]}',
      ARI_TEST_SYNTHETIC_PASSWORD: password,
      ARI_TEST_REDIRECT_URI: REDIRECT,
      ARI_TEST_TOKEN_A: canary,
    };
    const passwordFail = await captureProcessStreams(() =>
      runCli(['node', 'consent-harness.mjs', 'run'], {
        env,
        fetch: async (url) => {
          const href = `${url}`;
          if (href.includes('/oauth/authorize?')) {
            return jsonResponse(302, '', { location: '/oauth/consent?authorization_id=authz-run' });
          }
          if (href.includes('grant_type=password')) {
            return jsonResponse(400, { error: 'invalid_grant' });
          }
          throw new Error('unexpected request');
        },
      }),
    );
    assert.equal(passwordFail.result, 4);
    assert.equal(jsonLine(passwordFail.stdout, '"stage":"password_login"').probeRan, false);
    assertStreamsClean(passwordFail, [password, canary, tokenB, refreshB]);

    let verifier = '';
    const exchangeFail = await captureProcessStreams(() =>
      runCli(['node', 'consent-harness.mjs', 'run'], {
        env,
        fetch: async (url, init) => {
          const href = `${url}`;
          if (href.includes('grant_type=password')) {
            return jsonResponse(200, {
              access_token: tokenB,
              refresh_token: refreshB,
              token_type: 'bearer',
            });
          }
          if (href.includes('/oauth/authorize?')) {
            return jsonResponse(302, '', {
              location: '/oauth/consent?authorization_id=authz-run',
            });
          }
          if (init?.method === 'GET' && href.includes('/oauth/authorizations/')) {
            return jsonResponse(200, { authorization_id: 'authz-run' });
          }
          if (href.endsWith('/consent')) {
            return jsonResponse(200, { redirect_url: `${REDIRECT}?code=${code}` });
          }
          if (href.endsWith('/oauth/token')) {
            verifier = new URLSearchParams(init.body).get('code_verifier') ?? '';
            return jsonResponse(400, { error: 'invalid_grant' });
          }
          throw new Error('unexpected request');
        },
      }),
    );
    assert.equal(exchangeFail.result, 4);
    assert.equal(jsonLine(exchangeFail.stdout, '"stage":"exchange"').probeRan, false);
    assert.equal(verifier.length > 0, true);
    assertStreamsClean(exchangeFail, [tokenB, refreshB, code, verifier, password, canary]);
    assert.equal(exchangeFail.stderr.includes(tokenB), false);
    assert.equal(exchangeFail.stderr.includes(code), false);
  });

  test('openid-negative CLI expects failure and does not print an id_token', async () => {
    const tokenB = 'token-b-value-must-not-leak-bbbb';
    const refreshB = 'refresh-b-must-not-leak-bbbb';
    const code = 'openid-code-must-not-leak-cccc';
    const idToken = 'id-token-value-must-not-leak-dddd';
    const access = 'token-a-value-must-not-leak-aaaa';
    const password = 'synthetic-password-must-not-leak';
    const env = {
      ARI_TEST_PROJECT_REF: 'odbcejsuuqdzhabjmozi',
      ARI_TEST_SUPABASE_URL: 'https://odbcejsuuqdzhabjmozi.supabase.co',
      ARI_TEST_PUBLISHABLE_KEY: 'publishable-key',
      ARI_TEST_EXPECTED_CLIENT_ID: CLIENT,
      ARI_TEST_REDIRECT_URI: REDIRECT,
      ARI_TEST_SYNTHETIC_PASSWORD: password,
    };
    let probeCalled = false;
    const calls = [];
    const fetchImpl = async (url, init) => {
      calls.push({ url: `${url}`, init });
      const href = `${url}`;
      if (href.includes('grant_type=password')) {
        return jsonResponse(200, {
          access_token: tokenB,
          refresh_token: refreshB,
          token_type: 'bearer',
        });
      }
      if (href.includes('/oauth/authorize?')) {
        return jsonResponse(302, '', { location: '/oauth/consent?authorization_id=authz-openid' });
      }
      if (init?.method === 'GET' && href.includes('/oauth/authorizations/')) {
        return jsonResponse(200, { authorization_id: 'authz-openid' });
      }
      if (href.endsWith('/consent')) {
        return jsonResponse(200, { redirect_url: `${REDIRECT}?code=${code}` });
      }
      return jsonResponse(200, { id_token: idToken, access_token: access });
    };
    const captured = await captureProcessStreams(() =>
      runCli(['node', 'consent-harness.mjs', 'openid-negative'], {
        env,
        fetch: fetchImpl,
        runProbe: async () => {
          probeCalled = true;
          return { ok: true };
        },
      }),
    );
    const exitCode = captured.result;
    const receipt = jsonLine(captured.stdout, '"label":"openid_negative"');
    assert.equal(probeCalled, false);
    assert.equal(receipt.probeRan, false);
    assert.equal(receipt.label, 'openid_negative');
    assert.equal(receipt.openidSent, true);
    assert.equal(receipt.rejectionStage, 'exchange');
    const authorize = calls.find((call) => call.url.includes('/oauth/authorize?'));
    assert.equal(new URL(authorize.url).searchParams.get('scope').includes('openid'), true);
    assert.equal(receipt.idTokenPresent, true);
    assert.equal(receipt.ok, false);
    assert.equal(exitCode, 4);
    assertStreamsClean(captured, [tokenB, refreshB, code, idToken, access, password]);
    assert.equal(captured.stderr.includes(idToken), false);
    assert.equal(captured.stderr.includes(access), false);
  });
});

test('loopback listener does not echo token query values', async () => {
  const server = await listenOnce();
  const secret = 'listener-token-must-not-echo';
  try {
    const response = await fetch(
      `http://127.0.0.1:${server.port}/callback?code=auth-code&access_token=${secret}`,
    );
    const body = await response.text();
    assert.equal(body.includes(secret), false);
    assert.equal(body.includes('auth-code'), false);
    assert.equal(body, 'rejected');
    const receipt = server.receipt();
    assert.equal(receipt.hasToken, true);
    assert.equal(JSON.stringify(receipt).includes(secret), false);
  } finally {
    await server.close();
  }
});
