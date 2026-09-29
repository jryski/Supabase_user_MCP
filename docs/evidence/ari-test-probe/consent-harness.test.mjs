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
      return jsonResponse(400, { error: 'invalid_scope' });
    },
  });
  assert.equal(atAuthorize.ok, true);
  assert.equal(atAuthorize.reason, 'openid_refused_client_scope');
  assert.notEqual(atAuthorize.reason, 'openid_rejected');
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
      return jsonResponse(403, {
        error: 'invalid_request',
        error_description: 'openid_scope_refused',
      });
    },
  });
  assert.equal(atExchange.ok, true);
  assert.equal(atExchange.reason, 'openid_rejected');
  assert.notEqual(atExchange.reason, 'openid_refused_client_scope');
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

test('generic oauth errors never count as openid_rejected', async () => {
  const pkce = createPkce();
  const session = 'synthetic-session-must-not-leak';
  const code = 'openid-code-must-not-leak';
  const access = 'access-token-must-not-leak';
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
  const route = (tokenBody, status) => async (url, init) => {
    const href = `${url}`;
    if (href.includes('/oauth/authorize?')) {
      return jsonResponse(302, '', { location: '/oauth/consent?authorization_id=authz-openid' });
    }
    if (init?.method === 'GET') return jsonResponse(200, { authorization_id: 'authz-openid' });
    if (href.endsWith('/consent')) {
      return jsonResponse(200, { redirect_url: `http://127.0.0.1:8787/callback?code=${code}` });
    }
    return jsonResponse(status, tokenBody);
  };
  const cases = [
    { status: 400, body: { error: 'invalid_grant' } },
    { status: 400, body: { error: 'invalid_request' } },
    { status: 401, body: { error: 'invalid_client' } },
    { status: 400, body: { error: 'invalid_scope' } },
    { status: 400, body: { error_description: 'openid_scope_refused' } },
    {
      status: 403,
      body: { error: 'invalid_grant', error_description: 'hook said something else' },
    },
  ];
  for (const item of cases) {
    const result = await runOpenIdNegative({
      ...base,
      fetch: route(item.body, item.status),
    });
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'exchange_inconclusive');
    assert.notEqual(result.reason, 'openid_rejected');
    assert.notEqual(result.reason, 'openid_refused_client_scope');
  }
  const withAccessToken = await runOpenIdNegative({
    ...base,
    fetch: route(
      { error: 'invalid_request', error_description: 'openid_scope_refused', access_token: access },
      403,
    ),
  });
  assert.equal(withAccessToken.ok, false);
  assert.equal(withAccessToken.reason, 'access_token_present');
  assert.notEqual(withAccessToken.reason, 'openid_rejected');
  const authorizeGeneric = await runOpenIdNegative({
    ...base,
    fetch: async () => jsonResponse(400, { error: 'invalid_request' }),
  });
  assert.equal(authorizeGeneric.ok, false);
  assert.equal(authorizeGeneric.reason, 'authorize_inconclusive');
  assert.notEqual(authorizeGeneric.reason, 'openid_rejected');
  const printed = JSON.stringify({ withAccessToken, authorizeGeneric });
  assert.equal(printed.includes(session), false);
  assert.equal(printed.includes(code), false);
  assert.equal(printed.includes(access), false);
  assert.equal(printed.includes(pkce.codeVerifier), false);
});

test('openid_negative does not pass a generic 500, transport failure, or missing authorization', async () => {
  const pkce = createPkce();
  const sessionId = '44444444-4444-4444-8444-444444444444';
  const decoySessionId = '55555555-5555-4555-8555-555555555555';
  const payload = Buffer.from(
    JSON.stringify({
      session_id: sessionId,
      user_metadata: { session_id: decoySessionId },
    }),
  ).toString('base64url');
  const session = `eyJhbGciOiJFUzI1NiJ9.${payload}.c2ln`;
  const code = 'openid-code-must-not-leak';
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
  const route = (tokenResponse) => async (url, init) => {
    const href = `${url}`;
    if (href.includes('/oauth/authorize?')) {
      return jsonResponse(302, '', { location: '/oauth/consent?authorization_id=authz-openid' });
    }
    if (init?.method === 'GET') return jsonResponse(200, { authorization_id: 'authz-openid' });
    if (href.endsWith('/consent')) {
      return jsonResponse(200, { redirect_url: `http://127.0.0.1:8787/callback?code=${code}` });
    }
    return tokenResponse();
  };

  const serverError = await runOpenIdNegative({
    ...base,
    fetch: route(() => jsonResponse(500, { message: 'internal server error' })),
  });
  assert.equal(serverError.ok, false);
  assert.equal(serverError.reason, 'exchange_server_error');
  assert.notEqual(serverError.reason, 'openid_rejected');
  assert.equal(serverError.rejectionStage, 'exchange');
  assert.equal(serverError.exchangeStatus, 500);
  assert.equal(serverError.idTokenPresent, false);
  assert.equal(serverError.passwordSessionId, sessionId);
  assert.notEqual(serverError.passwordSessionId, decoySessionId);

  const transport = await runOpenIdNegative({
    ...base,
    fetch: route(() => {
      throw new Error('socket hang up');
    }),
  });
  assert.equal(transport.ok, false);
  assert.equal(transport.reason, 'exchange_transport_failed');
  assert.notEqual(transport.reason, 'openid_rejected');
  assert.equal(transport.passwordSessionId, sessionId);

  const missingAuthorization = await runOpenIdNegative({
    ...base,
    fetch: async () => jsonResponse(200, { message: 'continue' }),
  });
  assert.equal(missingAuthorization.ok, false);
  assert.equal(missingAuthorization.reason, 'authorize_inconclusive');
  assert.notEqual(missingAuthorization.reason, 'openid_rejected');
  assert.equal(missingAuthorization.rejectionStage, 'authorize');
  assert.equal(missingAuthorization.passwordSessionId, sessionId);

  const authorizeServer = await runOpenIdNegative({
    ...base,
    fetch: async () => jsonResponse(500, { error: 'server_error' }),
  });
  assert.equal(authorizeServer.ok, false);
  assert.equal(authorizeServer.reason, 'authorize_server_error');
  assert.notEqual(authorizeServer.reason, 'openid_rejected');

  const consentServer = await runOpenIdNegative({
    ...base,
    fetch: async (url, init) => {
      const href = `${url}`;
      if (href.includes('/oauth/authorize?')) {
        return jsonResponse(302, '', { location: '/oauth/consent?authorization_id=authz-openid' });
      }
      if (init?.method === 'GET') return jsonResponse(200, { authorization_id: 'authz-openid' });
      if (href.endsWith('/consent')) return jsonResponse(500, { message: 'internal' });
      throw new Error('unexpected request');
    },
  });
  assert.equal(consentServer.ok, false);
  assert.equal(consentServer.reason, 'consent_server_error');
  assert.notEqual(consentServer.reason, 'openid_rejected');

  const printed = JSON.stringify({
    serverError,
    transport,
    missingAuthorization,
    authorizeServer,
    consentServer,
  });
  assert.equal(printed.includes(session), false);
  assert.equal(printed.includes(code), false);
  assert.equal(printed.includes(pkce.codeVerifier), false);
  assert.equal(printed.includes(decoySessionId), false);
});

test('failure receipts keep the password session id and drop the access token', async () => {
  const sessionId = '44444444-4444-4444-8444-444444444444';
  const payload = Buffer.from(JSON.stringify({ session_id: sessionId })).toString('base64url');
  const tokenB = `eyJhbGciOiJFUzI1NiJ9.${payload}.c2ln`;
  const code = 'auth-code-must-not-leak-cccc';
  const password = 'synthetic-password-must-not-leak';
  const env = {
    ARI_TEST_PROJECT_REF: 'odbcejsuuqdzhabjmozi',
    ARI_TEST_SUPABASE_URL: 'https://odbcejsuuqdzhabjmozi.supabase.co',
    ARI_TEST_PUBLISHABLE_KEY: 'publishable-key',
    ARI_TEST_EXPECTED_CLIENT_ID: CLIENT,
    ARI_TEST_JWKS_JSON: '{"keys":[]}',
    ARI_TEST_SYNTHETIC_PASSWORD: password,
    ARI_TEST_REDIRECT_URI: REDIRECT,
  };
  const captured = await captureProcessStreams(() =>
    runCli(['node', 'consent-harness.mjs', 'run'], {
      env,
      fetch: async (url, init) => {
        const href = `${url}`;
        if (href.includes('grant_type=password')) {
          return jsonResponse(200, { access_token: tokenB, token_type: 'bearer' });
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
        if (href.endsWith('/oauth/token')) return jsonResponse(500, { message: 'internal' });
        throw new Error('unexpected request');
      },
    }),
  );
  const receipt = jsonLine(captured.stdout, '"stage":"exchange"');
  assert.equal(captured.result, 4);
  assert.equal(receipt.probeRan, false);
  assert.equal(receipt.passwordSessionId, sessionId);
  assertStreamsClean(captured, [tokenB, code, password]);
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
  assert.match(cleanup, /probe\.tokenA\.source_session_id/);
  assert.match(cleanup, /passwordSessionId/);
  assert.match(cleanup, /Do not decode Token A/);
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
  let result;
  try {
    result = await fn();
  } finally {
    // setImmediate returns before a setTimeout(0) queued in the same turn.
    await new Promise((resolve) => {
      setImmediate(resolve);
    });
    await new Promise((resolve) => {
      setTimeout(resolve, 0);
    });
    process.stdout.write = stdoutWrite;
    process.stderr.write = stderrWrite;
    for (const method of CONSOLE_METHODS) console[method] = savedConsole[method];
    release();
  }
  return {
    result,
    stdout: stdoutChunks.join(''),
    stderr: stderrChunks.join(''),
    console: consoleChunks.join('\n'),
  };
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

  test('runCli retains safe auth, realtime, and openid receipt fields', async () => {
    const tokenA = 'token-a-value-must-not-leak-aaaa';
    const tokenB = 'token-b-value-must-not-leak-bbbb';
    const refreshA = 'refresh-a-must-not-leak-aaaa';
    const refreshB = 'refresh-b-must-not-leak-bbbb';
    const code = 'auth-code-must-not-leak-cccc';
    const password = 'synthetic-password-must-not-leak';
    const planted = 'planted/diagnostic-token-must-not-leak-zzzz';
    const closedJwt =
      'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJjbG9zZWQtcm93In0.c2lnLWNsb3NlZC1yb3ctc2VjcmV0';
    const env = {
      ARI_TEST_PROJECT_REF: 'odbcejsuuqdzhabjmozi',
      ARI_TEST_SUPABASE_URL: 'https://odbcejsuuqdzhabjmozi.supabase.co',
      ARI_TEST_PUBLISHABLE_KEY: 'publishable-key',
      ARI_TEST_EXPECTED_CLIENT_ID: CLIENT,
      ARI_TEST_JWKS_JSON: '{"keys":[]}',
      ARI_TEST_SYNTHETIC_PASSWORD: password,
      ARI_TEST_REDIRECT_URI: REDIRECT,
    };
    const fetchUntilToken = (tokenResponse) => async (url, init) => {
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
      return tokenResponse();
    };
    const probeRun = await captureProcessStreams(() =>
      runCli(['node', 'consent-harness.mjs', 'run'], {
        env,
        fetch: fetchUntilToken(() =>
          jsonResponse(200, {
            access_token: tokenA,
            refresh_token: refreshA,
            token_type: 'bearer',
          }),
        ),
        runProbe: async () => ({
          ok: false,
          exitCode: 4,
          reason: 'inconclusive',
          requests: 3,
          rows: [
            {
              id: 'L6-auth-get-user',
              credential: 'token_a',
              status: 403,
              error_code: 'session_not_found',
              verdict: 'deny',
              msg: planted,
              access_token: tokenA,
            },
            {
              id: 'L6-auth-put-user',
              credential: 'token_a',
              status: 403,
              error_code: planted,
              verdict: 'inconclusive',
            },
            {
              id: 'L5-realtime-token-a',
              credential: 'token_a',
              status: 'denied',
              verdict: 'deny',
              diagnostic: {
                event: 'phx_reply',
                topic: 'realtime:ari-probe-synthetic',
                ref: '1',
                payloadStatus: 'error',
                reason: 'unauthorized',
                code: 403,
                socketClose: false,
                timeoutClass: null,
                access_token: tokenA,
                response: planted,
              },
            },
            {
              id: 'L5-realtime-token-b',
              credential: 'token_b',
              status: 'transport',
              verdict: 'inconclusive',
              diagnostic: {
                reason: closedJwt,
                payloadStatus: 'closed',
                socketClose: true,
                code: 1006,
                access_token: tokenB,
              },
            },
            {
              id: 'L5-realtime-token-a-timeout',
              credential: 'token_a',
              status: 'transport',
              verdict: 'realtime_transport',
              diagnostic: {
                reason: null,
                payloadStatus: null,
                socketClose: false,
                timeoutClass: 'realtime_timeout',
                access_token: tokenA,
              },
            },
          ],
        }),
      }),
    );
    const probeReceipt = jsonLine(probeRun.stdout, '"packet":"ari-test-consent-probe"');
    const authRow = probeReceipt.probe.rows.find((row) => row.id === 'L6-auth-get-user');
    const unsafeAuth = probeReceipt.probe.rows.find((row) => row.id === 'L6-auth-put-user');
    const denied = probeReceipt.probe.rows.find((row) => row.id === 'L5-realtime-token-a');
    const closed = probeReceipt.probe.rows.find((row) => row.id === 'L5-realtime-token-b');
    assert.equal(authRow.error_code, 'session_not_found');
    assert.equal(authRow.verdict, 'deny');
    assert.equal(unsafeAuth.error_code, null);
    assert.deepEqual(denied.diagnostic, {
      reason: 'unauthorized',
      status: 'error',
      closeCodeClass: null,
    });
    assert.deepEqual(closed.diagnostic, {
      reason: null,
      status: 'closed',
      closeCodeClass: 'socket_close_1006',
    });
    const timedOut = probeReceipt.probe.rows.find(
      (row) => row.id === 'L5-realtime-token-a-timeout',
    );
    assert.equal(timedOut.diagnostic.closeCodeClass, 'realtime_timeout');
    assert.equal(timedOut.diagnostic.reason, null);
    assert.equal(JSON.stringify(probeReceipt).includes('access_token'), false);
    assertStreamsClean(probeRun, [
      tokenA,
      tokenB,
      refreshA,
      refreshB,
      code,
      password,
      planted,
      closedJwt,
    ]);

    const openidHeld = await captureProcessStreams(() =>
      runCli(['node', 'consent-harness.mjs', 'openid-negative'], {
        env,
        fetch: fetchUntilToken(() =>
          jsonResponse(403, {
            error: 'invalid_request',
            error_description: 'openid_scope_refused',
          }),
        ),
      }),
    );
    const held = jsonLine(openidHeld.stdout, '"label":"openid_negative"');
    assert.equal(held.reason, 'openid_rejected');
    assert.equal(held.policyMarker, 'openid_scope_refused');
    assert.equal(held.accessTokenPresent, false);
    assert.equal(held.idTokenPresent, false);
    assert.equal(held.hookInstalledByThisPacket, false);
    assert.equal(held.acceptance, false);
    assertStreamsClean(openidHeld, [tokenB, refreshB, code, password, planted]);

    const openidToken = await captureProcessStreams(() =>
      runCli(['node', 'consent-harness.mjs', 'openid-negative'], {
        env,
        fetch: fetchUntilToken(() =>
          jsonResponse(403, {
            error: 'invalid_request',
            error_description: 'openid_scope_refused',
            access_token: tokenA,
          }),
        ),
      }),
    );
    const withToken = jsonLine(openidToken.stdout, '"label":"openid_negative"');
    assert.equal(withToken.reason, 'access_token_present');
    assert.equal(withToken.policyMarker, 'openid_scope_refused');
    assert.equal(withToken.accessTokenPresent, true);
    assert.equal(withToken.idTokenPresent, false);
    assertStreamsClean(openidToken, [tokenA, tokenB, refreshB, code, password]);

    const openidGeneric = await captureProcessStreams(() =>
      runCli(['node', 'consent-harness.mjs', 'openid-negative'], {
        env,
        fetch: fetchUntilToken(() =>
          jsonResponse(400, {
            error: 'invalid_grant',
            error_description: planted,
          }),
        ),
      }),
    );
    const generic = jsonLine(openidGeneric.stdout, '"label":"openid_negative"');
    assert.equal(generic.reason, 'exchange_inconclusive');
    assert.equal(generic.policyMarker, null);
    assert.equal(generic.accessTokenPresent, false);
    assert.equal(generic.idTokenPresent, false);
    assert.notEqual(generic.reason, 'openid_rejected');
    assertStreamsClean(openidGeneric, [tokenB, refreshB, code, password, planted]);
  });

  test('runCli keeps a scrubbed realtime denial sentence and drops a planted jwt', async () => {
    const tokenA = 'token-a-value-must-not-leak-aaaa';
    const tokenB = 'token-b-value-must-not-leak-bbbb';
    const refreshA = 'refresh-a-must-not-leak-aaaa';
    const refreshB = 'refresh-b-must-not-leak-bbbb';
    const code = 'auth-code-must-not-leak-cccc';
    const password = 'synthetic-password-must-not-leak';
    const sentence =
      'Unauthorized: You do not have permissions to read from this Channel topic: ari-probe-synthetic';
    const plantedJwt =
      'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJwbGFudGVkLXJlYWx0aW1lIn0.c2lnbmF0dXJlLXBsYW50ZWQtc2VjcmV0';
    const longRun = 'abcdefghijklmnopqrstuvwxyz012345';
    const env = {
      ARI_TEST_PROJECT_REF: 'odbcejsuuqdzhabjmozi',
      ARI_TEST_SUPABASE_URL: 'https://odbcejsuuqdzhabjmozi.supabase.co',
      ARI_TEST_PUBLISHABLE_KEY: 'publishable-key',
      ARI_TEST_EXPECTED_CLIENT_ID: CLIENT,
      ARI_TEST_JWKS_JSON: '{"keys":[]}',
      ARI_TEST_SYNTHETIC_PASSWORD: password,
      ARI_TEST_REDIRECT_URI: REDIRECT,
    };
    const captured = await captureProcessStreams(() =>
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
          return jsonResponse(200, {
            access_token: tokenA,
            refresh_token: refreshA,
            token_type: 'bearer',
          });
        },
        runProbe: async () => ({
          ok: false,
          exitCode: 4,
          reason: 'inconclusive',
          requests: 1,
          rows: [
            {
              id: 'L5-realtime-token-a',
              credential: 'token_a',
              status: 'denied',
              verdict: 'deny',
              diagnostic: {
                event: 'phx_reply',
                topic: 'realtime:ari-probe-synthetic',
                ref: '1',
                payloadStatus: 'error',
                reason: `  ${sentence}   ${plantedJwt}\n${longRun}\u0001  `,
                code: null,
                socketClose: false,
                timeoutClass: null,
                access_token: tokenA,
              },
            },
          ],
        }),
      }),
    );
    const receipt = jsonLine(captured.stdout, '"packet":"ari-test-consent-probe"');
    const denied = receipt.probe.rows.find((row) => row.id === 'L5-realtime-token-a');
    assert.deepEqual(denied.diagnostic, {
      reason: sentence,
      status: 'error',
      closeCodeClass: null,
    });
    assert.equal(captured.stdout.includes(sentence), true);
    assert.equal(captured.stdout.includes(plantedJwt), false);
    assert.equal(captured.stderr.includes(plantedJwt), false);
    assert.equal(captured.stdout.includes(longRun), false);
    assert.equal(captured.stderr.includes(longRun), false);
    assertStreamsClean(captured, [tokenA, tokenB, refreshA, refreshB, code, password, plantedJwt]);
  });

  test('redacted Token A summary keeps session claims and drops the jwt, code, and verifier', async () => {
    const sourceSessionId = '22222222-2222-4222-8222-222222222222';
    const sessionId = '33333333-3333-4333-8333-333333333333';
    const agentId = 'hook-only-agent-parameter';
    const decoyClientId = 'decoy-client-must-not-bind';
    const decoyAgentId = 'decoy-agent-must-not-bind';
    const decoySourceSessionId = '55555555-5555-4555-8555-555555555555';
    const refreshA = 'refresh-a-must-not-leak-aaaa';
    const code = 'auth-code-must-not-leak-cccc';
    const password = 'synthetic-password-must-not-leak';
    const subject = '11111111-1111-4111-8111-111111111111';
    const issuer = 'https://odbcejsuuqdzhabjmozi.supabase.co/auth/v1';
    const unsignedJwt = (claims) => {
      const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
      return `eyJhbGciOiJFUzI1NiJ9.${payload}.c2ln`;
    };
    const tokenA = unsignedJwt({
      iss: issuer,
      sub: subject,
      role: 'mcp_ingress',
      aud: RESOURCE,
      session_id: sessionId,
      source_session_id: sourceSessionId,
      agent_id: agentId,
      client_id: CLIENT,
      user_metadata: {
        client_id: decoyClientId,
        agent_id: decoyAgentId,
        session_id: sessionId,
        source_session_id: decoySourceSessionId,
      },
    });
    const tokenB = unsignedJwt({
      iss: issuer,
      sub: subject,
      role: 'authenticated',
      aud: 'authenticated',
    });
    const env = {
      ARI_TEST_PROJECT_REF: 'odbcejsuuqdzhabjmozi',
      ARI_TEST_SUPABASE_URL: 'https://odbcejsuuqdzhabjmozi.supabase.co',
      ARI_TEST_PUBLISHABLE_KEY: 'publishable-key',
      ARI_TEST_EXPECTED_CLIENT_ID: CLIENT,
      ARI_TEST_JWKS_JSON: '{"keys":[]}',
      ARI_TEST_SYNTHETIC_PASSWORD: password,
      ARI_TEST_REDIRECT_URI: REDIRECT,
    };
    let verifier = '';
    const captured = await captureProcessStreams(() =>
      runCli(['node', 'consent-harness.mjs', 'run'], {
        env,
        fetch: async (url, init) => {
          const href = `${url}`;
          if (href.includes('grant_type=password')) {
            return jsonResponse(200, { access_token: tokenB, token_type: 'bearer' });
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
            verifier = new URLSearchParams(init.body).get('code_verifier') ?? '';
            return jsonResponse(200, {
              access_token: tokenA,
              refresh_token: refreshA,
              token_type: 'bearer',
            });
          }
          throw new Error('unexpected request');
        },
      }),
    );
    assert.equal(verifier.length > 0, true);
    const receipt = jsonLine(captured.stdout, '"packet":"ari-test-consent-probe"');
    const summary = receipt.probe.tokenA;
    assert.equal(summary.role, 'mcp_ingress');
    assert.equal(summary.aud, RESOURCE);
    assert.equal(summary.iss, issuer);
    assert.equal(summary.sub, subject);
    assert.equal(summary.session_id, sessionId);
    assert.equal(summary.source_session_id, sourceSessionId);
    assert.notEqual(summary.source_session_id, summary.session_id);
    const cleanupSessionId = summary.source_session_id;
    assert.equal(cleanupSessionId, sourceSessionId);
    assert.notEqual(cleanupSessionId, summary.session_id);
    assert.notEqual(cleanupSessionId, decoySourceSessionId);
    assert.deepEqual(
      { client_id: summary.client_id, agent_id: summary.agent_id },
      { client_id: CLIENT, agent_id: agentId },
    );
    const receiptText = JSON.stringify(receipt);
    assert.equal(receiptText.includes(decoyClientId), false);
    assert.equal(receiptText.includes(decoyAgentId), false);
    assert.equal(receiptText.includes(decoySourceSessionId), false);
    assertStreamsClean(captured, [tokenA, tokenB, refreshA, code, verifier, password]);
  });

  test('Warden mutation: setTimeout console.log of token A before runProbe fails the sentinel scan', async () => {
    const tokenA = 'token-a-value-must-not-leak-aaaa';
    const tokenB = 'token-b-value-must-not-leak-bbbb';
    const refreshA = 'refresh-a-must-not-leak-aaaa';
    const refreshB = 'refresh-b-must-not-leak-bbbb';
    const code = 'auth-code-must-not-leak-cccc';
    const password = 'synthetic-password-must-not-leak';
    const env = {
      ARI_TEST_PROJECT_REF: 'odbcejsuuqdzhabjmozi',
      ARI_TEST_SUPABASE_URL: 'https://odbcejsuuqdzhabjmozi.supabase.co',
      ARI_TEST_PUBLISHABLE_KEY: 'publishable-key',
      ARI_TEST_EXPECTED_CLIENT_ID: CLIENT,
      ARI_TEST_JWKS_JSON: '{"keys":[]}',
      ARI_TEST_SYNTHETIC_PASSWORD: password,
      ARI_TEST_REDIRECT_URI: REDIRECT,
    };
    const captured = await captureProcessStreams(() =>
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
        },
        runProbe: async () => ({
          ok: false,
          exitCode: 3,
          reason: 'jwt_malformed',
          rows: [],
          requests: 0,
        }),
      }),
    );
    assert.equal(captured.result, 3);
    assertStreamsClean(captured, [tokenA, tokenB, refreshA, refreshB, code, password]);
  });

  test('capture drains a deferred console.log before restoring streams', async () => {
    const marker = 'deferred-console-marker';
    const captured = await captureProcessStreams(async () => {
      setTimeout(() => console.log(marker), 0);
      return 'done';
    });
    assert.equal(captured.result, 'done');
    assert.equal(captured.console.includes(marker), true);
  });

  test('capture restores stdout, stderr, and console after rejection', async () => {
    const stdoutWrite = process.stdout.write;
    const stderrWrite = process.stderr.write;
    const savedConsole = Object.fromEntries(
      CONSOLE_METHODS.map((method) => [method, console[method]]),
    );
    await assert.rejects(
      captureProcessStreams(async () => {
        throw new Error('probe_rejected');
      }),
      /probe_rejected/,
    );
    assert.equal(process.stdout.write, stdoutWrite);
    assert.equal(process.stderr.write, stderrWrite);
    for (const method of CONSOLE_METHODS) assert.equal(console[method], savedConsole[method]);
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
