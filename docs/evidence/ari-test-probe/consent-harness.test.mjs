import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  authSessionControl,
  buildAuthorizeUrl,
  CONTROLS,
  createPkce,
  DISCOVERY,
  listenOnce,
  planConsent,
  redactCallback,
  redactTokenBody,
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
    authSessionControl(403, JSON.stringify({ error: 'session_not_found', access_token: 'x' })).reason,
    'credential_in_body',
  );
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
