/**
 * Loopback consent and code exchange for the controller host.
 * plan, redact, and listenOnce do not dial a network. performConsent,
 * exchangeAuthorizationCode, runConsentExchange, and runOpenIdNegative dial
 * only through the fetch function the caller passes. This packet does not
 * install a hook. Do not put owner keys, refresh tokens, access tokens,
 * authorization codes, or verifiers in a URL, log, channel, or artifact.
 */
import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';

export const FORBIDDEN_PROJECT_REF = 'lygftpbjgqgvuunkwnxf';
export const DISCOVERY = Object.freeze({
  oauthAuthorizationServer: '/.well-known/oauth-authorization-server',
  oidc: '/.well-known/openid-configuration',
  fetchedByThisPacket: false,
  pkce: 'S256',
  oidcDiscoveryDoesNotAuthorizeIdToken: true,
  note: 'OAuth AS metadata is the code+PKCE coverage note. OIDC discovery is recorded and not used to mint. An id_token in a token body fails the receipt.',
});

export const CONTROLS = Object.freeze([
  'a_mint',
  'auth_session_not_found',
  'openid_exchange_no_id_token',
  'unmapped_client_fails',
  'password_login_unchanged',
  'data_api_deny_with_b_positive',
  'mcp_edge_downstream_credential_unresolved',
]);

const TOKEN_KEYS = new Set([
  'access_token',
  'refresh_token',
  'id_token',
  'provider_token',
  'provider_refresh_token',
]);

function parseJson(body) {
  if (typeof body !== 'string') return body;
  try {
    return JSON.parse(body);
  } catch {
    return undefined;
  }
}

export function isLoopbackHostname(hostname) {
  return hostname === '127.0.0.1' || hostname === 'localhost' || hostname === '::1';
}

export function assertRedirectUri(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    return { ok: false, reason: 'redirect_not_loopback' };
  }
  if (url.protocol !== 'http:' || !isLoopbackHostname(url.hostname)) {
    return { ok: false, reason: 'redirect_not_loopback' };
  }
  if (
    url.username !== '' ||
    url.password !== '' ||
    url.search !== '' ||
    url.hash !== '' ||
    url.pathname !== '/callback'
  ) {
    return { ok: false, reason: 'redirect_not_exact' };
  }
  return { ok: true, redirectUri: url.origin + url.pathname };
}

export function assertScopes(scopes, options = {}) {
  const allowOpenId = options.allowOpenId === true;
  if (!Array.isArray(scopes) || scopes.length === 0) {
    return { ok: false, reason: 'scope_not_configured' };
  }
  if (scopes.some((item) => typeof item !== 'string' || item.length === 0)) {
    return { ok: false, reason: 'scope_not_configured' };
  }
  const openidSent = scopes.some((item) => item.toLowerCase() === 'openid');
  if (openidSent && !allowOpenId) {
    return { ok: false, reason: 'openid_scope_refused' };
  }
  return { ok: true, scope: scopes.join(' '), openidSent };
}

export function createPkce() {
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
  return { codeVerifier, codeChallenge, codeChallengeMethod: 'S256' };
}

export function buildAuthorizeUrl(input) {
  if (`${input.authorizeEndpoint ?? ''} ${input.resource ?? ''}`.includes(FORBIDDEN_PROJECT_REF)) {
    return { ok: false, reason: 'forbidden_target' };
  }
  const openidNegative = input.label === 'openid_negative';
  const redirect = assertRedirectUri(input.redirectUri);
  if (!redirect.ok) return redirect;
  const scopes = assertScopes(input.scopes, { allowOpenId: openidNegative });
  if (!scopes.ok) return scopes;
  if (typeof input.clientId !== 'string' || input.clientId.length === 0) {
    return { ok: false, reason: 'oauth_client_id_required' };
  }
  if (typeof input.resource !== 'string' || input.resource.length === 0) {
    return { ok: false, reason: 'mcp_resource_required' };
  }
  if (typeof input.codeChallenge !== 'string' || input.codeChallenge.length === 0) {
    return { ok: false, reason: 'pkce_challenge_required' };
  }
  let authorize;
  try {
    authorize = new URL(input.authorizeEndpoint);
  } catch {
    return { ok: false, reason: 'authorize_endpoint_unreadable' };
  }
  authorize.searchParams.set('response_type', 'code');
  authorize.searchParams.set('client_id', input.clientId);
  authorize.searchParams.set('redirect_uri', redirect.redirectUri);
  authorize.searchParams.set('scope', scopes.scope);
  authorize.searchParams.set('code_challenge', input.codeChallenge);
  authorize.searchParams.set('code_challenge_method', 'S256');
  authorize.searchParams.set('resource', input.resource);
  if (typeof input.state === 'string' && input.state.length > 0) {
    authorize.searchParams.set('state', input.state);
  }
  return {
    ok: true,
    url: authorize.toString(),
    ...(openidNegative ? { label: 'openid_negative', openidSent: true } : {}),
  };
}

export function buildOpenIdNegativeAuthorizeUrl(input) {
  const scopes = Array.isArray(input.scopes) ? input.scopes : ['openid'];
  const hasOpenId = scopes.some(
    (item) => typeof item === 'string' && item.toLowerCase() === 'openid',
  );
  if (!hasOpenId) {
    return {
      ok: false,
      reason: 'openid_negative_scope_missing',
      label: 'openid_negative',
      openidSent: false,
    };
  }
  return buildAuthorizeUrl({ ...input, scopes, label: 'openid_negative' });
}

export function redactCallback(value) {
  let url;
  try {
    url = new URL(value, 'http://127.0.0.1');
  } catch {
    return { ok: false, reason: 'callback_unreadable' };
  }
  if (!isLoopbackHostname(url.hostname)) return { ok: false, reason: 'redirect_not_loopback' };
  const keys = [...url.searchParams.keys()];
  return {
    ok: true,
    hasCode: url.searchParams.has('code'),
    hasToken: keys.some((key) => /token/iu.test(key)),
  };
}

export function redactTokenBody(body) {
  const parsed = parseJson(body);
  if (
    parsed === undefined ||
    parsed === null ||
    typeof parsed !== 'object' ||
    Array.isArray(parsed)
  ) {
    return { ok: false, reason: 'token_body_unreadable', revocationClaimed: false };
  }
  const keys = Object.keys(parsed);
  if (keys.includes('id_token')) {
    return { ok: false, reason: 'id_token_present', revocationClaimed: false };
  }
  return {
    ok: true,
    reason: 'redacted',
    secretKeyNames: keys.filter((key) => TOKEN_KEYS.has(key)),
    revocationClaimed: false,
  };
}

export function redactResponseBody(body) {
  const parsed = parseJson(body);
  if (
    parsed === undefined ||
    parsed === null ||
    typeof parsed !== 'object' ||
    Array.isArray(parsed)
  ) {
    return { ok: false, reason: 'body_unreadable', revocationClaimed: false };
  }
  if (Object.hasOwn(parsed, 'id_token')) {
    return { ok: false, reason: 'id_token_present', revocationClaimed: false };
  }
  let hasCode = false;
  let hasToken = false;
  if (typeof parsed.redirect_url === 'string') {
    const callback = redactCallback(parsed.redirect_url);
    if (callback.ok) {
      hasCode = callback.hasCode === true;
      hasToken = callback.hasToken === true;
    } else {
      hasCode = /[?&]code=/u.test(parsed.redirect_url);
      hasToken = /token/iu.test(parsed.redirect_url);
    }
  }
  return {
    ok: true,
    reason: 'redacted',
    secretKeyNames: Object.keys(parsed).filter((key) => TOKEN_KEYS.has(key)),
    hasRedirect: typeof parsed.redirect_url === 'string',
    hasCode,
    hasToken,
    revocationClaimed: false,
  };
}

function baseReceipt(extra) {
  return {
    revocationClaimed: false,
    hookInstalledByThisPacket: false,
    acceptance: false,
    ...extra,
  };
}

function guardTarget(input) {
  if (typeof input.fetch !== 'function') return 'fetch_required';
  const haystack = `${input.authOrigin ?? ''} ${input.publishableKey ?? ''} ${input.resource ?? ''} ${input.clientId ?? ''}`;
  if (haystack.includes(FORBIDDEN_PROJECT_REF)) return 'forbidden_target';
  return null;
}

function userHeaders(input, json) {
  return {
    Authorization: `Bearer ${input.userAccessToken}`,
    apikey: input.publishableKey,
    ...(json ? { 'content-type': 'application/json' } : {}),
  };
}

async function readBody(response) {
  if (response === null || typeof response !== 'object' || typeof response.text !== 'function') {
    return '';
  }
  return response.text();
}

function headerValue(response, name) {
  const headers = response === null || typeof response !== 'object' ? undefined : response.headers;
  if (headers === null || headers === undefined || typeof headers.get !== 'function') return null;
  return headers.get(name);
}

function queryParam(value, key) {
  if (typeof value !== 'string' || value.length === 0) return null;
  try {
    return new URL(value, 'http://127.0.0.1').searchParams.get(key);
  } catch {
    return null;
  }
}

function idTokenIn(text) {
  const parsed = parseJson(text);
  return (
    parsed !== null &&
    typeof parsed === 'object' &&
    !Array.isArray(parsed) &&
    Object.hasOwn(parsed, 'id_token')
  );
}

function codeFrom(response, text) {
  const located = queryParam(headerValue(response, 'location'), 'code');
  if (located) return located;
  const parsed = parseJson(text);
  if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
    return queryParam(parsed.redirect_url, 'code');
  }
  return null;
}

function authorizationIdFrom(response, text) {
  const located = queryParam(headerValue(response, 'location'), 'authorization_id');
  if (located) return located;
  const parsed = parseJson(text);
  if (
    parsed !== null &&
    typeof parsed === 'object' &&
    !Array.isArray(parsed) &&
    typeof parsed.authorization_id === 'string' &&
    parsed.authorization_id.length > 0
  ) {
    return parsed.authorization_id;
  }
  return null;
}

async function consentWithCode(input) {
  const guard = guardTarget(input);
  if (guard) {
    return baseReceipt({
      ok: false,
      reason: guard,
      performed: false,
      hasCode: false,
      idTokenPresent: false,
      getAuthorization: false,
      postConsent: false,
    });
  }
  if (typeof input.authorizationId !== 'string' || input.authorizationId.length === 0) {
    return baseReceipt({
      ok: false,
      reason: 'authorization_id_required',
      performed: false,
      hasCode: false,
      idTokenPresent: false,
      getAuthorization: false,
      postConsent: false,
    });
  }
  if (typeof input.userAccessToken !== 'string' || input.userAccessToken.length === 0) {
    return baseReceipt({
      ok: false,
      reason: 'synthetic_session_required',
      performed: false,
      hasCode: false,
      idTokenPresent: false,
      getAuthorization: false,
      postConsent: false,
    });
  }
  let origin;
  try {
    origin = new URL(input.authOrigin);
  } catch {
    return baseReceipt({
      ok: false,
      reason: 'auth_origin_unreadable',
      performed: false,
      hasCode: false,
      idTokenPresent: false,
      getAuthorization: false,
      postConsent: false,
    });
  }
  const authorizationUrl = new URL(
    `/auth/v1/oauth/authorizations/${encodeURIComponent(input.authorizationId)}`,
    origin,
  );
  const consentUrl = new URL(
    `/auth/v1/oauth/authorizations/${encodeURIComponent(input.authorizationId)}/consent`,
    origin,
  );
  try {
    const got = await input.fetch(authorizationUrl, {
      method: 'GET',
      headers: userHeaders(input, false),
      redirect: 'manual',
    });
    const gotText = await readBody(got);
    const posted = await input.fetch(consentUrl, {
      method: 'POST',
      headers: userHeaders(input, true),
      body: JSON.stringify({ action: 'approve' }),
      redirect: 'manual',
    });
    const postedText = await readBody(posted);
    const idTokenPresent = idTokenIn(gotText) || idTokenIn(postedText);
    const code = codeFrom(posted, postedText) ?? codeFrom(got, gotText);
    return baseReceipt({
      ok: !idTokenPresent,
      reason: idTokenPresent ? 'id_token_present' : 'consent_performed',
      performed: true,
      label: 'synthetic_user_consent',
      getAuthorization: true,
      postConsent: true,
      getStatus: got.status,
      postStatus: posted.status,
      hasCode: typeof code === 'string' && code.length > 0,
      idTokenPresent,
      code,
    });
  } catch {
    return baseReceipt({
      ok: false,
      reason: 'consent_transport_failed',
      performed: false,
      hasCode: false,
      idTokenPresent: false,
      getAuthorization: false,
      postConsent: false,
    });
  }
}

export async function performConsent(input) {
  const consent = await consentWithCode(input);
  const receipt = { ...consent };
  delete receipt.code;
  return receipt;
}

export async function exchangeAuthorizationCode(input) {
  const guard = guardTarget(input);
  if (guard) {
    return baseReceipt({
      ok: false,
      reason: guard,
      exchanged: false,
      idTokenPresent: false,
      status: null,
    });
  }
  if (typeof input.codeVerifier !== 'string' || input.codeVerifier.length === 0) {
    return baseReceipt({
      ok: false,
      reason: 'pkce_verifier_required',
      exchanged: false,
      idTokenPresent: false,
      status: null,
    });
  }
  const challenge = createHash('sha256').update(input.codeVerifier).digest('base64url');
  if (typeof input.codeChallenge === 'string' && input.codeChallenge !== challenge) {
    return baseReceipt({
      ok: false,
      reason: 'pkce_s256_mismatch',
      exchanged: false,
      idTokenPresent: false,
      status: null,
      codeChallengeMethod: 'S256',
    });
  }
  if (typeof input.code !== 'string' || input.code.length === 0) {
    return baseReceipt({
      ok: false,
      reason: 'authorization_code_required',
      exchanged: false,
      idTokenPresent: false,
      status: null,
    });
  }
  const redirect = assertRedirectUri(input.redirectUri);
  if (!redirect.ok) {
    return baseReceipt({
      ok: false,
      reason: redirect.reason,
      exchanged: false,
      idTokenPresent: false,
      status: null,
    });
  }
  if (typeof input.clientId !== 'string' || input.clientId.length === 0) {
    return baseReceipt({
      ok: false,
      reason: 'oauth_client_id_required',
      exchanged: false,
      idTokenPresent: false,
      status: null,
    });
  }
  if (typeof input.resource !== 'string' || input.resource.length === 0) {
    return baseReceipt({
      ok: false,
      reason: 'mcp_resource_required',
      exchanged: false,
      idTokenPresent: false,
      status: null,
    });
  }
  let tokenUrl;
  try {
    tokenUrl = new URL('/auth/v1/oauth/token', input.authOrigin);
  } catch {
    return baseReceipt({
      ok: false,
      reason: 'auth_origin_unreadable',
      exchanged: false,
      idTokenPresent: false,
      status: null,
    });
  }
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: input.clientId,
    redirect_uri: redirect.redirectUri,
    code: input.code,
    code_verifier: input.codeVerifier,
    resource: input.resource,
  }).toString();
  try {
    const response = await input.fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        apikey: input.publishableKey,
      },
      body,
    });
    const text = await readBody(response);
    const redacted = redactResponseBody(text);
    return baseReceipt({
      ok: redacted.ok,
      reason: redacted.reason,
      exchanged: true,
      status: response.status,
      idTokenPresent: redacted.reason === 'id_token_present',
      secretKeyNames: redacted.secretKeyNames ?? [],
      codeChallengeMethod: 'S256',
    });
  } catch {
    return baseReceipt({
      ok: false,
      reason: 'exchange_transport_failed',
      exchanged: false,
      idTokenPresent: false,
      status: null,
    });
  }
}

export async function runConsentExchange(input) {
  const consent = await consentWithCode(input);
  const { code, ...consentReceipt } = consent;
  if (consent.ok !== true || typeof code !== 'string' || code.length === 0) {
    return {
      ...consentReceipt,
      consentPerformed: consent.performed === true,
      exchangePerformed: false,
      ok: false,
      reason: consent.ok === true ? 'authorization_code_missing' : consent.reason,
    };
  }
  const exchange = await exchangeAuthorizationCode({ ...input, code });
  const httpOk =
    typeof exchange.status === 'number' && exchange.status >= 200 && exchange.status < 300;
  return baseReceipt({
    ok: httpOk && exchange.ok === true && exchange.idTokenPresent !== true,
    reason: exchange.idTokenPresent === true ? 'id_token_present' : exchange.reason,
    label: 'synthetic_user_consent_exchange',
    consentPerformed: true,
    exchangePerformed: exchange.exchanged === true,
    getAuthorization: true,
    postConsent: true,
    hasCode: true,
    exchangeStatus: exchange.status,
    idTokenPresent: exchange.idTokenPresent === true,
    secretKeyNames: exchange.secretKeyNames ?? [],
    codeChallengeMethod: 'S256',
  });
}

function openIdReceipt(extra) {
  return baseReceipt({
    label: 'openid_negative',
    openidSent: false,
    rejectionStage: null,
    idTokenPresent: false,
    ...extra,
  });
}

export async function runOpenIdNegative(input) {
  const guard = guardTarget(input);
  if (guard) return openIdReceipt({ ok: false, reason: guard });
  const redirect = assertRedirectUri(input.redirectUri);
  if (!redirect.ok) return openIdReceipt({ ok: false, reason: redirect.reason });
  const pkce =
    typeof input.codeVerifier === 'string' && typeof input.codeChallenge === 'string'
      ? { codeVerifier: input.codeVerifier, codeChallenge: input.codeChallenge }
      : createPkce();
  const expectedChallenge = createHash('sha256').update(pkce.codeVerifier).digest('base64url');
  if (pkce.codeChallenge !== expectedChallenge) {
    return openIdReceipt({ ok: false, reason: 'pkce_s256_mismatch' });
  }
  let authorizeEndpoint;
  try {
    authorizeEndpoint = new URL('/auth/v1/oauth/authorize', input.authOrigin).toString();
  } catch {
    return openIdReceipt({ ok: false, reason: 'auth_origin_unreadable' });
  }
  const built = buildOpenIdNegativeAuthorizeUrl({
    authorizeEndpoint,
    clientId: input.clientId,
    redirectUri: redirect.redirectUri,
    scopes: input.scopes ?? ['openid', 'email'],
    resource: input.resource,
    codeChallenge: pkce.codeChallenge,
    state: input.state ?? 'openid-negative',
  });
  if (!built.ok) return openIdReceipt({ ok: false, reason: built.reason });
  let authorized;
  try {
    const response = await input.fetch(built.url, {
      method: 'GET',
      redirect: 'manual',
      headers: { apikey: input.publishableKey },
    });
    authorized = { response, text: await readBody(response) };
  } catch {
    return openIdReceipt({
      ok: false,
      reason: 'authorize_transport_failed',
      openidSent: true,
      rejectionStage: 'authorize',
    });
  }
  if (idTokenIn(authorized.text)) {
    return openIdReceipt({
      ok: false,
      reason: 'id_token_present',
      openidSent: true,
      rejectionStage: 'authorize',
      idTokenPresent: true,
    });
  }
  const authorizeError =
    authorized.response.status >= 400 ||
    queryParam(headerValue(authorized.response, 'location'), 'error') !== null;
  const authorizationId = authorizationIdFrom(authorized.response, authorized.text);
  if (authorizeError || authorizationId === null) {
    return openIdReceipt({
      ok: true,
      reason: 'openid_rejected',
      openidSent: true,
      rejectionStage: 'authorize',
      authorizeStatus: authorized.response.status,
    });
  }
  const consent = await consentWithCode({ ...input, authorizationId });
  if (consent.idTokenPresent === true) {
    return openIdReceipt({
      ok: false,
      reason: 'id_token_present',
      openidSent: true,
      rejectionStage: 'authorize',
      idTokenPresent: true,
    });
  }
  if (consent.ok !== true || typeof consent.code !== 'string' || consent.code.length === 0) {
    return openIdReceipt({
      ok: true,
      reason: 'openid_rejected',
      openidSent: true,
      rejectionStage: 'authorize',
      authorizeStatus: authorized.response.status,
    });
  }
  const exchange = await exchangeAuthorizationCode({
    ...input,
    code: consent.code,
    codeVerifier: pkce.codeVerifier,
    codeChallenge: pkce.codeChallenge,
    redirectUri: redirect.redirectUri,
  });
  if (exchange.idTokenPresent === true) {
    return openIdReceipt({
      ok: false,
      reason: 'id_token_present',
      openidSent: true,
      rejectionStage: 'exchange',
      idTokenPresent: true,
      exchangeStatus: exchange.status,
    });
  }
  const httpOk =
    typeof exchange.status === 'number' && exchange.status >= 200 && exchange.status < 300;
  if (httpOk && exchange.ok === true) {
    return openIdReceipt({
      ok: false,
      reason: 'openid_exchange_succeeded',
      openidSent: true,
      exchangeStatus: exchange.status,
    });
  }
  return openIdReceipt({
    ok: true,
    reason: 'openid_rejected',
    openidSent: true,
    rejectionStage: 'exchange',
    exchangeStatus: exchange.status,
    codeChallengeMethod: 'S256',
  });
}

export function authSessionControl(status, body) {
  const text = typeof body === 'string' ? body : JSON.stringify(body ?? '');
  if (/access_token|refresh_token|id_token/u.test(text)) {
    return { ok: false, reason: 'credential_in_body', revocationClaimed: false };
  }
  const parsed = parseJson(body);
  if (
    status === 403 &&
    parsed !== null &&
    typeof parsed === 'object' &&
    !Array.isArray(parsed) &&
    parsed.error === 'session_not_found'
  ) {
    return { ok: true, reason: 'session_not_found', revocationClaimed: false };
  }
  return { ok: false, reason: 'auth_session_control_missed', revocationClaimed: false };
}

export function planConsent() {
  return {
    packet: 'ari-test-consent',
    executed: false,
    hookInstalledByThisPacket: false,
    roleSqlAppliedByThisPacket: false,
    acceptance: false,
    revocationClaimed: false,
    tokenBCustody: false,
    redirectShape: 'http://127.0.0.1:<port>/callback',
    scopeConfiguredByController: true,
    openidScopeRefused: true,
    openidNegativeLabel: 'openid_negative',
    consentExchangeImplemented: true,
    discovery: DISCOVERY,
    controls: CONTROLS,
    forbiddenProjectRef: FORBIDDEN_PROJECT_REF,
  };
}

export function listenOnce({ port = 0 } = {}) {
  const server = createServer((request, response) => {
    let receipt = { ok: false, reason: 'callback_unreadable' };
    try {
      receipt = redactCallback(new URL(request.url ?? '/', 'http://127.0.0.1'));
    } catch {
      receipt = { ok: false, reason: 'callback_unreadable' };
    }
    server.receipt = receipt;
    response.writeHead(200, { 'content-type': 'text/plain', 'cache-control': 'no-store' });
    response.end(receipt.hasToken === true ? 'rejected' : 'received');
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      const address = server.address();
      resolve({
        port: typeof address === 'object' && address !== null ? address.port : port,
        receipt: () => server.receipt,
        close: () =>
          new Promise((done, fail) => {
            server.close((error) => (error ? fail(error) : done()));
          }),
      });
    });
  });
}

async function readStdin() {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 65_536) throw new Error('token_body_too_large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function main() {
  const command = process.argv[2] ?? 'plan';
  if (command === 'plan') {
    process.stdout.write(`${JSON.stringify(planConsent(), null, 2)}\n`);
    return;
  }
  if (command === 'redact') {
    try {
      const receipt = redactResponseBody(await readStdin());
      process.stdout.write(`${JSON.stringify(receipt)}\n`);
      process.exitCode = receipt.ok ? 0 : 4;
    } catch {
      process.stderr.write('token body was not redacted\n');
      process.exitCode = 2;
    }
    return;
  }
  process.stderr.write(
    'usage: node docs/evidence/ari-test-probe/consent-harness.mjs [plan|redact]\n',
  );
  process.exitCode = 2;
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(invokedPath).href) {
  main();
}
