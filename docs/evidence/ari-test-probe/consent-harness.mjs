/**
 * Loopback consent and code exchange for the controller host.
 * plan, redact, and listenOnce do not dial a network. performConsent,
 * exchangeAuthorizationCode, runConsentExchange, and runOpenIdNegative dial
 * only through the fetch function the caller passes. `run` keeps Token A and
 * Token B in memory and passes them to runProbe. It does not export or print
 * them. This packet does not install a hook. Do not put owner keys, refresh
 * tokens, access tokens, authorization codes, or verifiers in a URL, log,
 * channel, or artifact.
 */
import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import {
  ALLOWED_PROJECT_REF,
  EXPECTED_ORIGIN,
  MCP_RESOURCE,
  SERVICE_ROLE_ENV_NAMES,
  SYNTHETIC_EMAIL,
} from './decisions.mjs';
import { runProbe } from './probe.mjs';

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

const OAUTH_ERROR_NAME = /^[a-z0-9_]{1,64}$/u;
const SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

// Generic OAuth client errors are inconclusive. They are not an openid denial.
export const OPENID_POLICY_ERRORS = new Set([
  'access_denied',
  'invalid_client',
  'invalid_grant',
  'invalid_request',
  'invalid_scope',
  'unauthorized_client',
  'unsupported_grant_type',
  'unsupported_response_type',
]);
const HOOK_OPENID_MARKER = 'openid_scope_refused';

function oauthErrorName(parsed) {
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const error = parsed.error ?? parsed.error_code;
  if (typeof error !== 'string' || !OAUTH_ERROR_NAME.test(error)) return null;
  return error;
}

function oauthErrorFrom(response, text) {
  const fromLocation = queryParam(headerValue(response, 'location'), 'error');
  if (typeof fromLocation === 'string' && OAUTH_ERROR_NAME.test(fromLocation)) return fromLocation;
  return oauthErrorName(parseJson(text));
}

function jsonHasExactMarker(value, depth = 0) {
  if (value === HOOK_OPENID_MARKER) return true;
  if (depth > 4 || value === null || typeof value !== 'object') return false;
  const items = Array.isArray(value) ? value : Object.values(value);
  return items.some((item) => jsonHasExactMarker(item, depth + 1));
}

function responseHasHookMarker(response, text) {
  if (jsonHasExactMarker(parseJson(text))) return true;
  const location = headerValue(response, 'location');
  if (typeof location !== 'string') return false;
  for (const key of ['error', 'error_description', 'error_code', 'message']) {
    if (queryParam(location, key) === HOOK_OPENID_MARKER) return true;
  }
  return false;
}

function responseHasAccessToken(response, text) {
  const parsed = parseJson(text);
  if (
    parsed !== null &&
    typeof parsed === 'object' &&
    !Array.isArray(parsed) &&
    Object.hasOwn(parsed, 'access_token')
  ) {
    return true;
  }
  return queryParam(headerValue(response, 'location'), 'access_token') !== null;
}

function authorizeClientScopeRefusal(status, errorName, response, text) {
  return (
    typeof status === 'number' &&
    status < 500 &&
    errorName === 'invalid_scope' &&
    !idTokenIn(text) &&
    !responseHasAccessToken(response, text) &&
    !responseHasHookMarker(response, text)
  );
}

function exchangeHookDenial(exchange) {
  return (
    exchange.status === 403 &&
    exchange.hookMarker === true &&
    exchange.idTokenPresent !== true &&
    exchange.accessTokenPresent !== true
  );
}

function passwordSessionId(accessToken) {
  if (typeof accessToken !== 'string') return null;
  const parts = accessToken.split('.');
  if (parts.length < 2) return null;
  try {
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (claims === null || typeof claims !== 'object' || Array.isArray(claims)) return null;
    const sessionId = claims.session_id;
    if (typeof sessionId !== 'string' || !SESSION_ID.test(sessionId)) return null;
    return sessionId;
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
      oauthError: oauthErrorName(parseJson(postedText)) ?? oauthErrorName(parseJson(gotText)),
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

function secretResult(receipt) {
  return { accessToken: null, receipt };
}

async function exchangeWithSecrets(input) {
  const guard = guardTarget(input);
  if (guard) {
    return secretResult(
      baseReceipt({
        ok: false,
        reason: guard,
        exchanged: false,
        idTokenPresent: false,
        status: null,
      }),
    );
  }
  if (typeof input.codeVerifier !== 'string' || input.codeVerifier.length === 0) {
    return secretResult(
      baseReceipt({
        ok: false,
        reason: 'pkce_verifier_required',
        exchanged: false,
        idTokenPresent: false,
        status: null,
      }),
    );
  }
  const challenge = createHash('sha256').update(input.codeVerifier).digest('base64url');
  if (typeof input.codeChallenge === 'string' && input.codeChallenge !== challenge) {
    return secretResult(
      baseReceipt({
        ok: false,
        reason: 'pkce_s256_mismatch',
        exchanged: false,
        idTokenPresent: false,
        status: null,
        codeChallengeMethod: 'S256',
      }),
    );
  }
  if (typeof input.code !== 'string' || input.code.length === 0) {
    return secretResult(
      baseReceipt({
        ok: false,
        reason: 'authorization_code_required',
        exchanged: false,
        idTokenPresent: false,
        status: null,
      }),
    );
  }
  const redirect = assertRedirectUri(input.redirectUri);
  if (!redirect.ok) {
    return secretResult(
      baseReceipt({
        ok: false,
        reason: redirect.reason,
        exchanged: false,
        idTokenPresent: false,
        status: null,
      }),
    );
  }
  if (typeof input.clientId !== 'string' || input.clientId.length === 0) {
    return secretResult(
      baseReceipt({
        ok: false,
        reason: 'oauth_client_id_required',
        exchanged: false,
        idTokenPresent: false,
        status: null,
      }),
    );
  }
  if (typeof input.resource !== 'string' || input.resource.length === 0) {
    return secretResult(
      baseReceipt({
        ok: false,
        reason: 'mcp_resource_required',
        exchanged: false,
        idTokenPresent: false,
        status: null,
      }),
    );
  }
  let tokenUrl;
  try {
    tokenUrl = new URL('/auth/v1/oauth/token', input.authOrigin);
  } catch {
    return secretResult(
      baseReceipt({
        ok: false,
        reason: 'auth_origin_unreadable',
        exchanged: false,
        idTokenPresent: false,
        status: null,
      }),
    );
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
    const parsed = parseJson(text);
    const accessToken =
      parsed !== null &&
      typeof parsed === 'object' &&
      !Array.isArray(parsed) &&
      typeof parsed.access_token === 'string'
        ? parsed.access_token
        : null;
    return {
      accessToken,
      receipt: baseReceipt({
        ok: redacted.ok,
        reason: redacted.reason,
        exchanged: true,
        status: response.status,
        idTokenPresent: redacted.reason === 'id_token_present',
        oauthError: oauthErrorName(parsed),
        hookMarker: responseHasHookMarker(response, text),
        accessTokenPresent: accessToken !== null,
        secretKeyNames: redacted.secretKeyNames ?? [],
        codeChallengeMethod: 'S256',
      }),
    };
  } catch {
    return secretResult(
      baseReceipt({
        ok: false,
        reason: 'exchange_transport_failed',
        exchanged: false,
        idTokenPresent: false,
        status: null,
      }),
    );
  }
}

export async function exchangeAuthorizationCode(input) {
  const exchanged = await exchangeWithSecrets(input);
  return exchanged.receipt;
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

function openIdReceipt(extra, sessionId = null) {
  return baseReceipt({
    label: 'openid_negative',
    openidSent: false,
    rejectionStage: null,
    idTokenPresent: false,
    ...extra,
    ...(typeof sessionId === 'string' ? { passwordSessionId: sessionId } : {}),
  });
}

export async function runOpenIdNegative(input) {
  const sessionId = passwordSessionId(input.userAccessToken);
  const receipt = (extra) => openIdReceipt(extra, sessionId);
  const guard = guardTarget(input);
  if (guard) return receipt({ ok: false, reason: guard });
  const redirect = assertRedirectUri(input.redirectUri);
  if (!redirect.ok) return receipt({ ok: false, reason: redirect.reason });
  const pkce =
    typeof input.codeVerifier === 'string' && typeof input.codeChallenge === 'string'
      ? { codeVerifier: input.codeVerifier, codeChallenge: input.codeChallenge }
      : createPkce();
  const expectedChallenge = createHash('sha256').update(pkce.codeVerifier).digest('base64url');
  if (pkce.codeChallenge !== expectedChallenge) {
    return receipt({ ok: false, reason: 'pkce_s256_mismatch' });
  }
  let authorizeEndpoint;
  try {
    authorizeEndpoint = new URL('/auth/v1/oauth/authorize', input.authOrigin).toString();
  } catch {
    return receipt({ ok: false, reason: 'auth_origin_unreadable' });
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
  if (!built.ok) return receipt({ ok: false, reason: built.reason });
  let authorized;
  try {
    const response = await input.fetch(built.url, {
      method: 'GET',
      redirect: 'manual',
      headers: { apikey: input.publishableKey },
    });
    authorized = { response, text: await readBody(response) };
  } catch {
    return receipt({
      ok: false,
      reason: 'authorize_transport_failed',
      openidSent: true,
      rejectionStage: 'authorize',
    });
  }
  if (idTokenIn(authorized.text)) {
    return receipt({
      ok: false,
      reason: 'id_token_present',
      openidSent: true,
      rejectionStage: 'authorize',
      idTokenPresent: true,
    });
  }
  const authorizeStatus = authorized.response.status;
  const authorizeErrorName = oauthErrorFrom(authorized.response, authorized.text);
  const authorizationId = authorizationIdFrom(authorized.response, authorized.text);
  if (typeof authorizeStatus === 'number' && authorizeStatus >= 500) {
    return receipt({
      ok: false,
      reason: 'authorize_server_error',
      openidSent: true,
      rejectionStage: 'authorize',
      authorizeStatus,
    });
  }
  if (
    authorizeClientScopeRefusal(
      authorizeStatus,
      authorizeErrorName,
      authorized.response,
      authorized.text,
    )
  ) {
    return receipt({
      ok: true,
      reason: 'openid_refused_client_scope',
      openidSent: true,
      rejectionStage: 'authorize',
      authorizeStatus,
    });
  }
  if (authorizationId === null) {
    return receipt({
      ok: false,
      reason: 'authorize_inconclusive',
      openidSent: true,
      rejectionStage: 'authorize',
      authorizeStatus,
    });
  }
  const consent = await consentWithCode({ ...input, authorizationId });
  if (consent.idTokenPresent === true) {
    return receipt({
      ok: false,
      reason: 'id_token_present',
      openidSent: true,
      rejectionStage: 'authorize',
      idTokenPresent: true,
    });
  }
  if (consent.reason === 'consent_transport_failed') {
    return receipt({
      ok: false,
      reason: 'consent_transport_failed',
      openidSent: true,
      rejectionStage: 'consent',
    });
  }
  const consentStatus =
    typeof consent.postStatus === 'number' ? consent.postStatus : consent.getStatus;
  if (typeof consentStatus === 'number' && consentStatus >= 500) {
    return receipt({
      ok: false,
      reason: 'consent_server_error',
      openidSent: true,
      rejectionStage: 'consent',
      consentStatus,
    });
  }
  if (consent.ok !== true || typeof consent.code !== 'string' || consent.code.length === 0) {
    return receipt({
      ok: false,
      reason:
        consent.reason === 'authorization_id_required'
          ? 'authorize_inconclusive'
          : 'consent_inconclusive',
      openidSent: true,
      rejectionStage: consent.reason === 'authorization_id_required' ? 'authorize' : 'consent',
      consentStatus: consentStatus ?? null,
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
    return receipt({
      ok: false,
      reason: 'id_token_present',
      openidSent: true,
      rejectionStage: 'exchange',
      idTokenPresent: true,
      exchangeStatus: exchange.status,
    });
  }
  if (exchange.reason === 'exchange_transport_failed' || exchange.exchanged !== true) {
    return receipt({
      ok: false,
      reason:
        exchange.reason === 'exchange_transport_failed'
          ? 'exchange_transport_failed'
          : (exchange.reason ?? 'exchange_failed'),
      openidSent: true,
      rejectionStage: 'exchange',
      exchangeStatus: typeof exchange.status === 'number' ? exchange.status : null,
      codeChallengeMethod: 'S256',
    });
  }
  if (typeof exchange.status === 'number' && exchange.status >= 500) {
    return receipt({
      ok: false,
      reason: 'exchange_server_error',
      openidSent: true,
      rejectionStage: 'exchange',
      exchangeStatus: exchange.status,
      codeChallengeMethod: 'S256',
    });
  }
  const httpOk =
    typeof exchange.status === 'number' && exchange.status >= 200 && exchange.status < 300;
  if (httpOk && exchange.ok === true) {
    return receipt({
      ok: false,
      reason: 'openid_exchange_succeeded',
      openidSent: true,
      exchangeStatus: exchange.status,
    });
  }
  if (
    exchange.status === 403 &&
    exchange.hookMarker === true &&
    exchange.accessTokenPresent === true
  ) {
    return receipt({
      ok: false,
      reason: 'access_token_present',
      openidSent: true,
      rejectionStage: 'exchange',
      exchangeStatus: exchange.status,
      codeChallengeMethod: 'S256',
    });
  }
  if (exchangeHookDenial(exchange)) {
    return receipt({
      ok: true,
      reason: 'openid_rejected',
      openidSent: true,
      rejectionStage: 'exchange',
      exchangeStatus: exchange.status,
      codeChallengeMethod: 'S256',
    });
  }
  if (typeof exchange.oauthError === 'string' && OPENID_POLICY_ERRORS.has(exchange.oauthError)) {
    return receipt({
      ok: false,
      reason: 'exchange_inconclusive',
      openidSent: true,
      rejectionStage: 'exchange',
      exchangeStatus: typeof exchange.status === 'number' ? exchange.status : null,
      codeChallengeMethod: 'S256',
    });
  }
  return receipt({
    ok: false,
    reason: 'exchange_inconclusive',
    openidSent: true,
    rejectionStage: 'exchange',
    exchangeStatus: typeof exchange.status === 'number' ? exchange.status : null,
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
    inProcessProbe: true,
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

function remember(secrets, value) {
  if (typeof value === 'string' && value.length >= 8) secrets.push(value);
}

function scrub(receipt, secrets) {
  const text = JSON.stringify(receipt);
  for (const secret of secrets) {
    if (text.includes(secret)) {
      return {
        ok: false,
        reason: 'receipt_included_credential',
        packet: 'ari-test-consent-probe',
        hookInstalledByThisPacket: false,
        acceptance: false,
        revocationClaimed: false,
        exportedToEnv: false,
        probeRan: false,
      };
    }
  }
  return receipt;
}

function packetFlags(extra) {
  return {
    packet: 'ari-test-consent-probe',
    hookInstalledByThisPacket: false,
    acceptance: false,
    revocationClaimed: false,
    exportedToEnv: false,
    tokenBLabel: 'POSITIVE_CONTROL_NOT_MCP',
    tokenBSource: 'password_login',
    ...extra,
  };
}

function claimSummary(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const text = (key) => (typeof value[key] === 'string' ? value[key] : null);
  return {
    role: text('role'),
    aud: value.aud ?? null,
    iss: text('iss'),
    sub: text('sub'),
    session_id: text('session_id'),
    source_session_id: text('source_session_id'),
    agent_id: text('agent_id'),
    client_id: text('client_id'),
  };
}

function publicProbeSummary(probe) {
  if (probe === null || typeof probe !== 'object') {
    return { ok: false, reason: 'probe_unreadable' };
  }
  return {
    ok: probe.ok === true,
    exitCode: typeof probe.exitCode === 'number' ? probe.exitCode : null,
    reason: typeof probe.reason === 'string' ? probe.reason : null,
    requests: typeof probe.requests === 'number' ? probe.requests : 0,
    rows: Array.isArray(probe.rows)
      ? probe.rows.map((row) => ({
          id: row.id ?? null,
          credential: row.credential ?? null,
          status: row.status ?? null,
          verdict: row.verdict ?? null,
          label: row.label ?? null,
        }))
      : [],
    tokenA: claimSummary(probe.tokenA),
    tokenB: claimSummary(probe.tokenB),
  };
}

async function passwordLogin(input) {
  const url = new URL('/auth/v1/token', input.authOrigin);
  url.searchParams.set('grant_type', 'password');
  const response = await input.fetch(url, {
    method: 'POST',
    headers: {
      apikey: input.publishableKey,
      'content-type': 'application/json',
    },
    body: JSON.stringify({ email: SYNTHETIC_EMAIL, password: input.password }),
  });
  const text = await readBody(response);
  const parsed = parseJson(text);
  const accessToken =
    parsed !== null &&
    typeof parsed === 'object' &&
    !Array.isArray(parsed) &&
    typeof parsed.access_token === 'string'
      ? parsed.access_token
      : null;
  const redacted = redactResponseBody(text);
  const httpOk = response.status >= 200 && response.status < 300;
  return {
    accessToken,
    receipt: baseReceipt({
      ok: httpOk && redacted.ok === true && accessToken !== null,
      reason: redacted.reason === 'id_token_present' || !httpOk ? redacted.reason : 'redacted',
      label: 'POSITIVE_CONTROL_NOT_MCP',
      status: response.status,
      idTokenPresent: redacted.reason === 'id_token_present',
      secretKeyNames: redacted.secretKeyNames ?? [],
    }),
  };
}

async function startAuthorization(input) {
  const pkce = createPkce();
  let authorizeEndpoint;
  try {
    authorizeEndpoint = new URL('/auth/v1/oauth/authorize', input.authOrigin).toString();
  } catch {
    return {
      ok: false,
      reason: 'auth_origin_unreadable',
      pkce,
      authorizationId: null,
      idTokenPresent: false,
      status: null,
    };
  }
  const built = buildAuthorizeUrl({
    authorizeEndpoint,
    clientId: input.clientId,
    redirectUri: input.redirectUri,
    scopes: input.scopes ?? ['email'],
    resource: input.resource ?? MCP_RESOURCE,
    codeChallenge: pkce.codeChallenge,
    state: input.state ?? 'ari-probe',
  });
  if (!built.ok) {
    return {
      ok: false,
      reason: built.reason,
      pkce,
      authorizationId: null,
      idTokenPresent: false,
      status: null,
    };
  }
  try {
    const response = await input.fetch(built.url, {
      method: 'GET',
      redirect: 'manual',
      headers: { apikey: input.publishableKey },
    });
    const text = await readBody(response);
    const authorizationId = authorizationIdFrom(response, text);
    const idTokenPresent = idTokenIn(text);
    return {
      ok: typeof authorizationId === 'string' && authorizationId.length > 0 && !idTokenPresent,
      reason: idTokenPresent
        ? 'id_token_present'
        : authorizationId
          ? 'authorized'
          : 'authorization_id_missing',
      pkce,
      authorizationId,
      idTokenPresent,
      status: response.status,
    };
  } catch {
    return {
      ok: false,
      reason: 'authorize_transport_failed',
      pkce,
      authorizationId: null,
      idTokenPresent: false,
      status: null,
    };
  }
}

export async function runInProcessProbe(input) {
  const secrets = [];
  const fetchImpl = input.fetch;
  remember(secrets, input.password);
  remember(secrets, input.publishableKey);
  remember(secrets, input.env?.ARI_TEST_TOKEN_A);
  remember(secrets, input.env?.ARI_TEST_TOKEN_B);
  for (const name of SERVICE_ROLE_ENV_NAMES) remember(secrets, input.env?.[name]);
  const guard = guardTarget({
    ...input,
    fetch: fetchImpl,
    resource: input.resource ?? MCP_RESOURCE,
  });
  if (guard) {
    return scrub(
      packetFlags({ ok: false, reason: guard, stage: 'guard', probeRan: false }),
      secrets,
    );
  }
  if (input.projectRef !== ALLOWED_PROJECT_REF || input.authOrigin !== EXPECTED_ORIGIN) {
    return scrub(
      packetFlags({ ok: false, reason: 'target_not_ari_test', stage: 'guard', probeRan: false }),
      secrets,
    );
  }
  if (typeof input.clientId !== 'string' || input.clientId.length === 0) {
    return scrub(
      packetFlags({
        ok: false,
        reason: 'oauth_client_id_required',
        stage: 'guard',
        probeRan: false,
      }),
      secrets,
    );
  }
  if (typeof input.password !== 'string' || input.password.length === 0) {
    return scrub(
      packetFlags({
        ok: false,
        reason: 'synthetic_password_required',
        stage: 'password_login',
        probeRan: false,
      }),
      secrets,
    );
  }
  const started = await startAuthorization({ ...input, fetch: fetchImpl });
  remember(secrets, started.pkce?.codeVerifier);
  if (!started.ok) {
    return scrub(
      packetFlags({
        ok: false,
        reason: started.reason,
        stage: 'authorize',
        probeRan: false,
        openidSent: false,
        idTokenPresent: started.idTokenPresent === true,
      }),
      secrets,
    );
  }
  const login = await passwordLogin({ ...input, fetch: fetchImpl });
  remember(secrets, login.accessToken);
  if (login.accessToken === null || login.receipt.ok !== true) {
    return scrub(
      packetFlags({
        ok: false,
        reason:
          login.receipt.idTokenPresent === true ? 'id_token_present' : 'password_login_failed',
        stage: 'password_login',
        probeRan: false,
        idTokenPresent: login.receipt.idTokenPresent === true,
        tokenBInMemory: false,
      }),
      secrets,
    );
  }
  const residualSessionId = passwordSessionId(login.accessToken);
  const residualSession =
    typeof residualSessionId === 'string' ? { passwordSessionId: residualSessionId } : {};
  const consent = await consentWithCode({
    fetch: fetchImpl,
    authOrigin: input.authOrigin,
    authorizationId: started.authorizationId,
    userAccessToken: login.accessToken,
    publishableKey: input.publishableKey,
  });
  const code = typeof consent.code === 'string' ? consent.code : null;
  remember(secrets, code);
  if (consent.ok !== true || code === null) {
    return scrub(
      packetFlags({
        ok: false,
        reason: consent.ok === true ? 'authorization_code_missing' : consent.reason,
        stage: 'consent',
        consentPerformed: consent.performed === true,
        probeRan: false,
        idTokenPresent: consent.idTokenPresent === true,
        tokenBInMemory: true,
        ...residualSession,
      }),
      secrets,
    );
  }
  const exchanged = await exchangeWithSecrets({
    fetch: fetchImpl,
    authOrigin: input.authOrigin,
    clientId: input.clientId,
    redirectUri: input.redirectUri,
    resource: input.resource ?? MCP_RESOURCE,
    publishableKey: input.publishableKey,
    code,
    codeVerifier: started.pkce.codeVerifier,
    codeChallenge: started.pkce.codeChallenge,
  });
  const tokenA = exchanged.accessToken;
  const exchange = exchanged.receipt;
  remember(secrets, tokenA);
  if (typeof tokenA !== 'string' || exchange.ok !== true || exchange.idTokenPresent === true) {
    return scrub(
      packetFlags({
        ok: false,
        reason:
          exchange.idTokenPresent === true
            ? 'id_token_present'
            : (exchange.reason ?? 'exchange_failed'),
        stage: 'exchange',
        consentPerformed: true,
        exchangePerformed: exchange.exchanged === true,
        probeRan: false,
        idTokenPresent: exchange.idTokenPresent === true,
        tokenAInMemory: false,
        tokenBInMemory: true,
        codeChallengeMethod: 'S256',
        ...residualSession,
      }),
      secrets,
    );
  }
  const probeImpl = input.runProbe ?? runProbe;
  let probe;
  try {
    probe = await probeImpl({
      projectRef: input.projectRef,
      supabaseUrl: input.authOrigin,
      publishableKey: input.publishableKey,
      expectedClientId: input.clientId,
      jwks: input.jwks,
      tokenA,
      tokenB: login.accessToken,
      env: input.env ?? {},
      fetch: fetchImpl,
      allowLoopback: input.allowLoopback === true,
      mcpEdge: input.mcpEdge,
      joinRealtime: input.joinRealtime,
    });
  } catch {
    probe = { ok: false, exitCode: 4, reason: 'probe_failed', rows: [], requests: 0 };
  }
  return scrub(
    packetFlags({
      ok: probe?.ok === true,
      reason: typeof probe?.reason === 'string' ? probe.reason : 'probe_finished',
      stage: 'probe',
      order: ['authorize', 'password_login', 'consent', 'exchange', 'probe'],
      consentPerformed: true,
      exchangePerformed: true,
      probeRan: true,
      tokenAInMemory: true,
      tokenBInMemory: true,
      idTokenPresent: false,
      codeChallengeMethod: 'S256',
      openidSent: false,
      probe: publicProbeSummary(probe),
      ...(probe?.ok === true ? {} : residualSession),
    }),
    secrets,
  );
}

export async function runLabelledOpenIdNegative(input) {
  const secrets = [];
  remember(secrets, input.password);
  remember(secrets, input.publishableKey);
  remember(secrets, input.env?.ARI_TEST_TOKEN_A);
  remember(secrets, input.env?.ARI_TEST_TOKEN_B);
  let userAccessToken = typeof input.userAccessToken === 'string' ? input.userAccessToken : '';
  remember(secrets, userAccessToken);
  if (typeof input.password === 'string' && input.password.length > 0) {
    const login = await passwordLogin({ ...input, fetch: input.fetch });
    remember(secrets, login.accessToken);
    if (login.accessToken === null || login.receipt.idTokenPresent === true) {
      return scrub(
        packetFlags({
          ok: false,
          label: 'openid_negative',
          reason:
            login.receipt.idTokenPresent === true ? 'id_token_present' : 'password_login_failed',
          openidSent: false,
          probeRan: false,
          rejectionStage: null,
          idTokenPresent: login.receipt.idTokenPresent === true,
        }),
        secrets,
      );
    }
    userAccessToken = login.accessToken;
  }
  const result = await runOpenIdNegative({
    ...input,
    userAccessToken,
    resource: input.resource ?? MCP_RESOURCE,
    scopes: input.scopes ?? ['openid', 'email'],
  });
  return scrub(
    {
      ...result,
      probeRan: false,
      exportedToEnv: false,
      tokenAInMemory: false,
      acceptance: false,
      hookInstalledByThisPacket: false,
    },
    secrets,
  );
}

export function runConfigFromEnv(env) {
  return {
    authOrigin: env.ARI_TEST_SUPABASE_URL,
    publishableKey: env.ARI_TEST_PUBLISHABLE_KEY,
    clientId: env.ARI_TEST_EXPECTED_CLIENT_ID,
    redirectUri:
      typeof env.ARI_TEST_REDIRECT_URI === 'string' && env.ARI_TEST_REDIRECT_URI.length > 0
        ? env.ARI_TEST_REDIRECT_URI
        : 'http://127.0.0.1:8787/callback',
    resource: MCP_RESOURCE,
    projectRef: env.ARI_TEST_PROJECT_REF,
    jwks: env.ARI_TEST_JWKS_JSON,
    password: env.ARI_TEST_SYNTHETIC_PASSWORD,
    email: SYNTHETIC_EMAIL,
    env,
    allowLoopback: env.ARI_TEST_ALLOW_LOOPBACK === '1',
  };
}

function writeReceipt(receipt, stdout, stderr) {
  stdout.write(`${JSON.stringify(receipt)}\n`);
  if (receipt?.reason === 'receipt_included_credential') {
    stderr.write('receipt included a credential\n');
    return 2;
  }
  if (receipt?.ok === true) return 0;
  if (typeof receipt?.probe?.exitCode === 'number') return receipt.probe.exitCode;
  return 4;
}

export async function runCli(argv, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  const env = io.env ?? process.env;
  const fetchImpl = io.fetch ?? globalThis.fetch;
  const command = argv[2] ?? 'plan';
  if (command === 'plan') {
    stdout.write(`${JSON.stringify(planConsent(), null, 2)}\n`);
    return 0;
  }
  if (command === 'redact') {
    try {
      const receipt = redactResponseBody(await (io.readStdin ?? readStdin)());
      stdout.write(`${JSON.stringify(receipt)}\n`);
      return receipt.ok ? 0 : 4;
    } catch {
      stderr.write('token body was not redacted\n');
      return 2;
    }
  }
  if (command === 'run') {
    const receipt = await runInProcessProbe({
      ...runConfigFromEnv(env),
      fetch: fetchImpl,
      runProbe: io.runProbe,
      mcpEdge: io.mcpEdge,
      joinRealtime: io.joinRealtime,
    });
    return writeReceipt(receipt, stdout, stderr);
  }
  if (command === 'openid-negative') {
    const receipt = await runLabelledOpenIdNegative({
      ...runConfigFromEnv(env),
      fetch: fetchImpl,
    });
    return writeReceipt(receipt, stdout, stderr);
  }
  stderr.write(
    'usage: node docs/evidence/ari-test-probe/consent-harness.mjs [plan|redact|run|openid-negative]\n',
  );
  return 2;
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
  process.exitCode = await runCli(process.argv);
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(invokedPath).href) {
  main();
}
