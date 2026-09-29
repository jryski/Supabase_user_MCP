/**
 * Pure guards for the Ari TEST probe. No network and no credentials.
 * Token B is a positive control only. It is not an MCP credential.
 */

export const ALLOWED_PROJECT_REF = 'odbcejsuuqdzhabjmozi';
export const FORBIDDEN_PROJECT_REFS = Object.freeze(['lygftpbjgqgvuunkwnxf']);
export const INGRESS_ROLE = 'mcp_ingress';
export const MCP_RESOURCE = 'https://odbcejsuuqdzhabjmozi.supabase.co/mcp';
export const MARKER = 'ari-probe-marker-odbcejsuuqdzhabjmozi';
export const EXPECTED_CLIENT_ID = 'ari-probe-synthetic-client';
export const MCP_EDGE_ACCEPTANCE = 'downstream_credential_unresolved';
export const SYNTHETIC_EMAIL = 'ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid';
export const EXPECTED_ISSUER = `https://${ALLOWED_PROJECT_REF}.supabase.co/auth/v1`;
export const EXPECTED_ORIGIN = `https://${ALLOWED_PROJECT_REF}.supabase.co`;

export const SERVICE_ROLE_ENV_NAMES = Object.freeze([
  'SUPABASE_SERVICE_ROLE_KEY',
  'SUPABASE_SECRET_KEY',
  'SERVICE_ROLE_KEY',
  'SUPABASE_SERVICE_KEY',
]);

const REALTIME_TOPIC = 'ari-probe-synthetic';

export function assertTarget({ projectRef, supabaseUrl, allowLoopback = false }) {
  const haystack = `${projectRef ?? ''} ${supabaseUrl ?? ''}`;
  for (const forbidden of FORBIDDEN_PROJECT_REFS) {
    if (haystack.includes(forbidden)) {
      return { ok: false, exitCode: 2, reason: 'forbidden_target' };
    }
  }
  if (projectRef !== ALLOWED_PROJECT_REF) {
    return { ok: false, exitCode: 2, reason: 'target_not_ari_test' };
  }
  if (allowLoopback) {
    let parsed;
    try {
      parsed = new URL(supabaseUrl);
    } catch {
      return { ok: false, exitCode: 2, reason: 'url_mismatch' };
    }
    const loopback = parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost';
    if (!loopback || !['http:', 'https:'].includes(parsed.protocol)) {
      return { ok: false, exitCode: 2, reason: 'url_mismatch' };
    }
    return { ok: true };
  }
  if (supabaseUrl !== EXPECTED_ORIGIN) {
    return { ok: false, exitCode: 2, reason: 'url_mismatch' };
  }
  return { ok: true };
}

export function serviceRoleEnvPresent(env) {
  return SERVICE_ROLE_ENV_NAMES.filter((name) => {
    const value = env[name];
    return typeof value === 'string' && value.length > 0;
  });
}

export function decodeJwtClaims(token) {
  if (typeof token !== 'string') throw new Error('jwt_malformed');
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new Error('jwt_malformed');
  }
  let claims;
  try {
    claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch {
    throw new Error('jwt_malformed');
  }
  if (claims === null || typeof claims !== 'object' || Array.isArray(claims)) {
    throw new Error('jwt_payload');
  }
  return claims;
}

export function canonicalAudience(value) {
  try {
    const parsed = new URL(value);
    parsed.hash = '';
    parsed.username = '';
    parsed.password = '';
    parsed.protocol = parsed.protocol.toLowerCase();
    parsed.hostname = parsed.hostname.toLowerCase();
    if (
      (parsed.protocol === 'https:' && parsed.port === '443') ||
      (parsed.protocol === 'http:' && parsed.port === '80')
    ) {
      parsed.port = '';
    }
    const pathname = parsed.pathname === '/' ? '' : parsed.pathname.replace(/\/$/u, '');
    return `${parsed.protocol}//${parsed.host}${pathname}${parsed.search}`;
  } catch {
    return undefined;
  }
}

export function audienceList(aud) {
  if (typeof aud === 'string' && aud.length > 0) return [aud];
  if (Array.isArray(aud) && aud.every((value) => typeof value === 'string' && value.length > 0)) {
    return [...aud];
  }
  return [];
}

function issuerAllowed(claims) {
  return claims.iss === EXPECTED_ISSUER;
}

export function classifyTokenA(claims) {
  if (!issuerAllowed(claims)) return { ok: false, reason: 'token_a_issuer' };
  if (typeof claims.sub !== 'string' || claims.sub.length === 0) {
    return { ok: false, reason: 'token_a_sub' };
  }
  if (claims.role === 'authenticated') {
    return { ok: false, reason: 'role_flip_prerequisite_missing' };
  }
  if (claims.role === 'service_role' || claims.role === 'anon') {
    return { ok: false, reason: 'token_a_privileged_role' };
  }
  if (claims.role !== INGRESS_ROLE) return { ok: false, reason: 'ingress_role_mismatch' };
  const audiences = audienceList(claims.aud);
  const sole = audiences.length === 1 ? canonicalAudience(audiences[0]) : undefined;
  if (sole !== MCP_RESOURCE) return { ok: false, reason: 'aud_not_singleton_resource' };
  return { ok: true, sub: claims.sub };
}

export function classifyTokenB(claims) {
  if (!issuerAllowed(claims)) return { ok: false, reason: 'token_b_issuer' };
  if (claims.role !== 'authenticated') return { ok: false, reason: 'token_b_not_user_session' };
  if (!audienceList(claims.aud).includes('authenticated')) {
    return { ok: false, reason: 'token_b_aud' };
  }
  if (typeof claims.sub !== 'string' || claims.sub.length === 0) {
    return { ok: false, reason: 'token_b_sub' };
  }
  return {
    ok: true,
    sub: claims.sub,
    label: 'POSITIVE_CONTROL_NOT_MCP',
    wiredIntoMcp: false,
  };
}

export function publishableKeyRejected(key) {
  if (typeof key !== 'string' || key.length === 0) return 'publishable_key_missing';
  if (key.startsWith('sb_secret_')) return 'publishable_key_is_secret';
  const parts = key.split('.');
  if (parts.length !== 3) return undefined;
  try {
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (claims?.role === 'service_role') return 'publishable_key_is_service_role';
  } catch {
    return 'publishable_key_unreadable';
  }
  return undefined;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function containsMarker(body) {
  return typeof body === 'string' && body.includes(MARKER);
}

export function httpOutcome(status) {
  if (typeof status !== 'number' || !Number.isInteger(status)) return 'transport';
  if (status === 0) return 'transport';
  if (status === 429 || (status >= 300 && status < 400) || status >= 500) return 'inconclusive';
  return 'http';
}

function inconclusive() {
  return { verdict: 'inconclusive', stop: false };
}

function stopNoGo(verdict) {
  return { verdict, stop: true };
}

export function parseJson(body) {
  if (typeof body !== 'string') return undefined;
  try {
    return JSON.parse(body);
  } catch {
    return undefined;
  }
}

export function postgres42501(body) {
  const parsed = parseJson(body);
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return false;
  return parsed.code === '42501' || parsed.code === 42501;
}

const ROLE_DOES_NOT_EXIST = /role\s+(?:"[^"]+"|'[^']+'|…|\.{3})\s+does not exist/i;

/** Named failure: Postgres 22023 or `role "…" does not exist`. Not a permission denial. */
export function ingressRoleMissing(body) {
  if (typeof body !== 'string' || body.length === 0) return false;
  const parsed = parseJson(body);
  if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
    if (parsed.code === '22023' || parsed.code === 22023) return true;
  }
  return ROLE_DOES_NOT_EXIST.test(body);
}

function ingressRoleVerdict(surface) {
  if (surface === 'rest') return inconclusive();
  return { verdict: 'ingress_role_missing', stop: true };
}

export function authRowVerdict(status, mutation, body = '') {
  if (ingressRoleMissing(body)) return ingressRoleVerdict('auth');
  if (httpOutcome(status) !== 'http') return inconclusive();
  if (status >= 200 && status < 300) {
    return stopNoGo(mutation ? 'NO_GO_TOKEN_A_MUTATION' : 'NO_GO_TOKEN_A_AUTH_READ');
  }
  if (status === 401 || status === 403) return { verdict: 'deny', stop: false };
  return inconclusive();
}

export function tokenBAuthUserVerdict(status, body, expectedSub) {
  if (ingressRoleMissing(body)) return ingressRoleVerdict('auth');
  if (httpOutcome(status) !== 'http') return inconclusive();
  if (status !== 200) return stopNoGo('positive_control_missed');
  const parsed = parseJson(body);
  if (
    parsed === undefined ||
    parsed === null ||
    typeof parsed !== 'object' ||
    Array.isArray(parsed)
  ) {
    return inconclusive();
  }
  if (parsed.id !== expectedSub) return stopNoGo('positive_control_missed');
  return { verdict: 'positive_control', stop: false };
}

function markerRows(body) {
  const parsed = parseJson(body);
  if (!Array.isArray(parsed)) return undefined;
  return parsed.some(
    (row) =>
      row !== null && typeof row === 'object' && !Array.isArray(row) && row.marker === MARKER,
  );
}

function graphqlCollection(body) {
  const parsed = parseJson(body);
  if (
    parsed === undefined ||
    parsed === null ||
    typeof parsed !== 'object' ||
    Array.isArray(parsed)
  ) {
    return { parse: false };
  }
  const errors = Array.isArray(parsed.errors) ? parsed.errors : [];
  const data = parsed.data;
  const collection =
    data !== null && typeof data === 'object' && !Array.isArray(data)
      ? data.ariProbeMarkerCollection
      : undefined;
  const nodes = [];
  const edges = collection?.edges;
  if (Array.isArray(edges)) {
    for (const edge of edges) {
      if (edge?.node?.marker !== undefined) nodes.push(edge.node.marker);
    }
  }
  return {
    parse: true,
    errors,
    collectionPresent: collection !== undefined && collection !== null,
    nodes,
  };
}

export function dataRowVerdict(surface, kind, status, body) {
  if (ingressRoleMissing(body)) return ingressRoleVerdict(surface);
  if (httpOutcome(status) !== 'http') return inconclusive();
  if (kind === 'publishable') {
    return containsMarker(body)
      ? stopNoGo('baseline_not_isolated')
      : { verdict: 'no_marker', stop: false };
  }
  if (kind === 'token_a') return tokenADataVerdict(surface, status, body);
  if (kind === 'token_b') return tokenBDataVerdict(surface, status, body);
  return stopNoGo('unknown_kind');
}

function tokenADataVerdict(surface, status, body) {
  if (containsMarker(body)) return stopNoGo('NO_GO_TOKEN_A_GAINED_ACCESS');
  if (surface === 'rest') {
    if ((status === 401 || status === 403) && postgres42501(body)) {
      return { verdict: 'deny', stop: false };
    }
    return inconclusive();
  }
  if (surface === 'graphql') return tokenAGraphqlVerdict(status, body);
  if (surface === 'storage') return tokenAStorageVerdict(status, body);
  return inconclusive();
}

function tokenAGraphqlVerdict(status, body) {
  if (status !== 200) {
    if ((status === 401 || status === 403) && postgres42501(body)) {
      return { verdict: 'deny', stop: false };
    }
    return inconclusive();
  }
  const parsed = parseJson(body);
  if (
    parsed === undefined ||
    parsed === null ||
    typeof parsed !== 'object' ||
    Array.isArray(parsed)
  ) {
    return inconclusive();
  }
  const errors = parsed.errors;
  if (Array.isArray(errors) && graphqlErrorsNameCollection(errors)) {
    return { verdict: 'deny', stop: false };
  }
  const data = parsed.data;
  if (data !== null && typeof data === 'object' && !Array.isArray(data)) {
    if (data.ariProbeMarkerCollection == null) return { verdict: 'deny', stop: false };
  }
  return inconclusive();
}

function graphqlErrorsNameCollection(errors) {
  const text = JSON.stringify(errors).toLowerCase();
  return text.includes('ariprobemarkercollection') || text.includes('unknown field');
}

function tokenAStorageVerdict(status, body) {
  if (status === 404) return { verdict: 'deny', stop: false };
  if (status === 400 || status === 403) {
    const text = typeof body === 'string' ? body.toLowerCase() : '';
    if (
      text.includes('not_found') ||
      text.includes('object not found') ||
      text.includes('unauthorized')
    ) {
      return { verdict: 'deny', stop: false };
    }
  }
  return inconclusive();
}

function tokenBDataVerdict(surface, status, body) {
  if (status !== 200) return stopNoGo('positive_control_missed');
  if (surface === 'rest') {
    const matched = markerRows(body);
    if (matched === undefined) return inconclusive();
    return matched
      ? { verdict: 'positive_control', stop: false }
      : stopNoGo('positive_control_missed');
  }
  if (surface === 'graphql') {
    const graph = graphqlCollection(body);
    if (!graph.parse || graph.errors.length > 0) return inconclusive();
    return graph.nodes.includes(MARKER)
      ? { verdict: 'positive_control', stop: false }
      : stopNoGo('positive_control_missed');
  }
  if (surface === 'storage') {
    return typeof body === 'string' && body.trim() === MARKER
      ? { verdict: 'positive_control', stop: false }
      : stopNoGo('positive_control_missed');
  }
  return stopNoGo('unknown_kind');
}

export function storageSeedVerdict(status, body = '') {
  if (ingressRoleMissing(body)) return ingressRoleVerdict('storage');
  if (httpOutcome(status) !== 'http') return inconclusive();
  if ((status >= 200 && status < 300) || status === 409) {
    return { verdict: 'seeded', stop: false };
  }
  return inconclusive();
}

export function classifyRealtimeReply(message) {
  if (message === null || typeof message !== 'object') return 'transport';
  if (message.event !== 'phx_reply') return 'transport';
  const payload = message.payload;
  if (payload === null || typeof payload !== 'object') return 'transport';
  if (payload.status === 'ok') return 'ok';
  if (payload.status !== 'error') return 'transport';
  const response = payload.response;
  const reason = typeof response?.reason === 'string' ? response.reason.toLowerCase() : '';
  const code = response?.status ?? response?.code;
  if (
    reason.includes('unauthor') ||
    reason.includes('forbidden') ||
    reason === 'access_denied' ||
    code === 401 ||
    code === 403
  ) {
    return 'denied';
  }
  return 'transport';
}

export function realtimeVerdict(kind, status) {
  if (kind === 'token_a') {
    if (status === 'ok') return stopNoGo('NO_GO_TOKEN_A_GAINED_ACCESS');
    if (status === 'denied') return { verdict: 'deny', stop: false };
    return inconclusive();
  }
  if (kind === 'token_b') {
    if (status === 'ok') return { verdict: 'positive_control', stop: false };
    if (status === 'transport') return inconclusive();
    return stopNoGo('positive_control_missed');
  }
  return stopNoGo('unknown_kind');
}

export function mcpEdgeAcceptance(status, body) {
  const parsed = parseJson(body);
  if (
    status === 403 &&
    parsed !== null &&
    typeof parsed === 'object' &&
    !Array.isArray(parsed) &&
    Object.keys(parsed).length === 1 &&
    parsed.error === MCP_EDGE_ACCEPTANCE
  ) {
    return { ok: true, verdict: 'mcp_edge_accepted_fail_closed' };
  }
  return { ok: false, reason: 'token_a_mcp_edge_not_accepted' };
}

export function publicJwks(value) {
  const parsed = typeof value === 'string' ? parseJson(value) : value;
  if (
    parsed === undefined ||
    parsed === null ||
    typeof parsed !== 'object' ||
    Array.isArray(parsed)
  ) {
    return { ok: false, reason: 'jwks_unreadable' };
  }
  if (!Array.isArray(parsed.keys) || parsed.keys.length === 0) {
    return { ok: false, reason: 'jwks_unreadable' };
  }
  if (parsed.keys.some((key) => key !== null && typeof key === 'object' && key.d !== undefined)) {
    return { ok: false, reason: 'jwks_contains_private_key' };
  }
  return { ok: true, jwks: parsed };
}

export async function verifyTokenA(token, jwks, expectedClientId, now = Date.now()) {
  const loaded = publicJwks(jwks);
  if (!loaded.ok) return loaded;
  const { createLocalJWKSet, jwtVerify } = await import('jose');
  try {
    const { payload } = await jwtVerify(token, createLocalJWKSet(loaded.jwks), {
      issuer: EXPECTED_ISSUER,
      audience: MCP_RESOURCE,
      clockTolerance: 0,
      currentDate: new Date(now),
    });
    if (payload.client_id !== expectedClientId) return { ok: false, reason: 'token_a_client' };
    if (typeof payload.exp !== 'number') return { ok: false, reason: 'token_a_expired' };
    if (typeof payload.session_id !== 'string' || !UUID_PATTERN.test(payload.session_id)) {
      return { ok: false, reason: 'token_a_session' };
    }
    return { ok: true };
  } catch (error) {
    const code = error !== null && typeof error === 'object' ? error.code : undefined;
    if (code === 'ERR_JWT_EXPIRED') return { ok: false, reason: 'token_a_expired' };
    return { ok: false, reason: 'token_a_signature' };
  }
}

export function matrixBlocked(rows) {
  const allowed = new Set([
    'deny',
    'no_marker',
    'positive_control',
    'seeded',
    'mcp_edge_accepted_fail_closed',
  ]);
  return rows.find((row) => !allowed.has(row.verdict));
}

export function plan() {
  return {
    packet: 'ari-test-probe',
    projectRef: ALLOWED_PROJECT_REF,
    forbiddenProjectRefs: FORBIDDEN_PROJECT_REFS,
    mcpResource: MCP_RESOURCE,
    ingressRole: INGRESS_ROLE,
    roleFlipShipped: false,
    hookInstalledByThisPacket: false,
    tokenBLabel: 'POSITIVE_CONTROL_NOT_MCP',
    wiredIntoMcp: false,
    acceptance: false,
    realtimeTopic: REALTIME_TOPIC,
    rows: [
      'L7 baseline SECURITY DEFINER / PUBLIC EXECUTE before the run',
      'L0 Token A signature, expiry, client, and MCP-edge acceptance',
      'L6 Token B GET /auth/v1/user expects 200',
      'L6 GET /auth/v1/user with Token A expects 401 or 403',
      'L6 PUT /auth/v1/user with Token A; stop on 2xx',
      'L6 POST /auth/v1/factors with Token A; stop on 2xx',
      'L6 POST /auth/v1/logout with Token A; stop on 2xx',
      'L5 REST publishable, Token A deny, Token B positive',
      'L5 GraphQL publishable, Token A deny, Token B positive',
      'L5 Storage publishable, Token A deny, Token B positive',
      'L5 Realtime Token A deny, Token B positive',
    ],
  };
}

export { REALTIME_TOPIC };
