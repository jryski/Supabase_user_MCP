/**
 * Pure guards for the Ari TEST probe. No network and no credentials.
 * Token B is a positive control only. It is not an MCP credential.
 */

export const ALLOWED_PROJECT_REF = 'odbcejsuuqdzhabjmozi';
export const FORBIDDEN_PROJECT_REFS = Object.freeze(['lygftpbjgqgvuunkwnxf']);
export const INGRESS_ROLE = 'mcp_ingress';
export const MCP_RESOURCE = 'https://odbcejsuuqdzhabjmozi.supabase.co/mcp';
export const MARKER = 'ari-probe-marker-odbcejsuuqdzhabjmozi';
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

export function containsMarker(body) {
  return typeof body === 'string' && body.includes(MARKER);
}

export function authRowVerdict(status, mutation) {
  const success = status >= 200 && status < 300;
  if (!success) return { verdict: 'deny', stop: false };
  if (mutation) return { verdict: 'NO_GO_TOKEN_A_MUTATION', stop: true };
  return { verdict: 'NO_GO_TOKEN_A_AUTH_READ', stop: true };
}

export function dataRowVerdict(kind, body) {
  const seen = containsMarker(body);
  if (kind === 'publishable') {
    return seen
      ? { verdict: 'baseline_not_isolated', stop: true }
      : { verdict: 'no_marker', stop: false };
  }
  if (kind === 'token_a') {
    return seen
      ? { verdict: 'NO_GO_TOKEN_A_GAINED_ACCESS', stop: true }
      : { verdict: 'deny', stop: false };
  }
  if (kind === 'token_b') {
    return seen
      ? { verdict: 'positive_control', stop: false }
      : { verdict: 'positive_control_missed', stop: true };
  }
  return { verdict: 'unknown_kind', stop: true };
}

export function realtimeVerdict(kind, status) {
  if (kind === 'token_a') {
    return status === 'ok'
      ? { verdict: 'NO_GO_TOKEN_A_GAINED_ACCESS', stop: true }
      : { verdict: 'deny', stop: false };
  }
  if (kind === 'token_b') {
    return status === 'ok'
      ? { verdict: 'positive_control', stop: false }
      : { verdict: 'positive_control_missed', stop: true };
  }
  return { verdict: 'unknown_kind', stop: true };
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
      'L6 GET /auth/v1/user with Token A',
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
