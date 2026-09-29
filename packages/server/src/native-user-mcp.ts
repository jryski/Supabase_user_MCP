import {
  fromSupabaseUrl,
  type JWTClaims,
  type SupabaseContext,
  type SupabaseEnv,
  withOAuthProtectedResource,
  withSupabase,
} from '@supabase/server';
import {
  audienceValues,
  canonicalizeResourceUri,
  DOWNSTREAM_CREDENTIAL_UNRESOLVED,
  extractServerControlledClientId,
  MAX_RESPONSE_BYTES,
  MAX_TOOL_EXECUTION_MS,
  RemoteOAuthClientIdSchema,
  RemotePrincipalIdSchema,
  userMetadataAttemptsAuthorization,
} from '@supabase-user-mcp/contracts';

/**
 * G2 native-user adapter.
 *
 * Token A is the inbound MCP bearer. `@supabase/server` 1.7.2 verifies it with
 * the stable nested form `withOAuthProtectedResource(withSupabase({ auth: 'user' }, …))`
 * against upstream Supabase Auth (issuer, audience, JWKS). That library also
 * builds an unused same-bearer user client and an unused admin client before
 * the handler runs. This adapter never calls either client.
 *
 * Token B, a distinct Data API credential, is unresolved on this adapter.
 * A verified Token A with no `onVerified` dispatch fails closed with
 * `downstream_credential_unresolved`.
 *
 * MCP-side check: `aud` must be one value, and that value must canonicalize
 * to the MCP resource. Jose matches any array entry, so extra audiences are
 * rejected here. Token A `role` must be the configured ingress role
 * `mcp_ingress`. `role=authenticated` is rejected. This module does not
 * create the Postgres role and does not install an Auth hook.
 *
 * When `expectedAgentId` is set, Token A must also carry that `agent_id`
 * and a signed `source_session_id`: a non-nil UUID distinct from the decoy
 * `session_id`. `onVerified` runs only after those checks. Omitting it
 * keeps the default 403.
 */
export const SUPABASE_SERVER_PIN = '1.7.2' as const;
export const MCP_INGRESS_ROLE = 'mcp_ingress' as const;
const NIL_SESSION_ID = '00000000-0000-0000-0000-000000000000';
export const SUPABASE_JS_PIN = '2.117.2' as const;
export const NATIVE_USER_MCP_CONFIG_ERROR = 'NATIVE_USER_MCP_INVALID_CONFIGURATION' as const;

/** Not a project secret. Satisfies library admin-client construction only. */
const LIBRARY_ADMIN_CONSTRUCTION_PLACEHOLDER = 'g2-unused-admin-client-not-a-credential';

export const NATIVE_USER_MCP_CREDENTIAL_SPLIT = Object.freeze({
  tokenA: 'upstream-supabase-auth-jwt' as const,
  tokenB: 'unresolved' as const,
  dataApi: DOWNSTREAM_CREDENTIAL_UNRESOLVED,
  sameBearerPassthrough: false as const,
  liveRevocation: 'not-implemented' as const,
});

const JSON_HEADERS = Object.freeze({
  'content-type': 'application/json',
  'cache-control': 'no-store',
});

export class NativeUserMcpConfigError extends Error {
  readonly code = NATIVE_USER_MCP_CONFIG_ERROR;

  constructor() {
    super(NATIVE_USER_MCP_CONFIG_ERROR);
    this.name = 'NativeUserMcpConfigError';
  }
}

export interface VerifiedNativeUserPrincipal {
  readonly sub: string;
  readonly clientId: string;
  readonly sessionId: string;
  readonly sourceSessionId: string;
  readonly agentId: string;
  readonly issuer: string;
  readonly resourceServer: string;
}

/**
 * Invoked only after Token A verifies. The request still carries Token A.
 * Callers must not copy that bearer into a Data API client.
 */
export type VerifiedNativeUserDispatch = (
  principal: VerifiedNativeUserPrincipal,
  request: Request,
) => Response | Promise<Response>;

export interface NativeUserMcpConfig {
  /** Public MCP resource URL. Bound as the Token A audience. */
  readonly resourceServer: string;
  /** Supabase project URL. Issuer is `{url}/auth/v1` via `fromSupabaseUrl`. */
  readonly supabaseUrl: string;
  /** Server-controlled OAuth client id required on Token A. */
  readonly expectedClientId: string;
  /**
   * Postgres role claim required on Token A. Only `mcp_ingress` is accepted.
   * `authenticated` is rejected as configuration and as a token role.
   */
  readonly ingressRole: string;
  /**
   * Publishable key used only so `@supabase/server` can construct its unused
   * user client. The handler does not send it.
   */
  readonly publishableKey: string;
  /** Inline asymmetric JWKS, or an https (or loopback http) JWKS URL. */
  readonly jwks: Exclude<SupabaseEnv['jwks'], null>;
  /**
   * When set, `agent_id` must match and `source_session_id` must be a
   * non-decoy UUID. Required when `onVerified` is set.
   */
  readonly expectedAgentId?: string;
  /**
   * Optional dispatch after verification. Absent means the handler returns
   * 403 `downstream_credential_unresolved`.
   */
  readonly onVerified?: VerifiedNativeUserDispatch;
}

interface ResolvedNativeUserMcpConfig {
  readonly resourceServer: string;
  readonly issuer: string;
  readonly expectedClientId: string;
  readonly ingressRole: typeof MCP_INGRESS_ROLE;
  readonly env: SupabaseEnv;
  readonly expectedAgentId: string | undefined;
  readonly onVerified: VerifiedNativeUserDispatch | undefined;
}

export function nativeUserMcpIssuer(supabaseUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(supabaseUrl);
  } catch {
    invalidConfig();
  }
  if (
    parsed.protocol !== 'https:' ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.hash !== '' ||
    parsed.search !== ''
  ) {
    invalidConfig();
  }
  return fromSupabaseUrl(parsed.origin + parsed.pathname.replace(/\/$/u, ''));
}

function invalidConfig(): never {
  throw new NativeUserMcpConfigError();
}

const ADAPTER_AUTH_ERROR = 'invalid_token' as const;
const LIBRARY_ERROR_CODE_HEADER = 'x-supabase-server-error';

function jsonResponse(status: number, error: string): Response {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: JSON_HEADERS,
  });
}

function isAdapterAuthBody(body: string): boolean {
  try {
    const parsed = JSON.parse(body) as unknown;
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return false;
    const record = parsed as Record<string, unknown>;
    return Object.keys(record).length === 1 && record.error === ADAPTER_AUTH_ERROR;
  } catch {
    return false;
  }
}

/**
 * `@supabase/server` 1.7.2 still returns `{ code, message }` on auth failure
 * when `errors.detailed` is false, including the `[@supabase/server]` message
 * prefix, and sets `x-supabase-server-error`. Map every such 401 onto the
 * adapter body `{ error: "invalid_token" }`.
 */
async function normalizeLibraryAuthFailure(response: Response): Promise<Response> {
  if (response.status !== 401) return response;
  const body = await response.text();
  if (isAdapterAuthBody(body)) {
    return new Response(body, { status: 401, headers: response.headers });
  }
  const headers = new Headers(response.headers);
  headers.delete('content-length');
  headers.delete(LIBRARY_ERROR_CODE_HEADER);
  headers.set('content-type', 'application/json');
  headers.set('cache-control', 'no-store');
  return new Response(JSON.stringify({ error: ADAPTER_AUTH_ERROR }), {
    status: 401,
    headers,
  });
}

function isJwtShaped(value: string): boolean {
  return value.split('.').length === 3;
}

function isLoopbackHttp(url: URL): boolean {
  if (url.protocol !== 'http:') return false;
  return url.hostname === 'localhost' || url.hostname === '::1' || url.hostname.startsWith('127.');
}

function sessionIdRejected(value: unknown): boolean {
  if (typeof value !== 'string') return true;
  if (value.length === 0 || value.trim().length === 0 || value.trim() !== value) return true;
  if (value.toLowerCase() === NIL_SESSION_ID) return true;
  return !RemotePrincipalIdSchema.safeParse(value).success;
}

function assertIngressRole(value: string): typeof MCP_INGRESS_ROLE {
  if (value !== MCP_INGRESS_ROLE) invalidConfig();
  return MCP_INGRESS_ROLE;
}

function assertAgentId(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  if (value.length === 0 || value.length > 128 || value !== value.trim() || /\s/u.test(value)) {
    invalidConfig();
  }
  if (isJwtShaped(value)) invalidConfig();
  return value;
}

function assertPublishableKey(value: string): string {
  const key = value.trim();
  if (key.length === 0 || key.length > 256 || key !== value || isJwtShaped(key)) invalidConfig();
  if (/\s/u.test(key)) invalidConfig();
  return key;
}

function assertJwks(jwks: Exclude<SupabaseEnv['jwks'], null>): Exclude<SupabaseEnv['jwks'], null> {
  if (jwks instanceof URL) {
    if (jwks.username !== '' || jwks.password !== '' || jwks.hash !== '') invalidConfig();
    if (jwks.protocol === 'https:' || isLoopbackHttp(jwks)) return jwks;
    invalidConfig();
  }
  if (!Array.isArray(jwks.keys) || jwks.keys.length === 0) invalidConfig();
  for (const key of jwks.keys) {
    if (key.kty === 'oct') invalidConfig();
    if (key.alg === 'HS256' || key.alg === 'HS384' || key.alg === 'HS512') invalidConfig();
    if (key.kty !== 'EC' && key.kty !== 'RSA' && key.kty !== 'OKP') invalidConfig();
  }
  return jwks;
}

function resolveNativeUserMcpConfig(config: NativeUserMcpConfig): ResolvedNativeUserMcpConfig {
  let resourceServer: string;
  let supabaseUrl: URL;
  try {
    resourceServer = canonicalizeResourceUri(config.resourceServer);
    supabaseUrl = new URL(config.supabaseUrl);
  } catch {
    invalidConfig();
  }
  if (
    supabaseUrl.protocol !== 'https:' ||
    supabaseUrl.username !== '' ||
    supabaseUrl.password !== '' ||
    supabaseUrl.hash !== '' ||
    supabaseUrl.search !== ''
  ) {
    invalidConfig();
  }
  const expectedClientId = RemoteOAuthClientIdSchema.safeParse(config.expectedClientId);
  if (!expectedClientId.success) invalidConfig();
  const ingressRole = assertIngressRole(config.ingressRole);
  const expectedAgentId = assertAgentId(config.expectedAgentId);
  if (config.onVerified !== undefined && expectedAgentId === undefined) invalidConfig();
  const issuer = nativeUserMcpIssuer(config.supabaseUrl);
  const env: SupabaseEnv = {
    url: supabaseUrl.origin + supabaseUrl.pathname.replace(/\/$/u, ''),
    publishableKeys: { default: assertPublishableKey(config.publishableKey) },
    secretKeys: { default: LIBRARY_ADMIN_CONSTRUCTION_PLACEHOLDER },
    jwks: assertJwks(config.jwks),
  };
  return {
    resourceServer,
    issuer,
    expectedClientId: expectedClientId.data,
    ingressRole,
    env,
    expectedAgentId,
    onVerified: config.onVerified,
  };
}

function canonicalAudience(value: string): string | undefined {
  try {
    return canonicalizeResourceUri(value);
  } catch {
    return undefined;
  }
}

function explicitResourceMismatch(claims: JWTClaims, resourceServer: string): boolean {
  if (typeof claims.resource !== 'string' || claims.resource.length === 0) return false;
  return canonicalAudience(claims.resource) !== resourceServer;
}

function mcpClaimsRejected(claims: JWTClaims, expected: ResolvedNativeUserMcpConfig): boolean {
  if (!RemotePrincipalIdSchema.safeParse(claims.sub).success) return true;
  // Require the configured isolated ingress role. A Data API `authenticated`
  // bearer is rejected here and cannot pass this check.
  if (claims.role === 'authenticated') return true;
  if (claims.role !== expected.ingressRole) return true;
  if (typeof claims.exp !== 'number' || !Number.isSafeInteger(claims.exp)) return true;
  if (claims.iss !== expected.issuer) return true;
  const audiences = audienceValues(claims.aud);
  // Jose accepts an `aud` array when any entry matches the resource, so
  // `[resource, other]` passes the library. Require a true singleton whose
  // one value canonicalizes to the MCP resource.
  const soleAudience = audiences.length === 1 ? audiences[0] : undefined;
  if (soleAudience === undefined || canonicalAudience(soleAudience) !== expected.resourceServer) {
    return true;
  }
  if (explicitResourceMismatch(claims, expected.resourceServer)) return true;
  if (userMetadataAttemptsAuthorization(claims)) return true;
  if (extractServerControlledClientId(claims) !== expected.expectedClientId) return true;
  if (sessionIdRejected(claims.session_id)) return true;
  if (expected.expectedAgentId !== undefined) {
    if (claims.agent_id !== expected.expectedAgentId) return true;
    if (sessionIdRejected(claims.source_session_id)) return true;
    if (claims.source_session_id === claims.session_id) return true;
  }
  return false;
}

function verifiedPrincipal(
  claims: JWTClaims,
  expected: ResolvedNativeUserMcpConfig,
): VerifiedNativeUserPrincipal {
  const sessionId = claims.session_id;
  const sourceSessionId = claims.source_session_id;
  const agentId = claims.agent_id;
  if (
    expected.expectedAgentId === undefined ||
    typeof sessionId !== 'string' ||
    typeof sourceSessionId !== 'string' ||
    agentId !== expected.expectedAgentId
  ) {
    throw new NativeUserMcpConfigError();
  }
  return {
    sub: claims.sub,
    clientId: expected.expectedClientId,
    sessionId,
    sourceSessionId,
    agentId,
    issuer: expected.issuer,
    resourceServer: expected.resourceServer,
  };
}

async function respondAfterVerifiedMcpAuth(
  request: Request,
  ctx: SupabaseContext,
  expected: ResolvedNativeUserMcpConfig,
): Promise<Response> {
  if (ctx.authMode !== 'user' || ctx.jwtClaims === null || ctx.userClaims === null) {
    return jsonResponse(401, ADAPTER_AUTH_ERROR);
  }
  if (ctx.userClaims.id !== ctx.jwtClaims.sub || mcpClaimsRejected(ctx.jwtClaims, expected)) {
    return jsonResponse(401, ADAPTER_AUTH_ERROR);
  }
  if (expected.onVerified === undefined) {
    return jsonResponse(403, DOWNSTREAM_CREDENTIAL_UNRESOLVED);
  }
  try {
    return await expected.onVerified(verifiedPrincipal(ctx.jwtClaims, expected), request);
  } catch {
    return jsonResponse(403, DOWNSTREAM_CREDENTIAL_UNRESOLVED);
  }
}

async function boundIngress(request: Request): Promise<Request | Response> {
  const declared = request.headers.get('content-length');
  if (declared !== null) {
    if (!/^\d+$/u.test(declared)) return jsonResponse(400, 'invalid_request');
    const size = Number(declared);
    if (!Number.isSafeInteger(size) || size > MAX_RESPONSE_BYTES) {
      return jsonResponse(413, 'payload_too_large');
    }
  }
  if (request.body === null) return request;

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  const deadline = Date.now() + MAX_TOOL_EXECUTION_MS;
  try {
    while (true) {
      if (Date.now() > deadline) {
        await reader.cancel();
        return jsonResponse(408, 'deadline_exceeded');
      }
      const result = await reader.read();
      if (result.done) break;
      length += result.value.byteLength;
      if (length > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        return jsonResponse(413, 'payload_too_large');
      }
      chunks.push(result.value);
    }
  } catch {
    return jsonResponse(400, 'invalid_request');
  }

  const body = length === 0 ? null : Buffer.concat(chunks, length);
  return new Request(request.url, {
    method: request.method,
    headers: request.headers,
    signal: request.signal,
    ...(body === null ? {} : { body }),
  });
}

/**
 * Fetch handler for the native-user MCP resource.
 *
 * Discovery is served by `withOAuthProtectedResource`. Token A is verified by
 * nested `withSupabase({ auth: 'user' })`. Data API dispatch stays fail-closed.
 */
export function createNativeUserMcpHandler(
  config: NativeUserMcpConfig,
): (request: Request) => Promise<Response> {
  const resolved = resolveNativeUserMcpConfig(config);
  const blockedDataApiFetch: typeof fetch = async () => {
    throw new Error(DOWNSTREAM_CREDENTIAL_UNRESOLVED);
  };
  const gated = withOAuthProtectedResource(
    {
      resourceServer: resolved.resourceServer,
      authorizationServer: resolved.issuer,
      errors: { detailed: false },
    },
    withSupabase(
      {
        auth: 'user',
        cors: 'disabled',
        audience: resolved.resourceServer,
        issuer: resolved.issuer,
        env: resolved.env,
        errors: { detailed: false },
        supabaseOptions: {
          global: {
            fetch: blockedDataApiFetch,
          },
        },
      },
      async (request, ctx) => respondAfterVerifiedMcpAuth(request, ctx, resolved),
    ),
  );

  return async (request: Request): Promise<Response> => {
    const bounded = await boundIngress(request);
    if (bounded instanceof Response) return bounded;
    return normalizeLibraryAuthFailure(await gated(bounded));
  };
}
