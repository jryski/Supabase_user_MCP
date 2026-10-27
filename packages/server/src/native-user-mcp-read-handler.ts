import { createMcpHandler } from '@modelcontextprotocol/server';
import {
  checkStorageBucketId,
  DOWNSTREAM_CREDENTIAL_UNRESOLVED,
  RemoteOAuthClientIdSchema,
} from '@supabase-user-mcp/contracts';

import { MCP_MAX_REQUEST_BODY_BYTES } from './mcp-limits.js';
import { readTestMarker } from './test-marker.js';
import {
  DOWNSTREAM_AUTHORIZATION_REQUIRED,
  DOWNSTREAM_B_GRANT_PROFILE,
  type DownstreamGrantPublicFact,
  type DownstreamHandshakePrincipal,
  DownstreamOAuthGrantStore,
} from './downstream-oauth-grant.js';
import { createFixedSupabaseClient } from './fixed-supabase-client.js';
import { isLoopbackRedirectHostname, isLoopbackRedirectHttpUrl } from './loopback-host.js';
import {
  createNativeUserMcpHandler,
  MCP_INGRESS_ROLE,
  type NativeUserMcpConfig,
  NativeUserMcpConfigError,
  nativeUserMcpIssuer,
  type VerifiedNativeUserPrincipal,
} from './native-user-mcp.js';
import { createAuthorizationPendingServer, createReadOnlyServer } from './server.js';
import { classifySourceSessionLiveness } from './source-session-liveness.js';
import { createUserScopedStorageClient } from './user-scoped-storage-client.js';

export { DOWNSTREAM_AUTHORIZATION_REQUIRED, DOWNSTREAM_B_GRANT_PROFILE };

const JSON_HEADERS = Object.freeze({
  'content-type': 'application/json',
  'cache-control': 'no-store',
});

export interface NativeUserMcpReadHandlerConfig {
  readonly resourceServer: string;
  readonly supabaseUrl: string;
  readonly expectedClientId: string;
  readonly expectedAgentId: string;
  readonly ingressRole: string;
  readonly publishableKey: string;
  readonly jwks: NativeUserMcpConfig['jwks'];
  readonly downstreamClientId: string;
  readonly downstreamRedirectUri: string;
  /** Programmatic TEST marker. Default CLI leaves this off. */
  readonly enableTestMarker?: boolean;
  readonly fetch?: typeof globalThis.fetch;
  readonly now?: () => number;
  readonly handshakeTtlMs?: number;
  readonly livenessTimeoutMs?: number;
  /** In-process counters for test harnesses. Never store a bearer here. */
  readonly observation?: ReadCompositionObservation;
  /**
   * Loopback diagnostic injection. Called only after liveness reports live.
   * A returned response replaces tool dispatch. It does not skip liveness
   * and it does not grant a credential.
   */
  readonly dispatchGate?: (
    request: Request,
  ) => Response | undefined | Promise<Response | undefined>;
  /** UUIDs only. The handler does not copy bearers into this callback. */
  readonly onGrantFact?: (fact: DownstreamGrantPublicFact) => void;
  /**
   * Opt-in remote pilot only (#110). Accept an `https` downstream redirect
   * whose TLS is terminated by an operator proxy in front of a loopback
   * listener, so the request may arrive as `http://<redirect host>`.
   * Requires an `https` redirect, an exact Host header, and no TEST
   * diagnostics. Off by default: the loopback-only callback rule is unchanged.
   * On its own this keeps the 403 handshake body, which hosted MCP clients do
   * not render. Hosted use also needs `downstreamAuthorizationViaToolResult`;
   * the remote pilot entrypoint sets both.
   */
  readonly httpsCallbackBehindTlsTerminator?: boolean;
  /**
   * Opt-in remote pilot only (#110). Before B exists, answer MCP requests
   * from a data-less server whose tool calls return the B authorization link
   * as tool text, so a hosted MCP client (which does not render a 403 body)
   * can show it to the user. Off by default: the 403 handshake body is kept.
   */
  readonly downstreamAuthorizationViaToolResult?: boolean;
  /**
   * Opt-in storage tools (#123). The fixed Storage bucket. Storage requests
   * carry the downstream grant B and the publishable key, exactly like the
   * Data API client; Token A is never used. Off by default.
   */
  readonly storageBucket?: string;
}

export interface ReadCompositionObservation {
  livenessChecks: number;
  livenessDenials: number;
  markerReads: number;
  tokenAOfferedAsB: boolean;
  tokenARejectedAsB: boolean;
  sourceSessionId: string | null;
  bSessionId: string | null;
}

function invalidConfig(): never {
  throw new NativeUserMcpConfigError();
}

function bearerToken(request: Request): string {
  const header = request.headers.get('authorization');
  if (header === null) return '';
  const match = /^Bearer\s+(\S+)$/u.exec(header);
  return match?.[1] ?? '';
}

function jsonResponse(status: number, body: Readonly<Record<string, unknown>>): Response {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

function livenessDenial(result: {
  readonly category?: string;
  readonly httpStatus?: number;
}): Response {
  const body: Record<string, unknown> = {
    error: DOWNSTREAM_CREDENTIAL_UNRESOLVED,
    stage: 'liveness',
    category: result.category ?? 'service_error',
  };
  if (result.httpStatus !== undefined) body.httpStatus = result.httpStatus;
  return jsonResponse(403, body);
}

function principalBinding(principal: VerifiedNativeUserPrincipal): DownstreamHandshakePrincipal {
  return {
    sourceSessionId: principal.sourceSessionId,
    sub: principal.sub,
    agentId: principal.agentId,
    aClientId: principal.clientId,
  };
}

/**
 * Callback GET only. Same Host rule as the remote HTTP profile: a present
 * Host must be the redirect host. http is accepted only for loopback.
 * A mismatch is hostile and must not fall through to code exchange.
 *
 * With `httpsBehindTerminator` (opt-in remote pilot), an `https` redirect is
 * accepted when the path matches exactly, the request URL host equals the
 * redirect host, a Host header is present and equals the redirect host, and
 * the request scheme is `https` or the terminator-translated `http`.
 */
function callbackUrl(
  request: Request,
  redirectUri: string,
  httpsBehindTerminator: boolean,
): URL | 'hostile' | undefined {
  let actual: URL;
  let expected: URL;
  try {
    actual = new URL(request.url);
    expected = new URL(redirectUri);
  } catch {
    return undefined;
  }
  const loopback = expected.protocol === 'http:' && isLoopbackRedirectHostname(expected.hostname);
  if (!loopback && httpsBehindTerminator && expected.protocol === 'https:') {
    if (actual.pathname !== expected.pathname) return undefined;
    if (actual.username !== '' || actual.password !== '') return 'hostile';
    if (actual.protocol !== 'https:' && actual.protocol !== 'http:') return 'hostile';
    if (actual.host !== expected.host) return 'hostile';
    const host = request.headers.get('host');
    if (host === null || host !== expected.host) return 'hostile';
    return actual;
  }
  if (actual.origin !== expected.origin || actual.pathname !== expected.pathname) return undefined;
  if (!loopback) return 'hostile';
  const host = request.headers.get('host');
  if (host !== null && host.length > 0 && host !== expected.host && host !== expected.hostname) {
    return 'hostile';
  }
  return actual;
}

/**
 * TEST-only composition: verify A, bind B from the one-time handshake, check
 * source-session liveness with B, then dispatch tools with B.
 * Token A is never placed on the Data API client.
 * Without this handler, `createNativeUserMcpHandler` stays fail-closed.
 */
export function createNativeUserMcpReadHandler(
  config: NativeUserMcpReadHandlerConfig,
): (request: Request) => Promise<Response> {
  if (!RemoteOAuthClientIdSchema.safeParse(config.downstreamClientId).success) invalidConfig();
  if (config.downstreamClientId === config.expectedClientId) invalidConfig();
  if (config.ingressRole !== MCP_INGRESS_ROLE) invalidConfig();
  const httpsBehindTerminator = config.httpsCallbackBehindTlsTerminator === true;
  // A plaintext callback must be an exact loopback host, by the same rule the
  // grant store applies (`isLoopbackRedirectHttpUrl`, which accepts `[::1]`).
  // Lookalike domains such as `127.0.0.1.example` never reach the grant store.
  let configuredRedirect: URL;
  try {
    configuredRedirect = new URL(config.downstreamRedirectUri);
  } catch {
    invalidConfig();
  }
  if (configuredRedirect.protocol === 'http:' && !isLoopbackRedirectHttpUrl(configuredRedirect)) {
    invalidConfig();
  }
  if (httpsBehindTerminator) {
    let redirect: URL;
    try {
      redirect = new URL(config.downstreamRedirectUri);
    } catch {
      invalidConfig();
    }
    if (redirect.protocol !== 'https:') invalidConfig();
    if (
      config.enableTestMarker === true ||
      config.observation !== undefined ||
      config.dispatchGate !== undefined
    ) {
      invalidConfig();
    }
  }
  const issuer = nativeUserMcpIssuer(config.supabaseUrl);
  let authOrigin: string;
  try {
    const project = new URL(config.supabaseUrl);
    authOrigin = project.origin + project.pathname.replace(/\/$/u, '');
  } catch {
    invalidConfig();
  }
  // Storage is reached at the project origin, never a path below it.
  const storageOrigin = new URL(authOrigin).origin;
  const fetchImpl = config.fetch;
  const storageBucket = config.storageBucket;
  if (storageBucket !== undefined && !checkStorageBucketId(storageBucket).ok) invalidConfig();
  const store = new DownstreamOAuthGrantStore({
    issuer,
    authOrigin,
    expectedBClientId: config.downstreamClientId,
    expectedAgentId: config.expectedAgentId,
    redirectUri: config.downstreamRedirectUri,
    jwks: config.jwks,
    ...(config.handshakeTtlMs === undefined ? {} : { handshakeTtlMs: config.handshakeTtlMs }),
    ...(config.now === undefined ? {} : { now: config.now }),
    ...(fetchImpl === undefined ? {} : { fetch: fetchImpl }),
    ...(config.onGrantFact === undefined ? {} : { onGrantFact: config.onGrantFact }),
  });
  const enableMarker = config.enableTestMarker === true;
  const authorizationViaTool = config.downstreamAuthorizationViaToolResult === true;
  if (authorizationViaTool && !httpsBehindTerminator) invalidConfig();

  const dispatchAuthorizationPending = async (
    request: Request,
    binding: DownstreamHandshakePrincipal,
  ): Promise<Response> => {
    const mcp = createMcpHandler(
      async () =>
        createAuthorizationPendingServer({
          beginAuthorization: () => {
            const handshake = store.pendingOrBeginHandshake(binding);
            return {
              authorizationUrl: handshake.authorizationUrl,
              expiresAtMs: handshake.expiresAtMs,
            };
          },
          ...(config.now === undefined ? {} : { now: config.now }),
        }),
      { maxRequestBodySize: MCP_MAX_REQUEST_BODY_BYTES },
    );
    try {
      return await mcp.fetch(request);
    } finally {
      await mcp.close();
    }
  };

  const dispatchWithTokenB = async (request: Request, accessToken: string): Promise<Response> => {
    const mcp = createMcpHandler(
      async () => {
        const client = createFixedSupabaseClient({
          origin: authOrigin,
          credentials: {
            projectPublishableKey: config.publishableKey,
            userAccessToken: accessToken,
          },
          ...(fetchImpl === undefined ? {} : { fetch: fetchImpl }),
        });
        const storageRegistration =
          storageBucket === undefined
            ? undefined
            : {
                client: createUserScopedStorageClient({
                  origin: storageOrigin,
                  bucket: storageBucket,
                  credentials: {
                    projectPublishableKey: config.publishableKey,
                    userAccessToken: accessToken,
                  },
                  ...(fetchImpl === undefined ? {} : { fetch: fetchImpl }),
                }),
              };
        return createReadOnlyServer({
          client,
          ...(storageRegistration === undefined ? {} : { storageRegistration }),
          ...(enableMarker
            ? {
                testMarker: {
                  readMarker: (signal) => {
                    if (config.observation !== undefined) config.observation.markerReads += 1;
                    return readTestMarker({
                      origin: authOrigin,
                      accessToken,
                      publishableKey: config.publishableKey,
                      signal,
                      ...(fetchImpl === undefined ? {} : { fetch: fetchImpl }),
                    });
                  },
                },
              }
            : {}),
        });
      },
      { maxRequestBodySize: MCP_MAX_REQUEST_BODY_BYTES },
    );
    try {
      return await mcp.fetch(request);
    } finally {
      await mcp.close();
    }
  };

  const onVerified = async (
    principal: VerifiedNativeUserPrincipal,
    request: Request,
  ): Promise<Response> => {
    const binding = principalBinding(principal);
    const observation = config.observation;
    if (observation !== undefined) {
      observation.sourceSessionId = principal.sourceSessionId;
      if (!observation.tokenAOfferedAsB) {
        const offered = bearerToken(request);
        if (offered.length > 0) {
          observation.tokenAOfferedAsB = true;
          observation.tokenARejectedAsB = await store.rejectsOfferedAccessToken(offered, binding);
        }
      }
    }
    const grant = store.resolve(binding);
    if (authorizationViaTool && (grant.status === 'missing' || grant.status === 'expired')) {
      return dispatchAuthorizationPending(request, binding);
    }
    if (grant.status === 'missing') {
      const handshake = store.beginHandshake(binding);
      return jsonResponse(403, {
        error: DOWNSTREAM_AUTHORIZATION_REQUIRED,
        handshake_id: handshake.id,
        state: handshake.state,
        authorization_url: handshake.authorizationUrl,
        expires_at: handshake.expiresAtMs,
        profile: DOWNSTREAM_B_GRANT_PROFILE,
      });
    }
    if (grant.status !== 'live') {
      return jsonResponse(403, { error: DOWNSTREAM_CREDENTIAL_UNRESOLVED });
    }
    if (observation !== undefined) observation.bSessionId = store.boundSessionId(binding);
    const liveness = await classifySourceSessionLiveness(
      {
        supabaseUrl: config.supabaseUrl,
        publishableKey: config.publishableKey,
        ...(config.livenessTimeoutMs === undefined ? {} : { timeoutMs: config.livenessTimeoutMs }),
        ...(fetchImpl === undefined ? {} : { fetch: fetchImpl }),
      },
      {
        accessToken: grant.accessToken,
        sourceSessionId: principal.sourceSessionId,
        aClientId: principal.clientId,
      },
    );
    if (observation !== undefined) {
      observation.livenessChecks += 1;
      if (!liveness.live) observation.livenessDenials += 1;
    }
    if (!liveness.live) return livenessDenial(liveness);
    if (config.dispatchGate !== undefined) {
      const gated = await config.dispatchGate(request.clone());
      if (gated !== undefined) return gated;
    }
    return dispatchWithTokenB(request, grant.accessToken);
  };

  const native = createNativeUserMcpHandler({
    resourceServer: config.resourceServer,
    supabaseUrl: config.supabaseUrl,
    expectedClientId: config.expectedClientId,
    ingressRole: config.ingressRole,
    publishableKey: config.publishableKey,
    jwks: config.jwks,
    expectedAgentId: config.expectedAgentId,
    onVerified,
  });

  return async (request: Request): Promise<Response> => {
    if (request.method === 'GET') {
      const url = callbackUrl(request, config.downstreamRedirectUri, httpsBehindTerminator);
      if (url === 'hostile') return jsonResponse(400, { error: 'invalid_request' });
      if (url !== undefined) {
        const code = url.searchParams.get('code') ?? '';
        const state = url.searchParams.get('state') ?? '';
        const bound = await store.completeCallback({
          code,
          state,
          redirectUri: config.downstreamRedirectUri,
        });
        if (!bound) return jsonResponse(403, { error: DOWNSTREAM_CREDENTIAL_UNRESOLVED });
        return jsonResponse(200, { bound: true, profile: DOWNSTREAM_B_GRANT_PROFILE });
      }
    }
    return native(request);
  };
}
