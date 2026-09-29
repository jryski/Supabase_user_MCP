import { createMcpHandler } from '@modelcontextprotocol/server';
import {
  DOWNSTREAM_CREDENTIAL_UNRESOLVED,
  RemoteOAuthClientIdSchema,
} from '@supabase-user-mcp/contracts';

import { readAriTestMarker } from './ari-test-marker.js';
import {
  DOWNSTREAM_AUTHORIZATION_REQUIRED,
  DOWNSTREAM_B_GRANT_PROFILE,
  type DownstreamHandshakePrincipal,
  DownstreamOAuthGrantStore,
} from './downstream-oauth-grant.js';
import { createFixedSupabaseClient } from './fixed-supabase-client.js';
import {
  createNativeUserMcpHandler,
  MCP_INGRESS_ROLE,
  type NativeUserMcpConfig,
  NativeUserMcpConfigError,
  nativeUserMcpIssuer,
  type VerifiedNativeUserPrincipal,
} from './native-user-mcp.js';
import { createReadOnlyServer } from './server.js';
import { probeSourceSessionLive } from './source-session-liveness.js';

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
  readonly enableAriTestMarker?: boolean;
  readonly fetch?: typeof globalThis.fetch;
  readonly now?: () => number;
  readonly handshakeTtlMs?: number;
  readonly livenessTimeoutMs?: number;
}

function invalidConfig(): never {
  throw new NativeUserMcpConfigError();
}

function jsonResponse(status: number, body: Readonly<Record<string, unknown>>): Response {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

function principalBinding(principal: VerifiedNativeUserPrincipal): DownstreamHandshakePrincipal {
  return {
    sourceSessionId: principal.sourceSessionId,
    sub: principal.sub,
    agentId: principal.agentId,
    aClientId: principal.clientId,
  };
}

function callbackUrl(request: Request, redirectUri: string): URL | undefined {
  let actual: URL;
  let expected: URL;
  try {
    actual = new URL(request.url);
    expected = new URL(redirectUri);
  } catch {
    return undefined;
  }
  if (actual.origin !== expected.origin || actual.pathname !== expected.pathname) return undefined;
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
  const issuer = nativeUserMcpIssuer(config.supabaseUrl);
  let authOrigin: string;
  try {
    const project = new URL(config.supabaseUrl);
    authOrigin = project.origin + project.pathname.replace(/\/$/u, '');
  } catch {
    invalidConfig();
  }
  const fetchImpl = config.fetch;
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
  });
  const enableMarker = config.enableAriTestMarker === true;

  const dispatchWithTokenB = async (request: Request, accessToken: string): Promise<Response> => {
    const mcp = createMcpHandler(async () => {
      const client = createFixedSupabaseClient({
        origin: authOrigin,
        credentials: {
          projectPublishableKey: config.publishableKey,
          userAccessToken: accessToken,
        },
        ...(fetchImpl === undefined ? {} : { fetch: fetchImpl }),
      });
      return createReadOnlyServer({
        client,
        ...(enableMarker
          ? {
              ariTestMarker: {
                readMarker: (signal) =>
                  readAriTestMarker({
                    origin: authOrigin,
                    accessToken,
                    publishableKey: config.publishableKey,
                    signal,
                    ...(fetchImpl === undefined ? {} : { fetch: fetchImpl }),
                  }),
              },
            }
          : {}),
      });
    });
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
    const grant = store.resolve(binding);
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
    const live = await probeSourceSessionLive(
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
    if (!live) return jsonResponse(403, { error: DOWNSTREAM_CREDENTIAL_UNRESOLVED });
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
      const url = callbackUrl(request, config.downstreamRedirectUri);
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
