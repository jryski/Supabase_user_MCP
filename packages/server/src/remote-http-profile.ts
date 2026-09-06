import {
  OAuthError,
  OAuthErrorCode,
  WebStandardStreamableHTTPServerTransport,
  bearerAuthChallengeResponse,
  getOAuthProtectedResourceMetadataUrl,
  oauthMetadataResponse,
  requireBearerAuth,
  type AuthInfo,
  type AuthorizationServerMetadata,
} from '@modelcontextprotocol/server';
import { canonicalizeResourceUri } from '@supabase-user-mcp/contracts';

import {
  createFixedSupabaseClient,
  type VerifiedFixedSupabaseClient,
} from './fixed-supabase-client.js';
import type { ReadToolGovernancePolicy, ReadToolOperationalEvent } from './read-tool-governor.js';
import {
  createRemoteAccessTokenVerifier,
  type AccessTokenRevocationAuthority,
  type RemoteTokenSigningKey,
} from './remote-token-verifier.js';
import { createReadOnlyServer, type ReadOnlyServer } from './server.js';

export interface RemoteHttpProfileConfig {
  readonly resourceUri: string;
  readonly issuer: string;
  readonly supabaseOrigin: string;
  readonly publishableKey: string;
  readonly signingKey: RemoteTokenSigningKey;
  readonly revocationAuthority: AccessTokenRevocationAuthority;
  readonly authorizationServerMetadata: AuthorizationServerMetadata;
  readonly fetch?: typeof globalThis.fetch;
  readonly now?: () => number;
  readonly emitOperationalEvent?: (event: ReadToolOperationalEvent) => void;
  readonly allowInsecureIssuer?: boolean;
  readonly governance?: ReadToolGovernancePolicy;
}

export type RemoteHttpHandler = (request: Request) => Promise<Response>;

const JSON_HEADERS = Object.freeze({
  'content-type': 'application/json',
  'cache-control': 'no-store',
});

function redactedAuthInfo(auth: AuthInfo): AuthInfo {
  return {
    token: 'redacted',
    clientId: auth.clientId,
    scopes: auth.scopes,
    ...(auth.expiresAt === undefined ? {} : { expiresAt: auth.expiresAt }),
    ...(auth.resource === undefined ? {} : { resource: auth.resource }),
  };
}

function bindVerifiedClientId(
  client: VerifiedFixedSupabaseClient,
  clientId: string,
): VerifiedFixedSupabaseClient {
  return Object.freeze({
    listMemoryRows: client.listMemoryRows,
    searchMemoryRows: client.searchMemoryRows,
    getMemoryRow: client.getMemoryRow,
    listRecentMemoryRows: client.listRecentMemoryRows,
    verifyUserIdentity: async (signal?: AbortSignal) => {
      const identity = await client.verifyUserIdentity(signal);
      return Object.freeze({ principalId: identity.principalId, clientId });
    },
  });
}

function hostMatchesResource(request: Request, resource: URL): boolean {
  const host = request.headers.get('host');
  if (host === null || host.length === 0) return true;
  return host === resource.host || host === resource.hostname;
}

function isMcpResourcePath(request: Request, resource: URL): boolean {
  const url = new URL(request.url);
  const expected = resource.pathname === '' ? '/' : resource.pathname;
  return url.pathname === expected || url.pathname === `${expected}/`;
}

export function createRemoteHttpProfile(config: RemoteHttpProfileConfig): RemoteHttpHandler {
  const resourceUri = canonicalizeResourceUri(config.resourceUri);
  const resourceUrl = new URL(resourceUri);
  const issuer = canonicalizeResourceUri(config.issuer);
  if (config.authorizationServerMetadata.issuer !== issuer) {
    throw new TypeError('Authorization-server metadata issuer must match the configured issuer.');
  }
  const verifier = createRemoteAccessTokenVerifier({
    issuer,
    resourceUri,
    signingKey: config.signingKey,
    revocationAuthority: config.revocationAuthority,
    ...(config.now === undefined ? {} : { now: config.now }),
    ...(config.fetch === undefined ? {} : { fetch: config.fetch }),
  });
  const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(resourceUrl);
  const metadataOptions = {
    oauthMetadata: config.authorizationServerMetadata,
    resourceServerUrl: resourceUrl,
    ...(config.allowInsecureIssuer === true ? { dangerouslyAllowInsecureIssuerUrl: true } : {}),
  };
  const requireAuth = requireBearerAuth({
    verifier,
    resourceMetadataUrl,
  });

  return async (request: Request): Promise<Response> => {
    const metadata = oauthMetadataResponse(request, metadataOptions);
    if (metadata !== undefined) return metadata;
    if (!hostMatchesResource(request, resourceUrl)) {
      return new Response(JSON.stringify({ error: 'invalid_request' }), {
        status: 400,
        headers: JSON_HEADERS,
      });
    }
    if (!isMcpResourcePath(request, resourceUrl)) {
      return new Response(JSON.stringify({ error: 'not_found' }), {
        status: 404,
        headers: JSON_HEADERS,
      });
    }

    const auth = await requireAuth(request);
    if (auth instanceof Response) return auth;

    const clientConfig = {
      origin: config.supabaseOrigin,
      credentials: {
        projectPublishableKey: config.publishableKey,
        userAccessToken: auth.token,
      },
      ...(config.fetch === undefined ? {} : { fetch: config.fetch }),
    };
    const client = bindVerifiedClientId(createFixedSupabaseClient(clientConfig), auth.clientId);

    let server: ReadOnlyServer;
    try {
      // Request-scoped server construction shares process-global limiterStates; it must not reset budgets.
      server = await createReadOnlyServer({
        client,
        ...(config.emitOperationalEvent === undefined
          ? {}
          : { emitOperationalEvent: config.emitOperationalEvent }),
        ...(config.governance === undefined ? {} : { governance: config.governance }),
      });
    } catch {
      return bearerAuthChallengeResponse(
        new OAuthError(OAuthErrorCode.InvalidToken, 'invalid_token'),
        { resourceMetadataUrl },
      );
    }

    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    try {
      await server.connect(transport);
      return await transport.handleRequest(request, { authInfo: redactedAuthInfo(auth) });
    } finally {
      await Promise.allSettled([server.close(), transport.close()]);
    }
  };
}

export function containsSecretMaterial(value: unknown, secrets: readonly string[]): boolean {
  if (secrets.length === 0) return false;
  const serialized = JSON.stringify(value);
  if (typeof serialized !== 'string') return false;
  return secrets.some((secret) => secret.length > 0 && serialized.includes(secret));
}
