import {
  getOAuthProtectedResourceMetadataUrl,
  oauthMetadataResponse,
  requireBearerAuth,
  type AuthorizationServerMetadata,
} from '@modelcontextprotocol/server';
import {
  DOWNSTREAM_CREDENTIAL_UNRESOLVED,
  canonicalizeResourceUri,
} from '@supabase-user-mcp/contracts';

import {
  createRemoteAccessTokenVerifier,
  type AccessTokenRevocationAuthority,
  type RemoteTokenSigningKey,
} from './remote-token-verifier.js';

export interface RemoteHttpProfileConfig {
  readonly resourceUri: string;
  readonly issuer: string;
  readonly expectedClientId: string;
  readonly signingKey: RemoteTokenSigningKey;
  readonly revocationAuthority: AccessTokenRevocationAuthority;
  readonly authorizationServerMetadata: AuthorizationServerMetadata;
  readonly fetch?: typeof globalThis.fetch;
  readonly now?: () => number;
  readonly allowInsecureIssuer?: boolean;
}

export type RemoteHttpHandler = (request: Request) => Promise<Response>;

const JSON_HEADERS = Object.freeze({
  'content-type': 'application/json',
  'cache-control': 'no-store',
});

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
    expectedClientId: config.expectedClientId,
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

    // MCP 2026-07-28 forbids forwarding the inbound bearer to the Data API.
    // Dual aud/resource is not a substitute. No supported separate downstream
    // credential exists yet, so data dispatch stays fail-closed.
    return new Response(JSON.stringify({ error: DOWNSTREAM_CREDENTIAL_UNRESOLVED }), {
      status: 403,
      headers: JSON_HEADERS,
    });
  };
}

export function containsSecretMaterial(value: unknown, secrets: readonly string[]): boolean {
  if (secrets.length === 0) return false;
  const serialized = JSON.stringify(value);
  if (typeof serialized !== 'string') return false;
  return secrets.some((secret) => secret.length > 0 && serialized.includes(secret));
}
