import {
  type AuthorizationServerMetadata,
  getOAuthProtectedResourceMetadataUrl,
  oauthMetadataResponse,
  requireBearerAuth,
} from '@modelcontextprotocol/server';
import {
  canonicalizeResourceUri,
  DOWNSTREAM_CREDENTIAL_UNRESOLVED,
} from '@supabase-user-mcp/contracts';

import type { LabDualGrantProfileHook } from './lab-dual-grant-broker.js';
import {
  type AccessTokenRevocationAuthority,
  createRemoteAccessTokenVerifier,
  type RemoteTokenSigningKey,
} from './remote-token-verifier.js';
import { assertBoundAuthorizationServerMetadata } from './validate-bound-authorization-server-metadata.js';

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
  /** Explicit lab opt-in. Absent or disabled keeps Data API dispatch fail-closed. */
  readonly labDualGrant?: LabDualGrantProfileHook;
}

export type RemoteHttpHandler = (request: Request) => Promise<Response>;

const JSON_HEADERS = Object.freeze({
  'content-type': 'application/json',
  'cache-control': 'no-store',
});

function hostMatchesResource(request: Request, resource: URL, allowLoopbackHost: boolean): boolean {
  const host = request.headers.get('host');
  if (host === null || host.length === 0) return true;
  if (host === resource.host || host === resource.hostname) return true;
  if (!allowLoopbackHost) return false;
  const hostname = host.startsWith('[') ? host : (host.split(':')[0] ?? host);
  return hostname === '127.0.0.1';
}

function isMcpResourcePath(request: Request, resource: URL): boolean {
  const url = new URL(request.url);
  const expected = resource.pathname === '' ? '/' : resource.pathname;
  return url.pathname === expected || url.pathname === `${expected}/`;
}

export function createRemoteHttpProfile(config: RemoteHttpProfileConfig): RemoteHttpHandler {
  const lab = config.labDualGrant?.enabled === true ? config.labDualGrant : undefined;
  const resourceUri = canonicalizeResourceUri(config.resourceUri);
  const resourceUrl = new URL(resourceUri);
  const issuer = canonicalizeResourceUri(lab?.mcpIssuer ?? config.issuer);
  const authorizationServerMetadata =
    lab?.authorizationServerMetadata() ?? config.authorizationServerMetadata;
  assertBoundAuthorizationServerMetadata(issuer, authorizationServerMetadata);
  const verifier = lab
    ? lab.mcpTokenVerifier
    : createRemoteAccessTokenVerifier({
        issuer,
        resourceUri,
        expectedClientId: config.expectedClientId,
        signingKey: config.signingKey,
        revocationAuthority: config.revocationAuthority,
        ...(config.now === undefined ? {} : { now: config.now }),
        ...(config.fetch === undefined ? {} : { fetch: config.fetch }),
      });
  const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(resourceUrl);
  const allowInsecureIssuer =
    config.allowInsecureIssuer === true || lab?.allowInsecureIssuer === true;
  const metadataOptions = {
    oauthMetadata: authorizationServerMetadata,
    resourceServerUrl: resourceUrl,
    ...(allowInsecureIssuer ? { dangerouslyAllowInsecureIssuerUrl: true } : {}),
  };
  const requireAuth = requireBearerAuth({
    verifier,
    resourceMetadataUrl,
  });

  return async (request: Request): Promise<Response> => {
    if (lab) {
      const handled = await lab.handleHttp(request);
      if (handled !== undefined) return handled;
    }
    const metadata = oauthMetadataResponse(request, metadataOptions);
    if (metadata !== undefined) return metadata;
    if (!hostMatchesResource(request, resourceUrl, lab !== undefined)) {
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
    if (lab) return lab.dispatchAuthorizedCall(request, auth);

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
