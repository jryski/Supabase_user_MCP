import { z } from 'zod';

import { AuthorizationIdentifierSchema } from './authorization.js';

export const MCP_RESOURCE_PARAMETER = 'resource' as const;
export const DATA_API_AUDIENCE = 'authenticated' as const;
export const ACCESS_TOKEN_REVOCATION_LATENCY_BOUND_MS = 5_000;
export const REMOTE_HTTP_PROFILE_NAME = 'remote-http-oauth-2.1' as const;
/** Disposable local-lab MCP resource URI used by the in-lab Custom Access Token Hook. */
export const LOCAL_LAB_MCP_RESOURCE_URI = 'https://mcp.loopback.invalid/mcp' as const;

/**
 * Access-token revocation is a live check on this JWT, not grant/refresh
 * lifecycle and not remaining `exp`. Enforcement must complete within this
 * bound on the next request after revocation.
 */
export const ACCESS_TOKEN_REVOCATION_POLICY = Object.freeze({
  mechanism: 'live-session-and-fingerprint' as const,
  cache: 'none' as const,
  latencyBoundMs: ACCESS_TOKEN_REVOCATION_LATENCY_BOUND_MS,
  signatureValidityInsufficient: true as const,
  distinctFromGrantRevocation: true as const,
  distinctFromRefreshRevocation: true as const,
});

export const REMOTE_IDENTITY_CLAIM_POLICY = Object.freeze({
  forbiddenAuthorizationClaimPaths: Object.freeze(['user_metadata', 'raw_user_meta_data'] as const),
  clientIdSources: Object.freeze(['client_id', 'app_metadata.client_id'] as const),
  resourceBinding: 'mandatory' as const,
  dataApiAudience: DATA_API_AUDIENCE,
  defaultAudAuthenticatedInsufficient: true as const,
  clientIdAloneInsufficient: true as const,
  oidcScopesAuthorizeData: false as const,
});

/** MCP 2026-07-28 forbids forwarding the inbound MCP bearer to an upstream API. */
export const DOWNSTREAM_CREDENTIAL_UNRESOLVED = 'downstream_credential_unresolved' as const;
export const REMOTE_DOWNSTREAM_CREDENTIAL_POLICY = Object.freeze({
  inboundMcpBearerForwardsToDataApi: false as const,
  dualAudienceDoesNotAuthorizePassthrough: true as const,
  separateDownstreamCredential: 'unresolved' as const,
  failClosedUntilResolved: true as const,
  error: DOWNSTREAM_CREDENTIAL_UNRESOLVED,
});

export const RemoteCanonicalUriSchema = z
  .string()
  .url()
  .refine((value) => {
    try {
      const parsed = new URL(value);
      return (
        (parsed.protocol === 'https:' || parsed.protocol === 'http:') &&
        parsed.username === '' &&
        parsed.password === '' &&
        parsed.hash === ''
      );
    } catch {
      return false;
    }
  }, 'Canonical resource and issuer URIs must be absolute http(s) URLs without credentials or fragments.');

export type RemoteCanonicalUri = z.infer<typeof RemoteCanonicalUriSchema>;

export const RemoteOAuthClientIdSchema = AuthorizationIdentifierSchema;
export type RemoteOAuthClientId = z.infer<typeof RemoteOAuthClientIdSchema>;

export const RemotePrincipalIdSchema = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
export type RemotePrincipalId = z.infer<typeof RemotePrincipalIdSchema>;

export const AccessTokenRevocationClassSchema = z.enum([
  'access_token',
  'session',
  'grant',
  'refresh_token',
]);
export type AccessTokenRevocationClass = z.infer<typeof AccessTokenRevocationClassSchema>;

export const RemoteTokenDenialClassSchema = z.enum([
  'missing_bearer',
  'malformed_bearer',
  'invalid_signature',
  'wrong_issuer',
  'expired',
  'not_yet_valid',
  'missing_resource_binding',
  'wrong_resource',
  'missing_data_api_audience',
  'wrong_role',
  'missing_subject',
  'missing_client_id',
  'wrong_client',
  'revoked_access_token',
  'revoked_session',
  'revoked_grant',
  'user_metadata_authority',
]);
export type RemoteTokenDenialClass = z.infer<typeof RemoteTokenDenialClassSchema>;

export function canonicalizeResourceUri(value: string): string {
  const parsed = new URL(RemoteCanonicalUriSchema.parse(value));
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
}

export function audienceValues(aud: unknown): readonly string[] {
  if (typeof aud === 'string' && aud.length > 0) return Object.freeze([aud]);
  if (Array.isArray(aud) && aud.every((value) => typeof value === 'string' && value.length > 0)) {
    return Object.freeze([...aud]);
  }
  return Object.freeze([]);
}

export function extractServerControlledClientId(
  claims: Readonly<Record<string, unknown>>,
): string | undefined {
  if (typeof claims.client_id === 'string' && claims.client_id.length > 0) {
    const parsed = RemoteOAuthClientIdSchema.safeParse(claims.client_id);
    return parsed.success ? parsed.data : undefined;
  }
  const appMetadata = claims.app_metadata;
  if (typeof appMetadata === 'object' && appMetadata !== null && !Array.isArray(appMetadata)) {
    const clientId = (appMetadata as Readonly<Record<string, unknown>>).client_id;
    if (typeof clientId === 'string' && clientId.length > 0) {
      const parsed = RemoteOAuthClientIdSchema.safeParse(clientId);
      return parsed.success ? parsed.data : undefined;
    }
  }
  return undefined;
}

export function userMetadataAttemptsAuthorization(
  claims: Readonly<Record<string, unknown>>,
): boolean {
  const userMetadata = claims.user_metadata;
  if (typeof userMetadata !== 'object' || userMetadata === null || Array.isArray(userMetadata)) {
    return false;
  }
  const record = userMetadata as Readonly<Record<string, unknown>>;
  return (
    'client_id' in record ||
    'read_only' in record ||
    'role' in record ||
    'capability' in record ||
    'capabilities' in record ||
    'resource' in record
  );
}
