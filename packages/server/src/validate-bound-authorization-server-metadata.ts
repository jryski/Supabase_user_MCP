import type { AuthorizationServerMetadata } from '@modelcontextprotocol/server';
import { canonicalizeResourceUri } from '@supabase-user-mcp/contracts';

export const BOUND_AUTHORIZATION_SERVER_METADATA_ERROR =
  'Authorization-server metadata is not bound to the configured issuer.';

export const ISSUER_MISMATCH_ERROR =
  'Authorization-server metadata issuer must match the configured issuer.';

const REQUIRED_ENDPOINT_FIELDS = Object.freeze([
  'authorization_endpoint',
  'token_endpoint',
  'jwks_uri',
] as const);

type MetadataWithRevocation = AuthorizationServerMetadata & {
  readonly revocation_endpoint?: unknown;
};

function rejectBoundMetadata(): never {
  throw new TypeError(BOUND_AUTHORIZATION_SERVER_METADATA_ERROR);
}

function parseBoundEndpoint(value: unknown): URL {
  if (typeof value !== 'string' || value.length === 0) rejectBoundMetadata();
  if (value.includes('#')) rejectBoundMetadata();
  try {
    const parsed = new URL(value);
    if (parsed.hash.length > 0) rejectBoundMetadata();
    return new URL(canonicalizeResourceUri(value));
  } catch {
    rejectBoundMetadata();
  }
}

function endpointPathWithinIssuerNamespace(issuerUrl: URL, endpointPath: string): boolean {
  const issuerPath = issuerUrl.pathname.replace(/\/$/u, '') || '';
  if (issuerPath === '') {
    return endpointPath.startsWith('/');
  }
  if (endpointPath === issuerPath) return true;
  return endpointPath.startsWith(`${issuerPath}/`);
}

function assertEndpointUnderIssuer(canonicalIssuer: string, endpoint: URL): void {
  const issuerUrl = new URL(canonicalIssuer);
  if (endpoint.protocol !== issuerUrl.protocol || endpoint.host !== issuerUrl.host) {
    rejectBoundMetadata();
  }
  if (endpoint.username !== '' || endpoint.password !== '') {
    rejectBoundMetadata();
  }
  if (endpoint.search.length > 0 || endpoint.hash.length > 0) {
    rejectBoundMetadata();
  }
  if (!endpointPathWithinIssuerNamespace(issuerUrl, endpoint.pathname)) {
    rejectBoundMetadata();
  }
}

function assertPkceContract(metadata: AuthorizationServerMetadata): void {
  const methods = metadata.code_challenge_methods_supported;
  if (!Array.isArray(methods) || methods.length === 0) rejectBoundMetadata();
  if (!methods.includes('S256')) rejectBoundMetadata();
  if (methods.includes('plain')) rejectBoundMetadata();
}

function assertRevocationEndpoint(canonicalIssuer: string, metadata: MetadataWithRevocation): void {
  if (!('revocation_endpoint' in metadata)) return;
  const revocation = metadata.revocation_endpoint;
  if (typeof revocation !== 'string' || revocation.length === 0) rejectBoundMetadata();
  assertEndpointUnderIssuer(canonicalIssuer, parseBoundEndpoint(revocation));
}

export function assertBoundAuthorizationServerMetadata(
  canonicalIssuer: string,
  metadata: AuthorizationServerMetadata,
): void {
  if (typeof metadata.issuer !== 'string' || metadata.issuer.length === 0) {
    rejectBoundMetadata();
  }
  if (metadata.issuer !== canonicalIssuer) {
    throw new TypeError(ISSUER_MISMATCH_ERROR);
  }
  assertPkceContract(metadata);
  for (const field of REQUIRED_ENDPOINT_FIELDS) {
    assertEndpointUnderIssuer(canonicalIssuer, parseBoundEndpoint(metadata[field]));
  }
  assertRevocationEndpoint(canonicalIssuer, metadata);
}
