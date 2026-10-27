import type { AuthorizationServerMetadata } from '@modelcontextprotocol/server';
import { canonicalizeResourceUri } from '@supabase-user-mcp/contracts';

export function createAuthorizationServerMetadata(issuer: string): AuthorizationServerMetadata {
  const canonical = canonicalizeResourceUri(issuer);
  return {
    issuer: canonical,
    authorization_endpoint: `${canonical}/oauth/authorize`,
    token_endpoint: `${canonical}/oauth/token`,
    revocation_endpoint: `${canonical}/oauth/revoke`,
    jwks_uri: `${canonical}/.well-known/jwks.json`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
  };
}
