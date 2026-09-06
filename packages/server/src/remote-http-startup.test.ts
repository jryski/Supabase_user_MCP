import { describe, expect, it } from 'vitest';

import { LOCAL_LAB_MCP_RESOURCE_URI } from '@supabase-user-mcp/contracts';

import { createAuthorizationServerMetadata } from './authorization-server-metadata.js';
import {
  REMOTE_HTTP_STARTUP_ERROR,
  createRemoteHttpHandlerFromEnvironment,
} from './remote-http-startup.js';
import { SYNTHETIC_OAUTH_HMAC_SECRET } from './synthetic-oauth-lab.js';

const ISSUER = 'http://127.0.0.1:62421/auth/v1';
const HMAC = Buffer.from(SYNTHETIC_OAUTH_HMAC_SECRET).toString('utf8');

describe('remote HTTP startup', () => {
  it('rejects argv, credential files, user tokens, and service_role', () => {
    const metadata = createAuthorizationServerMetadata(ISSUER);
    const authority = { inspectAccessToken: async () => 'active' as const };
    const valid = {
      SUPABASE_USER_MCP_RESOURCE_URI: LOCAL_LAB_MCP_RESOURCE_URI,
      SUPABASE_USER_MCP_AUTHORIZATION_SERVER: ISSUER,
      SUPABASE_USER_MCP_ORIGIN: 'https://m2-loopback.invalid',
      SUPABASE_USER_MCP_PUBLISHABLE_KEY: 'sb_publishable_lab_key',
      SUPABASE_USER_MCP_JWT_HMAC_SECRET: HMAC,
    };

    expect(() =>
      createRemoteHttpHandlerFromEnvironment({
        argv: ['--help'],
        env: valid,
        revocationAuthority: authority,
        authorizationServerMetadata: metadata,
      }),
    ).toThrow(REMOTE_HTTP_STARTUP_ERROR);

    for (const forbidden of [
      'SUPABASE_USER_MCP_CREDENTIAL_FILE',
      'SUPABASE_USER_MCP_USER_ACCESS_TOKEN',
      'SUPABASE_SERVICE_ROLE_KEY',
    ]) {
      expect(() =>
        createRemoteHttpHandlerFromEnvironment({
          env: { ...valid, [forbidden]: 'present' },
          revocationAuthority: authority,
          authorizationServerMetadata: metadata,
        }),
      ).toThrow(REMOTE_HTTP_STARTUP_ERROR);
    }
  });

  it('builds a loopback handler from environment without a user bearer cache', () => {
    const handler = createRemoteHttpHandlerFromEnvironment({
      env: {
        SUPABASE_USER_MCP_RESOURCE_URI: LOCAL_LAB_MCP_RESOURCE_URI,
        SUPABASE_USER_MCP_AUTHORIZATION_SERVER: ISSUER,
        SUPABASE_USER_MCP_ORIGIN: 'https://m2-loopback.invalid',
        SUPABASE_USER_MCP_PUBLISHABLE_KEY: 'sb_publishable_lab_key',
        SUPABASE_USER_MCP_JWT_HMAC_SECRET: HMAC,
      },
      revocationAuthority: { inspectAccessToken: async () => 'active' },
      authorizationServerMetadata: createAuthorizationServerMetadata(ISSUER),
    });
    expect(typeof handler).toBe('function');
  });
});
