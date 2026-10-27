import type { AuthorizationServerMetadata } from '@modelcontextprotocol/server';
import { getOAuthProtectedResourceMetadataUrl } from '@modelcontextprotocol/server';
import { LOCAL_LAB_MCP_RESOURCE_URI } from '@supabase-user-mcp/contracts';
import { describe, expect, it } from 'vitest';

import { createAuthorizationServerMetadata } from './authorization-server-metadata.js';
import {
  BOUND_AUTHORIZATION_SERVER_METADATA_ERROR,
  ISSUER_MISMATCH_ERROR,
} from './validate-bound-authorization-server-metadata.js';
import { createRemoteHttpProfile } from './remote-http-profile.js';
import { SYNTHETIC_OAUTH_HMAC_SECRET, SyntheticOAuthLab } from './synthetic-oauth-lab.js';
import {
  createRemoteHttpHandlerFromEnvironment,
  REMOTE_HTTP_STARTUP_ERROR,
} from './remote-http-startup.js';

const ISSUER = 'https://auth.loopback.invalid/auth/v1';
const RESOURCE = LOCAL_LAB_MCP_RESOURCE_URI;
const CLIENT = 'smp-lab-inspector';
const REDIRECT = 'http://127.0.0.1/oauth/callback';
const LOOPBACK_ISSUER = 'http://127.0.0.1:62421/auth/v1';
const HOSTILE_QUERY = `?leak=super-secret-token-material&x=${'A'.repeat(256)}`;
const HOSTILE_FRAGMENT = '#leak=super-secret-token-material';

function lab(): SyntheticOAuthLab {
  return new SyntheticOAuthLab({
    issuer: ISSUER,
    resourceUri: RESOURCE,
    client: { clientId: CLIENT, redirectUri: REDIRECT, tokenEndpointAuthMethod: 'none' },
  });
}

function profileConfig(
  metadata: AuthorizationServerMetadata,
  issuer = ISSUER,
): Parameters<typeof createRemoteHttpProfile>[0] {
  return {
    resourceUri: RESOURCE,
    issuer,
    expectedClientId: CLIENT,
    signingKey: { kind: 'hmac', secret: SYNTHETIC_OAUTH_HMAC_SECRET },
    revocationAuthority: lab(),
    authorizationServerMetadata: metadata,
  };
}

function boundMetadata(
  overrides: Partial<AuthorizationServerMetadata> = {},
): AuthorizationServerMetadata {
  return { ...createAuthorizationServerMetadata(ISSUER), ...overrides };
}

function expectBoundMetadataRejection(run: () => unknown, hostileMaterial?: string): void {
  let message = '';
  try {
    run();
  } catch (error) {
    message = error instanceof Error ? error.message : String(error);
  }
  expect(message).toMatch(new RegExp(BOUND_AUTHORIZATION_SERVER_METADATA_ERROR, 'i'));
  expect(message.length).toBeLessThan(256);
  if (hostileMaterial !== undefined) {
    expect(message).not.toContain(hostileMaterial);
    expect(message).not.toContain(HOSTILE_QUERY);
    expect(message).not.toContain(HOSTILE_FRAGMENT);
  }
}

function expectIssuerMismatch(run: () => unknown): void {
  expect(run).toThrow(ISSUER_MISMATCH_ERROR);
}

function validStartupEnv(issuer = LOOPBACK_ISSUER): Record<string, string> {
  return {
    SUPABASE_USER_MCP_RESOURCE_URI: RESOURCE,
    SUPABASE_USER_MCP_AUTHORIZATION_SERVER: issuer,
    SUPABASE_USER_MCP_ORIGIN: 'https://m2-loopback.invalid',
    SUPABASE_USER_MCP_PUBLISHABLE_KEY: 'sb_publishable_lab_key',
    SUPABASE_USER_MCP_OAUTH_CLIENT_ID: CLIENT,
  };
}

describe('issue63 authorization-server metadata fail-closed boundaries', () => {
  describe('required metadata at profile construction', () => {
    it('rejects missing or empty issuer, OAuth endpoints, JWKS URI, and PKCE methods', () => {
      const valid = createAuthorizationServerMetadata(ISSUER);
      for (const metadata of [
        { ...valid, issuer: '' },
        { ...valid, issuer: undefined },
        { ...valid, authorization_endpoint: '' },
        { ...valid, authorization_endpoint: undefined },
        { ...valid, token_endpoint: '' },
        { ...valid, token_endpoint: undefined },
        { ...valid, jwks_uri: '' },
        { ...valid, jwks_uri: undefined },
        { ...valid, code_challenge_methods_supported: undefined },
        { ...valid, code_challenge_methods_supported: [] },
      ] as AuthorizationServerMetadata[]) {
        expectBoundMetadataRejection(() => createRemoteHttpProfile(profileConfig(metadata)));
      }
    });

    it('rejects plain-only or S256-absent PKCE advertisements', () => {
      for (const pkce of [['plain'], ['plain', 'S256']] as const) {
        expectBoundMetadataRejection(() =>
          createRemoteHttpProfile(
            profileConfig(boundMetadata({ code_challenge_methods_supported: [...pkce] })),
          ),
        );
      }
    });
  });

  describe('isolated endpoint anchoring guards', () => {
    it('rejects cross-origin endpoints that mirror the issuer-relative path', () => {
      expectBoundMetadataRejection(() =>
        createRemoteHttpProfile(
          profileConfig(
            boundMetadata({
              token_endpoint: 'https://evil.loopback.invalid/auth/v1/oauth/token',
            }),
          ),
        ),
      );
    });

    it('rejects same-origin sibling-prefix paths outside the issuer segment boundary', () => {
      expectBoundMetadataRejection(() =>
        createRemoteHttpProfile(
          profileConfig(
            boundMetadata({
              token_endpoint: 'https://auth.loopback.invalid/auth/v10/oauth/token',
            }),
          ),
        ),
      );
    });

    it('rejects same-origin path-escaped endpoints outside the issuer namespace', () => {
      const escaped = `${ISSUER}/../oauth/token${HOSTILE_FRAGMENT}`;
      expectBoundMetadataRejection(
        () =>
          createRemoteHttpProfile(
            profileConfig(boundMetadata({ authorization_endpoint: escaped })),
          ),
        'super-secret-token-material',
      );

      const siblingPath = 'https://auth.loopback.invalid/oauth/token';
      expectBoundMetadataRejection(() =>
        createRemoteHttpProfile(profileConfig(boundMetadata({ token_endpoint: siblingPath }))),
      );
    });

    it('rejects same-origin endpoints that carry a query string', () => {
      expectBoundMetadataRejection(
        () =>
          createRemoteHttpProfile(
            profileConfig(
              boundMetadata({ token_endpoint: `${ISSUER}/oauth/token${HOSTILE_QUERY}` }),
            ),
          ),
        'super-secret-token-material',
      );
    });

    it('rejects credential-bearing same-host endpoint URLs', () => {
      expectBoundMetadataRejection(() =>
        createRemoteHttpProfile(
          profileConfig(
            boundMetadata({
              token_endpoint: 'https://u:p@auth.loopback.invalid/auth/v1/oauth/token',
            }),
          ),
        ),
      );
    });

    it('rejects cross-origin revocation_endpoint URLs with the same path shape', () => {
      expectBoundMetadataRejection(() =>
        createRemoteHttpProfile(
          profileConfig(
            boundMetadata({
              revocation_endpoint: 'https://evil.loopback.invalid/auth/v1/oauth/revoke',
            }),
          ),
        ),
      );
    });
  });

  describe('issuer and revocation contracts', () => {
    it('rejects a non-empty metadata issuer that differs from the configured issuer', () => {
      expectIssuerMismatch(() =>
        createRemoteHttpProfile(
          profileConfig(
            boundMetadata({ issuer: 'https://other.loopback.invalid/auth/v1' }),
            ISSUER,
          ),
        ),
      );
    });

    it('rejects a present revocation_endpoint with an empty or non-string value', () => {
      expectBoundMetadataRejection(() =>
        createRemoteHttpProfile(
          profileConfig(boundMetadata({ revocation_endpoint: '' as unknown as string })),
        ),
      );
      expectBoundMetadataRejection(() =>
        createRemoteHttpProfile(
          profileConfig(boundMetadata({ revocation_endpoint: 0 as unknown as string })),
        ),
      );
    });
  });

  describe('canonical issuer binding', () => {
    it('binds discovery to the once-canonicalized configured issuer when trailing slashes differ', async () => {
      const messyIssuer = 'https://auth.loopback.invalid/auth/v1//';
      const metadata = createAuthorizationServerMetadata(messyIssuer);
      const handler = createRemoteHttpProfile(profileConfig(metadata, messyIssuer));
      const authorization = await handler(
        new Request('https://mcp.loopback.invalid/.well-known/oauth-authorization-server'),
      );
      expect(authorization.status).toBe(200);
      const authorizationJson = (await authorization.json()) as { issuer?: string };
      expect(authorizationJson.issuer).toBe(metadata.issuer);

      const protectedResource = await handler(
        new Request(getOAuthProtectedResourceMetadataUrl(new URL(RESOURCE))),
      );
      const protectedJson = (await protectedResource.json()) as {
        authorization_servers?: string[];
      };
      expect(protectedJson.authorization_servers).toEqual([metadata.issuer]);
    });

    it('fail-closes when canonical issuer input cannot match metadata from a different normalization', () => {
      expectIssuerMismatch(() =>
        createRemoteHttpProfile(
          profileConfig(createAuthorizationServerMetadata(ISSUER), `${ISSUER}//`),
        ),
      );
    });
  });

  describe('accepted metadata contract', () => {
    it('accepts createAuthorizationServerMetadata output and serves discovery unchanged', async () => {
      const metadata = createAuthorizationServerMetadata(ISSUER);
      const handler = createRemoteHttpProfile(profileConfig(metadata));
      const authorization = await handler(
        new Request('https://mcp.loopback.invalid/.well-known/oauth-authorization-server'),
      );
      expect(authorization.status).toBe(200);
      expect(await authorization.json()).toEqual(metadata);

      const protectedResource = await handler(
        new Request(getOAuthProtectedResourceMetadataUrl(new URL(RESOURCE))),
      );
      expect(protectedResource.status).toBe(200);
      const body = (await protectedResource.json()) as { authorization_servers?: string[] };
      expect(body.authorization_servers).toEqual([ISSUER]);
    });

    it('rejects hostile metadata during startup handler construction', () => {
      const authority = { inspectAccessToken: async () => 'active' as const };
      const crossOrigin = {
        ...createAuthorizationServerMetadata(LOOPBACK_ISSUER),
        token_endpoint: `https://evil.loopback.invalid/oauth/token${HOSTILE_QUERY}`,
      };
      expect(() =>
        createRemoteHttpHandlerFromEnvironment({
          env: validStartupEnv(),
          revocationAuthority: authority,
          authorizationServerMetadata: crossOrigin,
        }),
      ).toThrow(REMOTE_HTTP_STARTUP_ERROR);
    });

    it('rejects a malformed authorization-server env issuer with REMOTE_HTTP_STARTUP_ERROR', () => {
      const authority = { inspectAccessToken: async () => 'active' as const };
      expect(() =>
        createRemoteHttpHandlerFromEnvironment({
          env: validStartupEnv('not-a-valid-issuer-uri'),
          revocationAuthority: authority,
          authorizationServerMetadata: createAuthorizationServerMetadata(LOOPBACK_ISSUER),
        }),
      ).toThrow(REMOTE_HTTP_STARTUP_ERROR);
    });

    it('canonicalizes a multi-trailing-slash loopback env issuer once through startup', async () => {
      const rawLoopbackIssuer = `${LOOPBACK_ISSUER}//`;
      const metadata = createAuthorizationServerMetadata(rawLoopbackIssuer);
      const authority = { inspectAccessToken: async () => 'active' as const };
      const construct = (): Promise<ReturnType<typeof createRemoteHttpHandlerFromEnvironment>> => {
        try {
          const handler = createRemoteHttpHandlerFromEnvironment({
            env: validStartupEnv(rawLoopbackIssuer),
            revocationAuthority: authority,
            authorizationServerMetadata: metadata,
          });
          return Promise.resolve(handler);
        } catch (error) {
          if (error instanceof Error && error.message === ISSUER_MISMATCH_ERROR) {
            throw new Error(`startup leaked issuer mismatch: ${error.message}`);
          }
          throw error;
        }
      };

      const handler = await construct();
      expect(typeof handler).toBe('function');

      const authorization = await handler(
        new Request('http://127.0.0.1/.well-known/oauth-authorization-server'),
      );
      expect(authorization.status).toBe(200);
      const authorizationJson = (await authorization.json()) as { issuer?: string };
      expect(authorizationJson.issuer).toBe(metadata.issuer);

      const protectedResource = await handler(
        new Request(getOAuthProtectedResourceMetadataUrl(new URL(RESOURCE))),
      );
      const protectedJson = (await protectedResource.json()) as {
        authorization_servers?: string[];
      };
      expect(protectedJson.authorization_servers).toEqual([metadata.issuer]);
    });
  });
});
