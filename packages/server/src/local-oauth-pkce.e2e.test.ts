import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';

import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { LOCAL_LAB_MCP_RESOURCE_URI, audienceValues } from '@supabase-user-mcp/contracts';
import { afterAll, describe, expect, it } from 'vitest';

import { createAuthorizationServerMetadata } from './authorization-server-metadata.js';
import { createGoTrueSessionRevocationAuthority } from './gotrue-revocation-authority.js';
import {
  approveLocalAuthorization,
  decodeJwtPayloadClaims,
  denyLocalAuthorization,
  exchangeLocalAuthorizationCode,
  generateS256PkceChallenge,
  logoutLocalSession,
  registerLocalPublicOAuthClient,
  startLocalAuthorization,
} from './local-oauth-pkce-client.js';
import { createRemoteHttpProfile } from './remote-http-profile.js';

const requiredEnvironment = [
  'M4_SUPABASE_URL',
  'M4_PUBLISHABLE_KEY',
  'M4_SERVICE_ROLE_KEY',
  'M4_JWT_SECRET',
  'M4_ALICE_TOKEN',
  'M4_BOB_TOKEN',
  'M4_DB_URL',
] as const;

const enabled = requiredEnvironment.every((key) => (process.env[key] ?? '').length > 0);
const localDescribe = enabled ? describe : describe.skip;
const VIRTUAL_ORIGIN = 'https://m2-loopback.invalid';
const RESOURCE = LOCAL_LAB_MCP_RESOURCE_URI;
const REDIRECT = 'http://127.0.0.1/oauth/callback';
const ALICE = '11111111-1111-4111-9111-111111111111';
const registeredClients: string[] = [];

function env(name: (typeof requiredEnvironment)[number]): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}

function loopbackFetch(actualOrigin: string): typeof globalThis.fetch {
  return async (input, init) => {
    const requested = new URL(
      typeof input === 'string' || input instanceof URL ? input : input.url,
    );
    const target = new URL(`${requested.pathname}${requested.search}`, actualOrigin);
    const response = await globalThis.fetch(target, init);
    Object.defineProperties(response, {
      redirected: { value: false },
      url: { value: requested.href },
    });
    return response;
  };
}

function seedGrantedClient(clientId: string, principalId: string): void {
  if (!/^[0-9a-f-]{36}$/i.test(clientId) || !/^[0-9a-f-]{36}$/i.test(principalId)) {
    throw new Error('fixture identifiers must be UUIDs');
  }
  execFileSync(
    'psql',
    [
      env('M4_DB_URL'),
      '-v',
      'ON_ERROR_STOP=1',
      '-c',
      `insert into policy_lab.clients (client_id, state, valid_until)
       values ('${clientId}', 'active', '2099-01-01')
       on conflict (client_id) do update set state = excluded.state, valid_until = excluded.valid_until;
       insert into policy_lab.memberships (principal_id, client_id, workspace_id, state, valid_until)
       values ('${principalId}', '${clientId}', 'workspace-mcp-alpha', 'active', '2099-01-01')
       on conflict (principal_id, client_id, workspace_id) do update
       set state = excluded.state, valid_until = excluded.valid_until;
       insert into policy_lab.capability_grants
         (principal_id, client_id, workspace_id, capability, state, valid_until)
       values
         ('${principalId}', '${clientId}', 'workspace-mcp-alpha', 'memory:read', 'active', '2099-01-01'),
         ('${principalId}', '${clientId}', 'workspace-mcp-alpha', 'memory:search', 'active', '2099-01-01')
       on conflict (principal_id, client_id, workspace_id, capability) do update
       set state = excluded.state, valid_until = excluded.valid_until;`,
    ],
    { stdio: 'pipe' },
  );
}

async function completePkce(userAccessToken: string, clientId: string): Promise<string> {
  const pkce = generateS256PkceChallenge();
  const started = await startLocalAuthorization({
    authOrigin: env('M4_SUPABASE_URL'),
    clientId,
    redirectUri: REDIRECT,
    resource: RESOURCE,
    codeChallenge: pkce.codeChallenge,
    state: randomUUID(),
    projectPublishableKey: env('M4_PUBLISHABLE_KEY'),
  });
  const approved = await approveLocalAuthorization({
    authOrigin: env('M4_SUPABASE_URL'),
    authorizationId: started.authorizationId,
    userAccessToken,
    projectPublishableKey: env('M4_PUBLISHABLE_KEY'),
  });
  const tokens = await exchangeLocalAuthorizationCode({
    authOrigin: env('M4_SUPABASE_URL'),
    clientId,
    redirectUri: REDIRECT,
    code: approved.code,
    codeVerifier: pkce.codeVerifier,
    resource: RESOURCE,
    projectPublishableKey: env('M4_PUBLISHABLE_KEY'),
  });
  return tokens.accessToken;
}

localDescribe('local GoTrue PKCE + remote MCP HTTP', () => {
  afterAll(() => {
    registeredClients.length = 0;
  });

  it('completes a real Auth PKCE/consent round trip, dual-binds, and preserves RLS', async () => {
    const authOrigin = env('M4_SUPABASE_URL');
    const client = await registerLocalPublicOAuthClient({
      authOrigin,
      serviceRoleKey: env('M4_SERVICE_ROLE_KEY'),
      clientName: 'm4-lab-inspector',
      redirectUri: REDIRECT,
    });
    registeredClients.push(client.clientId);
    seedGrantedClient(client.clientId, ALICE);

    const accessToken = await completePkce(env('M4_ALICE_TOKEN'), client.clientId);
    const claims = decodeJwtPayloadClaims(accessToken);
    expect(audienceValues(claims.aud)).toEqual(expect.arrayContaining(['authenticated', RESOURCE]));
    expect(claims.resource).toBe(RESOURCE);
    expect(claims.client_id).toBe(client.clientId);
    expect(claims.role).toBe('authenticated');
    const issuer = typeof claims.iss === 'string' ? claims.iss : `${authOrigin}/auth/v1`;

    const handler = createRemoteHttpProfile({
      resourceUri: RESOURCE,
      issuer,
      supabaseOrigin: VIRTUAL_ORIGIN,
      publishableKey: env('M4_PUBLISHABLE_KEY'),
      signingKey: { kind: 'hmac', secret: new TextEncoder().encode(env('M4_JWT_SECRET')) },
      revocationAuthority: createGoTrueSessionRevocationAuthority({
        origin: VIRTUAL_ORIGIN,
        publishableKey: env('M4_PUBLISHABLE_KEY'),
        fetch: loopbackFetch(authOrigin),
      }),
      authorizationServerMetadata: createAuthorizationServerMetadata(issuer),
      allowInsecureIssuer: true,
      fetch: loopbackFetch(authOrigin),
    });

    const transport = new StreamableHTTPClientTransport(new URL(RESOURCE), {
      fetch: async (input, init) => handler(new Request(input, init)),
      authProvider: { token: async () => accessToken },
    });
    const mcp = new Client({ name: 'm4-pkce-client', version: '0.0.0' }, { capabilities: {} });
    try {
      await mcp.connect(transport);
      const own = await mcp.callTool({
        name: 'memory_get',
        arguments: { id: 'mem_01JTESTALPHA000000000001' },
      });
      expect(own.structuredContent).toMatchObject({
        ok: true,
        record: { id: 'mem_01JTESTALPHA000000000001', contentTrust: 'untrusted' },
      });
      const cross = await mcp.callTool({
        name: 'memory_get',
        arguments: { id: 'mem_01JTESTBETA0000000000001' },
      });
      expect(cross.structuredContent).toMatchObject({
        ok: false,
        error: { code: 'RESOURCE_UNAVAILABLE' },
      });
    } finally {
      await Promise.allSettled([mcp.close(), transport.close()]);
    }

    const otherClient = await registerLocalPublicOAuthClient({
      authOrigin,
      serviceRoleKey: env('M4_SERVICE_ROLE_KEY'),
      clientName: 'm4-lab-unseeded',
      redirectUri: REDIRECT,
    });
    const otherToken = await completePkce(env('M4_ALICE_TOKEN'), otherClient.clientId);
    const otherHandlerDenied = await handler(
      new Request(RESOURCE, {
        method: 'POST',
        headers: { Authorization: `Bearer ${otherToken}`, Accept: 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2026-07-28',
            capabilities: {},
            clientInfo: { name: 'denied-client', version: '0.0.0' },
          },
        }),
      }),
    );
    expect([401, 200].includes(otherHandlerDenied.status)).toBe(true);
    if (otherHandlerDenied.status === 200) {
      const deniedTransport = new StreamableHTTPClientTransport(new URL(RESOURCE), {
        fetch: async (input, init) => handler(new Request(input, init)),
        authProvider: { token: async () => otherToken },
      });
      const deniedClient = new Client(
        { name: 'm4-other-client', version: '0.0.0' },
        { capabilities: {} },
      );
      try {
        await deniedClient.connect(deniedTransport);
        const denied = await deniedClient.callTool({
          name: 'memory_get',
          arguments: { id: 'mem_01JTESTALPHA000000000001' },
        });
        expect(denied.structuredContent).toMatchObject({
          ok: false,
          error: { code: 'RESOURCE_UNAVAILABLE' },
        });
      } finally {
        await Promise.allSettled([deniedClient.close(), deniedTransport.close()]);
      }
    }

    const bobToken = await completePkce(env('M4_BOB_TOKEN'), client.clientId);
    const bobTransport = new StreamableHTTPClientTransport(new URL(RESOURCE), {
      fetch: async (input, init) => handler(new Request(input, init)),
      authProvider: { token: async () => bobToken },
    });
    const bobClient = new Client({ name: 'm4-bob', version: '0.0.0' }, { capabilities: {} });
    try {
      await bobClient.connect(bobTransport);
      const bobRead = await bobClient.callTool({
        name: 'memory_get',
        arguments: { id: 'mem_01JTESTALPHA000000000001' },
      });
      expect(bobRead.structuredContent).toMatchObject({
        ok: false,
        error: { code: 'RESOURCE_UNAVAILABLE' },
      });
    } finally {
      await Promise.allSettled([bobClient.close(), bobTransport.close()]);
    }

    await logoutLocalSession({
      authOrigin,
      userAccessToken: accessToken,
      projectPublishableKey: env('M4_PUBLISHABLE_KEY'),
    });
    const revoked = await handler(
      new Request(RESOURCE, {
        method: 'POST',
        headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
        body: '{}',
      }),
    );
    expect(revoked.status).toBe(401);
    expect(await revoked.text()).not.toContain(accessToken);
  }, 20_000);

  it('denies consent and rejects a wrong PKCE verifier', async () => {
    const authOrigin = env('M4_SUPABASE_URL');
    const client = await registerLocalPublicOAuthClient({
      authOrigin,
      serviceRoleKey: env('M4_SERVICE_ROLE_KEY'),
      clientName: 'm4-lab-deny',
      redirectUri: REDIRECT,
    });
    const pkce = generateS256PkceChallenge();
    const started = await startLocalAuthorization({
      authOrigin,
      clientId: client.clientId,
      redirectUri: REDIRECT,
      resource: RESOURCE,
      codeChallenge: pkce.codeChallenge,
      state: 'deny-state',
      projectPublishableKey: env('M4_PUBLISHABLE_KEY'),
    });
    await denyLocalAuthorization({
      authOrigin,
      authorizationId: started.authorizationId,
      userAccessToken: env('M4_ALICE_TOKEN'),
      projectPublishableKey: env('M4_PUBLISHABLE_KEY'),
    });

    const retry = generateS256PkceChallenge();
    const approvedStart = await startLocalAuthorization({
      authOrigin,
      clientId: client.clientId,
      redirectUri: REDIRECT,
      resource: RESOURCE,
      codeChallenge: retry.codeChallenge,
      state: 'wrong-pkce',
      projectPublishableKey: env('M4_PUBLISHABLE_KEY'),
    });
    const approved = await approveLocalAuthorization({
      authOrigin,
      authorizationId: approvedStart.authorizationId,
      userAccessToken: env('M4_ALICE_TOKEN'),
      projectPublishableKey: env('M4_PUBLISHABLE_KEY'),
    });
    await expect(
      exchangeLocalAuthorizationCode({
        authOrigin,
        clientId: client.clientId,
        redirectUri: REDIRECT,
        code: approved.code,
        codeVerifier: generateS256PkceChallenge().codeVerifier,
        resource: RESOURCE,
        projectPublishableKey: env('M4_PUBLISHABLE_KEY'),
      }),
    ).rejects.toThrow(/token exchange failed/);
  }, 20_000);
});
