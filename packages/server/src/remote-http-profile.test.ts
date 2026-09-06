import { randomUUID } from 'node:crypto';

import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { getOAuthProtectedResourceMetadataUrl } from '@modelcontextprotocol/server';
import { describe, expect, it } from 'vitest';

import { LOCAL_LAB_MCP_RESOURCE_URI } from '@supabase-user-mcp/contracts';

import { createAuthorizationServerMetadata } from './authorization-server-metadata.js';
import { generateS256PkceChallenge } from './local-oauth-pkce-client.js';
import { containsSecretMaterial, createRemoteHttpProfile } from './remote-http-profile.js';
import { fingerprintAccessToken } from './remote-token-verifier.js';
import {
  mintSyntheticAccessToken,
  SYNTHETIC_OAUTH_HMAC_SECRET,
  SyntheticOAuthLab,
} from './synthetic-oauth-lab.js';

const ISSUER = 'https://auth.loopback.invalid/auth/v1';
const RESOURCE = LOCAL_LAB_MCP_RESOURCE_URI;
const ORIGIN = 'https://m2-loopback.invalid';
const PRINCIPAL = '11111111-1111-4111-9111-111111111111';
const OTHER = '22222222-2222-4222-9222-222222222222';
const CLIENT = 'smp-lab-inspector';
const REDIRECT = 'http://127.0.0.1/oauth/callback';
const PUBLISHABLE = 'sb_publishable_lab_key';

const MEMORY_ROW = Object.freeze({
  id: 'mem_abcdefghijklmnopqrstuvwxyz',
  title: 'Synthetic title',
  content: 'Synthetic content',
  createdAt: '2026-09-06T00:00:00.000Z',
  provenanceSummary: 'synthetic fixture',
});

function lab(): SyntheticOAuthLab {
  return new SyntheticOAuthLab({
    issuer: ISSUER,
    resourceUri: RESOURCE,
    client: { clientId: CLIENT, redirectUri: REDIRECT, tokenEndpointAuthMethod: 'none' },
  });
}

async function issueLabToken(oauth: SyntheticOAuthLab, principalId = PRINCIPAL): Promise<string> {
  const pkce = generateS256PkceChallenge();
  const authorizationId = oauth.startAuthorization({
    responseType: 'code',
    clientId: CLIENT,
    redirectUri: REDIRECT,
    codeChallenge: pkce.codeChallenge,
    codeChallengeMethod: 'S256',
    resource: RESOURCE,
    principalId,
  });
  const approved = oauth.approveAuthorization(authorizationId);
  const code = approved.searchParams.get('code');
  if (!code) throw new Error('missing code');
  const tokens = await oauth.exchangeAuthorizationCode({
    grantType: 'authorization_code',
    code,
    clientId: CLIENT,
    redirectUri: REDIRECT,
    codeVerifier: pkce.codeVerifier,
    resource: RESOURCE,
  });
  return tokens.accessToken;
}

function supabaseFetch(): typeof globalThis.fetch {
  return async (input) => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
    if (url.pathname === '/auth/v1/user') {
      const principal = url.searchParams.get('impersonate') === OTHER ? OTHER : PRINCIPAL;
      return new Response(JSON.stringify({ id: principal, aud: 'authenticated' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    if (url.pathname.endsWith('/authorized_memory_get_v1')) {
      return new Response(JSON.stringify({ record: MEMORY_ROW }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    if (url.pathname.endsWith('/authorized_memory_search_v1')) {
      return new Response(JSON.stringify({ rows: [] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    if (url.pathname.endsWith('/authorized_memory_list_recent_v1')) {
      return new Response(JSON.stringify({ rows: [] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    return new Response(JSON.stringify({ error: 'not_found' }), { status: 404 });
  };
}

function identityFetch(principalId: string): typeof globalThis.fetch {
  const inner = supabaseFetch();
  return async (input, init) => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
    if (url.pathname === '/auth/v1/user') {
      return new Response(JSON.stringify({ id: principalId, aud: 'authenticated' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    return inner(input, init);
  };
}

describe('remote HTTP profile', () => {
  it('serves RFC 9728 metadata and challenges missing bearer with resource_metadata', async () => {
    const oauth = lab();
    const handler = createRemoteHttpProfile({
      resourceUri: RESOURCE,
      issuer: ISSUER,
      supabaseOrigin: ORIGIN,
      publishableKey: PUBLISHABLE,
      signingKey: { kind: 'hmac', secret: SYNTHETIC_OAUTH_HMAC_SECRET },
      revocationAuthority: oauth,
      authorizationServerMetadata: createAuthorizationServerMetadata(ISSUER),
      fetch: supabaseFetch(),
    });
    const metadata = await handler(
      new Request(getOAuthProtectedResourceMetadataUrl(new URL(RESOURCE))),
    );
    expect(metadata.status).toBe(200);
    const body = (await metadata.json()) as { resource?: string; authorization_servers?: string[] };
    expect(body.resource).toBe(RESOURCE);
    expect(body.authorization_servers).toContain(ISSUER);

    const unauthorized = await handler(new Request(RESOURCE, { method: 'POST' }));
    expect(unauthorized.status).toBe(401);
    const challenge = unauthorized.headers.get('WWW-Authenticate') ?? '';
    expect(challenge).toMatch(/Bearer/i);
    expect(challenge).toContain('resource_metadata');
    const errorBody = await unauthorized.text();
    expect(errorBody).toContain('invalid_token');
  });

  it('connects an MCP Client over Streamable HTTP after PKCE and never echoes the bearer', async () => {
    const oauth = lab();
    const token = await issueLabToken(oauth);
    const events: Array<{ principalId?: string; clientId?: string }> = [];
    const handler = createRemoteHttpProfile({
      resourceUri: RESOURCE,
      issuer: ISSUER,
      supabaseOrigin: ORIGIN,
      publishableKey: PUBLISHABLE,
      signingKey: { kind: 'hmac', secret: SYNTHETIC_OAUTH_HMAC_SECRET },
      revocationAuthority: oauth,
      authorizationServerMetadata: createAuthorizationServerMetadata(ISSUER),
      fetch: identityFetch(PRINCIPAL),
      emitOperationalEvent: (event) => events.push(event),
    });
    const transport = new StreamableHTTPClientTransport(new URL(RESOURCE), {
      fetch: async (input, init) => handler(new Request(input, init)),
      authProvider: { token: async () => token },
    });
    const client = new Client({ name: 'remote-http-lab', version: '0.0.0' }, { capabilities: {} });
    try {
      await client.connect(transport);
      const listing = await client.listTools();
      expect(listing.tools.map((tool) => tool.name).toSorted()).toEqual([
        'memory_get',
        'memory_list_recent',
        'memory_search',
      ]);
      const got = await client.callTool({
        name: 'memory_get',
        arguments: { id: 'mem_abcdefghijklmnopqrstuvwxyz' },
      });
      expect(got.structuredContent).toMatchObject({
        ok: true,
        record: { id: 'mem_abcdefghijklmnopqrstuvwxyz', contentTrust: 'untrusted' },
      });
    } finally {
      await Promise.allSettled([client.close(), transport.close()]);
    }
    expect(containsSecretMaterial(events, [token])).toBe(false);
    expect(fingerprintAccessToken(token)).toHaveLength(64);
  });

  it('rejects revoked access tokens while the JWT is still unexpired', async () => {
    const oauth = lab();
    const token = await issueLabToken(oauth);
    const handler = createRemoteHttpProfile({
      resourceUri: RESOURCE,
      issuer: ISSUER,
      supabaseOrigin: ORIGIN,
      publishableKey: PUBLISHABLE,
      signingKey: { kind: 'hmac', secret: SYNTHETIC_OAUTH_HMAC_SECRET },
      revocationAuthority: oauth,
      authorizationServerMetadata: createAuthorizationServerMetadata(ISSUER),
      fetch: identityFetch(PRINCIPAL),
    });
    oauth.revokeAccessToken(token);
    const response = await handler(
      new Request(RESOURCE, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
      }),
    );
    expect(response.status).toBe(401);
    expect(await response.text()).not.toContain(token);
  });

  it('keeps two request-scoped servers on the same principal budget', async () => {
    const principalId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2';
    const token = await mintSyntheticAccessToken({
      issuer: ISSUER,
      resourceUri: RESOURCE,
      principalId,
      clientId: CLIENT,
      sessionId: randomUUID(),
    });
    const handler = createRemoteHttpProfile({
      resourceUri: RESOURCE,
      issuer: ISSUER,
      supabaseOrigin: ORIGIN,
      publishableKey: PUBLISHABLE,
      signingKey: { kind: 'hmac', secret: SYNTHETIC_OAUTH_HMAC_SECRET },
      revocationAuthority: { inspectAccessToken: async () => 'active' },
      authorizationServerMetadata: createAuthorizationServerMetadata(ISSUER),
      fetch: identityFetch(principalId),
      governance: { maxRequestsPerWindow: 1, requestWindowMs: 60_000 },
    });
    const call = async () => {
      const transport = new StreamableHTTPClientTransport(new URL(RESOURCE), {
        fetch: async (input, init) => handler(new Request(input, init)),
        authProvider: { token: async () => token },
      });
      const client = new Client({ name: 'rate-limit-lab', version: '0.0.0' }, { capabilities: {} });
      try {
        await client.connect(transport);
        return await client.callTool({
          name: 'memory_get',
          arguments: { id: 'mem_abcdefghijklmnopqrstuvwxyz' },
        });
      } finally {
        await Promise.allSettled([client.close(), transport.close()]);
      }
    };
    const first = await call();
    expect(first.structuredContent).toMatchObject({ ok: true });
    const second = await call();
    expect(second.structuredContent).toMatchObject({
      ok: false,
      error: { code: 'RESOURCE_UNAVAILABLE' },
    });
  });
});
