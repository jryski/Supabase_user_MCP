import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { getOAuthProtectedResourceMetadataUrl } from '@modelcontextprotocol/server';
import {
  DOWNSTREAM_CREDENTIAL_UNRESOLVED,
  LOCAL_LAB_MCP_RESOURCE_URI,
} from '@supabase-user-mcp/contracts';
import { describe, expect, it } from 'vitest';

import { createAuthorizationServerMetadata } from './authorization-server-metadata.js';
import { generateS256PkceChallenge } from './local-oauth-pkce-client.js';
import { createRemoteHttpProfile } from './remote-http-profile.js';
import {
  mintSyntheticAccessToken,
  SYNTHETIC_OAUTH_HMAC_SECRET,
  SyntheticOAuthLab,
} from './synthetic-oauth-lab.js';

const ISSUER = 'https://auth.loopback.invalid/auth/v1';
const RESOURCE = LOCAL_LAB_MCP_RESOURCE_URI;
const PRINCIPAL = '11111111-1111-4111-9111-111111111111';
const CLIENT = 'smp-lab-inspector';
const REDIRECT = 'http://127.0.0.1/oauth/callback';

function lab(): SyntheticOAuthLab {
  return new SyntheticOAuthLab({
    issuer: ISSUER,
    resourceUri: RESOURCE,
    client: { clientId: CLIENT, redirectUri: REDIRECT, tokenEndpointAuthMethod: 'none' },
  });
}

async function issueLabToken(oauth: SyntheticOAuthLab, clientId = CLIENT): Promise<string> {
  const pkce = generateS256PkceChallenge();
  const authorizationId = oauth.startAuthorization({
    responseType: 'code',
    clientId,
    redirectUri: REDIRECT,
    codeChallenge: pkce.codeChallenge,
    codeChallengeMethod: 'S256',
    resource: RESOURCE,
    principalId: PRINCIPAL,
  });
  const approved = oauth.approveAuthorization(authorizationId);
  const code = approved.searchParams.get('code');
  if (!code) throw new Error('missing code');
  const tokens = await oauth.exchangeAuthorizationCode({
    grantType: 'authorization_code',
    code,
    clientId,
    redirectUri: REDIRECT,
    codeVerifier: pkce.codeVerifier,
    resource: RESOURCE,
  });
  return tokens.accessToken;
}

function trackingFetch(calls: string[]): typeof globalThis.fetch {
  return async (input) => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
    calls.push(url.pathname);
    return new Response(JSON.stringify({ error: 'not_found' }), { status: 404 });
  };
}

function profile(oauth: SyntheticOAuthLab, fetchImpl?: typeof globalThis.fetch) {
  return createRemoteHttpProfile({
    resourceUri: RESOURCE,
    issuer: ISSUER,
    expectedClientId: CLIENT,
    signingKey: { kind: 'hmac', secret: SYNTHETIC_OAUTH_HMAC_SECRET },
    revocationAuthority: oauth,
    authorizationServerMetadata: createAuthorizationServerMetadata(ISSUER),
    ...(fetchImpl === undefined ? {} : { fetch: fetchImpl }),
  });
}

describe('remote HTTP profile', () => {
  it('does not construct a Data API client from the inbound MCP bearer', async () => {
    const source = await readFile(new URL('./remote-http-profile.ts', import.meta.url), 'utf8');
    expect(source).not.toMatch(/userAccessToken:\s*auth\.token/);
    expect(source).not.toContain('createFixedSupabaseClient');
    expect(source).not.toContain('createReadOnlyServer');
    expect(source).not.toContain('service_role');
    expect(source).not.toContain('urn:ietf:params:oauth:grant-type:token-exchange');
    expect(source).toContain('DOWNSTREAM_CREDENTIAL_UNRESOLVED');
  });

  it('serves RFC 9728 metadata and challenges missing bearer with resource_metadata', async () => {
    const oauth = lab();
    const handler = profile(oauth);
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

  it('verifies a PKCE bearer then fail-closes without forwarding it to the Data API', async () => {
    const oauth = lab();
    const token = await issueLabToken(oauth);
    const paths: string[] = [];
    const handler = profile(oauth, trackingFetch(paths));
    const response = await handler(
      new Request(RESOURCE, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
      }),
    );
    expect(response.status).toBe(403);
    const body = await response.text();
    expect(JSON.parse(body)).toEqual({ error: DOWNSTREAM_CREDENTIAL_UNRESOLVED });
    expect(body).not.toContain(token);
    expect(paths.some((path) => path.startsWith('/rest/v1'))).toBe(false);
  });

  it('rejects a wrong-client bearer before dispatch and makes zero Data API calls', async () => {
    const oauth = lab();
    const token = await mintSyntheticAccessToken({
      issuer: ISSUER,
      resourceUri: RESOURCE,
      principalId: PRINCIPAL,
      clientId: 'smp-other-client',
      sessionId: randomUUID(),
    });
    const paths: string[] = [];
    const handler = profile(oauth, trackingFetch(paths));
    const response = await handler(
      new Request(RESOURCE, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
        body: '{}',
      }),
    );
    expect(response.status).toBe(401);
    expect(await response.text()).not.toContain(token);
    expect(paths).toEqual([]);
  });

  it('rejects revoked access tokens while the JWT is still unexpired', async () => {
    const oauth = lab();
    const token = await issueLabToken(oauth);
    const handler = profile(oauth);
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

  it('rejects query-string access_token without Authorization and makes zero Data API calls', async () => {
    const oauth = lab();
    const validToken = await issueLabToken(oauth);
    const forgedToken = await mintSyntheticAccessToken({
      issuer: ISSUER,
      resourceUri: RESOURCE,
      principalId: PRINCIPAL,
      clientId: 'smp-attacker',
      sessionId: randomUUID(),
    });
    for (const queryToken of [validToken, forgedToken]) {
      const paths: string[] = [];
      const response = await profile(
        oauth,
        trackingFetch(paths),
      )(
        new Request(`${RESOURCE}?access_token=${encodeURIComponent(queryToken)}`, {
          method: 'POST',
          headers: { Accept: 'application/json' },
          body: '{}',
        }),
      );
      expect(response.status).toBe(401);
      const body = await response.text();
      expect(body).not.toContain(queryToken);
      expect(body).not.toContain(DOWNSTREAM_CREDENTIAL_UNRESOLVED);
      expect(paths).toEqual([]);
    }
  });

  it('ignores query-string access_token when Authorization bearer is valid and makes zero Data API calls', async () => {
    const oauth = lab();
    const token = await issueLabToken(oauth);
    const forgedQueryToken = await mintSyntheticAccessToken({
      issuer: ISSUER,
      resourceUri: RESOURCE,
      principalId: PRINCIPAL,
      clientId: 'smp-attacker',
      sessionId: randomUUID(),
    });
    const paths: string[] = [];
    const handler = profile(oauth, trackingFetch(paths));
    const response = await handler(
      new Request(`${RESOURCE}?access_token=${encodeURIComponent(forgedQueryToken)}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
      }),
    );
    expect(response.status).toBe(403);
    const body = await response.text();
    expect(JSON.parse(body)).toEqual({ error: DOWNSTREAM_CREDENTIAL_UNRESOLVED });
    expect(body).not.toContain(forgedQueryToken);
    expect(body).not.toContain(token);
    expect(paths).toEqual([]);
  });

  it('rejects alternate-header bearer tokens without Authorization and makes zero Data API calls', async () => {
    const oauth = lab();
    const token = await issueLabToken(oauth);
    const alternateHeaders = [
      { 'x-access-token': token },
      { 'x-supabase-access-token': token },
      { 'x-forwarded-authorization': `Bearer ${token}` },
      { 'x-authorization': `Bearer ${token}` },
    ] as const;
    for (const headers of alternateHeaders) {
      const paths: string[] = [];
      const handler = profile(oauth, trackingFetch(paths));
      const response = await handler(
        new Request(RESOURCE, {
          method: 'POST',
          headers: { Accept: 'application/json', ...headers },
          body: '{}',
        }),
      );
      expect(response.status).toBe(401);
      const body = await response.text();
      expect(body).not.toContain(token);
      expect(body).not.toContain(DOWNSTREAM_CREDENTIAL_UNRESOLVED);
      expect(paths).toEqual([]);
    }
    const pathsSmuggled: string[] = [];
    const smuggled = profile(oauth, trackingFetch(pathsSmuggled));
    const smuggledResponse = await smuggled(
      new Request(RESOURCE, {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer',
          'x-forwarded-authorization': `Bearer ${token}`,
        },
        body: '{}',
      }),
    );
    expect(smuggledResponse.status).toBe(401);
    const smuggledBody = await smuggledResponse.text();
    expect(smuggledBody).not.toContain(token);
    expect(smuggledBody).not.toContain(DOWNSTREAM_CREDENTIAL_UNRESOLVED);
    expect(pathsSmuggled).toEqual([]);
  });

  function toolsCallBody(credentialKey: string, credentialValue: string): string {
    return JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'probe', arguments: { [credentialKey]: credentialValue } },
    });
  }

  it('rejects tools/call argument bearer without Authorization and makes zero Data API calls', async () => {
    const oauth = lab();
    const token = await issueLabToken(oauth);
    for (const key of ['access_token', 'bearer', 'authorization'] as const) {
      const paths: string[] = [];
      const handler = profile(oauth, trackingFetch(paths));
      const response = await handler(
        new Request(RESOURCE, {
          method: 'POST',
          headers: { Accept: 'application/json', 'content-type': 'application/json' },
          body: toolsCallBody(key, key === 'authorization' ? `Bearer ${token}` : token),
        }),
      );
      expect(response.status).toBe(401);
      const body = await response.text();
      expect(body).not.toContain(token);
      expect(body).not.toContain(DOWNSTREAM_CREDENTIAL_UNRESOLVED);
      expect(paths).toEqual([]);
    }
  });

  it('keeps header-derived auth when tools/call arguments carry bearer tokens and makes zero Data API calls', async () => {
    const oauth = lab();
    const token = await issueLabToken(oauth);
    const paths: string[] = [];
    const handler = profile(oauth, trackingFetch(paths));
    const response = await handler(
      new Request(RESOURCE, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/json',
          'content-type': 'application/json',
        },
        body: toolsCallBody('access_token', token),
      }),
    );
    expect(response.status).toBe(403);
    const body = await response.text();
    expect(JSON.parse(body)).toEqual({ error: DOWNSTREAM_CREDENTIAL_UNRESOLVED });
    expect(body).not.toContain(token);
    expect(paths).toEqual([]);
  });

  it('denied auth never dispatches to the Data API or reaches downstream credential unresolved', async () => {
    const oauth = lab();
    const validToken = await issueLabToken(oauth);
    const wrongClientToken = await mintSyntheticAccessToken({
      issuer: ISSUER,
      resourceUri: RESOURCE,
      principalId: PRINCIPAL,
      clientId: 'smp-other-client',
      sessionId: randomUUID(),
    });
    oauth.revokeAccessToken(validToken);
    const cases: Array<{ label: string; headers: Record<string, string> }> = [
      { label: 'missing bearer', headers: { Accept: 'application/json' } },
      {
        label: 'malformed bearer',
        headers: { Authorization: 'Bearer', Accept: 'application/json' },
      },
      {
        label: 'wrong-client bearer',
        headers: { Authorization: `Bearer ${wrongClientToken}`, Accept: 'application/json' },
      },
      {
        label: 'revoked bearer',
        headers: { Authorization: `Bearer ${validToken}`, Accept: 'application/json' },
      },
    ];
    for (const { headers } of cases) {
      const paths: string[] = [];
      const handler = profile(oauth, trackingFetch(paths));
      const response = await handler(
        new Request(RESOURCE, {
          method: 'POST',
          headers,
          body: '{}',
        }),
      );
      expect(response.status).toBe(401);
      const body = await response.text();
      expect(body).not.toContain(DOWNSTREAM_CREDENTIAL_UNRESOLVED);
      const presented = headers.Authorization?.match(/^Bearer\s+(.+)$/i)?.[1] ?? '';
      if (presented.length > 0) {
        expect(body).not.toContain(presented);
      }
      expect(paths).toEqual([]);
    }
  });
});
