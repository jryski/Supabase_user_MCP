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
});
