import { randomUUID } from 'node:crypto';

import {
  DOWNSTREAM_CREDENTIAL_UNRESOLVED,
  LOCAL_LAB_MCP_RESOURCE_URI,
} from '@supabase-user-mcp/contracts';
import { describe, expect, it } from 'vitest';

import { createAuthorizationServerMetadata } from './authorization-server-metadata.js';
import { generateS256PkceChallenge } from './local-oauth-pkce-client.js';
import { createRemoteHttpProfile } from './remote-http-profile.js';
import type {
  AccessTokenRevocationAuthority,
  AccessTokenRevocationInspectInput,
} from './remote-token-verifier.js';
import {
  mintSyntheticAccessToken,
  SYNTHETIC_OAUTH_HMAC_SECRET,
  SyntheticOAuthLab,
} from './synthetic-oauth-lab.js';

const ISSUER = 'https://auth.loopback.invalid/auth/v1';
const RESOURCE = LOCAL_LAB_MCP_RESOURCE_URI;
const PRINCIPAL_A = '11111111-1111-4111-9111-111111111111';
const PRINCIPAL_B = '22222222-2222-4222-9222-222222222222';
const CLIENT = 'smp-lab-inspector';
const OTHER_CLIENT = 'smp-other-client';
const REDIRECT = 'http://127.0.0.1/oauth/callback';

function lab(): SyntheticOAuthLab {
  return new SyntheticOAuthLab({
    issuer: ISSUER,
    resourceUri: RESOURCE,
    client: { clientId: CLIENT, redirectUri: REDIRECT, tokenEndpointAuthMethod: 'none' },
  });
}

async function issueLabToken(
  oauth: SyntheticOAuthLab,
  options?: { principalId?: string; clientId?: string },
): Promise<string> {
  const clientId = options?.clientId ?? CLIENT;
  const principalId = options?.principalId ?? PRINCIPAL_A;
  const pkce = generateS256PkceChallenge();
  const authorizationId = oauth.startAuthorization({
    responseType: 'code',
    clientId,
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

function wrapRevocationAuthority(
  oauth: SyntheticOAuthLab,
  hook: (input: AccessTokenRevocationInspectInput) => Promise<void>,
): AccessTokenRevocationAuthority {
  return {
    inspectAccessToken: async (input) => {
      await hook(input);
      return oauth.inspectAccessToken(input);
    },
  };
}

function profile(
  oauth: SyntheticOAuthLab,
  options?: {
    fetchImpl?: typeof globalThis.fetch;
    revocationAuthority?: AccessTokenRevocationAuthority;
  },
) {
  return createRemoteHttpProfile({
    resourceUri: RESOURCE,
    issuer: ISSUER,
    expectedClientId: CLIENT,
    signingKey: { kind: 'hmac', secret: SYNTHETIC_OAUTH_HMAC_SECRET },
    revocationAuthority: options?.revocationAuthority ?? oauth,
    authorizationServerMetadata: createAuthorizationServerMetadata(ISSUER),
    ...(options?.fetchImpl === undefined ? {} : { fetch: options.fetchImpl }),
  });
}

function postMcp(token: string | undefined, id: number, signal?: AbortSignal): Request {
  return new Request(RESOURCE, {
    method: 'POST',
    ...(signal === undefined ? {} : { signal }),
    headers: {
      Accept: 'application/json',
      'content-type': 'application/json',
      ...(token === undefined ? {} : { Authorization: `Bearer ${token}` }),
    },
    body: JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/list', params: {} }),
  });
}

describe('remote HTTP profile process/concurrency (issue #63)', () => {
  it('rejects a wrong-client bearer concurrently without reaching revocation inspect', async () => {
    const oauth = lab();
    const allowedToken = await issueLabToken(oauth, { clientId: CLIENT });
    const otherClientToken = await mintSyntheticAccessToken({
      issuer: ISSUER,
      resourceUri: RESOURCE,
      principalId: PRINCIPAL_B,
      clientId: OTHER_CLIENT,
      sessionId: randomUUID(),
    });

    const inspectTokens: string[] = [];
    const handler = profile(oauth, {
      revocationAuthority: wrapRevocationAuthority(oauth, async (input) => {
        inspectTokens.push(input.accessToken);
      }),
    });

    const [allowed, denied] = await Promise.all([
      handler(postMcp(allowedToken, 10)),
      handler(postMcp(otherClientToken, 11)),
    ]);

    expect(allowed.status).toBe(403);
    expect(denied.status).toBe(401);
    const allowedBody = await allowed.text();
    const deniedBody = await denied.text();
    expect(allowedBody).not.toContain(otherClientToken);
    expect(deniedBody).not.toContain(allowedToken);
    expect(deniedBody).not.toContain(DOWNSTREAM_CREDENTIAL_UNRESOLVED);
    expect(inspectTokens).toEqual([allowedToken]);
  });

  it('does not let concurrent denials perturb a verified request held in revocation inspect', async () => {
    const oauth = lab();
    const validToken = await issueLabToken(oauth);
    const wrongClientToken = await mintSyntheticAccessToken({
      issuer: ISSUER,
      resourceUri: RESOURCE,
      principalId: PRINCIPAL_A,
      clientId: OTHER_CLIENT,
      sessionId: randomUUID(),
    });
    const revokedToken = await issueLabToken(oauth, { principalId: PRINCIPAL_B });
    oauth.revokeAccessToken(revokedToken);

    let validHoldingInspect!: () => void;
    const validInsideInspect = new Promise<void>((resolve) => {
      validHoldingInspect = resolve;
    });
    let releaseValid!: () => void;
    const releaseValidFromInspect = new Promise<void>((resolve) => {
      releaseValid = resolve;
    });

    const injectedFetchPaths: string[] = [];
    const handler = profile(oauth, {
      fetchImpl: trackingFetch(injectedFetchPaths),
      revocationAuthority: wrapRevocationAuthority(oauth, async (input) => {
        if (input.accessToken === validToken) {
          validHoldingInspect();
          await releaseValidFromInspect;
        }
      }),
    });

    const validInFlight = handler(postMcp(validToken, 20));
    await validInsideInspect;

    const deniedCases = await Promise.all([
      handler(postMcp(undefined, 21)),
      handler(postMcp(wrongClientToken, 22)),
      handler(postMcp(revokedToken, 23)),
    ]);
    expect(injectedFetchPaths).toEqual([]);

    for (const denied of deniedCases) {
      expect(denied.status).toBe(401);
      const body = await denied.text();
      expect(body).not.toContain(validToken);
      expect(body).not.toContain(DOWNSTREAM_CREDENTIAL_UNRESOLVED);
    }

    releaseValid();
    const validResponse = await validInFlight;
    expect(validResponse.status).toBe(403);
    const validBody = await validResponse.text();
    expect(JSON.parse(validBody)).toEqual({ error: DOWNSTREAM_CREDENTIAL_UNRESOLVED });
    expect(validBody).not.toContain(wrongClientToken);
    expect(validBody).not.toContain(revokedToken);
    expect(injectedFetchPaths).toEqual([]);
  });

  it('does not replay a bearer aborted during revocation inspect onto a later header-less request', async () => {
    const oauth = lab();
    const tokenA = await issueLabToken(oauth, { principalId: PRINCIPAL_A });
    const inspectedTokens: string[] = [];

    let holdingInspect!: () => void;
    const insideInspect = new Promise<void>((resolve) => {
      holdingInspect = resolve;
    });
    let releaseInspect!: () => void;
    const releaseFromInspect = new Promise<void>((resolve) => {
      releaseInspect = resolve;
    });

    const abortController = new AbortController();
    const handler = profile(oauth, {
      revocationAuthority: {
        inspectAccessToken: async (input) => {
          inspectedTokens.push(input.accessToken);
          if (input.accessToken === tokenA) {
            holdingInspect();
            abortController.abort();
            await releaseFromInspect;
          }
          return oauth.inspectAccessToken(input);
        },
      },
    });

    const abortedInFlight = handler(postMcp(tokenA, 30, abortController.signal));
    await insideInspect;
    releaseInspect();
    const abortedOutcome = await abortedInFlight;
    // requireBearerAuth does not consult Request.signal; abort does not cancel verification.
    expect(abortedOutcome.status).toBe(403);
    expect(JSON.parse(await abortedOutcome.text())).toEqual({
      error: DOWNSTREAM_CREDENTIAL_UNRESOLVED,
    });

    const headerLess = await handler(postMcp(undefined, 31));
    expect(headerLess.status).toBe(401);
    expect(await headerLess.text()).not.toContain(tokenA);
    expect(inspectedTokens).toEqual([tokenA]);
  });
});
