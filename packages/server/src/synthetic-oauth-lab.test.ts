import { randomUUID } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { LOCAL_LAB_MCP_RESOURCE_URI } from '@supabase-user-mcp/contracts';

import { generateS256PkceChallenge } from './local-oauth-pkce-client.js';
import { SyntheticOAuthLab, SyntheticOAuthLabError } from './synthetic-oauth-lab.js';

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

describe('synthetic OAuth lab PKCE', () => {
  it('issues dual-bound tokens after explicit consent and exact redirect', async () => {
    const oauth = lab();
    const pkce = generateS256PkceChallenge();
    const authorizationId = oauth.startAuthorization({
      responseType: 'code',
      clientId: CLIENT,
      redirectUri: REDIRECT,
      codeChallenge: pkce.codeChallenge,
      codeChallengeMethod: 'S256',
      resource: RESOURCE,
      principalId: PRINCIPAL,
      state: 'lab-state',
    });
    const approved = oauth.approveAuthorization(authorizationId);
    expect(approved.searchParams.get('state')).toBe('lab-state');
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
    await expect(
      oauth.inspectAccessToken({
        sessionId: randomUUID(),
        tokenFingerprint: 'deadbeef',
        nowMs: Date.now(),
        accessToken: tokens.accessToken,
      }),
    ).resolves.toBe('revoked');
    expect(tokens.tokenType).toBe('Bearer');
  });

  it('rejects missing PKCE, wrong verifier, deny, and redirect mismatch', async () => {
    const oauth = lab();
    expect(() =>
      oauth.startAuthorization({
        responseType: 'code',
        clientId: CLIENT,
        redirectUri: 'http://127.0.0.1/other',
        codeChallenge: generateS256PkceChallenge().codeChallenge,
        codeChallengeMethod: 'S256',
        resource: RESOURCE,
        principalId: PRINCIPAL,
      }),
    ).toThrow(SyntheticOAuthLabError);

    const pkce = generateS256PkceChallenge();
    const deniedId = oauth.startAuthorization({
      responseType: 'code',
      clientId: CLIENT,
      redirectUri: REDIRECT,
      codeChallenge: pkce.codeChallenge,
      codeChallengeMethod: 'S256',
      resource: RESOURCE,
      principalId: PRINCIPAL,
    });
    const denied = oauth.denyAuthorization(deniedId);
    expect(denied.searchParams.get('error')).toBe('access_denied');

    const approvedId = oauth.startAuthorization({
      responseType: 'code',
      clientId: CLIENT,
      redirectUri: REDIRECT,
      codeChallenge: pkce.codeChallenge,
      codeChallengeMethod: 'S256',
      resource: RESOURCE,
      principalId: PRINCIPAL,
    });
    const approved = oauth.approveAuthorization(approvedId);
    const code = approved.searchParams.get('code');
    if (!code) throw new Error('missing code');
    await expect(
      oauth.exchangeAuthorizationCode({
        grantType: 'authorization_code',
        code,
        clientId: CLIENT,
        redirectUri: REDIRECT,
        codeVerifier: generateS256PkceChallenge().codeVerifier,
        resource: RESOURCE,
      }),
    ).rejects.toMatchObject({ code: 'invalid_pkce' });
  });

  it('rotates refresh tokens without killing the prior access token, then grant-revoke does', async () => {
    const oauth = lab();
    const pkce = generateS256PkceChallenge();
    const authorizationId = oauth.startAuthorization({
      responseType: 'code',
      clientId: CLIENT,
      redirectUri: REDIRECT,
      codeChallenge: pkce.codeChallenge,
      codeChallengeMethod: 'S256',
      resource: RESOURCE,
      principalId: PRINCIPAL,
    });
    const approved = oauth.approveAuthorization(authorizationId);
    const code = approved.searchParams.get('code');
    if (!code) throw new Error('missing code');
    const first = await oauth.exchangeAuthorizationCode({
      grantType: 'authorization_code',
      code,
      clientId: CLIENT,
      redirectUri: REDIRECT,
      codeVerifier: pkce.codeVerifier,
      resource: RESOURCE,
    });
    const refreshed = await oauth.refresh({
      grantType: 'refresh_token',
      refreshToken: first.refreshToken,
      clientId: CLIENT,
      resource: RESOURCE,
    });
    const firstFingerprint = (await import('./remote-token-verifier.js')).fingerprintAccessToken(
      first.accessToken,
    );
    await expect(
      oauth.inspectAccessToken({
        sessionId: JSON.parse(
          Buffer.from(first.accessToken.split('.')[1] ?? '', 'base64url').toString('utf8'),
        ).session_id,
        tokenFingerprint: firstFingerprint,
        nowMs: Date.now(),
        accessToken: first.accessToken,
      }),
    ).resolves.toBe('active');
    oauth.revokeGrant(refreshed.refreshToken);
    await expect(
      oauth.inspectAccessToken({
        sessionId: JSON.parse(
          Buffer.from(first.accessToken.split('.')[1] ?? '', 'base64url').toString('utf8'),
        ).session_id,
        tokenFingerprint: firstFingerprint,
        nowMs: Date.now(),
        accessToken: first.accessToken,
      }),
    ).resolves.toBe('revoked');
  });
});
