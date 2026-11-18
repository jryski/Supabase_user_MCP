import { LOCAL_LAB_MCP_RESOURCE_URI } from '@supabase-user-mcp/contracts';
import { describe, expect, it } from 'vitest';

import { generateS256PkceChallenge } from './local-oauth-pkce-client.js';
import { containsSecretMaterial } from './remote-http-profile.js';
import { fingerprintAccessToken } from './remote-token-verifier.js';
import {
  SYNTHETIC_OAUTH_HMAC_SECRET,
  SyntheticOAuthLab,
  SyntheticOAuthLabError,
  type SyntheticTokenSuccess,
} from './synthetic-oauth-lab.js';

const ISSUER = 'https://auth.loopback.invalid/auth/v1';
const RESOURCE = LOCAL_LAB_MCP_RESOURCE_URI;
const PRINCIPAL = '11111111-1111-4111-9111-111111111111';
const CLIENT = 'smp-lab-inspector';
const REDIRECT = 'http://127.0.0.1/oauth/callback';
const WRONG_CLIENT = 'smp-lab-evil-client';
const WRONG_RESOURCE = 'https://mcp.evil.invalid/mcp';
const HMAC_SECRET_LITERAL = new TextDecoder().decode(SYNTHETIC_OAUTH_HMAC_SECRET);
const REFRESH_TOKEN_PUBLIC_SHAPE = /^rt_[A-Za-z0-9_-]{32}$/;

function lab(): SyntheticOAuthLab {
  return new SyntheticOAuthLab({
    issuer: ISSUER,
    resourceUri: RESOURCE,
    client: { clientId: CLIENT, redirectUri: REDIRECT, tokenEndpointAuthMethod: 'none' },
  });
}

function expectOpaqueRefreshTokenShape(refreshToken: string): void {
  expect(refreshToken).toMatch(REFRESH_TOKEN_PUBLIC_SHAPE);
}

function accessTokenSessionId(accessToken: string): string {
  return JSON.parse(Buffer.from(accessToken.split('.')[1] ?? '', 'base64url').toString('utf8'))
    .session_id as string;
}

async function issueInitialTokens(oauth: SyntheticOAuthLab): Promise<SyntheticTokenSuccess> {
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
  const tokens = await oauth.exchangeAuthorizationCode({
    grantType: 'authorization_code',
    code,
    clientId: CLIENT,
    redirectUri: REDIRECT,
    codeVerifier: pkce.codeVerifier,
    resource: RESOURCE,
  });
  expectOpaqueRefreshTokenShape(tokens.refreshToken);
  return tokens;
}

function refreshInput(
  refreshToken: string,
  overrides: Partial<{ clientId: string; resource: string }> = {},
) {
  return {
    grantType: 'refresh_token' as const,
    refreshToken,
    clientId: overrides.clientId ?? CLIENT,
    resource: overrides.resource ?? RESOURCE,
  };
}

function assertRefreshErrorDoesNotLeakMaterial(
  error: unknown,
  secrets: readonly string[],
): asserts error is SyntheticOAuthLabError {
  expect(error).toBeInstanceOf(SyntheticOAuthLabError);
  const labError = error as SyntheticOAuthLabError;
  const publicShape = {
    name: labError.name,
    code: labError.code,
    message: labError.message,
  };
  expect(containsSecretMaterial(publicShape, secrets)).toBe(false);
  for (const secret of secrets) {
    expect(labError.message).not.toContain(secret);
    if (labError.stack !== undefined) {
      expect(labError.stack).not.toContain(secret);
    }
  }
}

describe('issue63 refresh rotation and reuse guards', () => {
  it('returns a new refresh token distinct from the consumed token on success', async () => {
    const oauth = lab();
    const initial = await issueInitialTokens(oauth);
    const consumed = initial.refreshToken;

    const rotated = await oauth.refresh(refreshInput(consumed));
    expectOpaqueRefreshTokenShape(rotated.refreshToken);
    expect(rotated.refreshToken).not.toBe(consumed);

    await expect(
      oauth.inspectAccessToken({
        sessionId: accessTokenSessionId(rotated.accessToken),
        tokenFingerprint: fingerprintAccessToken(rotated.accessToken),
        nowMs: Date.now(),
        accessToken: rotated.accessToken,
      }),
    ).resolves.toBe('active');
  });

  it('rejects reuse of a refresh token after it was consumed by a successful refresh', async () => {
    const oauth = lab();
    const initial = await issueInitialTokens(oauth);
    const consumed = initial.refreshToken;
    const rotation = await oauth.refresh(refreshInput(consumed));
    expectOpaqueRefreshTokenShape(rotation.refreshToken);

    const secrets = [
      consumed,
      initial.accessToken,
      rotation.refreshToken,
      rotation.accessToken,
      HMAC_SECRET_LITERAL,
    ];
    await expect(oauth.refresh(refreshInput(consumed))).rejects.toSatisfy((error: unknown) => {
      assertRefreshErrorDoesNotLeakMaterial(error, secrets);
      expect((error as SyntheticOAuthLabError).code).toBe('invalid_grant');
      return true;
    });
  });

  it('allows one refresh with the rotated token and then rejects reuse of that rotated token', async () => {
    const oauth = lab();
    const initial = await issueInitialTokens(oauth);
    const firstRotation = await oauth.refresh(refreshInput(initial.refreshToken));
    expectOpaqueRefreshTokenShape(firstRotation.refreshToken);
    const consumedRotated = firstRotation.refreshToken;

    const secondRotation = await oauth.refresh(refreshInput(consumedRotated));
    expectOpaqueRefreshTokenShape(secondRotation.refreshToken);
    expect(secondRotation.refreshToken).not.toBe(consumedRotated);

    await expect(oauth.refresh(refreshInput(consumedRotated))).rejects.toMatchObject({
      code: 'invalid_grant',
    });
  });

  it('rejects wrong client and wrong resource without consuming a still-valid refresh token', async () => {
    const oauth = lab();
    const initial = await issueInitialTokens(oauth);
    const refreshToken = initial.refreshToken;
    const secrets = [refreshToken, initial.accessToken, HMAC_SECRET_LITERAL];

    await expect(
      oauth.refresh(refreshInput(refreshToken, { clientId: WRONG_CLIENT })),
    ).rejects.toSatisfy((error: unknown) => {
      assertRefreshErrorDoesNotLeakMaterial(error, secrets);
      expect((error as SyntheticOAuthLabError).code).toBe('invalid_client');
      return true;
    });

    await expect(
      oauth.refresh(refreshInput(refreshToken, { resource: WRONG_RESOURCE })),
    ).rejects.toSatisfy((error: unknown) => {
      assertRefreshErrorDoesNotLeakMaterial(error, secrets);
      expect((error as SyntheticOAuthLabError).code).toBe('invalid_resource');
      return true;
    });

    const afterRejectedAttempts = await oauth.refresh(refreshInput(refreshToken));
    expectOpaqueRefreshTokenShape(afterRejectedAttempts.refreshToken);
    expect(afterRejectedAttempts.refreshToken).not.toBe(refreshToken);
  });

  it('revokes the grant via the current rotated refresh token and blocks further refresh', async () => {
    const oauth = lab();
    const initial = await issueInitialTokens(oauth);
    const rotated = await oauth.refresh(refreshInput(initial.refreshToken));
    expectOpaqueRefreshTokenShape(rotated.refreshToken);
    oauth.revokeGrant(rotated.refreshToken);

    await expect(oauth.refresh(refreshInput(rotated.refreshToken))).rejects.toMatchObject({
      code: 'invalid_grant',
    });
  });
});
