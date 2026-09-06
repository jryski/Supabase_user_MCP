import { randomUUID } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { DATA_API_AUDIENCE, LOCAL_LAB_MCP_RESOURCE_URI } from '@supabase-user-mcp/contracts';

import { generateS256PkceChallenge } from './local-oauth-pkce-client.js';
import {
  mintSyntheticAccessToken,
  SYNTHETIC_OAUTH_HMAC_SECRET,
  SyntheticOAuthLab,
} from './synthetic-oauth-lab.js';
import {
  createRemoteAccessTokenVerifier,
  fingerprintAccessToken,
  RemoteAccessTokenVerificationError,
} from './remote-token-verifier.js';

const ISSUER = 'https://auth.loopback.invalid/auth/v1';
const RESOURCE = LOCAL_LAB_MCP_RESOURCE_URI;
const PRINCIPAL = '11111111-1111-4111-9111-111111111111';
const CLIENT = 'smp-lab-inspector';

async function denialOf(
  token: string,
  extras?: {
    now?: () => number;
    authority?: { inspectAccessToken: SyntheticOAuthLab['inspectAccessToken'] };
  },
): Promise<string> {
  const verifier = createRemoteAccessTokenVerifier({
    issuer: ISSUER,
    resourceUri: RESOURCE,
    signingKey: { kind: 'hmac', secret: SYNTHETIC_OAUTH_HMAC_SECRET },
    revocationAuthority: extras?.authority ?? {
      inspectAccessToken: async () => 'active',
    },
    ...(extras?.now === undefined ? {} : { now: extras.now }),
  });
  try {
    await verifier.verifyAccessToken(token);
    throw new Error('expected denial');
  } catch (error) {
    if (error instanceof RemoteAccessTokenVerificationError) return error.denialClass;
    throw error;
  }
}

describe('remote access-token verifier', () => {
  it('accepts dual-bound tokens and ignores user_metadata authority keys', async () => {
    const sessionId = randomUUID();
    const lab = new SyntheticOAuthLab({
      issuer: ISSUER,
      resourceUri: RESOURCE,
      client: {
        clientId: CLIENT,
        redirectUri: 'http://127.0.0.1/oauth/callback',
        tokenEndpointAuthMethod: 'none',
      },
    });
    const token = await mintSyntheticAccessToken({
      issuer: ISSUER,
      resourceUri: RESOURCE,
      principalId: PRINCIPAL,
      clientId: CLIENT,
      sessionId,
      extraClaims: { user_metadata: { client_id: 'forged-user', read_only: true } },
    });
    lab.revokeAccessToken('unrelated');
    const verifier = createRemoteAccessTokenVerifier({
      issuer: ISSUER,
      resourceUri: RESOURCE,
      signingKey: { kind: 'hmac', secret: SYNTHETIC_OAUTH_HMAC_SECRET },
      revocationAuthority: {
        inspectAccessToken: async () => 'active',
      },
    });
    const auth = await verifier.verifyAccessToken(token);
    expect(auth.clientId).toBe(CLIENT);
    expect(auth.token).toBe(token);
    expect(auth.resource?.href).toBe(RESOURCE);
    expect(JSON.stringify(auth.extra)).not.toContain(token);
  });

  it('rejects missing, malformed, expired, wrong-issuer, and wrong-role tokens', async () => {
    expect(await denialOf('not-a-jwt')).toBe('malformed_bearer');
    const expired = await mintSyntheticAccessToken({
      issuer: ISSUER,
      resourceUri: RESOURCE,
      principalId: PRINCIPAL,
      clientId: CLIENT,
      sessionId: randomUUID(),
      now: () => 0,
      expiresInSec: 1,
    });
    expect(await denialOf(expired, { now: () => 5_000 })).toBe('expired');
    const wrongIss = await mintSyntheticAccessToken({
      issuer: 'https://other.loopback.invalid/auth/v1',
      resourceUri: RESOURCE,
      principalId: PRINCIPAL,
      clientId: CLIENT,
      sessionId: randomUUID(),
    });
    expect(await denialOf(wrongIss)).toBe('wrong_issuer');
    const wrongRole = await mintSyntheticAccessToken({
      issuer: ISSUER,
      resourceUri: RESOURCE,
      principalId: PRINCIPAL,
      clientId: CLIENT,
      sessionId: randomUUID(),
      role: 'service_role',
    });
    expect(await denialOf(wrongRole)).toBe('wrong_role');
  });

  it('requires Data API audience and mandatory MCP resource binding', async () => {
    const sessionId = randomUUID();
    const dataApiOnly = await mintSyntheticAccessToken({
      issuer: ISSUER,
      resourceUri: RESOURCE,
      principalId: PRINCIPAL,
      clientId: CLIENT,
      sessionId,
      aud: [DATA_API_AUDIENCE],
      resource: null,
    });
    expect(await denialOf(dataApiOnly)).toBe('missing_resource_binding');
    const mcpOnly = await mintSyntheticAccessToken({
      issuer: ISSUER,
      resourceUri: RESOURCE,
      principalId: PRINCIPAL,
      clientId: CLIENT,
      sessionId,
      aud: [RESOURCE],
      resource: RESOURCE,
    });
    expect(await denialOf(mcpOnly)).toBe('missing_data_api_audience');
    const wrongResource = await mintSyntheticAccessToken({
      issuer: ISSUER,
      resourceUri: RESOURCE,
      principalId: PRINCIPAL,
      clientId: CLIENT,
      sessionId,
      aud: [DATA_API_AUDIENCE, 'https://other.loopback.invalid/mcp'],
      resource: 'https://other.loopback.invalid/mcp',
    });
    expect(await denialOf(wrongResource)).toBe('wrong_resource');
  });

  it('never authorizes from user_metadata client_id', async () => {
    const token = await mintSyntheticAccessToken({
      issuer: ISSUER,
      resourceUri: RESOURCE,
      principalId: PRINCIPAL,
      clientId: CLIENT,
      sessionId: randomUUID(),
      extraClaims: {
        client_id: '',
        app_metadata: {},
        user_metadata: { client_id: CLIENT, read_only: true },
      },
    });
    expect(await denialOf(token)).toBe('missing_client_id');
  });

  it('enforces access-token revocation separately from grant/refresh and remaining exp', async () => {
    const lab = new SyntheticOAuthLab({
      issuer: ISSUER,
      resourceUri: RESOURCE,
      client: {
        clientId: CLIENT,
        redirectUri: 'http://127.0.0.1/oauth/callback',
        tokenEndpointAuthMethod: 'none',
      },
    });
    const verifier = createRemoteAccessTokenVerifier({
      issuer: ISSUER,
      resourceUri: RESOURCE,
      signingKey: { kind: 'hmac', secret: SYNTHETIC_OAUTH_HMAC_SECRET },
      revocationAuthority: lab,
    });
    const pkce = generateS256PkceChallenge();
    const authorizationId = lab.startAuthorization({
      responseType: 'code',
      clientId: CLIENT,
      redirectUri: 'http://127.0.0.1/oauth/callback',
      codeChallenge: pkce.codeChallenge,
      codeChallengeMethod: 'S256',
      resource: RESOURCE,
      principalId: PRINCIPAL,
    });
    const redirect = lab.approveAuthorization(authorizationId);
    const code = redirect.searchParams.get('code');
    if (!code) throw new Error('missing code');
    const tokens = await lab.exchangeAuthorizationCode({
      grantType: 'authorization_code',
      code,
      clientId: CLIENT,
      redirectUri: 'http://127.0.0.1/oauth/callback',
      codeVerifier: pkce.codeVerifier,
      resource: RESOURCE,
    });
    await expect(verifier.verifyAccessToken(tokens.accessToken)).resolves.toMatchObject({
      clientId: CLIENT,
    });
    lab.revokeAccessToken(tokens.accessToken);
    await expect(verifier.verifyAccessToken(tokens.accessToken)).rejects.toMatchObject({
      denialClass: 'revoked_access_token',
    });
    expect(fingerprintAccessToken(tokens.accessToken)).toHaveLength(64);
  });

  it('fails closed when live revocation exceeds the latency bound', async () => {
    const token = await mintSyntheticAccessToken({
      issuer: ISSUER,
      resourceUri: RESOURCE,
      principalId: PRINCIPAL,
      clientId: CLIENT,
      sessionId: randomUUID(),
    });
    let nowMs = 1_000;
    const verifier = createRemoteAccessTokenVerifier({
      issuer: ISSUER,
      resourceUri: RESOURCE,
      signingKey: { kind: 'hmac', secret: SYNTHETIC_OAUTH_HMAC_SECRET },
      now: () => nowMs,
      revocationAuthority: {
        inspectAccessToken: async () => {
          nowMs += 5_001;
          return 'active';
        },
      },
    });
    await expect(verifier.verifyAccessToken(token)).rejects.toMatchObject({
      denialClass: 'revoked_access_token',
    });
  });
});
