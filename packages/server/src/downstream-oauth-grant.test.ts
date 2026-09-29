import { exportJWK, generateKeyPair, type JWK, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import {
  DOWNSTREAM_B_GRANT_PROFILE,
  DOWNSTREAM_B_SCOPE,
  type DownstreamHandshakePrincipal,
  DownstreamOAuthGrantStore,
} from './downstream-oauth-grant.js';

const ISSUER = 'https://project.loopback.invalid/auth/v1';
const ORIGIN = 'https://project.loopback.invalid';
const REDIRECT = 'http://127.0.0.1:8788/oauth/downstream/callback';
const A_CLIENT = 'smp-lab-inspector';
const B_CLIENT = 'smp-downstream-b';
const AGENT = 'hook-only-agent';
const SUB = '11111111-1111-4111-8111-111111111111';
const SOURCE = '22222222-2222-4222-8222-222222222222';
const B_SESSION = '33333333-3333-4333-8333-333333333333';
const DECOY = '44444444-4444-4444-8444-444444444444';
const REFRESH = 'refresh-sentinel-must-not-remain';

const principal: DownstreamHandshakePrincipal = {
  sourceSessionId: SOURCE,
  sub: SUB,
  agentId: AGENT,
  aClientId: A_CLIENT,
};

async function keys() {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  return {
    privateKey,
    jwks: { keys: [{ ...jwk, kid: 'g2-test', alg: 'ES256', use: 'sig' }] as JWK[] },
  };
}

async function sign(
  privateKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'],
  claims: Record<string, unknown>,
  audience: string | readonly string[] = 'authenticated',
  expiresIn = '2m',
): Promise<string> {
  let jwt = new SignJWT(claims)
    .setProtectedHeader({ alg: 'ES256', kid: 'g2-test', typ: 'JWT' })
    .setSubject(typeof claims.sub === 'string' ? claims.sub : SUB)
    .setIssuer(typeof claims.iss === 'string' ? claims.iss : ISSUER)
    .setAudience(typeof audience === 'string' ? audience : [...audience])
    .setIssuedAt();
  jwt = jwt.setExpirationTime(expiresIn);
  return jwt.sign(privateKey);
}

function storeFor(
  material: Awaited<ReturnType<typeof keys>>,
  fetchImpl: typeof fetch,
  now = () => Date.now(),
): DownstreamOAuthGrantStore {
  return new DownstreamOAuthGrantStore({
    issuer: ISSUER,
    authOrigin: ORIGIN,
    expectedBClientId: B_CLIENT,
    expectedAgentId: AGENT,
    redirectUri: REDIRECT,
    jwks: material.jwks,
    now,
    fetch: fetchImpl,
  });
}

describe('downstream OAuth grant binding', () => {
  it('rejects an offered Token A and does not retain it', async () => {
    const material = await keys();
    const tokenA = await sign(
      material.privateKey,
      {
        role: 'mcp_ingress',
        client_id: A_CLIENT,
        agent_id: AGENT,
        session_id: DECOY,
        source_session_id: SOURCE,
      },
      'https://mcp.loopback.invalid/mcp',
    );
    const store = storeFor(material, async () => {
      throw new Error('offer must not exchange');
    });
    expect(await store.rejectsOfferedAccessToken(tokenA, principal)).toBe(true);
    expect(store.resolve(principal).status).toBe('missing');
    expect(store.containsRetainedMaterial(tokenA)).toBe(false);
    expect(store.boundSessionId(principal)).toBeNull();
  });

  it('binds only a handshake whose every field matches and drops refresh_token', async () => {
    expect(DOWNSTREAM_B_GRANT_PROFILE).toBe('TEST_ONLY_PUBLIC_PKCE');
    const material = await keys();
    const calls: string[] = [];
    const tokenB = await sign(material.privateKey, {
      role: 'authenticated',
      client_id: B_CLIENT,
      agent_id: AGENT,
      session_id: B_SESSION,
    });
    const fetchImpl: typeof fetch = async (input) => {
      calls.push(String(input));
      return new Response(JSON.stringify({ access_token: tokenB, refresh_token: REFRESH }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const store = storeFor(material, fetchImpl);
    const handshake = store.beginHandshake(principal);
    const url = new URL(handshake.authorizationUrl);
    expect(handshake.state).toBe(handshake.id);
    expect(url.searchParams.get('state')).toBe(handshake.id);
    expect(url.searchParams.get('scope')).toBe(DOWNSTREAM_B_SCOPE);
    expect(url.searchParams.get('resource')).toBeNull();
    expect(url.searchParams.get('code_verifier')).toBeNull();
    expect(url.searchParams.get('client_id')).toBe(B_CLIENT);
    expect(store.containsRetainedMaterial(REFRESH)).toBe(false);

    expect(
      await store.completeCallback({
        code: 'one-time',
        state: 'not-the-handshake',
        redirectUri: REDIRECT,
      }),
    ).toBe(false);
    expect(calls).toEqual([]);
    expect(store.resolve(principal).status).toBe('missing');

    expect(
      await store.completeCallback({
        code: 'one-time',
        state: handshake.id,
        redirectUri: REDIRECT,
      }),
    ).toBe(true);
    expect(store.containsRetainedMaterial(REFRESH)).toBe(false);
    expect(store.containsRetainedMaterial(tokenB)).toBe(true);
    const live = store.resolve(principal);
    expect(live.status).toBe('live');
    if (live.status === 'live') expect(live.accessToken).toBe(tokenB);
    expect(store.resolve({ ...principal, sourceSessionId: DECOY }).status).toBe('missing');
    expect(
      await store.completeCallback({
        code: 'replay',
        state: handshake.id,
        redirectUri: REDIRECT,
      }),
    ).toBe(false);
  });

  it('rejects Token A, field mismatches, and expiry without storing a candidate', async () => {
    const material = await keys();
    const otherKey = await generateKeyPair('ES256', { extractable: true });
    const cases = [
      await sign(
        material.privateKey,
        {
          role: 'mcp_ingress',
          client_id: A_CLIENT,
          agent_id: AGENT,
          session_id: DECOY,
          source_session_id: SOURCE,
        },
        'https://mcp.loopback.invalid/mcp',
      ),
      await sign(material.privateKey, {
        role: 'authenticated',
        client_id: 'smp-other-client',
        agent_id: AGENT,
        session_id: B_SESSION,
      }),
      await sign(material.privateKey, {
        role: 'authenticated',
        client_id: B_CLIENT,
        agent_id: 'other-agent',
        session_id: B_SESSION,
      }),
      await sign(material.privateKey, {
        role: 'authenticated',
        client_id: B_CLIENT,
        agent_id: AGENT,
        session_id: B_SESSION,
        sub: '55555555-5555-4555-8555-555555555555',
      }),
      await sign(material.privateKey, {
        role: 'authenticated',
        client_id: B_CLIENT,
        agent_id: AGENT,
        session_id: '00000000-0000-0000-0000-000000000000',
      }),
      await sign(otherKey.privateKey, {
        role: 'authenticated',
        client_id: B_CLIENT,
        agent_id: AGENT,
        session_id: B_SESSION,
      }),
      await sign(
        material.privateKey,
        {
          role: 'authenticated',
          client_id: B_CLIENT,
          agent_id: AGENT,
          session_id: B_SESSION,
        },
        'authenticated',
        '0s',
      ),
    ];
    for (const accessToken of cases) {
      const fetchImpl: typeof fetch = async () =>
        new Response(JSON.stringify({ access_token: accessToken, refresh_token: REFRESH }), {
          status: 200,
        });
      const store = storeFor(material, fetchImpl);
      const handshake = store.beginHandshake(principal);
      expect(
        await store.completeCallback({
          code: 'code',
          state: handshake.id,
          redirectUri: REDIRECT,
        }),
      ).toBe(false);
      expect(store.resolve(principal).status).toBe('missing');
      expect(store.containsRetainedMaterial(accessToken)).toBe(false);
      expect(store.containsRetainedMaterial(REFRESH)).toBe(false);
    }

    let now = 1_000;
    const tokenB = await sign(material.privateKey, {
      role: 'authenticated',
      client_id: B_CLIENT,
      agent_id: AGENT,
      session_id: B_SESSION,
    });
    const timed = storeFor(
      material,
      async () => new Response(JSON.stringify({ access_token: tokenB, refresh_token: null })),
      () => now,
    );
    const handshake = timed.beginHandshake(principal);
    now = handshake.expiresAtMs + 1;
    expect(
      await timed.completeCallback({ code: 'late', state: handshake.id, redirectUri: REDIRECT }),
    ).toBe(false);
    expect(timed.resolve(principal).status).toBe('missing');
  });
});
