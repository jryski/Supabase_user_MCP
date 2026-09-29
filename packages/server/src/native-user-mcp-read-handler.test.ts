import { DOWNSTREAM_CREDENTIAL_UNRESOLVED } from '@supabase-user-mcp/contracts';
import { exportJWK, generateKeyPair, type JWK, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import { DOWNSTREAM_AUTHORIZATION_REQUIRED } from './downstream-oauth-grant.js';
import { MCP_INGRESS_ROLE } from './native-user-mcp.js';
import { createNativeUserMcpReadHandler } from './native-user-mcp-read-handler.js';

const RESOURCE = 'https://mcp.loopback.invalid/mcp';
const SUPABASE_URL = 'https://project.loopback.invalid';
const ISSUER = 'https://project.loopback.invalid/auth/v1';
const A_CLIENT = 'smp-lab-inspector';
const B_CLIENT = 'smp-downstream-b';
const AGENT = 'hook-only-agent';
const SUB = '11111111-1111-4111-8111-111111111111';
const SOURCE = '22222222-2222-4222-8222-222222222222';
const DECOY = '44444444-4444-4444-8444-444444444444';
const B_SESSION = '33333333-3333-4333-8333-333333333333';
const REDIRECT = 'http://127.0.0.1:8788/oauth/downstream/callback';
const PUBLISHABLE = 'sb_publishable_g2_test_not_a_secret';
const REFRESH = 'refresh-sentinel-must-not-remain';

async function keys() {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  return {
    privateKey,
    jwks: { keys: [{ ...jwk, kid: 'g2-test', alg: 'ES256', use: 'sig' }] as JWK[] },
  };
}

async function signA(
  privateKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'],
  claims: Record<string, unknown> = {},
): Promise<string> {
  return new SignJWT({
    role: MCP_INGRESS_ROLE,
    client_id: A_CLIENT,
    session_id: DECOY,
    source_session_id: SOURCE,
    agent_id: AGENT,
    ...claims,
  })
    .setProtectedHeader({ alg: 'ES256', kid: 'g2-test', typ: 'JWT' })
    .setSubject(SUB)
    .setIssuer(ISSUER)
    .setAudience(RESOURCE)
    .setIssuedAt()
    .setExpirationTime('2m')
    .sign(privateKey);
}

async function signB(
  privateKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'],
): Promise<string> {
  return new SignJWT({
    role: 'authenticated',
    client_id: B_CLIENT,
    agent_id: AGENT,
    session_id: B_SESSION,
  })
    .setProtectedHeader({ alg: 'ES256', kid: 'g2-test', typ: 'JWT' })
    .setSubject(SUB)
    .setIssuer(ISSUER)
    .setAudience('authenticated')
    .setIssuedAt()
    .setExpirationTime('2m')
    .sign(privateKey);
}

function mcpPost(token: string): Request {
  return new Request(RESOURCE, {
    method: 'POST',
    headers: {
      accept: 'application/json, text/event-stream',
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'external-test', version: '0.0.0' },
      },
    }),
  });
}

describe('native user MCP read composition', () => {
  it('requires a bound handshake, then calls liveness with B before tools', async () => {
    const material = await keys();
    const tokenA = await signA(material.privateKey);
    const tokenB = await signB(material.privateKey);
    let live = true;
    const calls: Array<{ url: string; authorization: string | null; body: string }> = [];
    const fetchImpl: typeof fetch = async (input, init) => {
      const url = String(input);
      const authorization = new Headers(init?.headers).get('authorization');
      const body = typeof init?.body === 'string' ? init.body : '';
      calls.push({ url, authorization, body });
      if (url.endsWith('/auth/v1/oauth/token')) {
        return new Response(JSON.stringify({ access_token: tokenB, refresh_token: REFRESH }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (url.endsWith('/rpc/ari_probe_source_session_live_v1')) {
        return new Response(live ? 'true' : 'false', { status: 200 });
      }
      if (url.endsWith('/auth/v1/user')) {
        return new Response(JSON.stringify({ id: SUB, aud: 'authenticated' }), { status: 200 });
      }
      return new Response('unexpected', { status: 500 });
    };
    const handler = createNativeUserMcpReadHandler({
      resourceServer: RESOURCE,
      supabaseUrl: SUPABASE_URL,
      expectedClientId: A_CLIENT,
      expectedAgentId: AGENT,
      ingressRole: MCP_INGRESS_ROLE,
      publishableKey: PUBLISHABLE,
      jwks: material.jwks,
      downstreamClientId: B_CLIENT,
      downstreamRedirectUri: REDIRECT,
      fetch: fetchImpl,
    });

    const first = await handler(mcpPost(tokenA));
    expect(first.status).toBe(403);
    const handshake = (await first.json()) as {
      error: string;
      handshake_id: string;
      state: string;
      authorization_url: string;
    };
    expect(handshake.error).toBe(DOWNSTREAM_AUTHORIZATION_REQUIRED);
    expect(handshake.state).toBe(handshake.handshake_id);
    const authorize = new URL(handshake.authorization_url);
    expect(authorize.searchParams.get('state')).toBe(handshake.handshake_id);
    expect(authorize.searchParams.get('scope')).toBe('email');
    expect(authorize.searchParams.get('resource')).toBeNull();
    expect(JSON.stringify(handshake)).not.toContain(tokenA);
    expect(JSON.stringify(handshake)).not.toContain(REFRESH);
    expect(calls).toEqual([]);

    const unknown = await handler(new Request(`${REDIRECT}?code=nope&state=not-a-handshake`));
    expect(unknown.status).toBe(403);
    expect(calls).toEqual([]);

    const hostile = await handler(
      new Request(`${REDIRECT}?code=once&state=${handshake.handshake_id}`, {
        headers: { host: 'evil.example' },
      }),
    );
    expect(hostile.status).toBe(400);
    expect(await hostile.json()).toEqual({ error: 'invalid_request' });
    expect(calls).toEqual([]);

    const bound = await handler(
      new Request(`${REDIRECT}?code=once&state=${handshake.handshake_id}`, {
        headers: { host: '127.0.0.1:8788' },
      }),
    );
    expect(bound.status).toBe(200);
    expect(await bound.json()).toMatchObject({ bound: true });
    expect(calls.some((call) => call.body.includes(REFRESH))).toBe(false);
    expect(JSON.stringify(calls)).not.toContain(REFRESH);

    live = false;
    const denied = await handler(mcpPost(tokenA));
    expect(denied.status).toBe(403);
    expect(await denied.json()).toEqual({ error: DOWNSTREAM_CREDENTIAL_UNRESOLVED });
    expect(calls.some((call) => call.url.endsWith('/auth/v1/user'))).toBe(false);
    const liveness = calls.find((call) => call.url.includes('ari_probe_source_session_live_v1'));
    expect(liveness?.authorization).toBe(`Bearer ${tokenB}`);
    expect(liveness?.authorization).not.toContain(tokenA);
    expect(JSON.parse(liveness?.body ?? '{}')).toEqual({
      source_session_id: SOURCE,
      a_client_id: A_CLIENT,
    });

    live = true;
    const accepted = await handler(mcpPost(tokenA));
    expect(accepted.status).toBe(200);
    const userCall = calls.find((call) => call.url.endsWith('/auth/v1/user'));
    expect(userCall?.authorization).toBe(`Bearer ${tokenB}`);
    expect(calls.every((call) => call.authorization !== `Bearer ${tokenA}`)).toBe(true);
    const body = await accepted.text();
    expect(body).not.toContain(tokenA);
    expect(body).not.toContain(tokenB);
    expect(body).not.toContain(REFRESH);
  });

  it('rejects a decoy source session and a missing agent before any handshake', async () => {
    const material = await keys();
    const handler = createNativeUserMcpReadHandler({
      resourceServer: RESOURCE,
      supabaseUrl: SUPABASE_URL,
      expectedClientId: A_CLIENT,
      expectedAgentId: AGENT,
      ingressRole: MCP_INGRESS_ROLE,
      publishableKey: PUBLISHABLE,
      jwks: material.jwks,
      downstreamClientId: B_CLIENT,
      downstreamRedirectUri: REDIRECT,
      fetch: async () => {
        throw new Error('fetch must not run');
      },
    });
    const decoy = await signA(material.privateKey, { source_session_id: DECOY, session_id: DECOY });
    const missingAgent = await signA(material.privateKey, { agent_id: 'other-agent' });
    for (const token of [decoy, missingAgent]) {
      const response = await handler(mcpPost(token));
      expect(response.status).toBe(401);
      expect(await response.json()).toEqual({ error: 'invalid_token' });
    }
  });
});
