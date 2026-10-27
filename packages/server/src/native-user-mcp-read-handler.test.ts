import { DOWNSTREAM_CREDENTIAL_UNRESOLVED } from '@supabase-user-mcp/contracts';
import { exportJWK, generateKeyPair, type JWK, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import { DOWNSTREAM_AUTHORIZATION_REQUIRED } from './downstream-oauth-grant.js';
import { MCP_INGRESS_ROLE, NativeUserMcpConfigError } from './native-user-mcp.js';
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
      if (url.endsWith('/rpc/source_session_live_v1')) {
        return new Response(live ? 'true' : 'false', { status: 200 });
      }
      if (url.endsWith('/auth/v1/user')) {
        return new Response(JSON.stringify({ id: SUB, aud: 'authenticated' }), { status: 200 });
      }
      return new Response('unexpected', { status: 500 });
    };
    const observation = {
      livenessChecks: 0,
      livenessDenials: 0,
      markerReads: 0,
      tokenAOfferedAsB: false,
      tokenARejectedAsB: false,
      sourceSessionId: null as string | null,
      bSessionId: null as string | null,
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
      observation,
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
    expect(await denied.json()).toEqual({
      error: DOWNSTREAM_CREDENTIAL_UNRESOLVED,
      stage: 'liveness',
      category: 'false',
      httpStatus: 200,
    });
    expect(observation.livenessChecks).toBe(1);
    expect(observation.livenessDenials).toBe(1);
    expect(observation.markerReads).toBe(0);
    expect(observation.sourceSessionId).toBe(SOURCE);
    expect(observation.bSessionId).toBe(B_SESSION);
    expect(calls.some((call) => call.url.endsWith('/auth/v1/user'))).toBe(false);
    const liveness = calls.find((call) => call.url.includes('source_session_live_v1'));
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

  it('refuses a plaintext callback whose host only looks like loopback', async () => {
    const material = await keys();
    const build = (downstreamRedirectUri: string) =>
      createNativeUserMcpReadHandler({
        resourceServer: RESOURCE,
        supabaseUrl: SUPABASE_URL,
        expectedClientId: A_CLIENT,
        expectedAgentId: AGENT,
        ingressRole: MCP_INGRESS_ROLE,
        publishableKey: PUBLISHABLE,
        jwks: material.jwks,
        downstreamClientId: B_CLIENT,
        downstreamRedirectUri,
        fetch: async () => new Response('unexpected', { status: 500 }),
      });
    for (const redirect of [
      'http://127.0.0.1.evil.example:8788/oauth/downstream/callback',
      'http://127.0.0.1evil.example/oauth/downstream/callback',
      'http://localhost.evil.example/oauth/downstream/callback',
      'http://evil.example@127.0.0.1:8788/oauth/downstream/callback',
      'http://evil.example/oauth/downstream/callback',
    ]) {
      expect(() => build(redirect), redirect).toThrow();
    }
    expect(typeof build(REDIRECT)).toBe('function');
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

describe('ADR-0005 dual-resource binding', () => {
  it('never forwards the inbound Authorization header to the Data API', async () => {
    const material = await keys();
    const tokenA = await signA(material.privateKey);
    const tokenB = await signB(material.privateKey);
    const calls: Array<{ url: string; headers: Record<string, string>; body: string }> = [];
    const fetchImpl: typeof fetch = async (input, init) => {
      const url = String(input);
      const headers = Object.fromEntries(new Headers(init?.headers).entries());
      const body = typeof init?.body === 'string' ? init.body : '';
      calls.push({ url, headers, body });
      if (url.endsWith('/auth/v1/oauth/token')) {
        return new Response(JSON.stringify({ access_token: tokenB, refresh_token: REFRESH }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (url.endsWith('/rpc/source_session_live_v1')) return new Response('true', { status: 200 });
      if (url.endsWith('/auth/v1/user')) {
        return new Response(JSON.stringify({ id: SUB, aud: 'authenticated' }), { status: 200 });
      }
      if (url.includes('/rest/v1/rpc/authorized_memory_search_v1')) {
        return new Response('[]', { status: 200, headers: { 'content-type': 'application/json' } });
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
    const { handshake_id: handshakeId } = (await first.json()) as { handshake_id: string };
    const bound = await handler(
      new Request(`${REDIRECT}?code=once&state=${handshakeId}`, {
        headers: { host: '127.0.0.1:8788' },
      }),
    );
    expect(bound.status).toBe(200);

    const toolCall = new Request(RESOURCE, {
      method: 'POST',
      headers: {
        accept: 'application/json, text/event-stream',
        authorization: `Bearer ${tokenA}`,
        'content-type': 'application/json',
        'mcp-protocol-version': '2025-06-18',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'memory_search', arguments: { query: 'synthetic lunch note' } },
      }),
    });
    const response = await handler(toolCall);
    expect(response.status).toBe(200);
    await response.text();

    const dataApi = calls.filter((call) => call.url.includes('/rest/v1/'));
    expect(dataApi.some((call) => call.url.includes('authorized_memory_search_v1'))).toBe(true);
    for (const call of dataApi) {
      expect(call.headers.authorization).toBe(`Bearer ${tokenB}`);
      expect(call.headers.apikey).toBe(PUBLISHABLE);
    }
    for (const call of calls) {
      expect(JSON.stringify(call)).not.toContain(tokenA);
    }
  });
});

describe('storage tools through the read handler', () => {
  it('sends every Storage and storage RPC request with B and the publishable key, never A', async () => {
    const material = await keys();
    const tokenA = await signA(material.privateKey);
    const tokenB = await signB(material.privateKey);
    const calls: Array<{ url: string; headers: Record<string, string>; body: string }> = [];
    const json = (value: unknown) =>
      new Response(JSON.stringify(value), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    const fetchImpl: typeof fetch = async (input, init) => {
      const url = String(input);
      const headers = Object.fromEntries(new Headers(init?.headers).entries());
      const body = typeof init?.body === 'string' ? init.body : '';
      calls.push({ url, headers, body });
      if (url.endsWith('/auth/v1/oauth/token')) {
        return json({ access_token: tokenB, refresh_token: REFRESH });
      }
      if (url.endsWith('/rpc/source_session_live_v1')) return new Response('true', { status: 200 });
      if (url.endsWith('/auth/v1/user')) return json({ id: SUB, aud: 'authenticated' });
      // Answer storage only for B, so forwarding A would also break the tool call.
      if (headers.authorization !== `Bearer ${tokenB}`) return new Response('{}', { status: 401 });
      if (url.endsWith('/rest/v1/rpc/mcp_storage_session_capabilities_v1')) {
        return json(['storage:read']);
      }
      if (url.endsWith('/rest/v1/rpc/mcp_storage_principal_v1')) return json(SUB);
      if (url.endsWith('/storage/v1/object/list/mcp-user-storage')) {
        return json([
          {
            name: 'note.txt',
            id: '55555555-5555-4555-8555-555555555555',
            updated_at: '2026-10-27T16:00:00.000Z',
            metadata: { size: 5, mimetype: 'text/plain' },
          },
        ]);
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
      storageBucket: 'mcp-user-storage',
    });

    const first = await handler(mcpPost(tokenA));
    const { handshake_id: handshakeId } = (await first.json()) as { handshake_id: string };
    const bound = await handler(
      new Request(`${REDIRECT}?code=once&state=${handshakeId}`, {
        headers: { host: '127.0.0.1:8788' },
      }),
    );
    expect(bound.status).toBe(200);

    const response = await handler(
      new Request(RESOURCE, {
        method: 'POST',
        headers: {
          accept: 'application/json, text/event-stream',
          authorization: `Bearer ${tokenA}`,
          'content-type': 'application/json',
          'mcp-protocol-version': '2025-06-18',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 3,
          method: 'tools/call',
          params: { name: 'storage_list', arguments: {} },
        }),
      }),
    );
    expect(response.status).toBe(200);
    const text = await response.text();
    expect(text).toContain('note.txt');
    expect(text).not.toContain('"isError":true');

    const storage = calls.filter(
      (call) => call.url.includes('/storage/v1/') || call.url.includes('/rpc/mcp_storage_'),
    );
    expect(storage.map((call) => new URL(call.url).pathname)).toEqual([
      '/rest/v1/rpc/mcp_storage_session_capabilities_v1',
      '/rest/v1/rpc/mcp_storage_principal_v1',
      '/storage/v1/object/list/mcp-user-storage',
    ]);
    for (const call of storage) {
      expect(call.url.startsWith(`${SUPABASE_URL}/`)).toBe(true);
      expect(call.headers.authorization).toBe(`Bearer ${tokenB}`);
      expect(call.headers.apikey).toBe(PUBLISHABLE);
    }
    for (const call of calls) {
      expect(JSON.stringify(call)).not.toContain(tokenA);
    }
  });

  it('accepts a valid storage bucket and refuses an invalid one', async () => {
    const material = await keys();
    const base = {
      resourceServer: RESOURCE,
      supabaseUrl: SUPABASE_URL,
      expectedClientId: A_CLIENT,
      expectedAgentId: AGENT,
      ingressRole: MCP_INGRESS_ROLE,
      publishableKey: PUBLISHABLE,
      jwks: material.jwks,
      downstreamClientId: B_CLIENT,
      downstreamRedirectUri: REDIRECT,
    };
    expect(() =>
      createNativeUserMcpReadHandler({ ...base, storageBucket: 'mcp-user-storage' }),
    ).not.toThrow();
    for (const storageBucket of ['../b', '', 'a/b']) {
      expect(() => createNativeUserMcpReadHandler({ ...base, storageBucket })).toThrow(
        NativeUserMcpConfigError,
      );
    }
  });
});
