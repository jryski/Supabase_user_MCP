import { DOWNSTREAM_CREDENTIAL_UNRESOLVED } from '@supabase-user-mcp/contracts';
import { exportJWK, generateKeyPair, type JWK, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import { DOWNSTREAM_AUTHORIZATION_REQUIRED } from './downstream-oauth-grant.js';
import { MCP_INGRESS_ROLE, NativeUserMcpConfigError } from './native-user-mcp.js';
import {
  createNativeUserMcpReadHandler,
  type NativeUserMcpReadHandlerConfig,
} from './native-user-mcp-read-handler.js';
import {
  createNativeUserMcpRemotePilotFromEnvironment,
  NATIVE_REMOTE_PILOT_A_CLIENT_ID_ENV,
  NATIVE_REMOTE_PILOT_AGENT_ID_ENV,
  NATIVE_REMOTE_PILOT_B_CLIENT_ID_ENV,
  NATIVE_REMOTE_PILOT_B_REDIRECT_URI_ENV,
  NATIVE_REMOTE_PILOT_CUSTODY,
  NATIVE_REMOTE_PILOT_JWKS_URL_ENV,
  NATIVE_REMOTE_PILOT_OPT_IN_ENV,
  NATIVE_REMOTE_PILOT_OPT_IN_VALUE,
  NATIVE_REMOTE_PILOT_REQUIRED_ENV,
  NATIVE_REMOTE_PILOT_SUPABASE_URL_ENV,
} from './native-user-mcp-remote-pilot.js';
import { LISTEN_PORT_ENV, PUBLISHABLE_KEY_ENV, RESOURCE_URI_ENV } from './remote-http-startup.js';

const PUBLIC_HOST = 'mcp.pilot.invalid';
const RESOURCE = `https://${PUBLIC_HOST}/mcp`;
const REDIRECT = `https://${PUBLIC_HOST}/oauth/downstream/callback`;
const TERMINATED_CALLBACK = `http://${PUBLIC_HOST}/oauth/downstream/callback`;
const SUPABASE_URL = 'https://project.pilot.invalid';
const ISSUER = 'https://project.pilot.invalid/auth/v1';
const A_CLIENT = 'smp-pilot-claude';
const B_CLIENT = 'smp-pilot-downstream-b';
const AGENT = 'hook-only-agent';
const SUB = '11111111-1111-4111-8111-111111111111';
const SOURCE = '22222222-2222-4222-8222-222222222222';
const B_SESSION = '33333333-3333-4333-8333-333333333333';
const PUBLISHABLE = 'sb_publishable_pilot_test_not_a_secret';
const REFRESH = 'refresh-sentinel-must-not-remain';

async function keys() {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  return {
    privateKey,
    jwks: { keys: [{ ...jwk, kid: 'pilot-test', alg: 'ES256', use: 'sig' }] as JWK[] },
  };
}

type PrivateKey = Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];

function signA(privateKey: PrivateKey): Promise<string> {
  return new SignJWT({
    role: MCP_INGRESS_ROLE,
    client_id: A_CLIENT,
    session_id: '44444444-4444-4444-8444-444444444444',
    source_session_id: SOURCE,
    agent_id: AGENT,
  })
    .setProtectedHeader({ alg: 'ES256', kid: 'pilot-test', typ: 'JWT' })
    .setSubject(SUB)
    .setIssuer(ISSUER)
    .setAudience(RESOURCE)
    .setIssuedAt()
    .setExpirationTime('2m')
    .sign(privateKey);
}

function signB(privateKey: PrivateKey): Promise<string> {
  return new SignJWT({
    role: 'authenticated',
    client_id: B_CLIENT,
    agent_id: AGENT,
    session_id: B_SESSION,
  })
    .setProtectedHeader({ alg: 'ES256', kid: 'pilot-test', typ: 'JWT' })
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
      host: PUBLIC_HOST,
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

function callback(url: string, state: string, host: string | null): Request {
  const headers: Record<string, string> = {};
  if (host !== null) headers.host = host;
  return new Request(`${url}?code=once&state=${state}`, { headers });
}

function baseConfig(
  jwks: NativeUserMcpReadHandlerConfig['jwks'],
  fetchImpl?: typeof fetch,
): NativeUserMcpReadHandlerConfig {
  return {
    resourceServer: RESOURCE,
    supabaseUrl: SUPABASE_URL,
    expectedClientId: A_CLIENT,
    expectedAgentId: AGENT,
    ingressRole: MCP_INGRESS_ROLE,
    publishableKey: PUBLISHABLE,
    jwks,
    downstreamClientId: B_CLIENT,
    downstreamRedirectUri: REDIRECT,
    ...(fetchImpl === undefined ? {} : { fetch: fetchImpl }),
  };
}

function stubFetch(tokenB: string, liveRef: { live: boolean }) {
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
      return new Response(liveRef.live ? 'true' : 'false', { status: 200 });
    }
    if (url.endsWith('/auth/v1/user')) {
      return new Response(JSON.stringify({ id: SUB, aud: 'authenticated' }), { status: 200 });
    }
    return new Response('unexpected', { status: 500 });
  };
  return { calls, fetchImpl };
}

async function beginHandshake(
  handler: (request: Request) => Promise<Response>,
  tokenA: string,
): Promise<string> {
  const first = await handler(mcpPost(tokenA));
  expect(first.status).toBe(403);
  const body = (await first.json()) as { error: string; handshake_id: string };
  expect(body.error).toBe(DOWNSTREAM_AUTHORIZATION_REQUIRED);
  return body.handshake_id;
}

describe('native user MCP remote pilot: https callback (opt-in)', () => {
  it('keeps the default loopback-only rule: an https callback stays hostile', async () => {
    const material = await keys();
    const liveRef = { live: true };
    const { calls, fetchImpl } = stubFetch(await signB(material.privateKey), liveRef);
    const handler = createNativeUserMcpReadHandler(baseConfig(material.jwks, fetchImpl));
    const state = await beginHandshake(handler, await signA(material.privateKey));
    const response = await handler(callback(REDIRECT, state, PUBLIC_HOST));
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'invalid_request' });
    expect(calls).toEqual([]);
  });

  it('refuses the opt-in with a loopback redirect or any TEST diagnostic', async () => {
    const material = await keys();
    const optIn = { ...baseConfig(material.jwks), httpsCallbackBehindTlsTerminator: true };
    expect(() =>
      createNativeUserMcpReadHandler({
        ...optIn,
        downstreamRedirectUri: 'http://127.0.0.1:8788/oauth/downstream/callback',
      }),
    ).toThrow(NativeUserMcpConfigError);
    expect(() => createNativeUserMcpReadHandler({ ...optIn, enableAriTestMarker: true })).toThrow(
      NativeUserMcpConfigError,
    );
    expect(() =>
      createNativeUserMcpReadHandler({ ...optIn, dispatchGate: () => undefined }),
    ).toThrow(NativeUserMcpConfigError);
    expect(() =>
      createNativeUserMcpReadHandler({
        ...optIn,
        observation: {
          livenessChecks: 0,
          livenessDenials: 0,
          markerReads: 0,
          tokenAOfferedAsB: false,
          tokenARejectedAsB: false,
          sourceSessionId: null,
          bSessionId: null,
        },
      }),
    ).toThrow(NativeUserMcpConfigError);
  });

  it('binds B through a TLS-terminated https callback, then reads with B after liveness', async () => {
    const material = await keys();
    const tokenA = await signA(material.privateKey);
    const tokenB = await signB(material.privateKey);
    const liveRef = { live: true };
    const { calls, fetchImpl } = stubFetch(tokenB, liveRef);
    const handler = createNativeUserMcpReadHandler({
      ...baseConfig(material.jwks, fetchImpl),
      httpsCallbackBehindTlsTerminator: true,
    });
    const state = await beginHandshake(handler, tokenA);

    // Hostile shapes never reach code exchange.
    for (const hostile of [
      callback(TERMINATED_CALLBACK, state, null),
      callback(TERMINATED_CALLBACK, state, 'evil.invalid'),
      callback(TERMINATED_CALLBACK, state, `${PUBLIC_HOST}:8443`),
      callback('http://evil.invalid/oauth/downstream/callback', state, PUBLIC_HOST),
    ]) {
      const response = await handler(hostile);
      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({ error: 'invalid_request' });
    }
    expect(calls).toEqual([]);

    const bound = await handler(callback(TERMINATED_CALLBACK, state, PUBLIC_HOST));
    expect(bound.status).toBe(200);
    expect(await bound.json()).toMatchObject({ bound: true });
    expect(JSON.stringify(calls)).not.toContain(REFRESH);

    // One-time handshake: a replay is refused without another exchange.
    const exchanges = calls.length;
    const replay = await handler(callback(TERMINATED_CALLBACK, state, PUBLIC_HOST));
    expect(replay.status).toBe(403);
    expect(calls.length).toBe(exchanges);

    liveRef.live = false;
    const denied = await handler(mcpPost(tokenA));
    expect(denied.status).toBe(403);
    expect(await denied.json()).toMatchObject({
      error: DOWNSTREAM_CREDENTIAL_UNRESOLVED,
      stage: 'liveness',
    });

    liveRef.live = true;
    const accepted = await handler(mcpPost(tokenA));
    expect(accepted.status).toBe(200);
    const liveness = calls.find((call) => call.url.includes('source_session_live_v1'));
    expect(liveness?.authorization).toBe(`Bearer ${tokenB}`);
    expect(calls.every((call) => call.authorization !== `Bearer ${tokenA}`)).toBe(true);
    const text = await accepted.text();
    expect(text).not.toContain(tokenA);
    expect(text).not.toContain(tokenB);
  });

  it('keeps B grants in memory only: a restarted handler requires authorization again', async () => {
    const material = await keys();
    const tokenA = await signA(material.privateKey);
    const liveRef = { live: true };
    const { fetchImpl } = stubFetch(await signB(material.privateKey), liveRef);
    const config = {
      ...baseConfig(material.jwks, fetchImpl),
      httpsCallbackBehindTlsTerminator: true,
    };
    const first = createNativeUserMcpReadHandler(config);
    const state = await beginHandshake(first, tokenA);
    expect((await first(callback(TERMINATED_CALLBACK, state, PUBLIC_HOST))).status).toBe(200);
    expect((await first(mcpPost(tokenA))).status).toBe(200);

    const restarted = createNativeUserMcpReadHandler(config);
    await beginHandshake(restarted, tokenA);
    expect(NATIVE_REMOTE_PILOT_CUSTODY).toMatchObject({
      grantStorage: 'process-memory-only',
      refreshTokens: 'discarded-at-exchange',
      durableProductionCustody: false,
    });
  });
});

function mcpRpc(token: string, id: number, method: string, params: unknown): Request {
  return new Request(RESOURCE, {
    method: 'POST',
    headers: {
      accept: 'application/json, text/event-stream',
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      host: PUBLIC_HOST,
    },
    body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
  });
}

async function rpcResult(response: Response): Promise<Record<string, unknown>> {
  const text = await response.text();
  const type = response.headers.get('content-type') ?? '';
  const payload = type.includes('text/event-stream')
    ? text
        .split('\n')
        .filter((line) => line.startsWith('data:'))
        .map((line) => line.slice(5).trim())
        .join('')
    : text;
  return JSON.parse(payload) as Record<string, unknown>;
}

describe('native user MCP remote pilot: authorization surfaced through tool results', () => {
  const pilotConfig = (
    jwks: NativeUserMcpReadHandlerConfig['jwks'],
    fetchImpl: typeof fetch,
  ): NativeUserMcpReadHandlerConfig => ({
    ...baseConfig(jwks, fetchImpl),
    httpsCallbackBehindTlsTerminator: true,
    downstreamAuthorizationViaToolResult: true,
  });

  it('is refused without the https pilot callback', async () => {
    const material = await keys();
    expect(() =>
      createNativeUserMcpReadHandler({
        ...baseConfig(material.jwks),
        downstreamAuthorizationViaToolResult: true,
      }),
    ).toThrow(NativeUserMcpConfigError);
  });

  it('connects without B, returns the link only from a tool call, then reads with B', async () => {
    const material = await keys();
    const tokenA = await signA(material.privateKey);
    const tokenB = await signB(material.privateKey);
    const liveRef = { live: true };
    const { calls, fetchImpl } = stubFetch(tokenB, liveRef);
    const handler = createNativeUserMcpReadHandler(pilotConfig(material.jwks, fetchImpl));

    // A hosted client can connect and list tools before B exists, and no
    // handshake, liveness, or data call happens on these requests.
    const init = await handler(mcpPost(tokenA));
    expect(init.status).toBe(200);
    const listed = await rpcResult(await handler(mcpRpc(tokenA, 2, 'tools/list', {})));
    const pendingTools = (listed.result as { tools: Array<{ name: string }> }).tools;
    expect(pendingTools.map((tool) => tool.name).sort()).toEqual([
      'memory_get',
      'memory_list_recent',
      'memory_search',
    ]);
    expect(calls).toEqual([]);

    // A tool call returns the authorization link as tool text, not data.
    const pending = await rpcResult(
      await handler(mcpRpc(tokenA, 3, 'tools/call', { name: 'memory_list_recent', arguments: {} })),
    );
    const result = pending.result as { isError: boolean; content: Array<{ text: string }> };
    expect(result.isError).toBe(true);
    const text = result.content[0]?.text ?? '';
    const link = /(https:\/\/\S+)/u.exec(text)?.[1] ?? '';
    const authorize = new URL(link);
    expect(authorize.origin).toBe(SUPABASE_URL);
    expect(authorize.searchParams.get('client_id')).toBe(B_CLIENT);
    expect(authorize.searchParams.get('redirect_uri')).toBe(REDIRECT);
    const state = authorize.searchParams.get('state') ?? '';
    expect(state).not.toBe('');
    expect(text).not.toContain(tokenA);
    expect(calls).toEqual([]);

    // The user opens the link; the callback binds B.
    expect((await handler(callback(TERMINATED_CALLBACK, state, PUBLIC_HOST))).status).toBe(200);

    // The same tool list is served once B exists.
    const boundList = await rpcResult(await handler(mcpRpc(tokenA, 4, 'tools/list', {})));
    expect((boundList.result as { tools: unknown[] }).tools).toEqual(pendingTools);

    // Now dispatch goes through liveness with B, never A.
    liveRef.live = false;
    const denied = await handler(
      mcpRpc(tokenA, 5, 'tools/call', { name: 'memory_list_recent', arguments: {} }),
    );
    expect(denied.status).toBe(403);
    const liveness = calls.find((call) => call.url.includes('source_session_live_v1'));
    expect(liveness?.authorization).toBe(`Bearer ${tokenB}`);
    expect(calls.every((call) => call.authorization !== `Bearer ${tokenA}`)).toBe(true);
  });

  it('reuses one pending link across repeated tool calls, reissuing only near expiry', async () => {
    const material = await keys();
    const tokenA = await signA(material.privateKey);
    const liveRef = { live: true };
    const { calls, fetchImpl } = stubFetch(await signB(material.privateKey), liveRef);
    let clock = Date.now();
    const handler = createNativeUserMcpReadHandler({
      ...pilotConfig(material.jwks, fetchImpl),
      handshakeTtlMs: 90_000,
      now: () => clock,
    });
    const stateOf = async (id: number) => {
      const body = await rpcResult(
        await handler(
          mcpRpc(tokenA, id, 'tools/call', { name: 'memory_list_recent', arguments: {} }),
        ),
      );
      const text = (body.result as { content: Array<{ text: string }> }).content[0]?.text ?? '';
      return new URL(/(https:\/\/\S+)/u.exec(text)?.[1] ?? '').searchParams.get('state') ?? '';
    };
    // Parallel or repeated calls show the user one stable link.
    const first = await stateOf(1);
    expect(await stateOf(2)).toBe(first);
    expect(await stateOf(3)).toBe(first);
    // With under a minute left, a new link replaces it and the old one dies.
    clock += 31_000;
    const reissued = await stateOf(4);
    expect(reissued).not.toBe(first);
    expect((await handler(callback(TERMINATED_CALLBACK, first, PUBLIC_HOST))).status).toBe(403);
    expect(calls).toEqual([]);
    expect((await handler(callback(TERMINATED_CALLBACK, reissued, PUBLIC_HOST))).status).toBe(200);
  });

  it('keeps the plain 403 handshake body when only the https callback is enabled', async () => {
    const material = await keys();
    const liveRef = { live: true };
    const { calls, fetchImpl } = stubFetch(await signB(material.privateKey), liveRef);
    const handler = createNativeUserMcpReadHandler({
      ...baseConfig(material.jwks, fetchImpl),
      httpsCallbackBehindTlsTerminator: true,
    });
    const response = await handler(mcpPost(await signA(material.privateKey)));
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: DOWNSTREAM_AUTHORIZATION_REQUIRED });
    expect(calls).toEqual([]);
  });
});

describe('native user MCP remote pilot: environment entrypoint', () => {
  const validEnv = (): Record<string, string> => ({
    [NATIVE_REMOTE_PILOT_OPT_IN_ENV]: NATIVE_REMOTE_PILOT_OPT_IN_VALUE,
    [RESOURCE_URI_ENV]: RESOURCE,
    [NATIVE_REMOTE_PILOT_SUPABASE_URL_ENV]: SUPABASE_URL,
    [NATIVE_REMOTE_PILOT_A_CLIENT_ID_ENV]: A_CLIENT,
    [NATIVE_REMOTE_PILOT_AGENT_ID_ENV]: AGENT,
    [PUBLISHABLE_KEY_ENV]: PUBLISHABLE,
    [NATIVE_REMOTE_PILOT_JWKS_URL_ENV]: `${SUPABASE_URL}/auth/v1/.well-known/jwks.json`,
    [NATIVE_REMOTE_PILOT_B_CLIENT_ID_ENV]: B_CLIENT,
    [NATIVE_REMOTE_PILOT_B_REDIRECT_URI_ENV]: REDIRECT,
    [LISTEN_PORT_ENV]: '8788',
  });

  it('builds the handler without starting a listener and reports custody', () => {
    const env = validEnv();
    expect(Object.keys(env).sort()).toEqual([...NATIVE_REMOTE_PILOT_REQUIRED_ENV].sort());
    const pilot = createNativeUserMcpRemotePilotFromEnvironment({ env });
    expect(pilot.listenPort).toBe(8788);
    expect(pilot.custody).toBe(NATIVE_REMOTE_PILOT_CUSTODY);
    expect(typeof pilot.handler).toBe('function');
  });

  it('fails closed on missing opt-in, forbidden secrets, insecure or mismatched URLs, argv', () => {
    const cases: Array<Record<string, string | undefined>> = [
      { [NATIVE_REMOTE_PILOT_OPT_IN_ENV]: undefined },
      { [NATIVE_REMOTE_PILOT_OPT_IN_ENV]: 'yes' },
      { SUPABASE_SERVICE_ROLE_KEY: 'present' },
      { SUPABASE_SECRET_KEY: 'present' },
      { SUPABASE_USER_MCP_USER_ACCESS_TOKEN: 'present' },
      { [RESOURCE_URI_ENV]: `http://${PUBLIC_HOST}/mcp` },
      {
        [NATIVE_REMOTE_PILOT_B_REDIRECT_URI_ENV]: 'https://other.invalid/oauth/downstream/callback',
      },
      { [NATIVE_REMOTE_PILOT_B_REDIRECT_URI_ENV]: RESOURCE },
      { [NATIVE_REMOTE_PILOT_B_REDIRECT_URI_ENV]: `${REDIRECT}?x=1` },
      { [NATIVE_REMOTE_PILOT_JWKS_URL_ENV]: 'https://keys.other.invalid/jwks.json' },
      { [NATIVE_REMOTE_PILOT_B_CLIENT_ID_ENV]: A_CLIENT },
      { [LISTEN_PORT_ENV]: '0' },
      { [NATIVE_REMOTE_PILOT_AGENT_ID_ENV]: '' },
    ];
    for (const override of cases) {
      const env: Record<string, string | undefined> = { ...validEnv(), ...override };
      expect(() => createNativeUserMcpRemotePilotFromEnvironment({ env })).toThrow(
        NativeUserMcpConfigError,
      );
    }
    expect(() =>
      createNativeUserMcpRemotePilotFromEnvironment({ env: validEnv(), argv: ['--debug'] }),
    ).toThrow(NativeUserMcpConfigError);
  });
});
