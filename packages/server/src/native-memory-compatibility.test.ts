import { exportJWK, generateKeyPair, type JWK, SignJWT } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { MCP_INGRESS_ROLE, NativeUserMcpConfigError } from './native-user-mcp.js';
import {
  createNativeUserMcpApplicationHandler,
  createNativeUserMcpReadHandler,
  type NativeUserMcpReadHandlerConfig,
} from './native-user-mcp-read-handler.js';
import {
  createNativeUserMcpRemotePilotFromEnvironment,
  NATIVE_REMOTE_PILOT_OPT_IN_VALUE,
  NATIVE_REMOTE_PILOT_RPC_SCHEMA_ENV,
} from './native-user-mcp-remote-pilot.js';

const PROJECT = 'https://project.compatibility.invalid';
const RESOURCE = 'https://mcp.compatibility.invalid/mcp';
const CALLBACK = 'https://mcp.compatibility.invalid/oauth/downstream/callback';
const LOCAL_CALLBACK = 'http://127.0.0.1:8788/oauth/downstream/callback';
const USER = '11111111-1111-4111-8111-111111111111';
const SOURCE = '22222222-2222-4222-8222-222222222222';
const B_SESSION = '33333333-3333-4333-8333-333333333333';
const A_CLIENT = 'synthetic-memory-client-a';
const B_CLIENT = 'synthetic-memory-client-b';
const AGENT = 'synthetic-memory-agent';
const PUBLISHABLE = 'sb_publishable_synthetic';
const BUCKET = 'mcp-user-storage';
const MODES = ['read-only', 'application', 'pilot'] as const;
type Mode = (typeof MODES)[number];
type RpcReply = {
  result?: { isError?: boolean; structuredContent?: unknown; content?: Array<{ text: string }> };
  error?: { code: number };
};
let materialPromise: ReturnType<typeof signingMaterial> | undefined;

async function signingMaterial() {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  return {
    privateKey,
    jwks: { keys: [{ ...jwk, kid: 'memory-compatibility', alg: 'ES256', use: 'sig' }] as JWK[] },
  };
}

const json = (value: unknown) =>
  new Response(JSON.stringify(value), { headers: { 'content-type': 'application/json' } });

function request(token: string, method: string, params: Record<string, unknown> = {}): Request {
  return new Request(RESOURCE, {
    method: 'POST',
    headers: {
      accept: 'application/json, text/event-stream',
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      'mcp-protocol-version': '2025-06-18',
      host: 'mcp.compatibility.invalid',
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
}

async function reply(response: Response): Promise<RpcReply> {
  expect(response.status).toBe(200);
  const text = await response.text();
  const frame =
    text
      .split('\n')
      .find((line) => line.startsWith('data: '))
      ?.slice(6) ?? text;
  return JSON.parse(frame) as RpcReply;
}

async function fixture(mode: Mode, rpcSchema?: unknown, storage = false) {
  materialPromise ??= signingMaterial();
  const material = await materialPromise;
  const issuer = `${PROJECT}/auth/v1`;
  const sign = (claims: Record<string, unknown>, audience: string) =>
    new SignJWT(claims)
      .setProtectedHeader({ alg: 'ES256', kid: 'memory-compatibility', typ: 'JWT' })
      .setSubject(USER)
      .setIssuer(issuer)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime('2m')
      .sign(material.privateKey);
  const tokenA = await sign(
    {
      role: MCP_INGRESS_ROLE,
      client_id: A_CLIENT,
      agent_id: AGENT,
      session_id: '44444444-4444-4444-8444-444444444444',
      source_session_id: SOURCE,
    },
    RESOURCE,
  );
  const tokenB = await sign(
    { role: 'authenticated', client_id: B_CLIENT, agent_id: AGENT, session_id: B_SESSION },
    'authenticated',
  );
  const calls: Array<{ url: string; headers: Record<string, string>; body: string }> = [];
  const current = { live: true };
  const row = {
    id: USER,
    title: 'Synthetic memory',
    content: 'Synthetic stored text.',
    createdAt: '2026-11-07T00:00:00.000Z',
    provenanceSummary: 'synthetic fixture',
  };
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = String(input);
    calls.push({
      url,
      headers: Object.fromEntries(new Headers(init?.headers).entries()),
      body: typeof init?.body === 'string' ? init.body : '',
    });
    if (url.endsWith('/.well-known/jwks.json')) return json(material.jwks);
    if (url.endsWith('/auth/v1/oauth/token')) return json({ access_token: tokenB });
    if (url.endsWith('/rpc/source_session_live_v1')) return json(current.live);
    if (url.endsWith('/auth/v1/user')) return json({ id: USER, aud: 'authenticated' });
    if (url.endsWith('/authorized_memory_get_v1')) return json({ record: row });
    if (url.endsWith('/authorized_memory_search_v1'))
      return json({ rows: [{ ...row, rank: 0.5 }] });
    if (url.endsWith('/authorized_memory_list_recent_v1')) return json({ rows: [row] });
    if (url.endsWith('/mcp_storage_session_capabilities_v1')) return json(['storage:read']);
    if (url.endsWith('/mcp_storage_principal_v1')) return json(USER);
    if (url.endsWith(`/storage/v1/object/list/${BUCKET}`))
      return json([
        {
          name: 'note.txt',
          id: USER,
          updated_at: '2026-11-07T00:00:00.000Z',
          metadata: { size: 1, mimetype: 'text/plain' },
        },
      ]);
    throw new Error('Unexpected synthetic endpoint');
  };
  const config: Omit<NativeUserMcpReadHandlerConfig, 'memoryRpcSchema'> & {
    memoryRpcSchema?: string;
  } = {
    resourceServer: RESOURCE,
    supabaseUrl: PROJECT,
    expectedClientId: A_CLIENT,
    expectedAgentId: AGENT,
    ingressRole: MCP_INGRESS_ROLE,
    publishableKey: PUBLISHABLE,
    jwks: material.jwks,
    downstreamClientId: B_CLIENT,
    downstreamRedirectUri: LOCAL_CALLBACK,
    fetch: fetchImpl,
    ...(rpcSchema === undefined ? {} : { memoryRpcSchema: rpcSchema as string }),
    ...(storage ? { storageBucket: BUCKET } : {}),
  };
  const env: Record<string, string | undefined> = {
    SUPABASE_USER_MCP_NATIVE_REMOTE_PILOT: NATIVE_REMOTE_PILOT_OPT_IN_VALUE,
    SUPABASE_USER_MCP_RESOURCE_URI: RESOURCE,
    SUPABASE_USER_MCP_SUPABASE_URL: PROJECT,
    SUPABASE_USER_MCP_A_CLIENT_ID: A_CLIENT,
    SUPABASE_USER_MCP_AGENT_ID: AGENT,
    SUPABASE_USER_MCP_PUBLISHABLE_KEY: PUBLISHABLE,
    SUPABASE_USER_MCP_JWKS_URL: `${PROJECT}/auth/v1/.well-known/jwks.json`,
    SUPABASE_USER_MCP_B_CLIENT_ID: B_CLIENT,
    SUPABASE_USER_MCP_B_REDIRECT_URI: CALLBACK,
    SUPABASE_USER_MCP_LISTEN_PORT: '8788',
    ...(rpcSchema === undefined
      ? {}
      : { [NATIVE_REMOTE_PILOT_RPC_SCHEMA_ENV]: rpcSchema as string }),
    ...(storage ? { SUPABASE_USER_MCP_STORAGE_BUCKET: BUCKET } : {}),
  };
  const build = () => {
    if (mode === 'pilot') {
      vi.spyOn(globalThis, 'fetch').mockImplementation(fetchImpl);
      return createNativeUserMcpRemotePilotFromEnvironment({ env, fetch: fetchImpl }).handler;
    }
    return mode === 'application'
      ? createNativeUserMcpApplicationHandler(config)
      : createNativeUserMcpReadHandler(config);
  };
  async function connect() {
    const handler = build();
    const initial = await handler(
      request(tokenA, 'initialize', {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'synthetic-memory-client', version: '0.0.0' },
      }),
    );
    let state: string;
    if (mode === 'pilot') {
      expect(initial.status).toBe(200);
      const pending = await reply(
        await handler(request(tokenA, 'tools/call', { name: 'memory_list_recent', arguments: {} })),
      );
      const text = pending.result?.content?.[0]?.text ?? '';
      state = new URL(/(https:\/\/\S+)/u.exec(text)?.[1] ?? '').searchParams.get('state') ?? '';
    } else {
      expect(initial.status).toBe(403);
      state = ((await initial.json()) as { state: string }).state;
    }
    const redirect = mode === 'pilot' ? CALLBACK : LOCAL_CALLBACK;
    const bound = await handler(
      new Request(`${redirect}?code=synthetic-once&state=${state}`, {
        headers: { host: new URL(redirect).host },
      }),
    );
    expect(bound.status).toBe(200);
    calls.length = 0;
    const call = (name: string, args: Record<string, unknown>) =>
      handler(request(tokenA, 'tools/call', { name, arguments: args }));
    return { handler, call };
  }
  return { build, connect, config, env, calls, current, tokenA, tokenB, row };
}

afterEach(() => vi.restoreAllMocks());

describe.each(MODES)('native memory schema: %s', (mode) => {
  it.each([undefined, ' approved_api '])(
    'carries UUID get/search/recent with B and the startup schema %s',
    async (schema) => {
      const f = await fixture(mode, schema);
      const session = await f.connect();
      for (const [name, args] of [
        ['memory_get', { id: USER }],
        ['memory_search', { query: 'synthetic', limit: 1 }],
        ['memory_list_recent', { limit: 1 }],
      ] as const) {
        const result = await reply(await session.call(name, args));
        expect(result.error).toBeUndefined();
        expect(result.result?.isError).toBe(false);
        expect(result.result?.structuredContent).toMatchObject({ ok: true });
        expect(JSON.stringify(result.result)).toContain(USER);
      }
      const memory = f.calls.filter((call) => call.url.includes('/authorized_memory_'));
      expect(memory).toHaveLength(3);
      for (const call of memory) {
        expect(call.headers['accept-profile']).toBe(schema?.trim() ?? 'memory');
        expect(call.headers['content-profile']).toBe(schema?.trim() ?? 'memory');
        expect(call.headers.authorization).toBe(`Bearer ${f.tokenB}`);
        expect(call.headers.apikey).toBe(PUBLISHABLE);
      }
      for (const call of f.calls.filter((entry) => entry.url.endsWith('/auth/v1/user'))) {
        expect(call.headers['accept-profile']).toBeUndefined();
        expect(call.headers['content-profile']).toBeUndefined();
      }
      expect(JSON.stringify(f.calls)).not.toContain(f.tokenA);
    },
  );

  it('rejects malformed schemas at construction without fetching or echoing them', async () => {
    for (const schema of ['', '  ', 'api,other', 'api/name', 'api\nInjected', 'UPPER', null, 7]) {
      const f = await fixture(mode, schema);
      let caught: unknown;
      try {
        f.build();
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(NativeUserMcpConfigError);
      expect((caught as Error).message).toBe('NATIVE_USER_MCP_INVALID_CONFIGURATION');
      expect(f.calls).toEqual([]);
    }
  });

  it('snapshots the operator setting before tool dispatch', async () => {
    const f = await fixture(mode, 'approved_api');
    const session = await f.connect();
    f.config.memoryRpcSchema = 'later_mutation';
    f.env[NATIVE_REMOTE_PILOT_RPC_SCHEMA_ENV] = 'later_mutation';
    expect((await reply(await session.call('memory_get', { id: USER }))).result?.isError).toBe(
      false,
    );
    const memory = f.calls.filter((call) => call.url.includes('/authorized_memory_'));
    expect(memory[0]?.headers['content-profile']).toBe('approved_api');
  });

  it('refuses tool-selected routing or identity before the memory RPC', async () => {
    const f = await fixture(mode, 'approved_api');
    const session = await f.connect();
    for (const field of ['schema', 'rpcSchema', 'rpc', 'origin', 'principalId']) {
      const result = await reply(
        await session.call('memory_get', { id: USER, [field]: 'forbidden' }),
      );
      expect(result.result?.isError).toBe(true);
    }
    expect(f.calls.filter((call) => call.url.includes('/authorized_memory_'))).toEqual([]);
  });

  it('keeps public liveness/storage routing separate and still denies revoked sessions', async () => {
    const f = await fixture(mode, 'approved_api', true);
    const session = await f.connect();
    expect((await reply(await session.call('storage_list', {}))).result?.isError).toBe(false);
    const plumbing = f.calls.filter((call) => call.url.includes('/rpc/mcp_storage_'));
    expect(plumbing.length).toBeGreaterThan(0);
    for (const call of plumbing) {
      expect(call.headers['accept-profile']).toBe('public');
      expect(call.headers['content-profile']).toBe('public');
      expect(call.headers.authorization).toBe(`Bearer ${f.tokenB}`);
    }
    for (const call of f.calls.filter((entry) =>
      entry.url.endsWith('/rpc/source_session_live_v1'),
    )) {
      expect(call.headers['accept-profile']).toBeUndefined();
      expect(call.headers['content-profile']).toBeUndefined();
    }
    f.current.live = false;
    const refused = await session.call('memory_get', { id: USER });
    expect(refused.status).toBe(403);
    expect(f.calls.filter((call) => call.url.includes('/authorized_memory_'))).toEqual([]);
  });
});
