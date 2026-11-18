import { Client } from '@modelcontextprotocol/client';
import { StreamTransport } from '@supabase/mcp-utils';
import { describe, expect, it, vi } from 'vitest';

import {
  MemoryGetInputSchema,
  MemoryGetOutputSchema,
  MemoryListRecentOutputSchema,
  MemorySearchOutputSchema,
} from '../packages/contracts/src/read-tools.js';
import {
  createFixedSupabaseClient,
  type FixedSupabaseClientConfig,
} from '../packages/server/src/fixed-supabase-client.js';
import {
  startReadOnlyStdioFromEnvironment,
  type StdioStartupDependencies,
} from '../packages/server/src/stdio-startup.js';
import { createReadOnlyServer } from '../packages/server/src/server.js';

const origin = 'https://synthetic-project.supabase.co';
const credentials = Object.freeze({
  projectPublishableKey: 'sb_publishable_synthetic',
  userAccessToken: 'header.synthetic.signature',
});
const opaqueId = 'mem_AAAAAAAAAAAAAAAAAAAAAA';
const uuidId = '11111111-1111-4111-9111-111111111111';
const row = (id: string) => ({
  id,
  title: 'Synthetic record',
  content: 'Synthetic stored text.',
  createdAt: '2026-11-06T00:00:00.000Z',
  provenanceSummary: 'synthetic fixture',
});
const response = (value: unknown) =>
  new Response(JSON.stringify(value), { headers: { 'content-type': 'application/json' } });

describe('memory compatibility without additional authority', () => {
  it('carries UUIDs through the registered MCP search, get and recent tools', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async (url) => {
      if (String(url).endsWith('/auth/v1/user'))
        return response({ id: uuidId, aud: 'authenticated' });
      if (String(url).endsWith('/authorized_memory_get_v1'))
        return response({ record: row(uuidId) });
      if (String(url).endsWith('/authorized_memory_search_v1'))
        return response({ rows: [{ ...row(uuidId), rank: 0.5 }] });
      if (String(url).endsWith('/authorized_memory_list_recent_v1'))
        return response({ rows: [row(uuidId)] });
      throw new Error('Unexpected synthetic endpoint');
    });
    const fixed = createFixedSupabaseClient({
      origin,
      credentials,
      fetch,
      rpcSchema: 'approved_api',
    });
    const server = await createReadOnlyServer({ client: fixed });
    const clientTransport = new StreamTransport();
    const serverTransport = new StreamTransport();
    const pipes = [
      clientTransport.readable.pipeTo(serverTransport.writable).catch(() => undefined),
      serverTransport.readable.pipeTo(clientTransport.writable).catch(() => undefined),
    ];
    const mcp = new Client(
      { name: 'synthetic-memory-compatibility', version: '0.0.0' },
      { capabilities: {} },
    );
    try {
      await server.connect(serverTransport);
      await mcp.connect(clientTransport);
      expect((await mcp.listTools()).tools.map((tool) => tool.name).sort()).toEqual([
        'memory_get',
        'memory_list_recent',
        'memory_search',
      ]);
      const get = await mcp.callTool({ name: 'memory_get', arguments: { id: uuidId } });
      expect(get.isError).toBe(false);
      expect(get.structuredContent).toEqual({
        ok: true,
        record: { ...row(uuidId), contentTrust: 'untrusted' },
      });
      for (const call of [
        { name: 'memory_search', arguments: { query: 'synthetic', limit: 1 } },
        { name: 'memory_list_recent', arguments: { limit: 1 } },
      ]) {
        const result = await mcp.callTool(call);
        expect(result.isError).toBe(false);
        expect(result.structuredContent).toMatchObject({
          ok: true,
          items: [{ id: uuidId, contentTrust: 'untrusted' }],
        });
      }
      const authHeaders = new Headers(fetch.mock.calls[0]?.[1]?.headers);
      expect(authHeaders.has('Accept-Profile')).toBe(false);
      expect(authHeaders.has('Content-Profile')).toBe(false);
    } finally {
      await Promise.allSettled([mcp.close(), server.close()]);
      await Promise.all(pipes);
    }
  });
  it.each([opaqueId, uuidId, 'ABCDEFAB-1234-7123-ABCD-123456789ABC'])(
    'preserves identifier bytes through get, search and recent contracts: %s',
    (id) => {
      const record = { ...row(id), contentTrust: 'untrusted' } as const;
      expect(MemoryGetInputSchema.parse({ id })).toEqual({ id });
      expect(MemoryGetOutputSchema.parse({ ok: true, record })).toEqual({ ok: true, record });
      expect(
        MemorySearchOutputSchema.parse({ ok: true, items: [{ ...record, rank: 0.5 }] }),
      ).toEqual({ ok: true, items: [{ ...record, rank: 0.5 }] });
      expect(MemoryListRecentOutputSchema.parse({ ok: true, items: [record] })).toEqual({
        ok: true,
        items: [record],
      });
    },
  );

  it.each([
    'MEM_AAAAAAAAAAAAAAAAAAAAAA',
    'mem_short',
    'mem_AAAAAAAAAAAAAAAAAAAAAA/../other',
    `${uuidId}\n`,
    ` ${uuidId}`,
    '11111111-1111-4111-7111-111111111111',
    '11111111-1111-4111-9111-11111111111z',
    `https://synthetic.invalid/${uuidId}`,
  ])('rejects invalid identifiers and preserves the existing mem_ prefix rule: %s', (id) => {
    expect(MemoryGetInputSchema.safeParse({ id }).success).toBe(false);
  });

  it.each([undefined, 'approved_api', 'a'.repeat(63)])(
    'uses a startup-fixed schema and the same three fixed RPCs: %s',
    async (rpcSchema) => {
      const fetch = vi.fn<typeof globalThis.fetch>().mockImplementation(async (url) => {
        if (String(url).endsWith('/authorized_memory_get_v1'))
          return response({ record: row(uuidId) });
        if (String(url).endsWith('/authorized_memory_search_v1'))
          return response({ rows: [{ ...row(uuidId), rank: 0.5 }] });
        if (String(url).endsWith('/authorized_memory_list_recent_v1'))
          return response({ rows: [row(uuidId)] });
        throw new Error('Unexpected synthetic RPC');
      });
      const config: FixedSupabaseClientConfig & { rpcSchema?: string } = {
        origin,
        credentials,
        fetch,
        ...(rpcSchema === undefined ? {} : { rpcSchema }),
      };
      const client = createFixedSupabaseClient(config);
      config.rpcSchema = 'later_mutation';
      await expect(client.getMemoryRow({ id: uuidId })).resolves.toEqual(row(uuidId));
      await expect(
        client.searchMemoryRows({ query: 'synthetic', mode: 'text', limit: 1 }),
      ).resolves.toEqual({ rows: [{ ...row(uuidId), rank: 0.5 }] });
      await expect(client.listRecentMemoryRows({ limit: 1 })).resolves.toEqual({
        rows: [row(uuidId)],
      });
      expect(fetch.mock.calls.map(([url]) => url)).toEqual([
        `${origin}/rest/v1/rpc/authorized_memory_get_v1`,
        `${origin}/rest/v1/rpc/authorized_memory_search_v1`,
        `${origin}/rest/v1/rpc/authorized_memory_list_recent_v1`,
      ]);
      expect(fetch.mock.calls.map(([, init]) => init?.body)).toEqual([
        JSON.stringify({ id: uuidId }),
        JSON.stringify({ query: 'synthetic', mode: 'text', limit: 1 }),
        JSON.stringify({ limit: 1 }),
      ]);
      for (const [, init] of fetch.mock.calls) {
        expect(init).toMatchObject({
          method: 'POST',
          headers: {
            'Accept-Profile': rpcSchema ?? 'memory',
            'Content-Profile': rpcSchema ?? 'memory',
            apikey: credentials.projectPublishableKey,
            Authorization: ['Bearer', credentials.userAccessToken].join(' '),
          },
        });
      }
    },
  );

  it('retains the default opaque get request and response exactly', async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(response({ record: row(opaqueId) }));
    const client = createFixedSupabaseClient({ origin, credentials, fetch });
    expect(JSON.stringify(await client.getMemoryRow({ id: opaqueId }))).toBe(
      JSON.stringify(row(opaqueId)),
    );
    expect(fetch.mock.calls[0]?.[1]?.body).toBe(JSON.stringify({ id: opaqueId }));
    expect(fetch.mock.calls[0]?.[1]?.headers).toMatchObject({
      'Accept-Profile': 'memory',
      'Content-Profile': 'memory',
    });
  });

  it.each([
    '',
    'api,other',
    'api/table',
    'api.name',
    'api\nInjected',
    'UPPER',
    '_private',
    'a'.repeat(64),
    null,
    7,
    {},
  ])('refuses malformed operator schema before any fetch: %j', (rpcSchema) => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    expect(() =>
      createFixedSupabaseClient({
        origin,
        credentials,
        fetch,
        rpcSchema,
      } as unknown as FixedSupabaseClientConfig),
    ).toThrowError('FIXED_CLIENT_INVALID_CREDENTIAL');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('rejects caller routing or identity fields on every RPC before fetch', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    const config = { origin, credentials, fetch, rpcSchema: 'approved_api' };
    const client = createFixedSupabaseClient(config);
    for (const field of ['schema', 'rpcSchema', 'rpc', 'origin', 'principalId']) {
      const extra = { [field]: 'forbidden' };
      await expect(client.getMemoryRow({ id: opaqueId, ...extra })).rejects.toMatchObject({
        code: 'FIXED_CLIENT_INVALID_REQUEST',
      });
      await expect(
        client.searchMemoryRows({ query: 'synthetic', mode: 'text', limit: 1, ...extra }),
      ).rejects.toMatchObject({ code: 'FIXED_CLIENT_INVALID_REQUEST' });
      await expect(client.listRecentMemoryRows({ limit: 1, ...extra })).rejects.toMatchObject({
        code: 'FIXED_CLIENT_INVALID_REQUEST',
      });
    }
    expect(fetch).not.toHaveBeenCalled();
  });

  it('preserves strict response keys and unavailable behavior', async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(response({ record: null }))
      .mockResolvedValueOnce(response({ record: { ...row(uuidId), ownerId: 'unexpected' } }));
    const client = createFixedSupabaseClient({ origin, credentials, fetch });
    await expect(client.getMemoryRow({ id: opaqueId })).resolves.toBeNull();
    await expect(client.getMemoryRow({ id: opaqueId })).rejects.toMatchObject({
      code: 'FIXED_CLIENT_MALFORMED_RESPONSE',
    });
  });

  it.each([undefined, 'approved_api'])(
    'passes only the operator environment schema through stdio startup: %s',
    async (rpcSchema) => {
      const client = {} as ReturnType<typeof createFixedSupabaseClient>;
      const dependencies: StdioStartupDependencies = {
        loadCredentials: vi.fn(async () => credentials),
        createClient: vi.fn(() => client),
        createServer: vi.fn(),
        serveStdio: vi.fn(),
      };
      await startReadOnlyStdioFromEnvironment({
        argv: [],
        env: {
          SUPABASE_USER_MCP_ORIGIN: origin,
          SUPABASE_USER_MCP_CREDENTIAL_FILE: '/synthetic/credential.json',
          ...(rpcSchema === undefined ? {} : { SUPABASE_USER_MCP_RPC_SCHEMA: rpcSchema }),
        },
        dependencies,
      });
      expect(dependencies.createClient).toHaveBeenCalledExactlyOnceWith({
        origin,
        credentials,
        ...(rpcSchema === undefined ? {} : { rpcSchema }),
      });
    },
  );
});
