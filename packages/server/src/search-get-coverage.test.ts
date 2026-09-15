import { Client } from '@modelcontextprotocol/client';
import { StreamTransport } from '@supabase/mcp-utils';
import { publicMemoryGetUnavailable } from '@supabase-user-mcp/contracts';
import { describe, expect, it, vi } from 'vitest';
import { createFixedSupabaseClient } from './fixed-supabase-client.js';
import { createReadOnlyServer } from './server.js';

const ORIGIN = 'https://project-ref.supabase.co';

interface MemoryRow {
  id: string;
  title: string;
  content: string;
  createdAt: string;
  provenanceSummary: string;
}

function jsonResponse(body: string, status = 200): Response {
  return new Response(body, { status, headers: { 'content-type': 'application/json' } });
}

function identityPayload(principalId: string): Response {
  return jsonResponse(
    JSON.stringify({
      id: principalId,
      aud: 'authenticated',
    }),
  );
}

async function withClient(
  server: ReturnType<typeof createReadOnlyServer>,
  run: (client: Client) => Promise<void>,
): Promise<void> {
  const clientTransport = new StreamTransport();
  const serverTransport = new StreamTransport();
  const pipes = [
    clientTransport.readable.pipeTo(serverTransport.writable).catch(() => undefined),
    serverTransport.readable.pipeTo(clientTransport.writable).catch(() => undefined),
  ];

  const mcpClient = new Client(
    {
      name: 'search-get-coverage-mcp-client',
      version: '0.0.0',
    },
    {
      capabilities: {},
    },
  );

  const startedServer = await server;

  try {
    await startedServer.connect(serverTransport);
    await mcpClient.connect(clientTransport);
    await run(mcpClient);
  } finally {
    await Promise.allSettled([mcpClient.close(), startedServer.close()]);
    await Promise.all(pipes);
  }
}

type MockedUpstreamResponse =
  | {
      rows: Array<MemoryRow & { rank: number }>;
    }
  | Response;

function makeFixedClient(
  principalId: string,
  responses: {
    searchResponse: MockedUpstreamResponse;
    getResponse: (input: { id: string }) => Response;
  },
) {
  return createFixedClientWithMockFetch(principalId, responses).client;
}

function createFixedClientWithMockFetch(
  principalId: string,
  responses: {
    searchResponse: MockedUpstreamResponse;
    getResponse: (input: { id: string }) => Response;
  },
) {
  const fetch = vi.fn<typeof globalThis.fetch>(async (url, init) => {
    const request = new URL(url);
    if (request.pathname.endsWith('/auth/v1/user')) {
      return identityPayload(principalId);
    }

    if (request.pathname.endsWith('/rest/v1/rpc/authorized_memory_search_v1')) {
      return responses.searchResponse instanceof Response
        ? responses.searchResponse
        : jsonResponse(JSON.stringify(responses.searchResponse));
    }

    if (request.pathname.endsWith('/rest/v1/rpc/authorized_memory_get_v1')) {
      const payload = JSON.parse(String(init?.body));
      return responses.getResponse(payload as { id: string });
    }

    return new Response('', { status: 500 });
  });

  const client = createFixedSupabaseClient({
    origin: ORIGIN,
    credentials: {
      projectPublishableKey: 'sb_publishable_key',
      userAccessToken: 'header.payload.signature',
    },
    fetch,
  });

  return { client, fetch };
}

describe('search-to-get contract coverage', () => {
  it('preserves authorized search locator provenance and untrusted marker through exact get', async () => {
    const row: MemoryRow & { rank: number } = {
      id: 'mem_1234567890123456789012',
      title: 'Synthetic title',
      content: 'Visible synthetic memory for allowed principal',
      createdAt: '2026-08-30T12:00:00.000Z',
      provenanceSummary: 'synthetic provenance marker',
      rank: 0.37,
    };

    const rowGet: MemoryRow = {
      id: row.id,
      title: row.title,
      content: row.content,
      createdAt: row.createdAt,
      provenanceSummary: row.provenanceSummary,
    };

    const client = makeFixedClient('11111111-1111-4111-9111-111111111111', {
      searchResponse: { rows: [row] },
      getResponse: (input) =>
        input.id === row.id
          ? jsonResponse(JSON.stringify({ record: rowGet }))
          : jsonResponse(JSON.stringify({ record: null })),
    });

    await withClient(createReadOnlyServer({ client }), async (mcp) => {
      const searchResult = await mcp.callTool({
        name: 'memory_search',
        arguments: {
          query: 'synthetic',
          filters: { tags: ['scope-ok'] },
          limit: 2,
        },
      });
      expect(searchResult.structuredContent).toMatchObject({
        ok: true,
        items: [
          {
            ...row,
            contentTrust: 'untrusted',
          },
        ],
      });

      const itemId = (searchResult.structuredContent as { items: Array<{ id: string }> }).items[0]
        ?.id;
      if (itemId === undefined) throw new Error('Search result missing expected item id.');

      const getResult = await mcp.callTool({
        name: 'memory_get',
        arguments: {
          id: itemId,
        },
      });

      expect(getResult.structuredContent).toMatchObject({
        ok: true,
        record: {
          ...rowGet,
          contentTrust: 'untrusted',
        },
      });
    });
  });

  it('returns the same public unavailable for a stale search locator and another missing target', async () => {
    const row: MemoryRow & { rank: number } = {
      id: 'mem_aaaaaaaaaaaaaaaaaaaaaaa',
      title: 'Protected title',
      content: 'Protected synthetic memory',
      createdAt: '2026-08-30T12:00:00.000Z',
      provenanceSummary: 'protected provenance',
      rank: 0.99,
    };

    const unavailableOutput = publicMemoryGetUnavailable('missing');

    const deniedClient = makeFixedClient('22222222-2222-4111-9111-222222222222', {
      searchResponse: { rows: [row] },
      getResponse: () => jsonResponse(JSON.stringify({ record: null })),
    });

    await withClient(createReadOnlyServer({ client: deniedClient }), async (mcp) => {
      const searchResult = await mcp.callTool({
        name: 'memory_search',
        arguments: { query: 'synthetic', limit: 1 },
      });
      const firstId = (searchResult.structuredContent as { items: Array<{ id: string }> }).items[0]
        ?.id;
      expect(firstId).toBe(row.id);

      const getByLocator = await mcp.callTool({
        name: 'memory_get',
        arguments: { id: firstId },
      });
      expect(getByLocator.structuredContent).toEqual(unavailableOutput);

      const getMissing = await mcp.callTool({
        name: 'memory_get',
        arguments: { id: 'mem_notfound12345678901234' },
      });
      expect(getMissing.structuredContent).toEqual(unavailableOutput);
    });
  });

  it('maps upstream get failures to a non-success error, not a silent unavailable success', async () => {
    const row: MemoryRow & { rank: number } = {
      id: 'mem_bbbbbbbbbbbbbbbbbbbbbbb',
      title: 'Transiently failing memory',
      content: 'Will fail upstream',
      createdAt: '2026-08-30T12:00:00.000Z',
      provenanceSummary: 'flaky provenance',
      rank: 0.12,
    };

    const { client, fetch: upstreamFetch } = createFixedClientWithMockFetch(
      '33333333-3333-4333-9333-333333333333',
      {
        searchResponse: { rows: [row] },
        getResponse: () => new Response('upstream down', { status: 502 }),
      },
    );

    await withClient(createReadOnlyServer({ client }), async (mcp) => {
      await mcp.callTool({
        name: 'memory_search',
        arguments: { query: 'synthetic', limit: 1 },
      });

      const getResult = await mcp.callTool({
        name: 'memory_get',
        arguments: { id: row.id },
      });

      expect(getResult.structuredContent).toMatchObject({
        ok: false,
        error: {
          code: 'INTERNAL_ERROR',
          retryable: false,
        },
      });

      const getCall = upstreamFetch.mock.calls.find(([url]) =>
        String(url).includes('/rest/v1/rpc/authorized_memory_get_v1'),
      );
      expect(getCall).toBeDefined();
      if (getCall === undefined) throw new Error('Expected upstream call.');
      const getCallIndex = upstreamFetch.mock.calls.indexOf(getCall);
      await expect(upstreamFetch.mock.results[getCallIndex]?.value).resolves.toMatchObject({
        status: 502,
        ok: false,
      });

      const [, getInit] = getCall as [string, RequestInit];
      expect(getInit?.body).toBeDefined();
      const getBody = JSON.parse(String(getInit.body));
      expect(getBody).toEqual({ id: row.id });
    });
  });

  it('maps upstream search failures to a non-success error, not empty success', async () => {
    const row: MemoryRow & { rank: number } = {
      id: 'mem_failedsearch000000000',
      title: 'Search-time synthetic memory',
      content: 'Unused when search fails',
      createdAt: '2026-08-30T12:00:00.000Z',
      provenanceSummary: 'search failed provenance',
      rank: 0.4,
    };

    const { client, fetch: upstreamFetch } = createFixedClientWithMockFetch(
      '44444444-4444-4333-9444-444444444444',
      {
        searchResponse: new Response(JSON.stringify({ rows: [row] }), { status: 502 }),
        getResponse: () => jsonResponse(JSON.stringify({ record: null })),
      },
    );

    await withClient(createReadOnlyServer({ client }), async (mcp) => {
      const searchResult = await mcp.callTool({
        name: 'memory_search',
        arguments: { query: 'synthetic', limit: 1 },
      });

      expect(searchResult.structuredContent).toMatchObject({
        ok: false,
        error: {
          code: 'INTERNAL_ERROR',
          retryable: false,
        },
      });

      const searchCall = upstreamFetch.mock.calls.find(([url]) =>
        String(url).includes('/rest/v1/rpc/authorized_memory_search_v1'),
      );
      expect(searchCall).toBeDefined();
      if (searchCall === undefined) throw new Error('Expected upstream call.');
      const searchCallIndex = upstreamFetch.mock.calls.indexOf(searchCall);
      await expect(upstreamFetch.mock.results[searchCallIndex]?.value).resolves.toMatchObject({
        status: 502,
        ok: false,
      });
      const searchBody = JSON.parse(String((searchCall as [string, RequestInit])[1]?.body));
      expect(searchBody).toMatchObject({
        query: 'synthetic',
        limit: 1,
      });
    });
  });

  it("uses fresh read-only server sessions without inheriting another user's prior result", async () => {
    const principalOne = '44444444-4444-4444-9444-444444444444';
    const principalTwo = '55555555-5555-4555-9555-555555555555';
    const sharedRowId = 'mem_cccccccccccccccccccccc';

    const sharedRowSearch: MemoryRow & { rank: number } = {
      id: sharedRowId,
      title: 'Shared row synthetic',
      content: 'Result seeded into user one',
      createdAt: '2026-08-30T12:00:00.000Z',
      provenanceSummary: 'shared provenance',
      rank: 0.44,
    };

    const ownRowForSecondPrincipal: MemoryRow & { rank: number } = {
      id: 'mem_dddddddddddddddddddddd',
      title: 'Principal two memory',
      content: 'Own synthetic result',
      createdAt: '2026-08-30T12:00:00.000Z',
      provenanceSummary: 'second provenance',
      rank: 0.33,
    };

    const firstClient = makeFixedClient(principalOne, {
      searchResponse: { rows: [sharedRowSearch] },
      getResponse: (input) =>
        input.id === sharedRowSearch.id
          ? jsonResponse(
              JSON.stringify({
                record: {
                  id: sharedRowSearch.id,
                  title: sharedRowSearch.title,
                  content: sharedRowSearch.content,
                  createdAt: sharedRowSearch.createdAt,
                  provenanceSummary: sharedRowSearch.provenanceSummary,
                },
              }),
            )
          : jsonResponse(JSON.stringify({ record: null })),
    });

    const secondClient = makeFixedClient(principalTwo, {
      searchResponse: { rows: [ownRowForSecondPrincipal] },
      getResponse: () => jsonResponse(JSON.stringify({ record: null })),
    });

    const capturedSharedId = {
      value: '' as string,
    };

    await withClient(createReadOnlyServer({ client: firstClient }), async (mcp) => {
      const searchResult = await mcp.callTool({
        name: 'memory_search',
        arguments: { query: 'synthetic', limit: 1 },
      });
      const id = (searchResult.structuredContent as { items: Array<{ id: string }> }).items[0]?.id;
      expect(id).toBe(sharedRowSearch.id);
      capturedSharedId.value = id ?? '';

      const firstGetResult = await mcp.callTool({
        name: 'memory_get',
        arguments: { id },
      });
      expect(firstGetResult.structuredContent).toMatchObject({
        ok: true,
        record: {
          id: sharedRowSearch.id,
          title: sharedRowSearch.title,
          content: sharedRowSearch.content,
          contentTrust: 'untrusted',
        },
      });
    });

    await withClient(createReadOnlyServer({ client: secondClient }), async (mcp) => {
      const secondSearchResult = await mcp.callTool({
        name: 'memory_search',
        arguments: { query: 'synthetic', limit: 1 },
      });
      const secondId = (secondSearchResult.structuredContent as { items: Array<{ id: string }> })
        .items[0]?.id;
      expect(secondId).toBe(ownRowForSecondPrincipal.id);
      expect(secondId).not.toEqual(capturedSharedId.value);

      const deniedByInheritance = await mcp.callTool({
        name: 'memory_get',
        arguments: { id: capturedSharedId.value },
      });
      expect(deniedByInheritance.structuredContent).toEqual(publicMemoryGetUnavailable('missing'));
    });
  });
});
