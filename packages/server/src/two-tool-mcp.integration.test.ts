import { Client } from '@modelcontextprotocol/client';
import { StreamTransport } from '@supabase/mcp-utils';
import { createReadToolMcpResult } from '@supabase-user-mcp/contracts';
import { describe, expect, it, vi } from 'vitest';
import { createFixedSupabaseClient } from './fixed-supabase-client.js';
import { createMemoryRetrieve } from './memory-retrieve.js';
import { createReadOnlyServer } from './server.js';

const ORIGIN = 'https://project-ref.supabase.co';
const PRINCIPAL = '11111111-1111-4111-9111-111111111111';

const TWO_TOOL_SERVER = { registerDraftTwoTools: true as const };

async function withReadOnlyMcpClient(
  run: (client: Client) => Promise<void>,
  fetch: typeof globalThis.fetch,
  serverOptions: { registerDraftTwoTools?: boolean } = {},
): Promise<void> {
  const clientTransport = new StreamTransport();
  const serverTransport = new StreamTransport();
  const pipes = [
    clientTransport.readable.pipeTo(serverTransport.writable).catch(() => undefined),
    serverTransport.readable.pipeTo(clientTransport.writable).catch(() => undefined),
  ];
  const mcpClient = new Client({ name: 'two-tool-sdk', version: '0.0.0' }, { capabilities: {} });
  const supabaseClient = createFixedSupabaseClient({
    origin: ORIGIN,
    credentials: {
      projectPublishableKey: 'sb_publishable_key',
      userAccessToken: 'header.payload.signature',
    },
    fetch,
  });
  const server = await createReadOnlyServer({ client: supabaseClient, ...serverOptions });
  try {
    await server.connect(serverTransport);
    await mcpClient.connect(clientTransport);
    await run(mcpClient);
  } finally {
    await Promise.allSettled([mcpClient.close(), server.close()]);
    await Promise.all(pipes);
  }
}

describe('memory_retrieve and session_capabilities_get MCP SDK integration', () => {
  it('invokes memory_retrieve through the real MCP client and maps found outcome', async () => {
    const record = {
      id: 'mem_1234567890123456789012',
      title: 'Two words',
      content: 'data only',
      createdAt: '2026-08-23T12:00:00.000Z',
      provenanceSummary: 'synthetic fixture',
    };
    const fetch = vi.fn<typeof globalThis.fetch>(async (url, init) => {
      if (String(url).includes('/auth/v1/user')) {
        return new Response(JSON.stringify({ id: PRINCIPAL, aud: 'authenticated' }), {
          headers: { 'content-type': 'application/json' },
        });
      }
      const body = JSON.parse(String(init?.body));
      return new Response(
        JSON.stringify(
          String(url).endsWith('authorized_memory_get_v1')
            ? { record }
            : { rows: body.query === 'two words' ? [{ ...record, rank: 0.5 }] : [] },
        ),
        { headers: { 'content-type': 'application/json' } },
      );
    });

    await withReadOnlyMcpClient(
      async (mcp) => {
        const result = await mcp.callTool({
          name: 'memory_retrieve',
          arguments: { query: 'two  words', limit: 2 },
        });
        expect(result.isError).toBe(false);
        expect(result.structuredContent).toMatchObject({
          ok: true,
          outcome: 'found',
          retrieval: { query_last_executed: 'two words' },
          result: { ok: true, record: { id: record.id, contentTrust: 'untrusted' } },
        });
        expect(result.structuredContent).not.toHaveProperty('legacy');
      },
      fetch,
      TWO_TOOL_SERVER,
    );
  });

  it('returns INVALID_REQUEST from the governed tool path when input fails Zod validation', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    const client = createFixedSupabaseClient({
      origin: ORIGIN,
      credentials: {
        projectPublishableKey: 'sb_publishable_key',
        userAccessToken: 'header.payload.signature',
      },
      fetch,
    });
    const retrieve = createMemoryRetrieve(client, {
      governance: { maxRequestsPerWindow: 5, requestWindowMs: 60_000 },
    });
    const output = await retrieve({ query: '   ' }, { principalId: PRINCIPAL });
    expect(output).toEqual({
      ok: false,
      error: {
        code: 'INVALID_REQUEST',
        message: 'Request is invalid.',
        retryable: false,
      },
    });
    expect(createReadToolMcpResult(output).isError).toBe(true);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('surfaces SDK protocol validation errors for invalid memory_retrieve input', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async (url) => {
      if (String(url).includes('/auth/v1/user')) {
        return new Response(JSON.stringify({ id: PRINCIPAL, aud: 'authenticated' }), {
          headers: { 'content-type': 'application/json' },
        });
      }
      return new Response(JSON.stringify({ rows: [] }), {
        headers: { 'content-type': 'application/json' },
      });
    });

    await withReadOnlyMcpClient(
      async (mcp) => {
        const result = await mcp.callTool({
          name: 'memory_retrieve',
          arguments: { query: '   ' },
        });
        expect(result.isError).toBe(true);
        expect(result.structuredContent).toBeUndefined();
      },
      fetch,
      TWO_TOOL_SERVER,
    );
  });

  it('invokes session_capabilities_get and projects only registered tools without granting authority', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async (url) => {
      if (String(url).includes('/auth/v1/user')) {
        return new Response(JSON.stringify({ id: PRINCIPAL, aud: 'authenticated' }), {
          headers: { 'content-type': 'application/json' },
        });
      }
      return new Response('{}', { status: 500 });
    });

    await withReadOnlyMcpClient(
      async (mcp) => {
        const listing = await mcp.listTools();
        const toolNames = listing.tools.map((tool) => tool.name).toSorted();
        expect(toolNames).toEqual([
          'memory_get',
          'memory_list_recent',
          'memory_retrieve',
          'memory_search',
          'session_capabilities_get',
        ]);

        const result = await mcp.callTool({ name: 'session_capabilities_get', arguments: {} });
        expect(result.isError).toBe(false);
        const content = result.structuredContent as {
          ok: boolean;
          discovery: { tools_list: { permission_authority: boolean } };
          visible_tools: Array<{
            name: string;
            access: Record<string, string>;
          }>;
        };
        expect(content.discovery.tools_list.permission_authority).toBe(false);
        expect(content.visible_tools.map((tool) => tool.name).toSorted()).toEqual(toolNames);
        for (const tool of content.visible_tools) {
          expect(tool.access).toEqual({
            declared: 'declared',
            verified: 'unknown',
            qualified: 'unknown',
            authorized: 'unknown',
            available: 'unknown',
          });
        }
        expect(createReadToolMcpResult(content).isError).toBe(false);
      },
      fetch,
      TWO_TOOL_SERVER,
    );
  });

  it('returns RESPONSE_LIMIT_EXCEEDED through the MCP server when the retrieve envelope exceeds wire budget', async () => {
    const row = {
      id: 'mem_1234567890123456789012',
      title: 'x',
      content: 'x'.repeat(8192),
      createdAt: '2026-08-23T12:00:00.000Z',
      provenanceSummary: 'synthetic',
      rank: 0.5,
    };
    const fetch = vi.fn<typeof globalThis.fetch>(async (url) => {
      if (String(url).includes('/auth/v1/user')) {
        return new Response(JSON.stringify({ id: PRINCIPAL, aud: 'authenticated' }), {
          headers: { 'content-type': 'application/json' },
        });
      }
      return new Response(
        JSON.stringify({
          rows: Array.from({ length: 20 }, (_, index) => ({
            ...row,
            id: `mem_${String(index).padStart(24, '0')}`,
          })),
          nextCursor: 'cur_AAAAAAAAAAAAAAAA',
        }),
        { headers: { 'content-type': 'application/json' } },
      );
    });

    await withReadOnlyMcpClient(
      async (mcp) => {
        const result = await mcp.callTool({
          name: 'memory_retrieve',
          arguments: { query: 'overflow' },
        });
        expect(result.isError).toBe(true);
        expect(result.structuredContent).toEqual({
          ok: false,
          error: {
            code: 'RESPONSE_LIMIT_EXCEEDED',
            message: 'Response limit exceeded.',
            retryable: false,
          },
        });
      },
      fetch,
      TWO_TOOL_SERVER,
    );
  });

  it('does not register draft two tools on the default read-only server', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async (url) => {
      if (String(url).includes('/auth/v1/user')) {
        return new Response(JSON.stringify({ id: PRINCIPAL, aud: 'authenticated' }), {
          headers: { 'content-type': 'application/json' },
        });
      }
      return new Response('{}', { status: 500 });
    });
    await withReadOnlyMcpClient(
      async (mcp) => {
        const listing = await mcp.listTools();
        expect(listing.tools.map((tool) => tool.name).toSorted()).toEqual([
          'memory_get',
          'memory_list_recent',
          'memory_search',
        ]);
      },
      fetch,
      {},
    );
  });
});
