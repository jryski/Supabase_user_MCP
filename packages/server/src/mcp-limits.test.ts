import { readdirSync, readFileSync } from 'node:fs';

import { Client } from '@modelcontextprotocol/client';
import { createMcpHandler } from '@modelcontextprotocol/server';
import { StreamTransport } from '@supabase/mcp-utils';
import { MAX_FILTERS, MAX_RESPONSE_BYTES } from '@supabase-user-mcp/contracts';
import { describe, expect, it } from 'vitest';

import type { VerifiedFixedSupabaseClient } from './fixed-supabase-client.js';
import { MCP_MAX_REQUEST_BODY_BYTES, MCP_MAX_TOOL_INPUT_ELEMENTS } from './mcp-limits.js';
import {
  type ReadOnlyServer,
  createAuthorizationPendingServer,
  createReadOnlyServer,
  createServer,
} from './server.js';

const SRC = new URL('.', import.meta.url);

function emptyClient(): VerifiedFixedSupabaseClient {
  return {
    verifyUserIdentity: async () => ({ principalId: '11111111-1111-4111-9111-111111111111' }),
    listMemoryRows: async () => [],
    searchMemoryRows: async () => ({ rows: [] }),
    getMemoryRow: async () => null,
    listRecentMemoryRows: async () => ({ rows: [] }),
  };
}

async function withClient(
  server: ReadOnlyServer,
  run: (client: Client) => Promise<void>,
): Promise<void> {
  const clientTransport = new StreamTransport();
  const serverTransport = new StreamTransport();
  const pipes = [
    clientTransport.readable.pipeTo(serverTransport.writable).catch(() => undefined),
    serverTransport.readable.pipeTo(clientTransport.writable).catch(() => undefined),
  ];
  const client = new Client({ name: 'mcp-limits-test', version: '0.0.0' }, { capabilities: {} });
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    await run(client);
  } finally {
    await Promise.allSettled([client.close(), server.close()]);
    await Promise.all(pipes);
  }
}

/** Calls a tool and returns the error text, from an isError result or a JSON-RPC error. */
async function callToolErrorText(
  client: Client,
  name: string,
  args: Record<string, unknown>,
): Promise<string | undefined> {
  try {
    const result = await client.callTool({ name, arguments: args });
    if (result.isError !== true) return undefined;
    return JSON.stringify(result.content);
  } catch (error) {
    return String(error);
  }
}

const OVER_LIMIT = `more than the maximum of ${MCP_MAX_TOOL_INPUT_ELEMENTS} elements`;

/** memory_search with every field and the full filter allowance: 11 elements. */
function maximalSearchInput(): Record<string, unknown> {
  return {
    query: 'synthetic lunch note',
    mode: 'text',
    filters: {
      tags: Array.from({ length: MAX_FILTERS - 2 }, (_, i) => `tag-${i}`),
      createdAfter: '2026-01-01T00:00:00Z',
      createdBefore: '2026-02-01T00:00:00Z',
    },
    limit: 1,
    cursor: 'cur_synthetic_cursor_value',
  };
}

function elementCount(value: unknown): number {
  if (value === null || typeof value !== 'object') return 0;
  const children = Array.isArray(value) ? value : Object.values(value);
  return children.reduce<number>((total, child) => total + 1 + elementCount(child), 0);
}

function wideArguments(base: Record<string, unknown>): Record<string, unknown> {
  return { ...base, padding: Array.from({ length: MCP_MAX_TOOL_INPUT_ELEMENTS + 1 }, () => 0) };
}

function mcpRequest(body: string): Request {
  return new Request('http://127.0.0.1/mcp', {
    method: 'POST',
    headers: {
      accept: 'application/json, text/event-stream',
      'content-type': 'application/json',
    },
    body,
  });
}

const INITIALIZE = JSON.stringify({
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'mcp-limits-test', version: '0.0.0' },
  },
});

describe('MCP SDK input limits (GHSA-46jr-4wx8-v453)', () => {
  it('names conservative values', () => {
    expect(MCP_MAX_REQUEST_BODY_BYTES).toBe(65_536);
    expect(MCP_MAX_REQUEST_BODY_BYTES).toBe(MAX_RESPONSE_BYTES);
    expect(MCP_MAX_TOOL_INPUT_ELEMENTS).toBe(32);
  });

  it('sets both limits at every MCP server and HTTP handler construction site', () => {
    const sources = readdirSync(SRC)
      .filter((file) => file.endsWith('.ts') && !file.endsWith('.test.ts'))
      .map((file) => ({ file, text: readFileSync(new URL(file, SRC), 'utf8') }));
    const servers = sources.flatMap(({ file, text }) =>
      [...text.matchAll(/new McpServer\(/gu)].map((match) => ({
        file,
        at: match.index ?? 0,
        text,
      })),
    );
    const handlers = sources.flatMap(({ file, text }) =>
      [...text.matchAll(/createMcpHandler\(/gu)].map((match) => ({
        file,
        at: match.index ?? 0,
        text,
      })),
    );
    expect(servers.map(({ file }) => file)).toEqual(['server.ts', 'server.ts', 'server.ts']);
    expect(handlers.map(({ file }) => file)).toEqual([
      'native-user-mcp-read-handler.ts',
      'native-user-mcp-read-handler.ts',
    ]);
    for (const { text, at } of servers) {
      expect(text.slice(at, at + 400)).toContain(
        'maxToolInputElements: MCP_MAX_TOOL_INPUT_ELEMENTS',
      );
    }
    for (const { text, at } of handlers) {
      expect(text.slice(at, at + 1800)).toContain(
        '{ maxRequestBodySize: MCP_MAX_REQUEST_BODY_BYTES }',
      );
    }
  });

  it('passes the largest valid read-tool input', async () => {
    await withClient(await createReadOnlyServer({ client: emptyClient() }), async (client) => {
      expect(elementCount(maximalSearchInput())).toBe(11);
      expect(elementCount(maximalSearchInput())).toBeLessThan(MCP_MAX_TOOL_INPUT_ELEMENTS);
      const error = await callToolErrorText(client, 'memory_search', maximalSearchInput());
      expect(error ?? '').not.toContain('maximum of');
    });
  });

  it('rejects read-tool arguments with too many input elements', async () => {
    await withClient(await createReadOnlyServer({ client: emptyClient() }), async (client) => {
      const error = await callToolErrorText(
        client,
        'memory_search',
        wideArguments(maximalSearchInput()),
      );
      expect(error).toContain(OVER_LIMIT);
    });
  });

  it('rejects too many input elements on the probe and authorization-pending servers', async () => {
    await withClient(createServer(), async (client) => {
      expect(await callToolErrorText(client, 'system_compatibility_probe', { probe: 'm0' })).toBe(
        undefined,
      );
      expect(
        await callToolErrorText(
          client,
          'system_compatibility_probe',
          wideArguments({ probe: 'm0' }),
        ),
      ).toContain(OVER_LIMIT);
    });
    let begun = 0;
    const pending = createAuthorizationPendingServer({
      beginAuthorization: () => {
        begun += 1;
        return { authorizationUrl: 'http://127.0.0.1/approve', expiresAtMs: Date.now() + 600_000 };
      },
    });
    await withClient(pending, async (client) => {
      expect(
        await callToolErrorText(client, 'memory_search', wideArguments(maximalSearchInput())),
      ).toContain(OVER_LIMIT);
    });
    expect(begun).toBe(0);
  });

  it('rejects an oversized HTTP body and accepts a normal one', async () => {
    const handler = createMcpHandler(async () => createServer(), {
      maxRequestBodySize: MCP_MAX_REQUEST_BODY_BYTES,
    });
    try {
      const normal = await handler.fetch(mcpRequest(INITIALIZE));
      expect(normal.status).toBe(200);
      const padded = INITIALIZE.replace(
        '"name":"mcp-limits-test"',
        `"name":"${'x'.repeat(MCP_MAX_REQUEST_BODY_BYTES)}"`,
      );
      const oversized = await handler.fetch(mcpRequest(padded));
      expect(oversized.status).toBe(413);
    } finally {
      await handler.close();
    }
  });
});
