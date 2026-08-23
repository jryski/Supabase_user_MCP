import { Client } from '@modelcontextprotocol/client';
import { createMcpServer, StreamTransport, tool } from '@supabase/mcp-utils';
import { describe, expect, it } from 'vitest';
import * as z from 'zod/v4';

import { createServer } from '../../packages/server/src/server.js';

async function withClient(
  server: { connect(transport: StreamTransport): Promise<void>; close(): Promise<void> },
  run: (client: Client) => Promise<void>,
): Promise<void> {
  const clientTransport = new StreamTransport();
  const serverTransport = new StreamTransport();
  const pipes = [
    clientTransport.readable.pipeTo(serverTransport.writable).catch(() => undefined),
    serverTransport.readable.pipeTo(clientTransport.writable).catch(() => undefined),
  ];
  const client = new Client(
    { name: 'upstream-stream-compatibility', version: '0.0.0' },
    { capabilities: {} },
  );

  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    await run(client);
  } finally {
    await Promise.allSettled([client.close(), server.close()]);
    await Promise.all(pipes);
  }
}

const compatibilityToolListing = {
  name: 'system_compatibility_probe',
  title: 'System compatibility probe',
  description:
    'Verifies the M0 MCP contract without reading data, writing data, or making network requests.',
  inputSchema: {
    type: 'object',
    properties: {
      probe: {
        type: 'string',
        const: 'm0',
        description: 'Fixed M0 probe value.',
      },
    },
    required: ['probe'],
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    additionalProperties: false,
  },
  outputSchema: {
    type: 'object',
    properties: {
      status: { type: 'string', const: 'ok' },
      milestone: { type: 'string', const: 'M0' },
      protocolTarget: { type: 'string', const: '2026-07-28' },
      dataAccess: { type: 'boolean', const: false },
      networkAccess: { type: 'boolean', const: false },
      writeAccess: { type: 'boolean', const: false },
    },
    required: [
      'status',
      'milestone',
      'protocolTarget',
      'dataAccess',
      'networkAccess',
      'writeAccess',
    ],
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    additionalProperties: false,
  },
  annotations: {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
} as const;

describe('official upstream StreamTransport compatibility seam', () => {
  it('preserves the complete fixed tool listing and successful call result', async () => {
    await withClient(createServer(), async (client) => {
      expect(await client.listTools()).toEqual({ tools: [compatibilityToolListing] });

      const result = await client.callTool({
        name: 'system_compatibility_probe',
        arguments: { probe: 'm0' },
      });

      expect(result).toEqual({
        content: [
          {
            type: 'text',
            text: 'M0 compatibility probe passed. No network or data operation was performed.',
          },
        ],
        structuredContent: {
          status: 'ok',
          milestone: 'M0',
          protocolTarget: '2026-07-28',
          dataAccess: false,
          networkAccess: false,
          writeAccess: false,
        },
      });
    });
  });

  it('preserves strict unknown-key rejection through the upstream transport', async () => {
    await withClient(createServer(), async (client) => {
      const result = await client.callTool({
        name: 'system_compatibility_probe',
        arguments: { probe: 'm0', unexpected: true },
      });

      expect(result.isError).toBe(true);
    });
  });

  it('characterizes upstream hidden as discovery-only, not authorization', async () => {
    let hiddenWriteExecuted = false;
    const upstreamServer = createMcpServer({
      name: 'upstream-hidden-characterization',
      version: '0.0.0',
      tools: {
        hidden_write: tool({
          description: 'Synthetic hidden write used only to characterize upstream behavior.',
          hidden: true,
          parameters: z.object({}),
          outputSchema: z.object({ wrote: z.literal(true) }),
          async execute() {
            hiddenWriteExecuted = true;
            return { wrote: true as const };
          },
        }),
      },
    });

    await withClient(upstreamServer, async (client) => {
      expect(await client.listTools()).toEqual({ tools: [] });

      const result = await client.callTool({ name: 'hidden_write', arguments: {} });
      expect(result.isError).not.toBe(true);
      expect(hiddenWriteExecuted).toBe(true);
    });
  });
});
