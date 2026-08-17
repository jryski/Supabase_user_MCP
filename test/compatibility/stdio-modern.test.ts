import { fileURLToPath } from 'node:url';

import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { COMPATIBILITY_PROBE_TOOL_NAME } from '@supabase-user-mcp/contracts';
import { describe, expect, it } from 'vitest';

const serverEntry = fileURLToPath(new URL('../../packages/server/dist/cli.js', import.meta.url));

describe('MCP 2026-07-28 stdio compatibility', () => {
  it('negotiates the modern era and validates structured tool input and output', async () => {
    const client = new Client(
      {
        name: 'supabase-user-mcp-compatibility-test',
        version: '0.0.0',
      },
      {
        versionNegotiation: {
          mode: { pin: '2026-07-28' },
          probe: {
            timeoutMs: 5_000,
            maxRetries: 0,
          },
        },
      },
    );
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [serverEntry],
      stderr: 'pipe',
    });

    await client.connect(transport);

    try {
      expect(client.getProtocolEra()).toBe('modern');

      const listed = await client.listTools();
      expect(listed.tools.map((tool) => tool.name)).toEqual([COMPATIBILITY_PROBE_TOOL_NAME]);

      const result = await client.callTool({
        name: COMPATIBILITY_PROBE_TOOL_NAME,
        arguments: { probe: 'm0' },
      });

      expect(result.structuredContent).toEqual({
        status: 'ok',
        milestone: 'M0',
        protocolTarget: '2026-07-28',
        dataAccess: false,
        networkAccess: false,
        writeAccess: false,
      });

      const invalidResult = await client.callTool({
        name: COMPATIBILITY_PROBE_TOOL_NAME,
        arguments: { probe: 'not-m0' },
      });

      expect(invalidResult.isError).toBe(true);
      expect(invalidResult.content).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: 'text',
            text: expect.stringContaining('Input validation error'),
          }),
        ]),
      );
    } finally {
      await client.close();
    }
  });
});
