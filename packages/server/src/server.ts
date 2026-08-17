import { McpServer } from '@modelcontextprotocol/server';
import {
  COMPATIBILITY_PROBE_TOOL,
  CompatibilityProbeOutputSchema,
} from '@supabase-user-mcp/contracts';

export const SERVER_NAME = 'supabase-user-mcp';
export const SERVER_VERSION = '0.0.0';
export const TARGET_PROTOCOL_VERSION = '2026-07-28';

export function createServer(): McpServer {
  const server = new McpServer(
    {
      name: SERVER_NAME,
      version: SERVER_VERSION,
    },
    {
      instructions:
        'M0 compatibility probe only. This server has no Supabase, network, read, or write access.',
    },
  );

  server.registerTool(
    COMPATIBILITY_PROBE_TOOL.name,
    {
      title: COMPATIBILITY_PROBE_TOOL.title,
      description: COMPATIBILITY_PROBE_TOOL.description,
      inputSchema: COMPATIBILITY_PROBE_TOOL.inputSchema,
      outputSchema: COMPATIBILITY_PROBE_TOOL.outputSchema,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async () => {
      const result = CompatibilityProbeOutputSchema.parse({
        status: 'ok',
        milestone: 'M0',
        protocolTarget: TARGET_PROTOCOL_VERSION,
        dataAccess: false,
        networkAccess: false,
        writeAccess: false,
      });

      return {
        content: [
          {
            type: 'text',
            text: 'M0 compatibility probe passed. No network or data operation was performed.',
          },
        ],
        structuredContent: result,
      };
    },
  );

  return server;
}
