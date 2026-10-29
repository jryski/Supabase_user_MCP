import { Client } from '@modelcontextprotocol/client';
import { StreamTransport } from '@supabase/mcp-utils';
import { describe, expect, it, vi } from 'vitest';

import type { ControlPlaneClient } from './control-plane-client.js';
import type { ControlPlaneOperationalEvent } from './control-plane-tool-governor.js';
import { createControlPlaneServer } from './control-plane-server.js';

const workItemId = '11111111-1111-4111-9111-111111111111';
const messageId = '22222222-2222-4222-9222-222222222222';

async function withClient(
  server: ReturnType<typeof createControlPlaneServer>,
  run: (client: Client) => Promise<void>,
): Promise<void> {
  const clientTransport = new StreamTransport();
  const serverTransport = new StreamTransport();
  const pipes = [
    clientTransport.readable.pipeTo(serverTransport.writable).catch(() => undefined),
    serverTransport.readable.pipeTo(clientTransport.writable).catch(() => undefined),
  ];
  const client = new Client(
    { name: 'control-plane-registration-test', version: '0.0.0' },
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

function fixedClient(): ControlPlaneClient {
  return {
    agentId: 'synthetic-ariadne',
    createWorkItem: vi.fn(async (input) => ({
      ok: true as const,
      receipt: {
        id: workItemId,
        itemNumber: 1,
        boardSlug: input.boardSlug,
        created: true as const,
        idempotencyKey: input.idempotencyKey,
      },
    })),
    postModelMessage: vi.fn(async () => ({
      ok: true as const,
      receipt: { id: messageId, seq: 2, posted: true as const },
    })),
  };
}

describe('privileged control-plane MCP registration', () => {
  it('registers exactly two fixed RPC-backed tools in a separate profile', async () => {
    await withClient(createControlPlaneServer({ client: fixedClient() }), async (client) => {
      const listing = await client.listTools();
      expect(listing.tools.map((tool) => tool.name).toSorted()).toEqual([
        'create_work_item',
        'post_model_message',
      ]);
      const create = listing.tools.find((tool) => tool.name === 'create_work_item');
      const post = listing.tools.find((tool) => tool.name === 'post_model_message');
      expect(create?.annotations).toEqual({
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      });
      expect(post?.annotations?.idempotentHint).toBe(false);
      for (const tool of listing.tools) {
        expect(tool.inputSchema.additionalProperties).toBe(false);
        expect(tool.outputSchema).toBeDefined();
        expect(Object.keys(tool.inputSchema.properties ?? {})).not.toEqual(
          expect.arrayContaining([
            'fromAgent',
            'sourceAgent',
            'principalId',
            'role',
            'sql',
            'schema',
            'table',
            'url',
            'method',
            'apikey',
          ]),
        );
      }
    });
  });

  it('routes both public handlers through validation and operational events', async () => {
    const backend = fixedClient();
    const events: ControlPlaneOperationalEvent[] = [];
    await withClient(
      createControlPlaneServer({
        client: backend,
        emitOperationalEvent: (event) => events.push(event),
      }),
      async (client) => {
        const created = await client.callTool({
          name: 'create_work_item',
          arguments: {
            boardSlug: 'synthetic-board',
            title: 'Synthetic item',
            idempotencyKey: 'synthetic-key',
          },
        });
        const posted = await client.callTool({
          name: 'post_model_message',
          arguments: { toAgent: 'synthetic-warden', subject: 'Subject', body: 'Body' },
        });
        expect(created.isError).toBe(false);
        expect(posted.isError).toBe(false);
      },
    );
    expect(backend.createWorkItem).toHaveBeenCalledOnce();
    expect(backend.postModelMessage).toHaveBeenCalledOnce();
    expect(events.map((event) => event.operation).toSorted()).toEqual([
      'planning.create_work_item',
      'public.post_model_message',
    ]);
    expect(events.every((event) => event.outcome === 'succeeded')).toBe(true);
  });

  it('rejects malformed requests before the privileged client is invoked', async () => {
    const backend = fixedClient();
    await withClient(createControlPlaneServer({ client: backend }), async (client) => {
      const result = await client.callTool({
        name: 'create_work_item',
        arguments: {
          boardSlug: 'synthetic-board',
          title: 'Synthetic item',
          idempotencyKey: 'synthetic-key',
          sql: 'insert into planning.work_items values (...)',
        },
      });
      expect(result.isError).toBe(true);
    });
    expect(backend.createWorkItem).not.toHaveBeenCalled();
  });
});
