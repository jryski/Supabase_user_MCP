import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { describe, expect, it } from 'vitest';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const fixtureServer = resolve(
  repoRoot,
  'packages/server/fixtures/synthetic-read-only-stdio-server.mjs',
);

async function withFreshProcessClient(
  mode: string,
  run: (client: Client) => Promise<void>,
): Promise<void> {
  const client = new Client(
    { name: 'process-stdio-regression', version: '0.0.0' },
    {
      versionNegotiation: {
        mode: { pin: '2026-07-28' },
        probe: { timeoutMs: 10_000, maxRetries: 0 },
      },
    },
  );
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [fixtureServer],
    env: { ...process.env, SYNTHETIC_STDIO_MODE: mode },
    stderr: 'inherit',
  });
  try {
    await client.connect(transport);
    await run(client);
  } finally {
    await client.close();
  }
}

describe('process stdio integration (fresh server per scenario)', () => {
  it.each(['default', 'found', 'empty', 'ambiguous', 'partial', 'unavailable'] as const)(
    'negotiates modern protocol and serves scenario %s',
    async (mode) => {
      await withFreshProcessClient(mode, async (client) => {
        expect(client.getProtocolEra()).toBe('modern');
        const names = (await client.listTools()).tools.map((tool) => tool.name).sort();
        if (mode === 'default') {
          expect(names).toEqual(['memory_get', 'memory_list_recent', 'memory_search']);
          return;
        }
        assert.equal(names.length, 5);
        const capabilities = await client.callTool({
          name: 'session_capabilities_get',
          arguments: {},
        });
        expect(capabilities.isError).toBe(false);
        const structured = capabilities.structuredContent as {
          visible_tools: Array<{ name: string; access: { authorized: string } }>;
        };
        expect(structured.visible_tools.map((tool) => tool.name).sort()).toEqual(names);
        expect(structured.visible_tools.every((tool) => tool.access.authorized === 'unknown')).toBe(
          true,
        );

        const result = await client.callTool({
          name: 'memory_retrieve',
          arguments: { query: 'business address', limit: 3 },
        });
        if (mode === 'unavailable') {
          expect(result.isError).toBe(true);
          expect((result.structuredContent as { ok: boolean }).ok).toBe(false);
        } else {
          expect(result.isError).toBe(false);
          const content = result.structuredContent as { outcome: string; result?: unknown };
          expect(content.outcome).toBe(mode === 'empty' ? 'scoped_no_match' : mode);
          if (mode === 'found') {
            expect((content.result as { record: { content: string } }).record.content).toMatch(
              /TEST FIXTURE ONLY/,
            );
          }
          if (mode === 'partial') {
            expect((content.result as { nextCursor: string }).nextCursor).toMatch(/^cur_/);
          }
        }

        const bad = await client.callTool({
          name: 'memory_retrieve',
          arguments: { query: '   ' },
        });
        expect(bad.isError).toBe(true);
      });
    },
    30_000,
  );
});
