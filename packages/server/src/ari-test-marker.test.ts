import { readFile } from 'node:fs/promises';
import { Client } from '@modelcontextprotocol/client';
import { StreamTransport } from '@supabase/mcp-utils';
import { describe, expect, it } from 'vitest';

import {
  ARI_TEST_MARKER_PATH,
  ARI_TEST_MARKER_TOOL_NAME,
  readAriTestMarker,
} from './ari-test-marker.js';
import type { VerifiedFixedSupabaseClient } from './fixed-supabase-client.js';
import { createReadOnlyServer } from './server.js';

const PRINCIPAL = '11111111-1111-4111-8111-111111111111';
const TOKEN_B = 'bbb.ccc.ddd';
const ORIGIN = 'https://project.loopback.invalid';

function emptyClient(): VerifiedFixedSupabaseClient {
  return {
    verifyUserIdentity: async () => ({ principalId: PRINCIPAL }),
    listMemoryRows: async () => [],
    searchMemoryRows: async () => ({ rows: [] }),
    getMemoryRow: async () => null,
    listRecentMemoryRows: async () => ({ rows: [] }),
  };
}

async function toolNames(server: ReturnType<typeof createReadOnlyServer>): Promise<string[]> {
  const clientTransport = new StreamTransport();
  const serverTransport = new StreamTransport();
  const pipes = [
    clientTransport.readable.pipeTo(serverTransport.writable).catch(() => undefined),
    serverTransport.readable.pipeTo(clientTransport.writable).catch(() => undefined),
  ];
  const client = new Client({ name: 'marker-test', version: '0.0.0' }, { capabilities: {} });
  const resolved = await server;
  try {
    await resolved.connect(serverTransport);
    await client.connect(clientTransport);
    const listing = await client.listTools();
    return listing.tools.map((tool) => tool.name).toSorted();
  } finally {
    await Promise.allSettled([client.close(), resolved.close()]);
    await Promise.all(pipes);
  }
}

describe('Ari TEST marker seam', () => {
  it('stays off the default server and the CLI', async () => {
    const names = await toolNames(createReadOnlyServer({ client: emptyClient() }));
    expect(names).not.toContain(ARI_TEST_MARKER_TOOL_NAME);
    const cli = await readFile(new URL('./cli.ts', import.meta.url), 'utf8');
    const stdio = await readFile(new URL('./stdio-startup.ts', import.meta.url), 'utf8');
    expect(cli).not.toContain('ariTestMarker');
    expect(stdio).not.toContain('ariTestMarker');
    expect(stdio).not.toContain(ARI_TEST_MARKER_TOOL_NAME);
  });

  it('registers the fixed GET only when the seam is enabled and uses Token B', async () => {
    const names = await toolNames(
      createReadOnlyServer({
        client: emptyClient(),
        ariTestMarker: { readMarker: async () => 'ari-probe-marker-odbcejsuuqdzhabjmozi' },
      }),
    );
    expect(names).toContain(ARI_TEST_MARKER_TOOL_NAME);

    const calls: Array<{ url: string; method: string; authorization: string | null }> = [];
    const marker = await readAriTestMarker({
      origin: ORIGIN,
      accessToken: TOKEN_B,
      publishableKey: 'sb_publishable_test',
      fetch: async (input, init) => {
        calls.push({
          url: String(input),
          method: init?.method ?? 'GET',
          authorization: new Headers(init?.headers).get('authorization'),
        });
        return new Response(JSON.stringify([{ marker: 'ari-probe-marker-odbcejsuuqdzhabjmozi' }]), {
          status: 200,
        });
      },
    });
    expect(marker).toBe('ari-probe-marker-odbcejsuuqdzhabjmozi');
    expect(calls).toEqual([
      {
        url: `${ORIGIN}${ARI_TEST_MARKER_PATH}`,
        method: 'GET',
        authorization: `Bearer ${TOKEN_B}`,
      },
    ]);
  });
});
