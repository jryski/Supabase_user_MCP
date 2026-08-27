import { describe, expect, it, vi } from 'vitest';

import type { FixedSupabaseClient } from './fixed-supabase-client.js';
import { createMemoryGet } from './memory-get.js';
import { createMemoryListRecent } from './memory-list-recent.js';
import { createMemorySearch } from './memory-search.js';
import type { ReadToolOperationalEvent } from './read-tool-governor.js';

const client: FixedSupabaseClient = {
  listMemoryRows: vi.fn(),
  searchMemoryRows: vi.fn(),
  getMemoryRow: vi.fn(),
  listRecentMemoryRows: vi.fn(),
};

describe('read-tool governor integration', () => {
  it.each([
    ['memory_search', createMemorySearch(client)],
    ['memory_get', createMemoryGet(client)],
    ['memory_list_recent', createMemoryListRecent(client)],
  ])('forces %s through validation and operational events', async (_name, execute) => {
    const events: ReadToolOperationalEvent[] = [];
    await expect(
      execute(
        { relation: 'private.memories' },
        {
          principalId: `integration-${_name}`,
          emitOperationalEvent: (event) => events.push(event),
        },
      ),
    ).resolves.toMatchObject({
      ok: false,
      error: { code: 'INVALID_REQUEST' },
    });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      outcome: 'blocked',
      denialClass: 'INVALID_REQUEST',
    });
  });
});
