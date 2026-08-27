import { MAX_RESPONSE_BYTES } from '@supabase-user-mcp/contracts';
import { describe, expect, it, vi } from 'vitest';

import type { FixedMemoryGetRow, FixedSupabaseClient } from './fixed-supabase-client.js';
import { createMemoryListRecent } from './memory-list-recent.js';

const row = (overrides: Partial<FixedMemoryGetRow> = {}): FixedMemoryGetRow => ({
  id: 'mem_1234567890123456789012',
  title: 'Visible memory',
  content: 'synthetic memory',
  createdAt: '2026-08-24T12:00:00.000Z',
  provenanceSummary: 'synthetic fixture',
  ...overrides,
});

function clientWith(result: {
  rows: FixedMemoryGetRow[];
  nextCursor?: string;
}): FixedSupabaseClient {
  return {
    listMemoryRows: vi.fn(),
    getMemoryRow: vi.fn(),
    listRecentMemoryRows: vi.fn().mockResolvedValue(result),
  };
}

describe('createMemoryListRecent', () => {
  it('validates input and maps bounded ordered records with allowlisted fields', async () => {
    const client = clientWith({
      rows: [
        row({ createdAt: '2026-08-24T11:00:00.000Z', id: `mem_${'B'.repeat(22)}` }),
        row({ createdAt: '2026-08-24T12:00:00.000Z', id: `mem_${'A'.repeat(22)}` }),
      ],
      nextCursor: `cur_${'A'.repeat(16)}`,
    });
    const listRecent = createMemoryListRecent(client);
    await expect(
      listRecent({
        filters: { tags: ['safe', 'verified'] },
        limit: 2,
        cursor: 'cur_12345678901234567890',
      }),
    ).resolves.toEqual({
      ok: true,
      items: [
        {
          ...row({ createdAt: '2026-08-24T12:00:00.000Z', id: `mem_${'A'.repeat(22)}` }),
          contentTrust: 'untrusted',
        },
        {
          ...row({ createdAt: '2026-08-24T11:00:00.000Z', id: `mem_${'B'.repeat(22)}` }),
          contentTrust: 'untrusted',
        },
      ],
      nextCursor: `cur_${'A'.repeat(16)}`,
    });
    expect(client.listRecentMemoryRows).toHaveBeenCalledWith(
      {
        filters: { tags: ['safe', 'verified'] },
        limit: 2,
        cursor: 'cur_12345678901234567890',
      },
      expect.any(AbortSignal),
    );
  });

  it('rejects malformed input before any client access', async () => {
    const client = clientWith({ rows: [] });
    await expect(
      createMemoryListRecent(client)({
        filters: { tags: ['a', 'b', 'c', 'd', 'e', 'f'] },
      }),
    ).resolves.toEqual({
      ok: false,
      error: { code: 'INVALID_REQUEST', message: 'Request is invalid.', retryable: false },
    });
    expect(client.listRecentMemoryRows).not.toHaveBeenCalled();
  });

  it('maps malformed upstream rows and oversized responses to closed errors', async () => {
    const malformedRow = {
      ...row(),
      ownerId: 'other-user',
    } as unknown as FixedMemoryGetRow;
    const malformed = clientWith({ rows: [malformedRow] });
    await expect(createMemoryListRecent(malformed)({ limit: 1 })).resolves.toMatchObject({
      ok: false,
      error: { code: 'INTERNAL_ERROR' },
    });

    const oversized = clientWith({
      rows: [row({ content: 'x'.repeat(MAX_RESPONSE_BYTES) })],
    });
    await expect(createMemoryListRecent(oversized)({ limit: 1 })).resolves.toMatchObject({
      ok: false,
      error: { code: 'RESPONSE_LIMIT_EXCEEDED' },
    });
  });

  it('maps fixed client timeout failures to deadline exceeded', async () => {
    vi.useFakeTimers();
    const client: FixedSupabaseClient = {
      listMemoryRows: vi.fn(),
      getMemoryRow: vi.fn(),
      listRecentMemoryRows: vi.fn(
        (_input, signal) =>
          new Promise<never>((_resolve, reject) => {
            signal?.addEventListener('abort', () =>
              reject(Object.assign(new Error('secret'), { code: 'FIXED_CLIENT_TIMEOUT' })),
            );
          }),
      ),
    };

    const pending = createMemoryListRecent(client, { timeoutMs: 25 })({ limit: 1 });
    await vi.advanceTimersByTimeAsync(25);
    await expect(pending).resolves.toEqual({
      ok: false,
      error: { code: 'DEADLINE_EXCEEDED', message: 'Request deadline exceeded.', retryable: false },
    });
    vi.useRealTimers();
  });

  it('preserves empty page for missing/unauthorized contexts without enumeration', async () => {
    const empty = clientWith({ rows: [] });
    await expect(createMemoryListRecent(empty)({ limit: 3 })).resolves.toEqual({
      ok: true,
      items: [],
    });
  });
});
