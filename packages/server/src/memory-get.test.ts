import { MAX_RESPONSE_BYTES, publicMemoryGetUnavailable } from '@supabase-user-mcp/contracts';
import { describe, expect, it, vi } from 'vitest';

import {
  FixedSupabaseClientError,
  type FixedMemoryGetRow,
  type FixedSupabaseClient,
} from './fixed-supabase-client.js';
import { createMemoryGet } from './memory-get.js';

const row = (overrides: Partial<FixedMemoryGetRow> = {}): FixedMemoryGetRow => ({
  id: 'mem_1234567890123456789012',
  title: 'Stored memory',
  content: 'visible synthetic memory',
  createdAt: '2026-08-24T12:00:00.000Z',
  provenanceSummary: 'synthetic evidence',
  ...overrides,
});

function clientWith(result: FixedMemoryGetRow | null): FixedSupabaseClient {
  return {
    listMemoryRows: vi.fn(),
    searchMemoryRows: vi.fn(),
    getMemoryRow: vi.fn().mockResolvedValue(result),
    listRecentMemoryRows: vi.fn(),
  };
}

describe('createMemoryGet', () => {
  it('validates input with the closed contract and maps allowlisted rows', async () => {
    const client = clientWith(row());
    const getMemory = createMemoryGet(client);
    await expect(getMemory({ id: 'mem_1234567890123456789012' })).resolves.toEqual({
      ok: true,
      record: { ...row(), contentTrust: 'untrusted' },
    });
    expect(client.getMemoryRow).toHaveBeenCalledWith(
      { id: 'mem_1234567890123456789012' },
      expect.any(AbortSignal),
    );
  });

  it('returns non-enumerating unavailable for missing and unauthorized identifiers', async () => {
    const unauthorized = clientWith(null);
    const output = await createMemoryGet(unauthorized)({ id: 'mem_1234567890123456789012' });
    expect(output).toEqual(publicMemoryGetUnavailable('missing'));
  });

  it.each([
    { id: '42' },
    { relation: 'private.memories' },
    { id: row().id, mode: 'text' },
    { id: row().id, token: 'attacker' },
  ])('rejects malformed or broadened input %#', async (unsafeInput) => {
    const client = clientWith(row());
    await expect(createMemoryGet(client)(unsafeInput)).resolves.toEqual({
      ok: false,
      error: { code: 'INVALID_REQUEST', message: 'Request is invalid.', retryable: false },
    });
    expect(client.getMemoryRow).not.toHaveBeenCalled();
  });

  it('maps bad upstream rows and oversized responses to closed secret-free errors', async () => {
    const malformed = {
      ...row(),
      contentTrust: 'trusted' as const,
      ownerId: 'blocked',
    } as FixedMemoryGetRow & { contentTrust: 'trusted'; ownerId: string };
    const withMalformed = {
      ...clientWith(null),
      getMemoryRow: vi.fn().mockResolvedValue(malformed),
    };
    await expect(createMemoryGet(withMalformed)({ id: row().id })).resolves.toEqual({
      ok: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Request could not be completed.',
        retryable: false,
      },
    });
    const oversized = clientWith(row({ content: 'x'.repeat(MAX_RESPONSE_BYTES) }));
    await expect(createMemoryGet(oversized)({ id: row().id })).resolves.toMatchObject({
      ok: false,
      error: { code: 'RESPONSE_LIMIT_EXCEEDED' },
    });
  });

  it('maps typed upstream failures to secret-free request outcomes', async () => {
    vi.useFakeTimers();
    const client: FixedSupabaseClient = {
      listMemoryRows: vi.fn(),
      searchMemoryRows: vi.fn(),
      listRecentMemoryRows: vi.fn(),
      getMemoryRow: vi.fn(
        (_input, signal) =>
          new Promise<never>((_resolve, reject) => {
            signal?.addEventListener('abort', () =>
              reject(Object.assign(new Error('secret'), { code: 'FIXED_CLIENT_TIMEOUT' })),
            );
          }),
      ),
    };

    const pending = createMemoryGet(client, { timeoutMs: 25 })({ id: row().id });
    await vi.advanceTimersByTimeAsync(25);
    await expect(pending).resolves.toEqual({
      ok: false,
      error: { code: 'DEADLINE_EXCEEDED', message: 'Request deadline exceeded.', retryable: false },
    });
    vi.useRealTimers();
  });

  it('hides secret-bearing upstream failures from malformed-result callers', async () => {
    const failing = {
      ...clientWith(null),
      getMemoryRow: vi
        .fn()
        .mockRejectedValue(new FixedSupabaseClientError('FIXED_CLIENT_UPSTREAM_STATUS')),
    };
    await expect(createMemoryGet(failing)({ id: row().id })).resolves.toMatchObject({
      ok: false,
      error: { code: 'INTERNAL_ERROR' },
    });
  });
});
