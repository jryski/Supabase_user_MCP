import {
  MAX_REQUEST_ID_BYTES,
  MAX_RESPONSE_BYTES,
  serializeReadToolWireResponse,
} from '@supabase-user-mcp/contracts';
import { expect, it, vi } from 'vitest';
import { createDefensiveRetrieval } from './defensive-retrieval.js';
import { createFixedSupabaseClient } from './fixed-supabase-client.js';

function fixture(fetch: typeof globalThis.fetch) {
  return createFixedSupabaseClient({
    origin: 'https://project-ref.supabase.co',
    credentials: {
      projectPublishableKey: 'sb_publishable_key',
      userAccessToken: 'header.payload.signature',
    },
    fetch,
  });
}
const record = {
  id: 'mem_1234567890123456789012',
  title: 'fixture',
  content: 'data',
  createdAt: '2026-08-23T12:00:00.000Z',
  provenanceSummary: 'synthetic',
};

it.each([1025, 70000])(
  'rejects oversized request ID (%i bytes) before invalid-input or cancellation paths',
  async (size) => {
    const fetch = vi.fn<typeof globalThis.fetch>(async () => new Response('{"rows":[]}'));
    const retrieve = createDefensiveRetrieval(fixture(fetch));
    for (const query of ['', 'valid']) {
      await expect(retrieve({ query }, { requestId: 'r'.repeat(size) })).rejects.toThrow(
        RangeError,
      );
      await expect(
        retrieve({ query }, { requestId: 'r'.repeat(size), signal: AbortSignal.abort() }),
      ).rejects.toThrow(RangeError);
    }
    expect(fetch).not.toHaveBeenCalled();
  },
);

it.each(['invalid', 'cancelled', 'upstream-error', 'empty'] as const)(
  'serializes %s with maximum valid escaped request ID',
  async (kind) => {
    const requestId = '\u0000'.repeat(MAX_REQUEST_ID_BYTES);
    const fetch = vi.fn<typeof globalThis.fetch>(
      async () => new Response('{"rows":[]}', { status: kind === 'upstream-error' ? 502 : 200 }),
    );
    const result = await createDefensiveRetrieval(fixture(fetch))(
      { query: kind === 'invalid' ? '' : 'valid' },
      {
        requestId,
        principalId: `review-${kind}`,
        ...(kind === 'cancelled' ? { signal: AbortSignal.abort() } : {}),
      },
    );
    expect(
      new TextEncoder().encode(serializeReadToolWireResponse(requestId, result)).byteLength,
    ).toBeLessThanOrEqual(MAX_RESPONSE_BYTES);
    expect(result.outcome).toBe(kind === 'empty' ? 'no-match-within-searched-scope' : 'error');
  },
);

it('rejects an exact-get identifier mismatch', async () => {
  const fetch = vi.fn<typeof globalThis.fetch>(
    async (url) =>
      new Response(
        JSON.stringify(
          String(url).endsWith('authorized_memory_get_v1')
            ? { record: { ...record, id: 'mem_abcdefghijklmnopqrstuv' } }
            : { rows: [{ ...record, rank: 0.5 }] },
        ),
      ),
  );
  const result = await createDefensiveRetrieval(fixture(fetch))(
    { query: 'valid' },
    { principalId: 'review-mismatch' },
  );
  expect(result).toMatchObject({ outcome: 'error', result: { error: { code: 'INTERNAL_ERROR' } } });
  expect(fetch).toHaveBeenCalledTimes(2);
});

it('returns a bounded error on response budget exhaustion', async () => {
  const rows = Array.from({ length: 20 }, (_, i) => ({
    ...record,
    id: `mem_${String(i).padStart(24, '0')}`,
    content: 'x'.repeat(8192),
    rank: 0.5,
  }));
  const fetch = vi.fn<typeof globalThis.fetch>(async () => new Response(JSON.stringify({ rows })));
  const requestId = 'r'.repeat(MAX_REQUEST_ID_BYTES);
  const result = await createDefensiveRetrieval(fixture(fetch))(
    { query: 'valid' },
    { requestId, principalId: 'review-bound' },
  );
  expect(result).toMatchObject({
    outcome: 'error',
    result: { error: { code: 'RESPONSE_LIMIT_EXCEEDED' } },
  });
  expect(
    new TextEncoder().encode(serializeReadToolWireResponse(requestId, result)).byteLength,
  ).toBeLessThanOrEqual(MAX_RESPONSE_BYTES);
  expect(fetch).toHaveBeenCalledTimes(1);
});

it('does not dispatch recovery after late upstream resolution following timeout', async () => {
  vi.useFakeTimers();
  try {
    let resolveFetch: ((value: Response) => void) | undefined;
    const fetch = vi.fn<typeof globalThis.fetch>(
      () =>
        new Promise<Response>((resolve) => {
          resolveFetch = resolve;
        }),
    );
    const pending = createDefensiveRetrieval(fixture(fetch), 20)(
      { query: 'two  words' },
      { principalId: 'review-late' },
    );
    await vi.advanceTimersByTimeAsync(21);
    expect(await pending).toMatchObject({
      outcome: 'error',
      result: { error: { code: 'DEADLINE_EXCEEDED' } },
    });
    if (!resolveFetch) throw new Error('Fetch was not reached');
    resolveFetch(new Response('{"rows":[]}'));
    await vi.advanceTimersByTimeAsync(1);
    expect(fetch).toHaveBeenCalledTimes(1);
  } finally {
    vi.useRealTimers();
  }
});
