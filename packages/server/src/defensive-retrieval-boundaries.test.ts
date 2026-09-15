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

it('does not reinterpret an input continuation cursor under a normalized query', async () => {
  const fetch = vi.fn<typeof globalThis.fetch>(
    async () => new Response(JSON.stringify({ rows: [] })),
  );
  const result = await createDefensiveRetrieval(fixture(fetch))(
    { query: 'two  words', cursor: 'cur_AAAAAAAAAAAAAAAA' },
    { principalId: 'boundary-cursor' },
  );
  expect(result).toMatchObject({
    outcome: 'no-match-within-searched-scope',
    completeness: 'unknown',
  });
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(JSON.parse(String(fetch.mock.calls[0]?.[1]?.body))).toMatchObject({
    query: 'two  words',
    cursor: 'cur_AAAAAAAAAAAAAAAA',
  });
});

it('preserves filters and context across the bounded retry and never implies complete absence', async () => {
  const fetch = vi.fn<typeof globalThis.fetch>(
    async () => new Response(JSON.stringify({ rows: [] })),
  );
  const result = await createDefensiveRetrieval(fixture(fetch))(
    { query: 'two  words', filters: { tags: ['allowed'] }, limit: 2 },
    {
      principalId: 'boundary-scope',
      clientId: 'synthetic-client',
      requestId: 'bounded-request',
    },
  );
  expect(result).toMatchObject({
    outcome: 'no-match-within-searched-scope',
    completeness: 'unknown',
    lastSearchQuery: 'two words',
  });
  expect(fetch).toHaveBeenCalledTimes(2);
  for (const [, init] of fetch.mock.calls)
    expect(JSON.parse(String(init?.body))).toMatchObject({
      filters: { tags: ['allowed'] },
      limit: 2,
    });
});

it('rejects invalid input before upstream dispatch', async () => {
  const fetch = vi.fn<typeof globalThis.fetch>();
  const result = await createDefensiveRetrieval(fixture(fetch))({
    query: 'two words',
    ownerId: 'other',
  });
  expect(result).toMatchObject({
    outcome: 'error',
    result: { error: { code: 'INVALID_REQUEST' } },
  });
  expect(fetch).not.toHaveBeenCalled();
});

it('uses the remaining overall deadline on retry, not a new timeout window', async () => {
  vi.useFakeTimers();
  try {
    let count = 0;
    const fetch = vi.fn<typeof globalThis.fetch>(async () => {
      count += 1;
      if (count === 1) {
        await new Promise((resolve) => setTimeout(resolve, 20));
        return new Response(JSON.stringify({ rows: [] }));
      }
      return new Promise(() => {});
    });
    const pending = createDefensiveRetrieval(fixture(fetch), 30)(
      { query: 'two  words' },
      { principalId: 'boundary-shared-deadline' },
    );
    await vi.advanceTimersByTimeAsync(21);
    expect(fetch).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(10);
    expect(await pending).toMatchObject({
      outcome: 'error',
      result: { error: { code: 'DEADLINE_EXCEEDED' } },
    });
    expect(fetch).toHaveBeenCalledTimes(2);
  } finally {
    vi.useRealTimers();
  }
});
