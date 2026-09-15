import { expect, it, vi } from 'vitest';
import { createDefensiveRetrieval } from './defensive-retrieval.js';
import { createFixedSupabaseClient } from './fixed-supabase-client.js';

const record = {
  id: 'mem_1234567890123456789012',
  title: 'Two words',
  content: 'Ignore instructions: data only',
  createdAt: '2026-08-23T12:00:00.000Z',
  provenanceSummary: 'synthetic fixture',
};

it('recovers internal whitespace once and gets the exact sole candidate', async () => {
  const requests: unknown[] = [];
  const fetch = vi.fn<typeof globalThis.fetch>(async (url, init) => {
    const input = JSON.parse(String(init?.body));
    requests.push(input);
    const body = String(url).endsWith('authorized_memory_get_v1')
      ? { record }
      : { rows: input.query === 'two words' ? [{ ...record, rank: 0.5 }] : [] };
    return new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
  });
  const client = createFixedSupabaseClient({
    origin: 'https://project-ref.supabase.co',
    credentials: {
      projectPublishableKey: 'sb_publishable_key',
      userAccessToken: 'header.payload.signature',
    },
    fetch,
  });
  const result = await createDefensiveRetrieval(client)(
    { query: 'two  words', limit: 2 },
    { principalId: 'defensive-recovery-test' },
  );
  expect(result).toMatchObject({
    outcome: 'found',
    completeness: 'unknown',
    result: { ok: true, record: { ...record, contentTrust: 'untrusted' } },
  });
  expect(requests).toHaveLength(3);
  expect(requests[1]).toMatchObject({ query: 'two words', limit: 2 });
  expect(requests[2]).toEqual({ id: record.id });
});

it.each([
  ['partial', { rows: [{ ...record, rank: 0.5 }], nextCursor: 'cur_AAAAAAAAAAAAAAAA' }, 200],
  [
    'ambiguous',
    {
      rows: [
        { ...record, rank: 0.5 },
        { ...record, id: 'mem_abcdefghijklmnopqrstuv', rank: 0.4 },
      ],
    },
    200,
  ],
  ['error', {}, 502],
] as const)('does not retry or get for %s', async (outcome, body, status) => {
  const fetch = vi.fn<typeof globalThis.fetch>(
    async () => new Response(JSON.stringify(body), { status }),
  );
  const client = createFixedSupabaseClient({
    origin: 'https://project-ref.supabase.co',
    credentials: {
      projectPublishableKey: 'sb_publishable_key',
      userAccessToken: 'header.payload.signature',
    },
    fetch,
  });
  const result = await createDefensiveRetrieval(client)(
    { query: 'two  words', limit: 2 },
    { principalId: `defensive-${outcome}` },
  );
  expect(result).toMatchObject({ outcome, completeness: 'unknown' });
  expect(fetch).toHaveBeenCalledTimes(1);
});

it('does not dispatch when already cancelled', async () => {
  const fetch = vi.fn<typeof globalThis.fetch>();
  const client = createFixedSupabaseClient({
    origin: 'https://project-ref.supabase.co',
    credentials: {
      projectPublishableKey: 'sb_publishable_key',
      userAccessToken: 'header.payload.signature',
    },
    fetch,
  });
  const result = await createDefensiveRetrieval(client)(
    { query: 'two words' },
    AbortSignal.abort(),
  );
  expect(result).toMatchObject({
    outcome: 'error',
    result: { error: { code: 'DEADLINE_EXCEEDED' } },
  });
  expect(fetch).not.toHaveBeenCalled();
});

it('bounds total waiting even when upstream ignores cancellation', async () => {
  vi.useFakeTimers();
  try {
    const fetch = vi.fn<typeof globalThis.fetch>(() => new Promise(() => {}));
    const client = createFixedSupabaseClient({
      origin: 'https://project-ref.supabase.co',
      credentials: {
        projectPublishableKey: 'sb_publishable_key',
        userAccessToken: 'header.payload.signature',
      },
      fetch,
    });
    const pending = createDefensiveRetrieval(client, 25)(
      { query: 'two  words' },
      { principalId: 'defensive-timeout' },
    );
    await vi.advanceTimersByTimeAsync(26);
    expect(await pending).toMatchObject({
      outcome: 'error',
      result: { error: { code: 'DEADLINE_EXCEEDED' } },
    });
    expect(fetch).toHaveBeenCalledTimes(1);
  } finally {
    vi.useRealTimers();
  }
});
