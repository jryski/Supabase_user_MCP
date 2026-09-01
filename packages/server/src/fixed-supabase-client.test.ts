import { describe, expect, it, vi } from 'vitest';
import { createFixedSupabaseClient, FixedSupabaseClientError } from './fixed-supabase-client.js';

const origin = 'https://project-ref.supabase.co';
const token = 'header.user-identity.signature';

function response(body: string, status = 200): Response {
  return new Response(body, { status, headers: { 'content-type': 'application/json' } });
}

describe('createFixedSupabaseClient', () => {
  it('verifies and returns the authenticated user identity through the fixed Auth endpoint', async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(
        response('{"id":"11111111-1111-4111-9111-111111111111","aud":"authenticated"}'),
      );
    const client = createFixedSupabaseClient({
      origin,
      credentials: { projectPublishableKey: 'sb_publishable_key', userAccessToken: token },
      fetch,
    }) as unknown as {
      verifyUserIdentity: (signal?: AbortSignal) => Promise<{ readonly principalId: string }>;
    };

    await expect(client.verifyUserIdentity()).resolves.toEqual({
      principalId: '11111111-1111-4111-9111-111111111111',
    });
    expect(fetch).toHaveBeenCalledWith(`${origin}/auth/v1/user`, {
      method: 'GET',
      redirect: 'error',
      headers: {
        Accept: 'application/json',
        Authorization: ['Bearer', token].join(' '),
        apikey: 'sb_publishable_key',
      },
      signal: expect.any(AbortSignal),
    });
  });

  it('fails closed when Auth rejects or returns a malformed principal', async () => {
    for (const [body, status, code] of [
      ['{}', 401, 'FIXED_CLIENT_INVALID_CREDENTIAL'],
      ['{"id":"not-a-uuid","aud":"authenticated"}', 200, 'FIXED_CLIENT_MALFORMED_RESPONSE'],
      [
        '{"id":"11111111-1111-4111-9111-111111111111","aud":"unexpected"}',
        200,
        'FIXED_CLIENT_MALFORMED_RESPONSE',
      ],
    ] as const) {
      const client = createFixedSupabaseClient({
        origin,
        credentials: { projectPublishableKey: 'sb_publishable_key', userAccessToken: token },
        fetch: vi.fn<typeof globalThis.fetch>().mockResolvedValue(response(body, status)),
      });
      await expect(client.verifyUserIdentity()).rejects.toMatchObject({ code });
    }
  });

  it('rejects redirected Auth identity responses even from a custom fetch', async () => {
    const redirected = response(
      '{"id":"11111111-1111-4111-9111-111111111111","aud":"authenticated"}',
    );
    Object.defineProperties(redirected, {
      redirected: { value: true },
      url: { value: 'https://evil.invalid/auth/v1/user' },
    });
    const client = createFixedSupabaseClient({
      origin,
      credentials: { projectPublishableKey: 'sb_publishable_key', userAccessToken: token },
      fetch: vi.fn<typeof globalThis.fetch>().mockResolvedValue(redirected),
    });
    await expect(client.verifyUserIdentity()).rejects.toMatchObject({
      code: 'FIXED_CLIENT_INVALID_CREDENTIAL',
    });
  });

  it('makes only the fixed search RPC with JWT, schema, fields, and bounded arguments', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(response('{"rows":[]}'));
    const client = createFixedSupabaseClient({
      origin,
      credentials: { projectPublishableKey: 'sb_publishable_key', userAccessToken: token },
      fetch,
    });
    const signal = new AbortController().signal;
    await client.searchMemoryRows(
      {
        query: 'needle',
        mode: 'semantic',
        filters: { tags: ['safe'] },
        limit: 7,
        cursor: 'cur_12345678901234567890',
      },
      signal,
    );
    const [url, init] = fetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${origin}/rest/v1/rpc/authorized_memory_search_v1`);
    expect(init).toMatchObject({
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'Accept-Profile': 'memory',
        'Content-Profile': 'memory',
        Authorization: `Bearer ${token}`,
        apikey: 'sb_publishable_key',
      },
      body: JSON.stringify({
        query: 'needle',
        mode: 'semantic',
        filters: { tags: ['safe'] },
        limit: 7,
        cursor: 'cur_12345678901234567890',
      }),
    });
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it('rejects runtime override attempts before fetch', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    const client = createFixedSupabaseClient({
      origin,
      credentials: { projectPublishableKey: 'key', userAccessToken: token },
      fetch,
    });
    await expect(
      (client.searchMemoryRows as (input: unknown) => Promise<unknown>)({
        query: 'x',
        origin: 'https://evil.invalid',
        rpc: 'steal',
        schema: 'private',
        limit: 100,
      }),
    ).rejects.toMatchObject({ code: 'FIXED_CLIENT_INVALID_REQUEST' });
    expect(fetch).not.toHaveBeenCalled();
  });

  it('rejects invalid cursors, excess rows, and non-allowlisted response fields', async () => {
    const credentials = { projectPublishableKey: 'key', userAccessToken: token };
    const input = { query: 'x', mode: 'text' as const, limit: 1 };
    for (const [body, status, code] of [
      ['{}', 400, 'FIXED_CLIENT_INVALID_CURSOR'],
      ['{"rows":[{"id":"a"},{"id":"b"}]}', 200, 'FIXED_CLIENT_MALFORMED_RESPONSE'],
      [
        '{"rows":[{"id":"a","title":"t","content":"c","createdAt":"2026-08-23T12:00:00.000Z","provenanceSummary":"p","rank":1,"ownerId":"hidden"}]}',
        200,
        'FIXED_CLIENT_MALFORMED_RESPONSE',
      ],
    ] as const) {
      const client = createFixedSupabaseClient({
        origin,
        credentials,
        fetch: vi.fn().mockResolvedValue(response(body, status)),
      });
      await expect(client.searchMemoryRows(input)).rejects.toMatchObject({ code });
    }
  });

  it('keeps the timeout active while consuming a stalled search response body', async () => {
    vi.useFakeTimers();
    const fetch = vi.fn((_url: string | URL | Request, init?: RequestInit) =>
      Promise.resolve(
        new Response(
          new ReadableStream({
            start(controller) {
              init?.signal?.addEventListener('abort', () =>
                controller.error(new DOMException('aborted', 'AbortError')),
              );
            },
          }),
        ),
      ),
    );
    const client = createFixedSupabaseClient({
      origin,
      credentials: { projectPublishableKey: 'key', userAccessToken: token },
      fetch,
      timeoutMs: 25,
    });
    const pending = client.searchMemoryRows({ query: 'x', mode: 'text', limit: 1 });
    const assertion = expect(pending).rejects.toMatchObject({ code: 'FIXED_CLIENT_TIMEOUT' });
    await vi.advanceTimersByTimeAsync(25);
    await assertion;
    vi.useRealTimers();
  });

  it('makes only the fixed bounded identity-preserving read', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(response('[{"id":"one"}]'));
    const client = createFixedSupabaseClient({
      origin,
      credentials: { projectPublishableKey: 'sb_publishable_key', userAccessToken: token },
      fetch,
      timeoutMs: 250,
      maxResponseBytes: 128,
    });

    await expect(client.listMemoryRows()).resolves.toEqual([{ id: 'one' }]);
    expect(fetch).toHaveBeenCalledOnce();
    const [url, init] = fetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${origin}/rest/v1/memories?select=id%2Ccontent&limit=100`);
    expect(init.method).toBe('GET');
    expect(init.headers).toEqual({
      Accept: 'application/json',
      'Accept-Profile': 'memory',
      Authorization: `Bearer ${token}`,
      apikey: 'sb_publishable_key',
    });
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it('offers no caller override surface and preserves the configured identity', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(response('[]'));
    const client = createFixedSupabaseClient({
      origin,
      credentials: { projectPublishableKey: 'publishable', userAccessToken: token },
      fetch,
    });
    expect(Object.keys(client)).toEqual([
      'verifyUserIdentity',
      'listMemoryRows',
      'searchMemoryRows',
      'getMemoryRow',
      'listRecentMemoryRows',
    ]);
    // Runtime hostile callers cannot smuggle origin, headers, method, or another identity.
    await (client.listMemoryRows as (value?: unknown) => Promise<unknown>)({
      origin: 'https://evil.invalid',
      method: 'DELETE',
      Authorization: 'Bearer attacker',
    });
    expect(fetch.mock.calls[0]?.[0]).toBe(
      `${origin}/rest/v1/memories?select=id%2Ccontent&limit=100`,
    );
    expect(fetch.mock.calls[0]?.[1]?.headers).toMatchObject({ Authorization: `Bearer ${token}` });
  });

  it('calls authorized get RPC with a fixed method, profile, and allowlisted body', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      response(
        JSON.stringify({
          record: {
            id: 'mem_ABCDEFGHIJKLMNOPQRSTUV',
            title: 'Visible memory',
            content: 'Synthetic',
            createdAt: '2026-08-24T12:00:00.000Z',
            provenanceSummary: 'synthetic fixture',
          },
        }),
      ),
    );
    const client = createFixedSupabaseClient({
      origin,
      credentials: { projectPublishableKey: 'key', userAccessToken: token },
      fetch,
    });

    await expect(client.getMemoryRow({ id: 'mem_ABCDEFGHIJKLMNOPQRSTUV' })).resolves.toMatchObject({
      id: 'mem_ABCDEFGHIJKLMNOPQRSTUV',
      title: 'Visible memory',
    });
    expect(fetch).toHaveBeenCalledOnce();
    const [url, init] = fetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${origin}/rest/v1/rpc/authorized_memory_get_v1`);
    expect(init.method).toBe('POST');
    expect(init.headers).toMatchObject({
      Accept: 'application/json',
      'Accept-Profile': 'memory',
      'Content-Profile': 'memory',
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      apikey: 'key',
    });
    expect(JSON.parse(init.body as string)).toEqual({ id: 'mem_ABCDEFGHIJKLMNOPQRSTUV' });
  });

  it('calls list-recent RPC with fixed envelope, pagination, and allowlisted rows', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      response(
        JSON.stringify({
          rows: [
            {
              id: 'mem_ABCDEFGHIJKLMNOPQRSTUV',
              title: 'Visible memory',
              content: 'Synthetic',
              createdAt: '2026-08-24T12:00:00.000Z',
              provenanceSummary: 'synthetic fixture',
            },
          ],
          nextCursor: 'cur_XXXXXXXXXXXXXXXXXX',
        }),
      ),
    );
    const client = createFixedSupabaseClient({
      origin,
      credentials: { projectPublishableKey: 'key', userAccessToken: token },
      fetch,
    });

    await expect(
      client.listRecentMemoryRows({
        filters: { tags: ['safe'] },
        limit: 1,
        cursor: 'cur_ABCDEFGHIJKLMNOPQRST',
      }),
    ).resolves.toMatchObject({
      rows: [{ id: 'mem_ABCDEFGHIJKLMNOPQRSTUV' }],
      nextCursor: 'cur_XXXXXXXXXXXXXXXXXX',
    });
    expect(fetch).toHaveBeenCalledOnce();
    const [url, init] = fetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${origin}/rest/v1/rpc/authorized_memory_list_recent_v1`);
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({
      filters: { tags: ['safe'] },
      limit: 1,
      cursor: 'cur_ABCDEFGHIJKLMNOPQRST',
    });
  });

  it('maps malformed get/list envelopes to fixed client malformed failures', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(response('{"record":null}'));
    const client = createFixedSupabaseClient({
      origin,
      credentials: { projectPublishableKey: 'key', userAccessToken: token },
      fetch,
    });
    await expect(client.getMemoryRow({ id: 'mem_ABCDEFGHIJKLMNOPQRSTUV' })).resolves.toBeNull();

    const missingRecord = createFixedSupabaseClient({
      origin,
      credentials: { projectPublishableKey: 'key', userAccessToken: token },
      fetch: vi.fn<typeof globalThis.fetch>().mockResolvedValue(response('{}')),
    });
    await expect(
      missingRecord.getMemoryRow({ id: 'mem_ABCDEFGHIJKLMNOPQRSTUV' }),
    ).rejects.toMatchObject({ code: 'FIXED_CLIENT_MALFORMED_RESPONSE' });

    const missingColumn = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      response(
        JSON.stringify({
          rows: [
            {
              id: 'mem_ABCDEFGHIJKLMNOPQRSTUV',
              title: 'Visible memory',
              content: 'Synthetic',
              createdAt: '2026-08-24T12:00:00.000Z',
              ownerId: 'hidden',
            },
          ],
        }),
      ),
    );
    const malformedListClient = createFixedSupabaseClient({
      origin,
      credentials: { projectPublishableKey: 'key', userAccessToken: token },
      fetch: missingColumn,
    });

    await expect(malformedListClient.listRecentMemoryRows({ limit: 1 })).rejects.toMatchObject({
      code: 'FIXED_CLIENT_MALFORMED_RESPONSE',
    });
  });

  it.each([
    [
      'invalid credential',
      {
        origin: 'http://project-ref.supabase.co',
        credentials: { projectPublishableKey: 'key', userAccessToken: token },
      },
      'FIXED_CLIENT_INVALID_CREDENTIAL',
    ],
    [
      'invalid identity',
      { origin, credentials: { projectPublishableKey: token, userAccessToken: token } },
      'FIXED_CLIENT_INVALID_CREDENTIAL',
    ],
  ])('rejects %s configuration', (_name, config, code) => {
    expect(() => createFixedSupabaseClient({ ...config, fetch: vi.fn() })).toThrowError(
      expect.objectContaining({ code }),
    );
  });

  it('returns typed secret-free failures for upstream failure classes', async () => {
    const cases: Array<[string, typeof globalThis.fetch, string]> = [
      [
        'network',
        vi.fn().mockRejectedValue(new Error(`leak ${token}`)),
        'FIXED_CLIENT_NETWORK_FAILURE',
      ],
      [
        'non-2xx',
        vi.fn().mockResolvedValue(response(`{"secret":"${token}"}`, 403)),
        'FIXED_CLIENT_UPSTREAM_STATUS',
      ],
      ['json', vi.fn().mockResolvedValue(response('{')), 'FIXED_CLIENT_MALFORMED_RESPONSE'],
      ['envelope', vi.fn().mockResolvedValue(response('{}')), 'FIXED_CLIENT_MALFORMED_RESPONSE'],
      [
        'oversized',
        vi.fn().mockResolvedValue(response('[]'.padEnd(129, ' '))),
        'FIXED_CLIENT_RESPONSE_TOO_LARGE',
      ],
    ];
    for (const [, fetch, code] of cases) {
      const client = createFixedSupabaseClient({
        origin,
        credentials: { projectPublishableKey: 'key', userAccessToken: token },
        fetch,
        maxResponseBytes: 128,
      });
      await expect(client.listMemoryRows()).rejects.toSatisfy((error: unknown) => {
        expect(error).toBeInstanceOf(FixedSupabaseClientError);
        expect(error).toMatchObject({ code, message: code });
        expect(JSON.stringify(error)).not.toContain(token);
        return true;
      });
    }
  });

  it('aborts at the bounded timeout', async () => {
    vi.useFakeTimers();
    const fetch = vi.fn(
      (_url: string | URL | Request, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) =>
          init?.signal?.addEventListener('abort', () =>
            reject(new DOMException('aborted', 'AbortError')),
          ),
        ),
    );
    const client = createFixedSupabaseClient({
      origin,
      credentials: { projectPublishableKey: 'key', userAccessToken: token },
      fetch,
      timeoutMs: 25,
    });
    const pending = client.listMemoryRows();
    const assertion = expect(pending).rejects.toMatchObject({ code: 'FIXED_CLIENT_TIMEOUT' });
    await vi.advanceTimersByTimeAsync(25);
    await assertion;
    vi.useRealTimers();
  });

  it('keeps the timeout active while consuming a stalled response body', async () => {
    vi.useFakeTimers();
    const fetch = vi.fn((_url: string | URL | Request, init?: RequestInit) =>
      Promise.resolve(
        new Response(
          new ReadableStream({
            start(controller) {
              init?.signal?.addEventListener('abort', () =>
                controller.error(new DOMException('aborted', 'AbortError')),
              );
            },
          }),
        ),
      ),
    );
    const client = createFixedSupabaseClient({
      origin,
      credentials: { projectPublishableKey: 'key', userAccessToken: token },
      fetch,
      timeoutMs: 25,
    });
    const pending = client.listMemoryRows();
    const assertion = expect(pending).rejects.toMatchObject({ code: 'FIXED_CLIENT_TIMEOUT' });
    await vi.advanceTimersByTimeAsync(25);
    await assertion;
    vi.useRealTimers();
  });
});
