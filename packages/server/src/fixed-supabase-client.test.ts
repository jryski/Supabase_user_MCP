import { describe, expect, it, vi } from 'vitest';
import { createFixedSupabaseClient, FixedSupabaseClientError } from './fixed-supabase-client.js';

const origin = 'https://project-ref.supabase.co';
const token = 'header.user-identity.signature';

function response(body: string, status = 200): Response {
  return new Response(body, { status, headers: { 'content-type': 'application/json' } });
}

describe('createFixedSupabaseClient', () => {
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
    expect(Object.keys(client)).toEqual(['listMemoryRows']);
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
});
