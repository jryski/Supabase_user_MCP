import { describe, expect, it } from 'vitest';

import { probeSourceSessionLive, SOURCE_SESSION_LIVENESS_RPC } from './source-session-liveness.js';

const ORIGIN = 'https://project.loopback.invalid';
const TOKEN_B = 'aaa.bbb.ccc';
const TOKEN_A = 'ddd.eee.fff';
const SOURCE = '22222222-2222-4222-8222-222222222222';
const A_CLIENT = 'smp-lab-inspector';

describe('source session liveness caller', () => {
  it('posts Token B and accepts only JSON true', async () => {
    const calls: Array<{ url: string; init: RequestInit | undefined }> = [];
    const fetchImpl: typeof fetch = async (input, init) => {
      calls.push({ url: String(input), init });
      return new Response('true', { status: 200, headers: { 'content-type': 'application/json' } });
    };
    const live = await probeSourceSessionLive(
      { supabaseUrl: ORIGIN, publishableKey: 'sb_publishable_test', fetch: fetchImpl },
      { accessToken: TOKEN_B, sourceSessionId: SOURCE, aClientId: A_CLIENT },
    );
    expect(live).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe(`${ORIGIN}/rest/v1/rpc/${SOURCE_SESSION_LIVENESS_RPC}`);
    expect(calls[0]?.init?.method).toBe('POST');
    const headers = new Headers(calls[0]?.init?.headers);
    expect(headers.get('authorization')).toBe(`Bearer ${TOKEN_B}`);
    expect(headers.get('authorization')).not.toContain(TOKEN_A);
    expect(JSON.parse(String(calls[0]?.init?.body))).toEqual({
      source_session_id: SOURCE,
      a_client_id: A_CLIENT,
    });
  });

  it('fails closed on false, non-boolean, HTTP errors, timeout, and null inputs', async () => {
    const responses = [
      new Response('false', { status: 200 }),
      new Response('{"live":true}', { status: 200 }),
      new Response('no', { status: 500 }),
    ];
    for (const response of responses) {
      const live = await probeSourceSessionLive(
        {
          supabaseUrl: ORIGIN,
          publishableKey: 'sb_publishable_test',
          fetch: async () => response,
        },
        { accessToken: TOKEN_B, sourceSessionId: SOURCE, aClientId: A_CLIENT },
      );
      expect(live).toBe(false);
    }

    let fetches = 0;
    const timed = await probeSourceSessionLive(
      {
        supabaseUrl: ORIGIN,
        publishableKey: 'sb_publishable_test',
        timeoutMs: 20,
        fetch: (_input, init) =>
          new Promise((_resolve, reject) => {
            fetches += 1;
            init?.signal?.addEventListener('abort', () => {
              reject(new DOMException('aborted', 'AbortError'));
            });
          }),
      },
      { accessToken: TOKEN_B, sourceSessionId: SOURCE, aClientId: A_CLIENT },
    );
    expect(timed).toBe(false);
    expect(fetches).toBe(1);

    const skipped = await probeSourceSessionLive(
      {
        supabaseUrl: ORIGIN,
        publishableKey: 'sb_publishable_test',
        fetch: async () => {
          fetches += 1;
          return new Response('true');
        },
      },
      { accessToken: TOKEN_B, sourceSessionId: SOURCE, aClientId: '' },
    );
    expect(skipped).toBe(false);
    expect(fetches).toBe(1);
  });

  it('allows http only for a loopback origin', async () => {
    let fetches = 0;
    const fetchImpl: typeof fetch = async (input) => {
      fetches += 1;
      expect(String(input)).toBe(
        `http://127.0.0.1:54321/rest/v1/rpc/${SOURCE_SESSION_LIVENESS_RPC}`,
      );
      return new Response('true', { status: 200 });
    };
    const cleartext = await probeSourceSessionLive(
      {
        supabaseUrl: 'http://project.loopback.invalid',
        publishableKey: 'sb_publishable_test',
        fetch: fetchImpl,
      },
      { accessToken: TOKEN_B, sourceSessionId: SOURCE, aClientId: A_CLIENT },
    );
    expect(cleartext).toBe(false);
    expect(fetches).toBe(0);
    const loopback = await probeSourceSessionLive(
      {
        supabaseUrl: 'http://127.0.0.1:54321',
        publishableKey: 'sb_publishable_test',
        fetch: fetchImpl,
      },
      { accessToken: TOKEN_B, sourceSessionId: SOURCE, aClientId: A_CLIENT },
    );
    expect(loopback).toBe(true);
    expect(fetches).toBe(1);
  });
});
