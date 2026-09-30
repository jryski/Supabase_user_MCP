import { describe, expect, it } from 'vitest';

import {
  classifySourceSessionLiveness,
  probeSourceSessionLive,
  SOURCE_SESSION_LIVENESS_RPC,
} from './source-session-liveness.js';

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

  it('classifies false, auth denial, service error, malformed JSON, timeout, and bad input', async () => {
    const cases: Array<{
      response?: Response;
      hang?: boolean;
      input?: { accessToken: string; sourceSessionId: string; aClientId: string };
      category: string;
      httpStatus?: number;
    }> = [
      { response: new Response('false', { status: 200 }), category: 'false', httpStatus: 200 },
      {
        response: new Response('{"live":true}', { status: 200 }),
        category: 'malformed_response',
        httpStatus: 200,
      },
      {
        response: new Response('not-json', { status: 200 }),
        category: 'malformed_response',
        httpStatus: 200,
      },
      {
        response: new Response('{"message":"secret-body"}', { status: 401 }),
        category: 'auth_denial',
        httpStatus: 401,
      },
      {
        response: new Response('{"message":"secret-body"}', { status: 500 }),
        category: 'service_error',
        httpStatus: 500,
      },
      {
        response: new Response('{"message":"secret-body"}', { status: 400 }),
        category: 'rpc_validation',
        httpStatus: 400,
      },
    ];
    for (const item of cases) {
      const result = await classifySourceSessionLiveness(
        {
          supabaseUrl: ORIGIN,
          publishableKey: 'sb_publishable_test',
          fetch: async () => item.response ?? new Response('true'),
        },
        item.input ?? { accessToken: TOKEN_B, sourceSessionId: SOURCE, aClientId: A_CLIENT },
      );
      expect(result.live).toBe(false);
      expect(result.category).toBe(item.category);
      expect(result.httpStatus).toBe(item.httpStatus);
      expect(JSON.stringify(result)).not.toContain('secret-body');
    }

    const timed = await classifySourceSessionLiveness(
      {
        supabaseUrl: ORIGIN,
        publishableKey: 'sb_publishable_test',
        timeoutMs: 20,
        fetch: (_input, init) =>
          new Promise((_resolve, reject) => {
            init?.signal?.addEventListener('abort', () => {
              reject(new DOMException('aborted', 'AbortError'));
            });
          }),
      },
      { accessToken: TOKEN_B, sourceSessionId: SOURCE, aClientId: A_CLIENT },
    );
    expect(timed).toEqual({ live: false, category: 'timeout' });

    const skipped = await classifySourceSessionLiveness(
      {
        supabaseUrl: ORIGIN,
        publishableKey: 'sb_publishable_test',
        fetch: async () => new Response('true'),
      },
      { accessToken: TOKEN_B, sourceSessionId: SOURCE, aClientId: '' },
    );
    expect(skipped).toEqual({ live: false, category: 'rpc_validation' });
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
