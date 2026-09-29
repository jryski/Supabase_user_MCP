import { ACCESS_TOKEN_REVOCATION_LATENCY_BOUND_MS } from '@supabase-user-mcp/contracts';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { createGoTrueSessionRevocationAuthority } from './gotrue-revocation-authority.js';

const ORIGIN = 'https://m2-loopback.invalid';
const PUBLISHABLE_KEY = 'sb_publishable_issue63_probe_key';
const ACCESS_TOKEN = 'eyJhbGciOiJIUzI1NiJ9.issue63_access_probe.signature';

function inspectInput() {
  return {
    sessionId: '11111111-1111-4111-8111-111111111111',
    tokenFingerprint: 'abc',
    nowMs: Date.now(),
    accessToken: ACCESS_TOKEN,
  };
}

function assertNoSecretLeakage(captured: readonly string[]) {
  const blob = captured.join('\0');
  expect(blob).not.toContain(ACCESS_TOKEN);
  expect(blob).not.toContain(PUBLISHABLE_KEY);
}

describe('GoTrue session revocation authority', () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('treats 401 as revoked and 200 as active without caching', async () => {
    const calls: string[] = [];
    const authority = createGoTrueSessionRevocationAuthority({
      origin: ORIGIN,
      publishableKey: PUBLISHABLE_KEY,
      fetch: async (input) => {
        const url = typeof input === 'string' || input instanceof URL ? String(input) : input.url;
        calls.push(url);
        const status = calls.length === 1 ? 200 : 401;
        return new Response(
          status === 200 ? '{"id":"11111111-1111-4111-9111-111111111111"}' : '{}',
          {
            status,
          },
        );
      },
    });
    const inspect = inspectInput();
    await expect(authority.inspectAccessToken(inspect)).resolves.toBe('active');
    await expect(authority.inspectAccessToken(inspect)).resolves.toBe('revoked');
    expect(calls).toHaveLength(2);
  });

  it('aborts a pending fetch at the revocation latency bound and resolves revoked', async () => {
    vi.useFakeTimers();
    const leakage: string[] = [];
    const authority = createGoTrueSessionRevocationAuthority({
      origin: ORIGIN,
      publishableKey: PUBLISHABLE_KEY,
      fetch: (_url, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => {
            const error = new DOMException('The operation was aborted', 'AbortError');
            leakage.push(error.message);
            reject(error);
          });
        }),
    });

    const pending = authority.inspectAccessToken(inspectInput());
    await vi.advanceTimersByTimeAsync(ACCESS_TOKEN_REVOCATION_LATENCY_BOUND_MS);
    await expect(pending).resolves.toBe('revoked');
    assertNoSecretLeakage(leakage);
  });

  it('clears timeout resources after success and failure without wall-clock sleeps', async () => {
    const clearTimeoutSpy = vi.spyOn(globalThis, 'clearTimeout');
    const setTimeoutSpy = vi.spyOn(globalThis, 'setTimeout');

    const successAuthority = createGoTrueSessionRevocationAuthority({
      origin: ORIGIN,
      publishableKey: PUBLISHABLE_KEY,
      fetch: async () =>
        new Response('{"id":"11111111-1111-4111-9111-111111111111"}', { status: 200 }),
    });
    await expect(successAuthority.inspectAccessToken(inspectInput())).resolves.toBe('active');
    const successTimer = setTimeoutSpy.mock.results.at(-1)?.value;
    expect(clearTimeoutSpy).toHaveBeenCalledWith(successTimer);

    clearTimeoutSpy.mockClear();
    setTimeoutSpy.mockClear();

    const failureAuthority = createGoTrueSessionRevocationAuthority({
      origin: ORIGIN,
      publishableKey: PUBLISHABLE_KEY,
      fetch: async () => new Response('{}', { status: 403 }),
    });
    await expect(failureAuthority.inspectAccessToken(inspectInput())).resolves.toBe('revoked');
    const failureTimer = setTimeoutSpy.mock.results.at(-1)?.value;
    expect(clearTimeoutSpy).toHaveBeenCalledWith(failureTimer);
  });

  it('issues exactly the bounded GoTrue user probe with redirect error and scoped credentials', async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(
        new Response('{"id":"11111111-1111-4111-9111-111111111111"}', { status: 200 }),
      );
    const authority = createGoTrueSessionRevocationAuthority({
      origin: ORIGIN,
      publishableKey: PUBLISHABLE_KEY,
      fetch,
    });

    await expect(authority.inspectAccessToken(inspectInput())).resolves.toBe('active');
    expect(fetch).toHaveBeenCalledOnce();
    const [url, init] = fetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${ORIGIN}/auth/v1/user`);
    expect(init.method).toBe('GET');
    expect(init.redirect).toBe('error');
    expect(init.headers).toEqual({
      Accept: 'application/json',
      Authorization: `Bearer ${ACCESS_TOKEN}`,
      apikey: PUBLISHABLE_KEY,
    });
    const headerBlob = JSON.stringify(init.headers);
    expect(headerBlob.match(/Bearer/g)?.length).toBe(1);
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it('fails closed on redirect-shaped, forbidden, and server-error responses while 200 stays active', async () => {
    const cases: Array<{ label: string; response: Response; expected: 'active' | 'revoked' }> = [
      {
        label: 'redirect-shaped',
        response: {
          redirected: true,
          status: 200,
          ok: true,
          clone: () => ({ text: async () => '{}' }),
        } as Response,
        expected: 'revoked',
      },
      {
        label: '403',
        response: new Response('{}', { status: 403 }),
        expected: 'revoked',
      },
      {
        label: '5xx',
        response: new Response('{}', { status: 503 }),
        expected: 'revoked',
      },
      {
        label: '200',
        response: new Response('{"id":"11111111-1111-4111-9111-111111111111"}', { status: 200 }),
        expected: 'active',
      },
    ];

    for (const { response, expected } of cases) {
      const leakage: string[] = [];
      const authority = createGoTrueSessionRevocationAuthority({
        origin: ORIGIN,
        publishableKey: PUBLISHABLE_KEY,
        fetch: async () => {
          leakage.push(await response.clone().text());
          return response;
        },
      });
      await expect(authority.inspectAccessToken(inspectInput())).resolves.toBe(expected);
      assertNoSecretLeakage(leakage);
    }
  });

  it('never exposes access token or publishable key in captured response or error material', async () => {
    const leakage: string[] = [];
    const authority = createGoTrueSessionRevocationAuthority({
      origin: ORIGIN,
      publishableKey: PUBLISHABLE_KEY,
      fetch: async () => {
        throw new Error('synthetic upstream failure without credential echo');
      },
    });

    const verdict = await authority.inspectAccessToken(inspectInput());
    expect(verdict).toBe('revoked');
    leakage.push(verdict);
    assertNoSecretLeakage(leakage);
  });
});
