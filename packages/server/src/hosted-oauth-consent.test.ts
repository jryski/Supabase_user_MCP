import { describe, expect, it, vi } from 'vitest';
import {
  createHostedOAuthConsentHandler,
  HOSTED_CONSENT_DEADLINE_MS,
  type HostedConsentChallenge,
  type HostedConsentChallengeStore,
} from './hosted-oauth-consent.js';
import type { OAuthConsentApi } from './oauth-consent.js';

const ORIGIN = 'https://portal.example.test';
const ROUTE = `${ORIGIN}/oauth/consent`;
const USER = '11111111-1111-4111-8111-111111111111';
const OTHER = '22222222-2222-4222-8222-222222222222';
const CLIENT = '33333333-3333-4333-8333-333333333333';
const REDIRECT = 'https://client.example.test/callback';
const AUTH_ID = 'pending-authorization';

function fixture() {
  let time = 1000;
  let userId = USER;
  let sessionId = 'opaque-host-session';
  let signedIn = true;
  let upstream: unknown = {
    authorization_id: AUTH_ID,
    client: { id: CLIENT, name: 'My client' },
    user: { id: USER },
    redirect_uri: REDIRECT,
    scope: 'openid email',
  };
  const get = vi.fn(async () => ({ data: upstream, error: null }));
  const approve = vi.fn(async () => ({
    data: { redirect_url: `${REDIRECT}?code=one&state=original` },
    error: null,
  }));
  const deny = vi.fn(async () => ({
    data: { redirect_url: `${REDIRECT}?error=access_denied&state=original` },
    error: null,
  }));
  const oauth = {
    getAuthorizationDetails: get,
    approveAuthorization: approve,
    denyAuthorization: deny,
  } as unknown as OAuthConsentApi;
  const entries = new Map<string, HostedConsentChallenge>();
  const challenges: HostedConsentChallengeStore = {
    async putIfAbsent(nonce, challenge) {
      if (entries.has(nonce)) return false;
      entries.set(nonce, challenge);
      return true;
    },
    async take(nonce) {
      const entry = entries.get(nonce);
      entries.delete(nonce);
      return entry;
    },
  };
  const handler = createHostedOAuthConsentHandler({
    routeUrl: ROUTE,
    binding: {
      expectedClientId: CLIENT,
      redirectUris: [REDIRECT],
      allowedScopes: ['openid', 'email'],
    },
    challenges,
    getVerifiedSession: async () => (signedIn ? { userId, sessionId, oauth } : undefined),
    now: () => time,
  });
  const load = () => handler(new Request(`${ROUTE}?authorization_id=${AUTH_ID}`));
  const submit = (nonce: string, decision = 'approve', headers: Record<string, string> = {}) =>
    handler(
      new Request(ROUTE, {
        method: 'POST',
        headers: {
          origin: ORIGIN,
          'content-type': 'application/x-www-form-urlencoded',
          ...headers,
        },
        body: new URLSearchParams({ nonce, decision }),
      }),
    );
  async function form() {
    const response = await load();
    const html = await response.text();
    return {
      response,
      html,
      nonce: /name="nonce" value="([A-Za-z0-9_-]+)"/u.exec(html)?.[1] ?? '',
    };
  }
  return {
    handler,
    load,
    submit,
    form,
    entries,
    get,
    approve,
    deny,
    setUser: (id: string) => {
      userId = id;
    },
    setSession: (id: string) => {
      sessionId = id;
    },
    setSignedIn: (value: boolean) => {
      signedIn = value;
    },
    setUpstream: (value: unknown) => {
      upstream = value;
    },
    expire: () => {
      time += 5 * 60_000;
    },
  };
}

describe('hosted own-account consent route', () => {
  it.each([
    'https://client.example.test/callback',
    'http://127.0.0.1:8765/callback',
    'http://localhost:8765/callback',
    'http://[::1]:8765/callback',
  ])('supports the existing registered callback transport %s', (callback) => {
    expect(() =>
      createHostedOAuthConsentHandler({
        routeUrl: ROUTE,
        binding: { expectedClientId: CLIENT, redirectUris: [callback], allowedScopes: ['openid'] },
        getVerifiedSession: async () => undefined,
        challenges: { putIfAbsent: async () => false, take: async () => undefined },
      }),
    ).not.toThrow();
  });

  it.each([
    'http://client.example.test/callback',
    'http://127.0.0.1.attacker.example.test/callback',
    'http://localhost.attacker.example.test/callback',
    'http://[::ffff:127.0.0.1]/callback',
  ])('refuses unencrypted nonloopback and lookalike callback %s', (callback) => {
    expect(() =>
      createHostedOAuthConsentHandler({
        routeUrl: ROUTE,
        binding: { expectedClientId: CLIENT, redirectUris: [callback], allowedScopes: ['openid'] },
        getVerifiedSession: async () => undefined,
        challenges: { putIfAbsent: async () => false, take: async () => undefined },
      }),
    ).toThrow();
  });

  it.each([undefined, null, {}, '', '   '])(
    'refuses missing, malformed or empty upstream scope %j',
    async (scope) => {
      const f = fixture();
      f.setUpstream({
        authorization_id: AUTH_ID,
        client: { id: CLIENT, name: 'My client' },
        user: { id: USER },
        redirect_uri: REDIRECT,
        scope,
      });
      expect((await f.load()).status).toBe(403);
      expect(f.entries.size).toBe(0);
      expect(f.approve).not.toHaveBeenCalled();
    },
  );

  it('bounds a stalled body even when the stream cancel hook never resolves', async () => {
    vi.useFakeTimers();
    try {
      const f = fixture();
      const cancel = vi.fn(() => new Promise<void>(() => {}));
      const body = new ReadableStream<Uint8Array>({ cancel });
      const request = new Request(ROUTE, {
        method: 'POST',
        headers: { origin: ORIGIN, 'content-type': 'application/x-www-form-urlencoded' },
        body,
        duplex: 'half',
      } as RequestInit);
      const operation = f.handler(request);
      await vi.advanceTimersByTimeAsync(HOSTED_CONSENT_DEADLINE_MS);
      const result = await operation;
      expect(result.status).toBe(503);
      expect(result.headers.get('cache-control')).toBe('no-store');
      expect(cancel).toHaveBeenCalledOnce();
      expect(f.approve).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it('bounds stalled verification and suppresses work from a late session result', async () => {
    vi.useFakeTimers();
    try {
      let finish: ((value: undefined) => void) | undefined;
      let seenSignal: AbortSignal | undefined;
      const putIfAbsent = vi.fn(async () => true);
      const handler = createHostedOAuthConsentHandler({
        routeUrl: ROUTE,
        binding: { expectedClientId: CLIENT, redirectUris: [REDIRECT], allowedScopes: ['openid'] },
        getVerifiedSession: (_request, signal) => {
          seenSignal = signal;
          return new Promise((resolve) => {
            finish = resolve;
          });
        },
        challenges: { putIfAbsent, take: async () => undefined },
      });
      const operation = handler(new Request(`${ROUTE}?authorization_id=${AUTH_ID}`));
      await vi.advanceTimersByTimeAsync(HOSTED_CONSENT_DEADLINE_MS);
      expect((await operation).status).toBe(503);
      expect(seenSignal?.aborted).toBe(true);
      finish?.(undefined);
      await vi.advanceTimersByTimeAsync(0);
      expect(putIfAbsent).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it('does not approve after an ignored upstream read completes beyond the deadline', async () => {
    vi.useFakeTimers();
    try {
      const f = fixture();
      const { nonce } = await f.form();
      let finish: ((value: { data: unknown; error: null }) => void) | undefined;
      f.get.mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            finish = resolve;
          }),
      );
      const operation = f.submit(nonce);
      await vi.advanceTimersByTimeAsync(HOSTED_CONSENT_DEADLINE_MS);
      expect((await operation).status).toBe(503);
      finish?.({
        data: {
          authorization_id: AUTH_ID,
          client: { id: CLIENT, name: 'My client' },
          user: { id: USER },
          redirect_uri: REDIRECT,
          scope: 'openid email',
        },
        error: null,
      });
      await vi.advanceTimersByTimeAsync(0);
      expect(f.approve).not.toHaveBeenCalled();
      expect(f.entries.has(nonce)).toBe(false);
      expect((await f.submit(nonce)).status).toBe(409);
    } finally {
      vi.useRealTimers();
    }
  });

  it('honors caller cancellation before any consent dispatch', async () => {
    const f = fixture();
    const { nonce } = await f.form();
    const controller = new AbortController();
    controller.abort();
    const result = await f.handler(
      new Request(ROUTE, {
        method: 'POST',
        signal: controller.signal,
        headers: { origin: ORIGIN, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ nonce, decision: 'approve' }),
      }),
    );
    expect(result.status).toBe(503);
    expect(f.approve).not.toHaveBeenCalled();
  });

  it('renders exact client, scope and redirect; approves only explicit same-origin form', async () => {
    const f = fixture();
    const { response, html, nonce } = await f.form();
    expect(response.status).toBe(200);
    expect(html).toContain(CLIENT);
    expect(html).toContain('openid, email');
    expect(html).toContain(REDIRECT);
    expect(nonce).toHaveLength(43);
    expect(f.approve).not.toHaveBeenCalled();
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
    const completed = await f.submit(nonce);
    expect(completed.status).toBe(303);
    expect(completed.headers.get('location')).toBe(`${REDIRECT}?code=one&state=original`);
    expect(f.approve).toHaveBeenCalledExactlyOnceWith(AUTH_ID, { skipBrowserRedirect: true });
    expect(f.deny).not.toHaveBeenCalled();
  });

  it('allows explicit denial without approving', async () => {
    const f = fixture();
    expect((await f.submit((await f.form()).nonce, 'deny')).status).toBe(303);
    expect(f.deny).toHaveBeenCalledExactlyOnceWith(AUTH_ID, { skipBrowserRedirect: true });
    expect(f.approve).not.toHaveBeenCalled();
  });

  it.each([OTHER, USER])(
    'binds the rendered form to its exact account and session (%s)',
    async (id) => {
      const f = fixture();
      const { nonce } = await f.form();
      f.setUser(id);
      if (id === USER) f.setSession('different-verified-session');
      expect((await f.submit(nonce)).status).toBe(409);
      expect(f.approve).not.toHaveBeenCalled();
    },
  );

  it('never accepts the same nonce twice, including concurrent submissions', async () => {
    const f = fixture();
    const { nonce } = await f.form();
    const responses = await Promise.all([f.submit(nonce), f.submit(nonce)]);
    expect(responses.map((r) => r.status).sort()).toEqual([303, 409]);
    expect(f.approve).toHaveBeenCalledTimes(1);
  });

  it('consumes a nonce after a lost upstream reply and refuses replay', async () => {
    const f = fixture();
    const { nonce } = await f.form();
    f.approve.mockRejectedValueOnce(new Error('secret-token upstream committed but reply lost'));
    const unknown = await f.submit(nonce);
    expect(unknown.status).toBe(409);
    expect(await unknown.text()).not.toContain('secret-token');
    expect((await f.submit(nonce)).status).toBe(409);
    expect(f.approve).toHaveBeenCalledTimes(1);
  });

  it('expires exactly at the five-minute boundary', async () => {
    const f = fixture();
    const { nonce } = await f.form();
    f.expire();
    expect((await f.submit(nonce)).status).toBe(409);
    expect(f.approve).not.toHaveBeenCalled();
  });

  it.each([
    { origin: 'https://attacker.example.test' },
    { origin: '' },
    { 'sec-fetch-site': 'cross-site' },
  ])('rejects cross-origin submissions before consuming state: %j', async (headers) => {
    const f = fixture();
    const { nonce } = await f.form();
    expect((await f.submit(nonce, 'approve', headers)).status).toBe(403);
    expect(f.entries.has(nonce)).toBe(true);
    expect(f.approve).not.toHaveBeenCalled();
  });

  it('requires a current verified session on GET and POST', async () => {
    const f = fixture();
    const { nonce } = await f.form();
    f.setSignedIn(false);
    expect((await f.load()).status).toBe(401);
    expect((await f.submit(nonce)).status).toBe(401);
    expect(f.approve).not.toHaveBeenCalled();
  });

  it('refuses client, user, redirect and scope mismatches without creating a form', async () => {
    for (const override of [
      { client: { id: OTHER, name: 'wrong' } },
      { user: { id: OTHER } },
      { redirect_uri: 'https://attacker.example.test/callback' },
      { scope: 'openid phone' },
    ]) {
      const f = fixture();
      f.setUpstream({
        authorization_id: AUTH_ID,
        client: { id: CLIENT, name: 'My client' },
        user: { id: USER },
        redirect_uri: REDIRECT,
        scope: 'openid email',
        ...override,
      });
      expect((await f.load()).status).toBe(403);
      expect(f.entries.size).toBe(0);
      expect(f.approve).not.toHaveBeenCalled();
    }
  });

  it('binds approval to exactly the details the user viewed, including allowed scope reductions', async () => {
    const f = fixture();
    const { nonce } = await f.form();
    f.setUpstream({
      authorization_id: AUTH_ID,
      client: { id: CLIENT, name: 'My client' },
      user: { id: USER },
      redirect_uri: REDIRECT,
      scope: 'openid',
    });
    expect((await f.submit(nonce)).status).toBe(409);
    expect(f.approve).not.toHaveBeenCalled();
  });

  it('HTML-escapes upstream labels and never renders user/session tokens', async () => {
    const f = fixture();
    f.setUpstream({
      authorization_id: AUTH_ID,
      client: { id: CLIENT, name: '<img src=x onerror="evil()">' },
      user: { id: USER },
      redirect_uri: REDIRECT,
      scope: 'openid email',
    });
    const { html } = await f.form();
    expect(html).toContain('&lt;img');
    expect(html).not.toContain('<img');
    expect(html).not.toContain('opaque-host-session');
    expect(html).not.toContain(USER);
  });

  it('follows already-recorded upstream consent only to the exact bound callback', async () => {
    const f = fixture();
    f.setUpstream({ redirect_url: `${REDIRECT}?code=already&state=original` });
    expect((await f.load()).status).toBe(303);
    expect(f.entries.size).toBe(0);
    f.setUpstream({ redirect_url: 'https://attacker.example.test/callback?code=stolen' });
    expect((await f.load()).status).toBe(403);
    expect(f.approve).not.toHaveBeenCalled();
  });

  it.each([
    '?authorization_id=a&authorization_id=b',
    '?authorization_id=a&redirect_uri=https://attacker.example.test',
    '?authorization_id=',
    '',
  ])('refuses malformed GET query %s', async (query) => {
    const f = fixture();
    expect((await f.handler(new Request(ROUTE + query))).status).toBe(400);
    expect(f.get).not.toHaveBeenCalled();
  });

  it.each([
    'nonce=a&nonce=b&decision=approve',
    'nonce=a&decision=approve&extra=x',
    `nonce=${'a'.repeat(3000)}&decision=approve`,
    'nonce=a&decision=maybe',
  ])('rejects duplicate, unknown, oversized or invalid forms', async (body) => {
    const f = fixture();
    expect(
      (
        await f.handler(
          new Request(ROUTE, {
            method: 'POST',
            headers: { origin: ORIGIN, 'content-type': 'application/x-www-form-urlencoded' },
            body,
          }),
        )
      ).status,
    ).toBe(400);
    expect(f.approve).not.toHaveBeenCalled();
  });

  it('returns sanitized no-store failure if host verification or state storage fails', async () => {
    const handler = createHostedOAuthConsentHandler({
      routeUrl: ROUTE,
      binding: { expectedClientId: CLIENT, redirectUris: [REDIRECT], allowedScopes: ['openid'] },
      getVerifiedSession: async () => {
        throw Error('private bearer secret');
      },
      challenges: { putIfAbsent: async () => false, take: async () => undefined },
    });
    const result = await handler(new Request(`${ROUTE}?authorization_id=a`));
    expect(result.status).toBe(503);
    expect(result.headers.get('cache-control')).toBe('no-store');
    expect(await result.text()).not.toContain('private bearer');
  });

  it('does not serve another origin/path or unsupported methods', async () => {
    const f = fixture();
    expect(
      (await f.handler(new Request('https://attacker.example.test/oauth/consent'))).status,
    ).toBe(404);
    expect((await f.handler(new Request(`${ORIGIN}/elsewhere`))).status).toBe(404);
    expect((await f.handler(new Request(ROUTE, { method: 'DELETE' }))).status).toBe(405);
  });
});
