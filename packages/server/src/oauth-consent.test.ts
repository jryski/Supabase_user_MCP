import { createClient } from '@supabase/supabase-js';
import { describe, expect, it } from 'vitest';

import {
  createOAuthConsentBlock,
  type OAuthConsentApi,
  OAuthConsentConfigError,
} from './oauth-consent.js';

const PROJECT = 'https://consent-lab.example.test';
const PUBLISHABLE = 'sb_publishable_consentlabsyntheticAAAA';
const USER = '11111111-1111-4111-8111-111111111111';
const OTHER_USER = '22222222-2222-4222-8222-222222222222';
const CLIENT = '33333333-3333-4333-8333-333333333333';
const ROGUE_CLIENT = '44444444-4444-4444-8444-444444444444';
const REDIRECT = 'http://127.0.0.1:8765/callback';
const AUTH_ID = 'authz_synthetic_0001';
const ACCESS_TOKEN = 'synthetic.user.session';

const binding = {
  expectedClientId: CLIENT,
  redirectUris: [REDIRECT],
  allowedScopes: ['openid', 'email'] as const,
};

interface Recorded {
  readonly method: string;
  readonly path: string;
  readonly authorization: string | null;
  readonly apikey: string | null;
  readonly body: string | null;
}

interface Upstream {
  details?: unknown;
  detailsStatus?: number;
  consentRedirect?: string;
}

function memoryStorage(seed: Record<string, string>): {
  getItem: (key: string) => string | null;
  setItem: (key: string, value: string) => void;
  removeItem: (key: string) => void;
} {
  const items = new Map(Object.entries(seed));
  return {
    getItem: (key) => items.get(key) ?? null,
    setItem: (key, value) => {
      items.set(key, value);
    },
    removeItem: (key) => {
      items.delete(key);
    },
  };
}

/**
 * A real supabase-js 2.117.2 client whose `auth.oauth` namespace talks to a
 * synthetic Auth server. The session is the caller's existing one, seeded in
 * memory; nothing signs in.
 */
function sdkClient(upstream: Upstream, options: { signedIn?: boolean } = {}) {
  const calls: Recorded[] = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    const body = request.method === 'GET' ? null : await request.text();
    calls.push({
      method: request.method,
      path: url.pathname,
      authorization: request.headers.get('authorization'),
      apikey: request.headers.get('apikey'),
      body,
    });
    const json = (status: number, value: unknown) =>
      new Response(JSON.stringify(value), {
        status,
        headers: { 'content-type': 'application/json' },
      });
    if (request.method === 'GET' && url.pathname === `/auth/v1/oauth/authorizations/${AUTH_ID}`) {
      return json(upstream.detailsStatus ?? 200, upstream.details ?? {});
    }
    if (
      request.method === 'POST' &&
      url.pathname === `/auth/v1/oauth/authorizations/${AUTH_ID}/consent`
    ) {
      const action = JSON.parse(body ?? '{}').action as string;
      const target = upstream.consentRedirect ?? REDIRECT;
      return json(200, {
        redirect_url:
          action === 'approve'
            ? `${target}?code=synthetic-code&state=s1`
            : `${target}?error=access_denied&state=s1`,
      });
    }
    return json(404, { msg: 'not found' });
  };
  const storageKey = 'consent-lab-session';
  const session = {
    access_token: ACCESS_TOKEN,
    refresh_token: 'synthetic-refresh',
    token_type: 'bearer',
    expires_in: 3600,
    expires_at: Math.floor(Date.now() / 1000) + 3600,
    user: { id: USER, aud: 'authenticated', app_metadata: {}, user_metadata: {}, created_at: '' },
  };
  const client = createClient(PROJECT, PUBLISHABLE, {
    global: { fetch: fetchImpl },
    auth: {
      storageKey,
      storage: memoryStorage(
        options.signedIn === false ? {} : { [storageKey]: JSON.stringify(session) },
      ),
      persistSession: true,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    },
  });
  return { api: client.auth.oauth as OAuthConsentApi, calls };
}

function pending(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    authorization_id: AUTH_ID,
    redirect_uri: REDIRECT,
    client: { id: CLIENT, name: 'Synthetic MCP client', uri: '', logo_uri: '' },
    user: { id: USER, email: 'user-a@example.test' },
    scope: 'openid email',
    ...overrides,
  };
}

describe('oauth consent block (supabase-js auth.oauth behind the client binding)', () => {
  it('shows a bound request and approves it with the existing session only', async () => {
    const block = createOAuthConsentBlock(binding);
    const { api, calls } = sdkClient({ details: pending() });

    const view = await block.inspect(api, AUTH_ID, USER);
    expect(view).toEqual({
      kind: 'consent_required',
      authorizationId: AUTH_ID,
      clientId: CLIENT,
      clientName: 'Synthetic MCP client',
      redirectUri: REDIRECT,
      scopes: ['openid', 'email'],
    });

    const outcome = await block.decide(api, AUTH_ID, USER, 'approve');
    expect(outcome).toEqual({
      kind: 'redirect',
      redirectUrl: `${REDIRECT}?code=synthetic-code&state=s1`,
    });
    // Only the official consent endpoints, with the user's own session and
    // the publishable key. No sign-in, token, user-admin or settings calls.
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      `GET /auth/v1/oauth/authorizations/${AUTH_ID}`,
      `GET /auth/v1/oauth/authorizations/${AUTH_ID}`,
      `POST /auth/v1/oauth/authorizations/${AUTH_ID}/consent`,
    ]);
    for (const call of calls) {
      expect(call.authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
      expect(call.apikey).toBe(PUBLISHABLE);
    }
    expect(JSON.parse(calls[2]?.body ?? '{}')).toEqual({ action: 'approve' });
  });

  it('passes a user denial through as deny', async () => {
    const block = createOAuthConsentBlock(binding);
    const { api, calls } = sdkClient({ details: pending() });
    const outcome = await block.decide(api, AUTH_ID, USER, 'deny');
    expect(outcome).toEqual({
      kind: 'redirect',
      redirectUrl: `${REDIRECT}?error=access_denied&state=s1`,
    });
    expect(JSON.parse(calls.at(-1)?.body ?? '{}')).toEqual({ action: 'deny' });
  });

  it.each([
    ['client_not_bound', { client: { id: ROGUE_CLIENT, name: 'x', uri: '', logo_uri: '' } }],
    ['redirect_not_bound', { redirect_uri: 'http://127.0.0.1:8765/callback/other' }],
    ['redirect_not_bound', { redirect_uri: 'https://attacker.example.test/callback' }],
    ['scope_not_bound', { scope: 'openid phone' }],
  ] as const)('refuses and denies upstream when the request is %s', async (reason, override) => {
    const block = createOAuthConsentBlock(binding);
    const { api, calls } = sdkClient({ details: pending(override) });
    expect(await block.inspect(api, AUTH_ID, USER)).toEqual({ kind: 'refused', reason });
    const outcome = await block.decide(api, AUTH_ID, USER, 'approve');
    expect(outcome).toEqual({ kind: 'refused', reason });
    const posts = calls.filter((c) => c.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(JSON.parse(posts[0]?.body ?? '{}')).toEqual({ action: 'deny' });
  });

  it('never approves an authorization that belongs to another user', async () => {
    const block = createOAuthConsentBlock(binding);
    const { api, calls } = sdkClient({
      details: pending({ user: { id: OTHER_USER, email: 'user-b@example.test' } }),
    });
    expect(await block.decide(api, AUTH_ID, USER, 'approve')).toEqual({
      kind: 'refused',
      reason: 'user_mismatch',
    });
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
  });

  it('reports sign_in_required without a session and adds no sign-in call', async () => {
    const block = createOAuthConsentBlock(binding);
    const { api, calls } = sdkClient({ details: pending() }, { signedIn: false });
    expect(await block.decide(api, AUTH_ID, USER, 'approve')).toEqual({
      kind: 'refused',
      reason: 'sign_in_required',
    });
    expect(calls).toEqual([]);
  });

  it('follows an existing consent only to a bound redirect URI', async () => {
    const block = createOAuthConsentBlock(binding);
    const ok = sdkClient({ details: { redirect_url: `${REDIRECT}?code=c&state=s` } });
    expect(await block.inspect(ok.api, AUTH_ID, USER)).toEqual({
      kind: 'redirect',
      redirectUrl: `${REDIRECT}?code=c&state=s`,
    });
    const bad = sdkClient({ details: { redirect_url: 'https://attacker.example.test/cb?code=c' } });
    expect(await block.inspect(bad.api, AUTH_ID, USER)).toEqual({
      kind: 'refused',
      reason: 'redirect_not_bound',
    });
  });

  it('refuses a consent result that redirects outside the binding', async () => {
    const block = createOAuthConsentBlock(binding);
    const { api } = sdkClient({
      details: pending(),
      consentRedirect: 'https://attacker.example.test/cb',
    });
    expect(await block.decide(api, AUTH_ID, USER, 'approve')).toEqual({
      kind: 'refused',
      reason: 'redirect_not_bound',
    });
  });

  it('maps upstream errors to authorization_unavailable', async () => {
    const block = createOAuthConsentBlock(binding);
    const { api } = sdkClient({ detailsStatus: 404, details: { msg: 'gone' } });
    expect(await block.inspect(api, AUTH_ID, USER)).toEqual({
      kind: 'refused',
      reason: 'authorization_unavailable',
    });
  });

  it('rejects malformed authorization ids and users before any call', async () => {
    const block = createOAuthConsentBlock(binding);
    const { api, calls } = sdkClient({ details: pending() });
    for (const id of ['', '../user', 'a/b', 'x'.repeat(129), 'id?x=1']) {
      expect(await block.inspect(api, id, USER)).toEqual({
        kind: 'refused',
        reason: 'invalid_authorization_id',
      });
    }
    expect(await block.inspect(api, AUTH_ID, 'not-a-uuid')).toEqual({
      kind: 'refused',
      reason: 'invalid_user',
    });
    expect(calls).toEqual([]);
  });

  it('fails closed on a loose binding', () => {
    const bad = [
      { ...binding, expectedClientId: '' },
      { ...binding, redirectUris: [] },
      { ...binding, redirectUris: ['http://127.0.0.1:8765/callback?x=1'] },
      { ...binding, redirectUris: ['http://127.0.0.1:8765/callback#f'] },
      { ...binding, redirectUris: ['javascript:alert(1)'] },
      { ...binding, allowedScopes: [] },
      { ...binding, allowedScopes: ['openid', 'admin'] as never },
    ];
    for (const config of bad) {
      expect(() => createOAuthConsentBlock(config)).toThrow(OAuthConsentConfigError);
    }
  });
});
