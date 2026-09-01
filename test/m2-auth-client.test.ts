import { describe, expect, it, vi } from 'vitest';

import { signInSyntheticM2User } from './support/m2-auth-client.js';

const USER_ID = '11111111-1111-4111-9111-111111111111';

describe('official Supabase Auth synthetic M2 seam', () => {
  it('signs in through fixed Auth with separate publishable key and returns only the access token', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(
      async () =>
        new Response(
          JSON.stringify({
            access_token: 'synthetic-user-token',
            token_type: 'bearer',
            expires_in: 3600,
            expires_at: 4_102_444_800,
            refresh_token: 'synthetic-refresh-token',
            user: {
              id: USER_ID,
              aud: 'authenticated',
              role: 'authenticated',
              email: 'alice.fixture@example.test',
              app_metadata: {},
              user_metadata: {},
              created_at: '2026-01-01T00:00:00Z',
              updated_at: '2026-01-01T00:00:00Z',
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    );

    await expect(
      signInSyntheticM2User({
        authUrl: 'http://127.0.0.1:54321/auth/v1',
        projectPublishableKey: 'synthetic-publishable-key',
        email: 'alice.fixture@example.test',
        password: 'SmpStrongPass!1',
        fetch,
      }),
    ).resolves.toBe('synthetic-user-token');

    expect(fetch).toHaveBeenCalledOnce();
    const [input, init] = fetch.mock.calls[0] ?? [];
    expect(String(input)).toBe('http://127.0.0.1:54321/auth/v1/token?grant_type=password');
    expect(init).toMatchObject({ method: 'POST' });
    expect(new Headers(init?.headers).get('apikey')).toBe('synthetic-publishable-key');
  });

  it('returns a stable secret-free failure when Auth rejects the credentials', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(
      async () =>
        new Response(
          JSON.stringify({ error: 'invalid_grant', error_description: 'sensitive detail' }),
          {
            status: 400,
            headers: { 'content-type': 'application/json' },
          },
        ),
    );

    await expect(
      signInSyntheticM2User({
        authUrl: 'http://127.0.0.1:54321/auth/v1',
        projectPublishableKey: 'synthetic-publishable-key',
        email: 'alice.fixture@example.test',
        password: 'wrong-password',
        fetch,
      }),
    ).rejects.toThrowError('Synthetic local Auth sign-in failed.');
  });

  it('fails closed when a successful Auth response has no access token', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(
      async () =>
        new Response(JSON.stringify({ user: { id: USER_ID } }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    );

    await expect(
      signInSyntheticM2User({
        authUrl: 'http://127.0.0.1:54321/auth/v1',
        projectPublishableKey: 'synthetic-publishable-key',
        email: 'alice.fixture@example.test',
        password: 'SmpStrongPass!1',
        fetch,
      }),
    ).rejects.toThrowError('Synthetic local Auth sign-in failed.');
  });
});
