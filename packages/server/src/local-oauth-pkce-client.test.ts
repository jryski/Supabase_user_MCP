import { describe, expect, it, vi } from 'vitest';

import {
  approveLocalAuthorization,
  denyLocalAuthorization,
  extractAuthorizationCode,
  extractAuthorizationId,
  extractConsentRedirectUrl,
  getLocalAuthorizationDetails,
} from './local-oauth-pkce-client.js';

const AUTH = 'http://127.0.0.1:62421';
const AUTH_ID = 'authorizationidauthorizationid12';
const CALLBACK = 'http://127.0.0.1/oauth/callback?code=lab-code&state=lab-state';

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('local OAuth PKCE client helpers', () => {
  it('extracts authorization_id, code, and redirect_url from official Auth fields', () => {
    expect(
      extractAuthorizationId('http://127.0.0.1:3000/oauth/consent?authorization_id=abc123'),
    ).toBe('abc123');
    expect(extractAuthorizationCode(CALLBACK)).toBe('lab-code');
    expect(extractConsentRedirectUrl({ redirect_url: CALLBACK })).toBe(CALLBACK);
    expect(() => extractConsentRedirectUrl({ redirect_to: CALLBACK })).toThrow(/redirect_url/);
  });

  it('treats GET details with authorization_id as pending consent', async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse(200, { authorization_id: AUTH_ID, scope: 'openid' }),
    );
    await expect(
      getLocalAuthorizationDetails({
        authOrigin: AUTH,
        authorizationId: AUTH_ID,
        userAccessToken: 'user-token',
        projectPublishableKey: 'publishable',
        fetch: fetchImpl,
      }),
    ).resolves.toEqual({ kind: 'pending', authorizationId: AUTH_ID });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(String(fetchImpl.mock.calls.flat()[0])).toBe(
      `${AUTH}/auth/v1/oauth/authorizations/${AUTH_ID}`,
    );
  });

  it('binds the user on GET then approves with redirect_url', async () => {
    const fetchImpl = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      if (init?.method === 'POST' && url.endsWith('/consent')) {
        expect(JSON.parse(String(init.body))).toEqual({ action: 'approve' });
        return jsonResponse(200, { redirect_url: CALLBACK });
      }
      return jsonResponse(200, { authorization_id: AUTH_ID });
    });
    const approved = await approveLocalAuthorization({
      authOrigin: AUTH,
      authorizationId: AUTH_ID,
      userAccessToken: 'user-token',
      projectPublishableKey: 'publishable',
      fetch: fetchImpl,
    });
    expect(approved).toEqual({ code: 'lab-code', location: CALLBACK });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('returns the auto-approved GET redirect without posting consent', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(200, { redirect_url: CALLBACK }));
    const approved = await approveLocalAuthorization({
      authOrigin: AUTH,
      authorizationId: AUTH_ID,
      userAccessToken: 'user-token',
      projectPublishableKey: 'publishable',
      fetch: fetchImpl,
    });
    expect(approved.code).toBe('lab-code');
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('binds the user on GET then denies consent', async () => {
    const fetchImpl = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
      if (init?.method === 'POST') {
        expect(JSON.parse(String(init.body))).toEqual({ action: 'deny' });
        return jsonResponse(200, {
          redirect_url: 'http://127.0.0.1/oauth/callback?error=access_denied',
        });
      }
      return jsonResponse(200, { authorization_id: AUTH_ID });
    });
    await expect(
      denyLocalAuthorization({
        authOrigin: AUTH,
        authorizationId: AUTH_ID,
        userAccessToken: 'user-token',
        projectPublishableKey: 'publishable',
        fetch: fetchImpl,
      }),
    ).resolves.toBeUndefined();
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });
});
