import { createHash, randomBytes } from 'node:crypto';

import { canonicalizeResourceUri } from '@supabase-user-mcp/contracts';

export interface LocalPkceChallenge {
  readonly codeVerifier: string;
  readonly codeChallenge: string;
}

export interface LocalOAuthClientRegistration {
  readonly clientId: string;
  readonly redirectUris: readonly string[];
}

export function generateS256PkceChallenge(): LocalPkceChallenge {
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
  return { codeVerifier, codeChallenge };
}

export function decodeJwtPayloadClaims(token: string): Record<string, unknown> {
  const parts = token.split('.');
  if (parts.length !== 3 || !parts[1]) {
    throw new Error('access token is not a JWT');
  }
  return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as Record<string, unknown>;
}

export function extractAuthorizationId(location: string): string {
  const url = new URL(location);
  const authorizationId = url.searchParams.get('authorization_id');
  if (!authorizationId) {
    throw new Error('authorization redirect did not include authorization_id');
  }
  return authorizationId;
}

export function extractAuthorizationCode(location: string): string {
  const url = new URL(location);
  const code = url.searchParams.get('code');
  if (!code) {
    throw new Error('approved authorization redirect did not include code');
  }
  return code;
}

export function extractConsentRedirectUrl(payload: unknown): string {
  if (payload === null || typeof payload !== 'object' || !('redirect_url' in payload)) {
    throw new Error('oauth consent response did not include redirect_url');
  }
  const redirectUrl = (payload as { redirect_url?: unknown }).redirect_url;
  if (typeof redirectUrl !== 'string' || redirectUrl.length === 0) {
    throw new Error('oauth consent response did not include redirect_url');
  }
  return redirectUrl;
}

type FetchLike = typeof globalThis.fetch;

function resolveFetch(fetchImpl: FetchLike | undefined): FetchLike {
  return fetchImpl ?? globalThis.fetch;
}

function userAuthHeaders(input: {
  readonly userAccessToken: string;
  readonly projectPublishableKey: string;
  readonly json?: boolean;
}): Record<string, string> {
  return {
    Authorization: `Bearer ${input.userAccessToken}`,
    apikey: input.projectPublishableKey,
    ...(input.json === true ? { 'Content-Type': 'application/json' } : {}),
  };
}

export type LocalAuthorizationDetails =
  | { readonly kind: 'pending'; readonly authorizationId: string }
  | { readonly kind: 'redirect'; readonly redirectUrl: string };

export async function getLocalAuthorizationDetails(input: {
  readonly authOrigin: string;
  readonly authorizationId: string;
  readonly userAccessToken: string;
  readonly projectPublishableKey: string;
  readonly fetch?: FetchLike;
}): Promise<LocalAuthorizationDetails> {
  const response = await resolveFetch(input.fetch)(
    new URL(`/auth/v1/oauth/authorizations/${input.authorizationId}`, input.authOrigin),
    {
      method: 'GET',
      headers: userAuthHeaders(input),
    },
  );
  if (!response.ok) {
    throw new Error(`get authorization details failed: ${response.status}`);
  }
  const body: unknown = await response.json();
  if (
    typeof body === 'object' &&
    body !== null &&
    'redirect_url' in body &&
    typeof (body as { redirect_url?: unknown }).redirect_url === 'string' &&
    (body as { redirect_url: string }).redirect_url.length > 0
  ) {
    return { kind: 'redirect', redirectUrl: (body as { redirect_url: string }).redirect_url };
  }
  if (
    typeof body === 'object' &&
    body !== null &&
    'authorization_id' in body &&
    typeof (body as { authorization_id?: unknown }).authorization_id === 'string' &&
    (body as { authorization_id: string }).authorization_id.length > 0
  ) {
    return {
      kind: 'pending',
      authorizationId: (body as { authorization_id: string }).authorization_id,
    };
  }
  throw new Error('authorization details were incomplete');
}

async function postLocalAuthorizationConsent(input: {
  readonly authOrigin: string;
  readonly authorizationId: string;
  readonly userAccessToken: string;
  readonly projectPublishableKey: string;
  readonly action: 'approve' | 'deny';
  readonly fetch?: FetchLike;
}): Promise<{ readonly status: number; readonly location: string | null; readonly body: unknown }> {
  const response = await resolveFetch(input.fetch)(
    new URL(`/auth/v1/oauth/authorizations/${input.authorizationId}/consent`, input.authOrigin),
    {
      method: 'POST',
      headers: userAuthHeaders({ ...input, json: true }),
      body: JSON.stringify({ action: input.action }),
    },
  );
  const location = response.headers.get('location');
  if (response.status === 303 && location) {
    return { status: response.status, location, body: null };
  }
  const body: unknown = await response.json().catch(() => null);
  return { status: response.status, location, body };
}

export async function registerLocalPublicOAuthClient(input: {
  readonly authOrigin: string;
  readonly serviceRoleKey: string;
  readonly clientName: string;
  readonly redirectUri: string;
}): Promise<LocalOAuthClientRegistration> {
  const response = await fetch(new URL('/auth/v1/admin/oauth/clients', input.authOrigin), {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${input.serviceRoleKey}`,
      apikey: input.serviceRoleKey,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      name: input.clientName,
      redirect_uris: [input.redirectUri],
      client_type: 'public',
      token_endpoint_auth_method: 'none',
    }),
  });
  if (!response.ok) {
    throw new Error(`oauth client registration failed: ${response.status}`);
  }
  const body = (await response.json()) as { client_id?: string; redirect_uris?: string[] };
  if (!body.client_id) {
    throw new Error('oauth client registration did not return client_id');
  }
  return {
    clientId: body.client_id,
    redirectUris: body.redirect_uris ?? [input.redirectUri],
  };
}

export async function startLocalAuthorization(input: {
  readonly authOrigin: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly resource: string;
  readonly codeChallenge: string;
  readonly state: string;
  readonly scope?: string;
  readonly projectPublishableKey?: string;
}): Promise<{ readonly authorizationId: string; readonly location: string }> {
  const resource = canonicalizeResourceUri(input.resource);
  const authorize = new URL('/auth/v1/oauth/authorize', input.authOrigin);
  authorize.searchParams.set('response_type', 'code');
  authorize.searchParams.set('client_id', input.clientId);
  authorize.searchParams.set('redirect_uri', input.redirectUri);
  authorize.searchParams.set('scope', input.scope ?? 'openid');
  authorize.searchParams.set('state', input.state);
  authorize.searchParams.set('code_challenge', input.codeChallenge);
  authorize.searchParams.set('code_challenge_method', 'S256');
  authorize.searchParams.set('resource', resource);
  const headers: Record<string, string> = {};
  if (input.projectPublishableKey !== undefined) {
    headers.apikey = input.projectPublishableKey;
  }
  const response = await fetch(authorize, {
    redirect: 'manual',
    ...(Object.keys(headers).length === 0 ? {} : { headers }),
  });
  const location = response.headers.get('location');
  if (!location) {
    throw new Error(`authorize did not redirect (${response.status})`);
  }
  return {
    authorizationId: extractAuthorizationId(location),
    location,
  };
}

export async function approveLocalAuthorization(input: {
  readonly authOrigin: string;
  readonly authorizationId: string;
  readonly userAccessToken: string;
  readonly projectPublishableKey: string;
  readonly fetch?: FetchLike;
}): Promise<{ readonly code: string; readonly location: string }> {
  // Official consent UI binds the user on GET /oauth/authorizations/{id} before POST /consent.
  const details = await getLocalAuthorizationDetails(input);
  if (details.kind === 'redirect') {
    return { code: extractAuthorizationCode(details.redirectUrl), location: details.redirectUrl };
  }
  const posted = await postLocalAuthorizationConsent({ ...input, action: 'approve' });
  if (posted.status === 303 && posted.location) {
    return { code: extractAuthorizationCode(posted.location), location: posted.location };
  }
  if (posted.status < 200 || posted.status >= 300) {
    throw new Error(`approve authorization failed: ${posted.status}`);
  }
  const location = extractConsentRedirectUrl(posted.body);
  return { code: extractAuthorizationCode(location), location };
}

export async function denyLocalAuthorization(input: {
  readonly authOrigin: string;
  readonly authorizationId: string;
  readonly userAccessToken: string;
  readonly projectPublishableKey: string;
  readonly fetch?: FetchLike;
}): Promise<void> {
  const details = await getLocalAuthorizationDetails(input);
  if (details.kind === 'redirect') {
    throw new Error('authorization already redirected; cannot deny');
  }
  const posted = await postLocalAuthorizationConsent({ ...input, action: 'deny' });
  if (posted.status !== 303 && (posted.status < 200 || posted.status >= 300)) {
    throw new Error(`deny authorization failed: ${posted.status}`);
  }
}

export async function exchangeLocalAuthorizationCode(input: {
  readonly authOrigin: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly code: string;
  readonly codeVerifier: string;
  readonly resource: string;
  readonly projectPublishableKey?: string;
}): Promise<{ readonly accessToken: string; readonly refreshToken: string | null }> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: input.clientId,
    redirect_uri: input.redirectUri,
    code: input.code,
    code_verifier: input.codeVerifier,
    resource: canonicalizeResourceUri(input.resource),
  });
  const response = await fetch(new URL('/auth/v1/oauth/token', input.authOrigin), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      ...(input.projectPublishableKey === undefined ? {} : { apikey: input.projectPublishableKey }),
    },
    body,
  });
  if (!response.ok) {
    throw new Error(`token exchange failed: ${response.status}`);
  }
  const payload = (await response.json()) as {
    access_token?: string;
    refresh_token?: string;
  };
  if (!payload.access_token) {
    throw new Error('token exchange did not return access_token');
  }
  return {
    accessToken: payload.access_token,
    refreshToken: payload.refresh_token ?? null,
  };
}

export async function refreshLocalAccessToken(input: {
  readonly authOrigin: string;
  readonly clientId: string;
  readonly refreshToken: string;
}): Promise<{ readonly accessToken: string; readonly refreshToken: string | null }> {
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: input.clientId,
    refresh_token: input.refreshToken,
  });
  const response = await fetch(new URL('/auth/v1/oauth/token', input.authOrigin), {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!response.ok) {
    throw new Error(`refresh failed: ${response.status}`);
  }
  const payload = (await response.json()) as {
    access_token?: string;
    refresh_token?: string;
  };
  if (!payload.access_token) {
    throw new Error('refresh did not return access_token');
  }
  return {
    accessToken: payload.access_token,
    refreshToken: payload.refresh_token ?? null,
  };
}

export async function revokeLocalGrant(input: {
  readonly authOrigin: string;
  readonly clientId: string;
  readonly userAccessToken: string;
  readonly projectPublishableKey: string;
}): Promise<void> {
  const url = new URL('/auth/v1/user/oauth/grants', input.authOrigin);
  url.searchParams.set('client_id', input.clientId);
  const response = await fetch(url, {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${input.userAccessToken}`,
      apikey: input.projectPublishableKey,
    },
  });
  if (!response.ok && response.status !== 204) {
    throw new Error(`grant revoke failed: ${response.status}`);
  }
}

export async function logoutLocalSession(input: {
  readonly authOrigin: string;
  readonly userAccessToken: string;
  readonly projectPublishableKey: string;
}): Promise<void> {
  const response = await fetch(new URL('/auth/v1/logout', input.authOrigin), {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${input.userAccessToken}`,
      apikey: input.projectPublishableKey,
    },
  });
  if (!response.ok && response.status !== 204) {
    throw new Error(`logout failed: ${response.status}`);
  }
}
