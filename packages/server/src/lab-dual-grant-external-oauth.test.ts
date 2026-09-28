import { randomBytes, randomUUID } from 'node:crypto';

import { LOCAL_LAB_MCP_RESOURCE_URI } from '@supabase-user-mcp/contracts';
import { createLocalJWKSet, type JWK, jwtVerify } from 'jose';
import { describe, expect, it } from 'vitest';

import { createAuthorizationServerMetadata } from './authorization-server-metadata.js';
import {
  createLabDualGrantBroker,
  type LabDualGrantBroker,
  LabDualGrantError,
  type LabUpstreamOAuth,
} from './lab-dual-grant-broker.js';
import { generateS256PkceChallenge } from './local-oauth-pkce-client.js';
import { createRemoteHttpProfile } from './remote-http-profile.js';
import {
  createRemoteHttpHandlerFromEnvironment,
  LAB_DUAL_GRANT_ENV,
} from './remote-http-startup.js';
import { SYNTHETIC_OAUTH_HMAC_SECRET, SyntheticOAuthLab } from './synthetic-oauth-lab.js';

const RESOURCE = LOCAL_LAB_MCP_RESOURCE_URI;
const UPSTREAM_ISSUER = 'http://127.0.0.1:54321/auth/v1';
const UPSTREAM_RESOURCE = 'http://127.0.0.1:54321/rest/v1';
const DATA_ORIGIN = 'http://127.0.0.1:54321';
const MCP_CLIENT = 'smp-lab-mcp-client';
const UPSTREAM_CLIENT = 'smp-lab-upstream-client';
const PUBLISHABLE = 'sb_publishable_lab_dual_grant';
const CLIENT_NAME = 'lab-maintained-mcp';
const CLIENT_VERSION = 'r2-test-9f3a';
const ISSUER_PORT = 8765;
const CALLBACK_PORT = 9876;
const CLIENT_CALLBACK = `http://127.0.0.1:${CALLBACK_PORT}/client/callback`;
const ISSUER = `http://127.0.0.1:${ISSUER_PORT}`;
const LOGIN_COOKIE = 'lab_login_session';

function principal(): string {
  return randomUUID();
}

function stateValue(): string {
  return randomBytes(16).toString('base64url');
}

function hidden(html: string, name: string): string {
  const match = new RegExp(`name="${name}" value="([^"]+)"`).exec(html);
  const value = match?.[1];
  if (value === undefined || value.length === 0) {
    throw new Error(`missing ${name}`);
  }
  return value;
}

function adapt(lab: SyntheticOAuthLab): LabUpstreamOAuth {
  return {
    startAuthorization: (request) => lab.startAuthorization(request),
    approveAuthorization: (id) => lab.approveAuthorization(id),
    denyAuthorization: (id) => lab.denyAuthorization(id),
    exchangeAuthorizationCode: (input) => lab.exchangeAuthorizationCode(input),
    refresh: (input) => lab.refresh(input),
    revokeGrant: (refreshToken) => lab.revokeGrant(refreshToken),
  };
}

function labFor(port: number): SyntheticOAuthLab {
  return new SyntheticOAuthLab({
    issuer: UPSTREAM_ISSUER,
    resourceUri: UPSTREAM_RESOURCE,
    client: {
      clientId: UPSTREAM_CLIENT,
      redirectUri: `http://127.0.0.1:${port}/lab/oauth/callback`,
      tokenEndpointAuthMethod: 'none',
    },
  });
}

async function createBroker(input?: {
  readonly mcpClientRedirectUri?: string;
  readonly port?: number;
}): Promise<LabDualGrantBroker> {
  const port = input?.port ?? ISSUER_PORT;
  const lab = labFor(port);
  return createLabDualGrantBroker({
    optIn: true,
    mcpIssuer: `http://127.0.0.1:${port}`,
    mcpClientId: MCP_CLIENT,
    mcpResourceUri: RESOURCE,
    upstreamIssuer: UPSTREAM_ISSUER,
    upstreamClientId: UPSTREAM_CLIENT,
    upstreamResourceUri: UPSTREAM_RESOURCE,
    exactRedirectUri: `http://127.0.0.1:${port}/lab/oauth/callback`,
    mcpClientRedirectUri: input?.mcpClientRedirectUri ?? CLIENT_CALLBACK,
    dataApiOrigin: DATA_ORIGIN,
    publishableKey: PUBLISHABLE,
    maintainedClientName: CLIENT_NAME,
    maintainedClientVersion: CLIENT_VERSION,
    upstream: adapt(lab),
    fetch: async (input, init) => {
      const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
      const authorization = new Headers(init?.headers).get('authorization') ?? '';
      const token = authorization.startsWith('Bearer ')
        ? authorization.slice('Bearer '.length)
        : '';
      const payload = JSON.parse(
        Buffer.from(token.split('.')[1] ?? '', 'base64url').toString('utf8'),
      ) as { sub?: string };
      if (url.pathname === '/auth/v1/user') {
        return Response.json({ id: payload.sub, aud: 'authenticated' });
      }
      if (url.pathname.endsWith('/authorized_memory_get_v1')) {
        return Response.json({ record: null });
      }
      return Response.json({ rows: [] });
    },
  });
}

function profile(broker: LabDualGrantBroker) {
  const lab = labFor(ISSUER_PORT);
  return createRemoteHttpProfile({
    resourceUri: RESOURCE,
    issuer: UPSTREAM_ISSUER,
    expectedClientId: UPSTREAM_CLIENT,
    signingKey: { kind: 'hmac', secret: SYNTHETIC_OAUTH_HMAC_SECRET },
    revocationAuthority: lab,
    authorizationServerMetadata: createAuthorizationServerMetadata(UPSTREAM_ISSUER),
    allowInsecureIssuer: true,
    labDualGrant: broker.profileHook,
  });
}

function authorizeUrl(query: Record<string, string>, port = ISSUER_PORT): string {
  const url = new URL(`http://127.0.0.1:${port}/oauth/authorize`);
  for (const [key, value] of Object.entries(query)) url.searchParams.set(key, value);
  return url.toString();
}

function authorizeQuery(input: {
  readonly redirectUri?: string;
  readonly clientId?: string;
  readonly resource?: string;
  readonly state?: string;
  readonly codeChallenge?: string;
  readonly codeChallengeMethod?: string;
  readonly responseType?: string;
}): Record<string, string> {
  const pkce = generateS256PkceChallenge();
  return {
    response_type: input.responseType ?? 'code',
    client_id: input.clientId ?? MCP_CLIENT,
    redirect_uri: input.redirectUri ?? CLIENT_CALLBACK,
    code_challenge: input.codeChallenge ?? pkce.codeChallenge,
    code_challenge_method: input.codeChallengeMethod ?? 'S256',
    state: input.state ?? stateValue(),
    resource: input.resource ?? RESOURCE,
  };
}

function labRequest(
  url: string,
  init?: {
    readonly method?: string;
    readonly cookie?: string;
    readonly host?: string;
    readonly body?: string;
    readonly contentType?: string;
  },
): Request {
  const headers = new Headers();
  headers.set('host', init?.host ?? `127.0.0.1:${ISSUER_PORT}`);
  if (init?.cookie !== undefined) headers.set('cookie', init.cookie);
  if (init?.body !== undefined) {
    headers.set('content-type', init.contentType ?? 'application/x-www-form-urlencoded');
  }
  return new Request(url, {
    method: init?.method ?? 'GET',
    headers,
    ...(init?.body === undefined ? {} : { body: init.body }),
  });
}

async function completeUpstream(
  broker: LabDualGrantBroker,
  sessionId: string,
  flowId: string,
): Promise<void> {
  const upstream = broker.beginUpstreamAuthorization({
    parentFlowId: flowId,
    loginSessionId: sessionId,
  });
  const approved = broker.approveUpstreamConsent(upstream.flowId);
  await broker.consumeUpstreamCallback({
    state: approved.searchParams.get('state') ?? '',
    iss: approved.searchParams.get('iss') ?? '',
    code: approved.searchParams.get('code') ?? '',
  });
}

describe('lab dual-grant external OAuth client compatibility', () => {
  it('registers an exact separate-port loopback callback and keeps the upstream callback on the issuer', async () => {
    const broker = await createBroker();
    expect(broker.profileHook.mcpIssuer).toBe(ISSUER);
    const metadata = broker.authorizationServerMetadata() as unknown as {
      authorization_endpoint: string;
      revocation_endpoint: string;
      jwks_uri: string;
    };
    expect(metadata.authorization_endpoint).toBe(`${ISSUER}/oauth/authorize`);
    expect(metadata.revocation_endpoint).toBe(`${ISSUER}/oauth/revoke`);
    expect(metadata.jwks_uri).toBe(`${ISSUER}/.well-known/jwks.json`);
    await broker.cleanup();

    const rejected = [
      { mcpClientRedirectUri: 'http://localhost:9876/client/callback' },
      { mcpClientRedirectUri: 'http://user:pass@127.0.0.1:9876/client/callback' },
      { mcpClientRedirectUri: 'http://127.0.0.1:9876/client/callback#frag' },
      { mcpClientRedirectUri: 'http://127.0.0.1:9876/client/callback?next=1' },
      { mcpClientRedirectUri: 'https://127.0.0.1:9876/client/callback' },
      { mcpClientRedirectUri: 'http://127.0.0.1:9876/*' },
      { mcpClientRedirectUri: 'http://127.0.0.1:9876/client/../callback' },
      { exactRedirectUri: `http://127.0.0.1:${CALLBACK_PORT}/lab/oauth/callback` },
    ];
    for (const override of rejected) {
      await expect(
        createLabDualGrantBroker({
          optIn: true,
          mcpIssuer: ISSUER,
          mcpClientId: MCP_CLIENT,
          mcpResourceUri: RESOURCE,
          upstreamIssuer: UPSTREAM_ISSUER,
          upstreamClientId: UPSTREAM_CLIENT,
          upstreamResourceUri: UPSTREAM_RESOURCE,
          exactRedirectUri: `${ISSUER}/lab/oauth/callback`,
          mcpClientRedirectUri: CLIENT_CALLBACK,
          dataApiOrigin: DATA_ORIGIN,
          publishableKey: PUBLISHABLE,
          maintainedClientName: CLIENT_NAME,
          maintainedClientVersion: CLIENT_VERSION,
          upstream: adapt(labFor(ISSUER_PORT)),
          fetch: async () => new Response(null, { status: 599 }),
          ...override,
        }),
      ).rejects.toBeInstanceOf(LabDualGrantError);
    }
  });

  it('serves HTTP authorize with explicit consent and a separate-port callback', async () => {
    const who = principal();
    const broker = await createBroker();
    const handler = profile(broker);
    const sessionId = broker.openLoginSession(who);
    const pkce = generateS256PkceChallenge();
    const state = stateValue();
    const query = authorizeQuery({
      codeChallenge: pkce.codeChallenge,
      state,
    });
    const before = broker.custodyCounts();
    const consent = await handler(
      labRequest(authorizeUrl(query), { cookie: `${LOGIN_COOKIE}=${sessionId}` }),
    );
    expect(consent.status).toBe(200);
    expect(consent.headers.get('location')).toBeNull();
    expect(consent.headers.get('content-type')).toContain('text/html');
    const html = await consent.text();
    expect(html).toContain('Consent is required');
    expect(html).not.toContain(who);
    expect(html).not.toContain('code=');
    expect(broker.custodyCounts().pendingFlows).toBe(before.pendingFlows + 1);
    const flowId = hidden(html, 'flow_id');
    const consentToken = hidden(html, 'consent_token');

    const approved = await handler(
      labRequest(authorizeUrl({}), {
        method: 'POST',
        cookie: `${LOGIN_COOKIE}=${sessionId}`,
        body: new URLSearchParams({
          flow_id: flowId,
          consent_token: consentToken,
          decision: 'approve',
        }).toString(),
      }),
    );
    expect(approved.status).toBe(302);
    const location = new URL(approved.headers.get('location') ?? '');
    expect(location.origin).toBe(`http://127.0.0.1:${CALLBACK_PORT}`);
    expect(location.pathname).toBe('/client/callback');
    expect(location.searchParams.get('state')).toBe(state);
    expect(location.searchParams.get('iss')).toBe(ISSUER);
    const code = location.searchParams.get('code') ?? '';
    expect(code.length).toBeGreaterThan(10);
    expect(approved.headers.get('location')).not.toContain(who);

    const replayedConsent = await handler(
      labRequest(authorizeUrl({}), {
        method: 'POST',
        cookie: `${LOGIN_COOKIE}=${sessionId}`,
        body: new URLSearchParams({
          flow_id: flowId,
          consent_token: consentToken,
          decision: 'approve',
        }).toString(),
      }),
    );
    expect(replayedConsent.status).toBe(400);
    expect(replayedConsent.headers.get('location')).toBeNull();

    await completeUpstream(broker, sessionId, flowId);
    const issued = await handler(
      labRequest(`${ISSUER}/oauth/token`, {
        method: 'POST',
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: MCP_CLIENT,
          redirect_uri: CLIENT_CALLBACK,
          code_verifier: pkce.codeVerifier,
          resource: RESOURCE,
        }).toString(),
      }),
    );
    expect(issued.status).toBe(200);
    const tokenBody = (await issued.json()) as { access_token?: string; token_type?: string };
    expect(tokenBody.token_type).toBe('Bearer');
    const accessToken = tokenBody.access_token ?? '';
    expect(accessToken.split('.').length).toBe(3);

    const discovery = await handler(
      new Request('https://mcp.loopback.invalid/.well-known/oauth-authorization-server'),
    );
    const metadata = (await discovery.json()) as {
      revocation_endpoint?: string;
      jwks_uri?: string;
    };
    expect(metadata.revocation_endpoint).toBe(`${ISSUER}/oauth/revoke`);
    expect(metadata.jwks_uri).toBe(`${ISSUER}/.well-known/jwks.json`);
    const jwksResponse = await handler(labRequest(metadata.jwks_uri ?? ''));
    expect(jwksResponse.status).toBe(200);
    const jwks = (await jwksResponse.json()) as { keys: JWK[] };
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).not.toHaveProperty('d');
    await expect(
      jwtVerify(accessToken, createLocalJWKSet({ keys: jwks.keys }), {
        issuer: ISSUER,
        audience: RESOURCE,
      }),
    ).resolves.toMatchObject({ payload: { client_id: MCP_CLIENT } });

    const reused = await handler(
      labRequest(`${ISSUER}/oauth/token`, {
        method: 'POST',
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: MCP_CLIENT,
          redirect_uri: CLIENT_CALLBACK,
          code_verifier: pkce.codeVerifier,
          resource: RESOURCE,
        }).toString(),
      }),
    );
    expect(reused.status).toBe(400);
    expect(await reused.json()).toEqual({ error: 'replay' });
    await broker.cleanup();
  });

  it('revokes an issued MCP access token at the advertised revocation endpoint', async () => {
    const who = principal();
    const broker = await createBroker();
    const handler = profile(broker);
    const sessionId = broker.openLoginSession(who);
    const pkce = generateS256PkceChallenge();
    const consent = await handler(
      labRequest(
        authorizeUrl(authorizeQuery({ codeChallenge: pkce.codeChallenge, state: stateValue() })),
        { cookie: `${LOGIN_COOKIE}=${sessionId}` },
      ),
    );
    const html = await consent.text();
    const flowId = hidden(html, 'flow_id');
    const approved = await handler(
      labRequest(`${ISSUER}/oauth/authorize`, {
        method: 'POST',
        cookie: `${LOGIN_COOKIE}=${sessionId}`,
        body: new URLSearchParams({
          flow_id: flowId,
          consent_token: hidden(html, 'consent_token'),
          decision: 'approve',
        }).toString(),
      }),
    );
    const code = new URL(approved.headers.get('location') ?? '').searchParams.get('code') ?? '';
    await completeUpstream(broker, sessionId, flowId);
    const issued = await handler(
      labRequest(`${ISSUER}/oauth/token`, {
        method: 'POST',
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: MCP_CLIENT,
          redirect_uri: CLIENT_CALLBACK,
          code_verifier: pkce.codeVerifier,
          resource: RESOURCE,
        }).toString(),
      }),
    );
    const accessToken = ((await issued.json()) as { access_token?: string }).access_token ?? '';
    const call = (): Promise<Response> =>
      handler(
        new Request(RESOURCE, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            Accept: 'application/json',
            'content-type': 'application/json',
            host: 'mcp.loopback.invalid',
          },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: 'tools/call',
            params: { name: 'memory_get', arguments: { id: 'mem_x' } },
          }),
        }),
      );
    expect((await call()).status).toBe(200);
    expect(broker.providerRevocationCount()).toBe(0);

    const wrongClient = await handler(
      labRequest(`${ISSUER}/oauth/revoke`, {
        method: 'POST',
        body: new URLSearchParams({
          token: accessToken,
          client_id: 'smp-lab-other-client',
          token_type_hint: 'access_token',
        }).toString(),
      }),
    );
    expect(wrongClient.status).toBe(400);
    expect((await call()).status).toBe(200);

    const hintedRefresh = await handler(
      labRequest(`${ISSUER}/oauth/revoke`, {
        method: 'POST',
        body: new URLSearchParams({
          token: accessToken,
          client_id: MCP_CLIENT,
          token_type_hint: 'refresh_token',
        }).toString(),
      }),
    );
    expect(hintedRefresh.status).toBe(200);
    expect(await hintedRefresh.text()).not.toContain(accessToken);
    expect((await call()).status).toBe(200);

    const revoked = await handler(
      labRequest(`${ISSUER}/oauth/revoke`, {
        method: 'POST',
        body: new URLSearchParams({
          token: accessToken,
          client_id: MCP_CLIENT,
        }).toString(),
      }),
    );
    expect(revoked.status).toBe(200);
    expect(await revoked.text()).not.toContain(accessToken);
    expect(broker.providerRevocationCount()).toBe(0);
    expect((await call()).status).toBe(401);
    const again = await handler(
      labRequest(`${ISSUER}/oauth/revoke`, {
        method: 'POST',
        body: new URLSearchParams({
          token: accessToken,
          client_id: MCP_CLIENT,
        }).toString(),
      }),
    );
    expect(again.status).toBe(200);
    expect((await call()).status).toBe(401);
    await broker.cleanup();
  });

  it('rejects authorize mismatches without issuing a code or changing custody', async () => {
    const alice = principal();
    const bob = principal();
    const broker = await createBroker();
    const handler = profile(broker);
    const aliceSession = broker.openLoginSession(alice);
    const bobSession = broker.openLoginSession(bob);
    const before = broker.custodyCounts();

    const hostile = await handler(
      labRequest(authorizeUrl(authorizeQuery({})), {
        host: 'attacker.example',
        cookie: `${LOGIN_COOKIE}=${aliceSession}`,
      }),
    );
    expect(hostile.status).toBe(400);
    expect(await hostile.json()).toEqual({ error: 'invalid_request' });

    const cases: Array<{ readonly query: Record<string, string>; readonly error: string }> = [
      { query: authorizeQuery({ clientId: 'smp-lab-other-client' }), error: 'wrong_client' },
      {
        query: authorizeQuery({ redirectUri: `http://127.0.0.1:${CALLBACK_PORT}/other` }),
        error: 'invalid_redirect',
      },
      {
        query: authorizeQuery({ resource: 'https://mcp.loopback.invalid/other' }),
        error: 'invalid_resource',
      },
      { query: authorizeQuery({ codeChallengeMethod: 'plain' }), error: 'invalid_pkce' },
      { query: authorizeQuery({ state: 'short' }), error: 'invalid_state' },
      { query: { ...authorizeQuery({}), prompt: 'none' }, error: 'consent_required' },
      { query: { ...authorizeQuery({}), principal_id: alice }, error: 'caller_mapping_rejected' },
    ];
    for (const item of cases) {
      const response = await handler(
        labRequest(authorizeUrl(item.query), { cookie: `${LOGIN_COOKIE}=${aliceSession}` }),
      );
      expect(response.status).toBe(400);
      expect(response.headers.get('location')).toBeNull();
      expect(await response.json()).toEqual({ error: item.error });
    }
    expect(broker.custodyCounts().pendingFlows).toBe(before.pendingFlows);

    const pkce = generateS256PkceChallenge();
    const state = stateValue();
    const consent = await handler(
      labRequest(authorizeUrl(authorizeQuery({ codeChallenge: pkce.codeChallenge, state })), {
        cookie: `${LOGIN_COOKIE}=${aliceSession}`,
      }),
    );
    expect(consent.status).toBe(200);
    const html = await consent.text();
    const flowId = hidden(html, 'flow_id');
    const consentToken = hidden(html, 'consent_token');
    const repeated = await handler(
      labRequest(authorizeUrl(authorizeQuery({ codeChallenge: pkce.codeChallenge, state })), {
        cookie: `${LOGIN_COOKIE}=${aliceSession}`,
      }),
    );
    expect(repeated.status).toBe(400);
    expect(await repeated.json()).toEqual({ error: 'invalid_state' });

    const crossed = await handler(
      labRequest(`${ISSUER}/oauth/authorize`, {
        method: 'POST',
        cookie: `${LOGIN_COOKIE}=${bobSession}`,
        body: new URLSearchParams({
          flow_id: flowId,
          consent_token: consentToken,
          decision: 'approve',
        }).toString(),
      }),
    );
    expect(crossed.status).toBe(400);
    expect(await crossed.json()).toEqual({ error: 'cross_user' });
    expect(crossed.headers.get('location')).toBeNull();

    const denied = await handler(
      labRequest(`${ISSUER}/oauth/authorize`, {
        method: 'POST',
        cookie: `${LOGIN_COOKIE}=${aliceSession}`,
        body: new URLSearchParams({
          flow_id: flowId,
          consent_token: consentToken,
          decision: 'deny',
        }).toString(),
      }),
    );
    expect(denied.status).toBe(302);
    const deniedLocation = new URL(denied.headers.get('location') ?? '');
    expect(deniedLocation.origin).toBe(`http://127.0.0.1:${CALLBACK_PORT}`);
    expect(deniedLocation.searchParams.get('error')).toBe('access_denied');
    expect(deniedLocation.searchParams.get('state')).toBe(state);
    expect(deniedLocation.searchParams.get('code')).toBeNull();

    const wrongVerifier = generateS256PkceChallenge();
    const secondSession = broker.openLoginSession(alice);
    const secondState = stateValue();
    const secondConsent = await handler(
      labRequest(
        authorizeUrl(
          authorizeQuery({ codeChallenge: wrongVerifier.codeChallenge, state: secondState }),
        ),
        { cookie: `${LOGIN_COOKIE}=${secondSession}` },
      ),
    );
    const secondHtml = await secondConsent.text();
    const secondFlow = hidden(secondHtml, 'flow_id');
    const secondApproved = await handler(
      labRequest(`${ISSUER}/oauth/authorize`, {
        method: 'POST',
        cookie: `${LOGIN_COOKIE}=${secondSession}`,
        body: new URLSearchParams({
          flow_id: secondFlow,
          consent_token: hidden(secondHtml, 'consent_token'),
          decision: 'approve',
        }).toString(),
      }),
    );
    const secondCode =
      new URL(secondApproved.headers.get('location') ?? '').searchParams.get('code') ?? '';
    await completeUpstream(broker, secondSession, secondFlow);
    const badPkce = await handler(
      labRequest(`${ISSUER}/oauth/token`, {
        method: 'POST',
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: secondCode,
          client_id: MCP_CLIENT,
          redirect_uri: CLIENT_CALLBACK,
          code_verifier: pkce.codeVerifier,
          resource: RESOURCE,
        }).toString(),
      }),
    );
    expect(badPkce.status).toBe(400);
    expect(await badPkce.json()).toEqual({ error: 'invalid_pkce' });
    expect(broker.custodyCounts().grants).toBe(1);
    expect(broker.providerRevocationCount()).toBe(0);
    await broker.cleanup();
  });

  it('keeps authorize, revoke, and JWKS fail-closed unless env and hook are both present', async () => {
    const broker = await createBroker();
    const metadata = createAuthorizationServerMetadata(UPSTREAM_ISSUER);
    const baseEnv = {
      SUPABASE_USER_MCP_RESOURCE_URI: RESOURCE,
      SUPABASE_USER_MCP_AUTHORIZATION_SERVER: UPSTREAM_ISSUER,
      SUPABASE_USER_MCP_ORIGIN: DATA_ORIGIN,
      SUPABASE_USER_MCP_PUBLISHABLE_KEY: PUBLISHABLE,
      SUPABASE_USER_MCP_OAUTH_CLIENT_ID: UPSTREAM_CLIENT,
    };
    const closed = createRemoteHttpHandlerFromEnvironment({
      env: baseEnv,
      revocationAuthority: { inspectAccessToken: async () => 'active' },
      authorizationServerMetadata: metadata,
      labDualGrant: broker.profileHook,
    });
    const flaggedWithoutHook = createRemoteHttpHandlerFromEnvironment({
      env: { ...baseEnv, [LAB_DUAL_GRANT_ENV]: '1' },
      revocationAuthority: { inspectAccessToken: async () => 'active' },
      authorizationServerMetadata: metadata,
    });
    const open = createRemoteHttpHandlerFromEnvironment({
      env: { ...baseEnv, [LAB_DUAL_GRANT_ENV]: '1' },
      revocationAuthority: { inspectAccessToken: async () => 'active' },
      authorizationServerMetadata: metadata,
      labDualGrant: broker.profileHook,
    });
    for (const handler of [closed, flaggedWithoutHook]) {
      for (const path of ['/oauth/authorize', '/oauth/revoke', '/.well-known/jwks.json']) {
        const response = await handler(new Request(`https://mcp.loopback.invalid${path}`));
        expect(response.status).toBe(404);
        expect(await response.json()).toEqual({ error: 'not_found' });
      }
    }
    const sessionId = broker.openLoginSession(principal());
    const consent = await open(
      labRequest(authorizeUrl(authorizeQuery({})), { cookie: `${LOGIN_COOKIE}=${sessionId}` }),
    );
    expect(consent.status).toBe(200);
    expect(consent.headers.get('content-type')).toContain('text/html');
    await broker.cleanup();
  });
});
