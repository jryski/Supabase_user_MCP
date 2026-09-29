import { readFile } from 'node:fs/promises';

import {
  DATA_API_AUDIENCE,
  DOWNSTREAM_CREDENTIAL_UNRESOLVED,
  MAX_RESPONSE_BYTES,
} from '@supabase-user-mcp/contracts';
import { exportJWK, generateKeyPair, type JWK, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import {
  createNativeUserMcpHandler,
  MCP_INGRESS_ROLE,
  NATIVE_USER_MCP_CREDENTIAL_SPLIT,
  type NativeUserMcpConfig,
  NativeUserMcpConfigError,
  SUPABASE_JS_PIN,
  SUPABASE_SERVER_PIN,
} from './native-user-mcp.js';

const RESOURCE = 'https://mcp.loopback.invalid/mcp';
const SUPABASE_URL = 'https://project.loopback.invalid';
const ISSUER = 'https://project.loopback.invalid/auth/v1';
const CLIENT = 'smp-lab-inspector';
const PRINCIPAL = '11111111-1111-4111-9111-111111111111';
const SESSION = '22222222-2222-4222-9222-222222222222';
const PUBLISHABLE_KEY = 'sb_publishable_g2_test_not_a_secret';
const ENV_SECRET_SENTINEL = 'sb_secret_env_sentinel_must_not_leak';

async function es256Jwks(): Promise<{
  readonly privateKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];
  readonly jwks: { keys: JWK[] };
}> {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  return {
    privateKey,
    jwks: { keys: [{ ...jwk, kid: 'g2-test', alg: 'ES256', use: 'sig' }] },
  };
}

async function signToken(
  privateKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'],
  claims: {
    readonly audience?: string | readonly string[];
    readonly clientId?: string;
    readonly issuer?: string;
    readonly role?: string;
    readonly sessionId?: string;
    readonly omitSessionId?: boolean;
    readonly resource?: string;
    readonly expiresIn?: string;
    readonly userMetadata?: Record<string, unknown>;
  } = {},
): Promise<string> {
  const payload: Record<string, unknown> = {
    role: claims.role ?? MCP_INGRESS_ROLE,
    client_id: claims.clientId ?? CLIENT,
  };
  if (claims.omitSessionId !== true) payload.session_id = claims.sessionId ?? SESSION;
  if (claims.resource !== undefined) payload.resource = claims.resource;
  if (claims.userMetadata !== undefined) payload.user_metadata = claims.userMetadata;
  const audience = claims.audience ?? RESOURCE;
  let jwt = new SignJWT(payload)
    .setProtectedHeader({ alg: 'ES256', kid: 'g2-test', typ: 'JWT' })
    .setSubject(PRINCIPAL)
    .setIssuer(claims.issuer ?? ISSUER)
    .setAudience(typeof audience === 'string' ? audience : [...audience])
    .setIssuedAt();
  jwt = jwt.setExpirationTime(claims.expiresIn ?? '2m');
  return jwt.sign(privateKey);
}

async function expectInvalidToken(response: Response, token?: string): Promise<void> {
  expect(response.status).toBe(401);
  expect(response.headers.get('x-supabase-server-error')).toBeNull();
  const body = await response.text();
  expect(JSON.parse(body)).toEqual({ error: 'invalid_token' });
  expect(body).not.toContain('[@supabase/server]');
  expect(body).not.toContain('INVALID_JWT');
  expect(body).not.toContain(DOWNSTREAM_CREDENTIAL_UNRESOLVED);
  if (token !== undefined) expect(body).not.toContain(token);
}

function handlerFor(jwks: NativeUserMcpConfig['jwks']): (request: Request) => Promise<Response> {
  return createNativeUserMcpHandler({
    resourceServer: RESOURCE,
    supabaseUrl: SUPABASE_URL,
    expectedClientId: CLIENT,
    ingressRole: MCP_INGRESS_ROLE,
    publishableKey: PUBLISHABLE_KEY,
    jwks,
  });
}

function mcpPost(
  token: string | undefined,
  body = '{"jsonrpc":"2.0","id":1,"method":"initialize"}',
): Request {
  const headers = new Headers({ accept: 'application/json', 'content-type': 'application/json' });
  if (token !== undefined) headers.set('authorization', `Bearer ${token}`);
  return new Request(RESOURCE, { method: 'POST', headers, body });
}

describe('native user MCP adapter', () => {
  it('pins @supabase/server 1.7.2 and does not dispatch the inbound bearer', async () => {
    const packageJson = JSON.parse(
      await readFile(new URL('../package.json', import.meta.url), 'utf8'),
    ) as { dependencies: Record<string, string> };
    expect(packageJson.dependencies['@supabase/server']).toBe(SUPABASE_SERVER_PIN);
    expect(packageJson.dependencies['@supabase/server']).toBe('1.7.2');
    expect(packageJson.dependencies['@supabase/supabase-js']).toBe(SUPABASE_JS_PIN);
    expect(NATIVE_USER_MCP_CREDENTIAL_SPLIT).toEqual({
      tokenA: 'upstream-supabase-auth-jwt',
      tokenB: 'unresolved',
      dataApi: DOWNSTREAM_CREDENTIAL_UNRESOLVED,
      sameBearerPassthrough: false,
      liveRevocation: 'not-implemented',
    });

    const source = await readFile(new URL('./native-user-mcp.ts', import.meta.url), 'utf8');
    expect(source).toContain('withOAuthProtectedResource(');
    expect(source).toContain('withSupabase(');
    expect(source).not.toMatch(/ctx\.supabase\b/);
    expect(source).not.toMatch(/ctx\.supabaseAdmin\b/);
    expect(source).not.toContain('createFixedSupabaseClient');
    expect(source).not.toContain('service_role');
    expect(source).not.toContain('urn:ietf:params:oauth:grant-type:token-exchange');
    expect(source).toContain(DOWNSTREAM_CREDENTIAL_UNRESOLVED);
  });

  it('serves protected-resource metadata without a bearer', async () => {
    const { jwks } = await es256Jwks();
    const handler = handlerFor(jwks);
    const response = await handler(new Request(`${RESOURCE}/oauth-protected-resource`));
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      resource: RESOURCE,
      authorization_servers: [ISSUER],
      bearer_methods_supported: ['header'],
    });
  });

  it('rejects a missing bearer before the unresolved credential response', async () => {
    const { jwks } = await es256Jwks();
    const handler = handlerFor(jwks);
    const response = await handler(mcpPost(undefined));
    const challenge = response.headers.get('WWW-Authenticate') ?? '';
    expect(challenge).toContain('resource_metadata');
    expect(challenge).toContain(`${RESOURCE}/oauth-protected-resource`);
    await expectInvalidToken(response);
  });

  it('verifies Token A then fail-closes without a Data API call', async () => {
    const previousSecret = process.env.SUPABASE_SECRET_KEY;
    const previousUrl = process.env.SUPABASE_URL;
    process.env.SUPABASE_SECRET_KEY = ENV_SECRET_SENTINEL;
    process.env.SUPABASE_URL = 'https://env-must-not-be-used.example';
    const calls: string[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (input) => {
      const url = typeof input === 'string' || input instanceof URL ? String(input) : input.url;
      calls.push(url);
      return new Response('network', { status: 500 });
    };
    try {
      const { privateKey, jwks } = await es256Jwks();
      const token = await signToken(privateKey);
      const handler = handlerFor(jwks);
      const response = await handler(mcpPost(token));
      expect(response.status).toBe(403);
      const body = await response.text();
      expect(JSON.parse(body)).toEqual({ error: DOWNSTREAM_CREDENTIAL_UNRESOLVED });
      expect(body).not.toContain(token);
      expect(body).not.toContain(PUBLISHABLE_KEY);
      expect(body).not.toContain(ENV_SECRET_SENTINEL);
      expect(body).not.toContain('g2-unused-admin-client-not-a-credential');
      expect(calls).toEqual([]);
    } finally {
      globalThis.fetch = originalFetch;
      if (previousSecret === undefined) delete process.env.SUPABASE_SECRET_KEY;
      else process.env.SUPABASE_SECRET_KEY = previousSecret;
      if (previousUrl === undefined) delete process.env.SUPABASE_URL;
      else process.env.SUPABASE_URL = previousUrl;
    }
  });

  it('rejects audience, client, expiry, and user_metadata authority before dispatch', async () => {
    const { privateKey, jwks } = await es256Jwks();
    const handler = handlerFor(jwks);
    const tokens = await Promise.all([
      signToken(privateKey, { clientId: 'smp-other-client' }),
      signToken(privateKey, { expiresIn: '0s' }),
      signToken(privateKey, { userMetadata: { client_id: CLIENT } }),
      signToken(privateKey, { resource: 'https://other.loopback.invalid/mcp' }),
    ]);
    for (const token of tokens) {
      await expectInvalidToken(await handler(mcpPost(token)), token);
    }
  });

  it('accepts a resource-only aud and rejects every other audience', async () => {
    const { privateKey, jwks } = await es256Jwks();
    const handler = handlerFor(jwks);
    for (const audience of [RESOURCE, [RESOURCE]] as const) {
      const token = await signToken(privateKey, { audience });
      const response = await handler(mcpPost(token));
      expect(response.status).toBe(403);
      const body = await response.text();
      expect(JSON.parse(body)).toEqual({ error: DOWNSTREAM_CREDENTIAL_UNRESOLVED });
      expect(body).not.toContain(token);
    }
    const caseVariant = 'https://MCP.loopback.invalid/mcp';
    for (const audience of [
      DATA_API_AUDIENCE,
      [DATA_API_AUDIENCE],
      [RESOURCE, DATA_API_AUDIENCE],
      [DATA_API_AUDIENCE, RESOURCE],
      [RESOURCE, 'https://other.loopback.invalid/api'],
      [RESOURCE, RESOURCE],
      [RESOURCE, caseVariant],
    ] as const) {
      const token = await signToken(privateKey, { audience });
      await expectInvalidToken(await handler(mcpPost(token)), token);
    }
  });

  it('accepts role mcp_ingress and rejects role authenticated', async () => {
    const { privateKey, jwks } = await es256Jwks();
    const handler = handlerFor(jwks);
    const accepted = await signToken(privateKey, { role: MCP_INGRESS_ROLE });
    const acceptedResponse = await handler(mcpPost(accepted));
    expect(acceptedResponse.status).toBe(403);
    const acceptedBody = await acceptedResponse.text();
    expect(JSON.parse(acceptedBody)).toEqual({ error: DOWNSTREAM_CREDENTIAL_UNRESOLVED });
    expect(acceptedBody).not.toContain(accepted);

    const rejected = await signToken(privateKey, { role: 'authenticated' });
    await expectInvalidToken(await handler(mcpPost(rejected)), rejected);

    const source = await readFile(new URL('./native-user-mcp.ts', import.meta.url), 'utf8');
    expect(source).toContain("if (claims.role === 'authenticated') return true;");
    expect(source).not.toContain("if (claims.role !== 'authenticated') return true;");

    expect(() =>
      createNativeUserMcpHandler({
        resourceServer: RESOURCE,
        supabaseUrl: SUPABASE_URL,
        expectedClientId: CLIENT,
        ingressRole: 'authenticated',
        publishableKey: PUBLISHABLE_KEY,
        jwks,
      }),
    ).toThrow(NativeUserMcpConfigError);
  });

  it('rejects nil and empty session_id', async () => {
    const { privateKey, jwks } = await es256Jwks();
    const handler = handlerFor(jwks);
    const source = await readFile(new URL('./native-user-mcp.ts', import.meta.url), 'utf8');
    expect(source).toContain('00000000-0000-0000-0000-000000000000');
    const tokens = await Promise.all([
      signToken(privateKey, { sessionId: '' }),
      signToken(privateKey, { sessionId: '   ' }),
      signToken(privateKey, { sessionId: '00000000-0000-0000-0000-000000000000' }),
      signToken(privateKey, { sessionId: '00000000-0000-0000-0000-000000000000'.toUpperCase() }),
    ]);
    for (const token of tokens) {
      await expectInvalidToken(await handler(mcpPost(token)), token);
    }
  });

  it('rejects wrong issuer, wrong signing key, service_role, and missing session_id', async () => {
    const { privateKey, jwks } = await es256Jwks();
    const otherKey = await generateKeyPair('ES256', { extractable: true });
    const handler = handlerFor(jwks);
    const tokens = await Promise.all([
      signToken(privateKey, { issuer: 'https://other.loopback.invalid/auth/v1' }),
      signToken(otherKey.privateKey, {}),
      signToken(privateKey, { role: 'service_role' }),
      signToken(privateKey, { omitSessionId: true }),
    ]);
    for (const token of tokens) {
      await expectInvalidToken(await handler(mcpPost(token)), token);
    }
  });

  it('does not accept a query-string access token', async () => {
    const { privateKey, jwks } = await es256Jwks();
    const token = await signToken(privateKey);
    const handler = handlerFor(jwks);
    const response = await handler(
      new Request(`${RESOURCE}?access_token=${encodeURIComponent(token)}`),
    );
    await expectInvalidToken(response, token);
  });

  it('rejects an oversized body before auth', async () => {
    const { jwks } = await es256Jwks();
    const handler = handlerFor(jwks);
    const response = await handler(
      new Request(RESOURCE, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: 'x'.repeat(MAX_RESPONSE_BYTES + 1),
      }),
    );
    expect(response.status).toBe(413);
    expect(await response.json()).toEqual({ error: 'payload_too_large' });
  });

  it('keeps the default 403 when no dispatch is configured and checks the paired principal when it is', async () => {
    const { privateKey, jwks } = await es256Jwks();
    const source = '55555555-5555-4555-8555-555555555555';
    const decoy = '44444444-4444-4444-8444-444444444444';
    const agent = 'hook-only-agent';
    const paired = await new SignJWT({
      role: MCP_INGRESS_ROLE,
      client_id: CLIENT,
      session_id: decoy,
      source_session_id: source,
      agent_id: agent,
    })
      .setProtectedHeader({ alg: 'ES256', kid: 'g2-test', typ: 'JWT' })
      .setSubject(PRINCIPAL)
      .setIssuer(ISSUER)
      .setAudience(RESOURCE)
      .setIssuedAt()
      .setExpirationTime('2m')
      .sign(privateKey);
    const untouched = createNativeUserMcpHandler({
      resourceServer: RESOURCE,
      supabaseUrl: SUPABASE_URL,
      expectedClientId: CLIENT,
      ingressRole: MCP_INGRESS_ROLE,
      publishableKey: PUBLISHABLE_KEY,
      jwks,
      expectedAgentId: agent,
    });
    const closed = await untouched(mcpPost(paired));
    expect(closed.status).toBe(403);
    expect(await closed.json()).toEqual({ error: DOWNSTREAM_CREDENTIAL_UNRESOLVED });

    let seen = '';
    const dispatched = createNativeUserMcpHandler({
      resourceServer: RESOURCE,
      supabaseUrl: SUPABASE_URL,
      expectedClientId: CLIENT,
      ingressRole: MCP_INGRESS_ROLE,
      publishableKey: PUBLISHABLE_KEY,
      jwks,
      expectedAgentId: agent,
      onVerified: (principal) => {
        seen = principal.sourceSessionId;
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      },
    });
    const opened = await dispatched(mcpPost(paired));
    expect(opened.status).toBe(200);
    expect(seen).toBe(source);

    const sameSession = await new SignJWT({
      role: MCP_INGRESS_ROLE,
      client_id: CLIENT,
      session_id: source,
      source_session_id: source,
      agent_id: agent,
    })
      .setProtectedHeader({ alg: 'ES256', kid: 'g2-test', typ: 'JWT' })
      .setSubject(PRINCIPAL)
      .setIssuer(ISSUER)
      .setAudience(RESOURCE)
      .setIssuedAt()
      .setExpirationTime('2m')
      .sign(privateKey);
    await expectInvalidToken(await dispatched(mcpPost(sameSession)), sameSession);
  });

  it('rejects symmetric JWKS and JWT-shaped publishable keys', async () => {
    expect(() =>
      createNativeUserMcpHandler({
        resourceServer: RESOURCE,
        supabaseUrl: SUPABASE_URL,
        expectedClientId: CLIENT,
        ingressRole: MCP_INGRESS_ROLE,
        publishableKey: PUBLISHABLE_KEY,
        jwks: { keys: [{ kty: 'oct', alg: 'HS256', kid: 'hmac', k: 'c2VjcmV0' }] },
      }),
    ).toThrow(NativeUserMcpConfigError);
    expect(() =>
      createNativeUserMcpHandler({
        resourceServer: RESOURCE,
        supabaseUrl: SUPABASE_URL,
        expectedClientId: CLIENT,
        ingressRole: MCP_INGRESS_ROLE,
        publishableKey: 'eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.sig',
        jwks: { keys: [{ kty: 'EC', alg: 'ES256', kid: 'g2', crv: 'P-256' }] },
      }),
    ).toThrow(NativeUserMcpConfigError);
  });
});
