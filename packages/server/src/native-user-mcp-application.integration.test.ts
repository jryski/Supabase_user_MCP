import {
  CAPABILITY_APPROVAL_ALLOWLIST_VERSION,
  CAPABILITY_DESCRIPTOR_VERSION,
  CAPABILITY_REGISTRY_VERSION,
  type CapabilityDescriptorBody,
  capabilityBodySha256,
} from '@supabase-user-mcp/contracts';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { describe, expect, it, vi } from 'vitest';
import { createCapabilityRegistrationProfile } from './capability-mcp-registration.js';
import { MCP_INGRESS_ROLE } from './native-user-mcp.js';
import { createNativeUserMcpApplicationHandler } from './native-user-mcp-read-handler.js';

// This is a synthetic release BUILD, never a runtime approval injection API.
const release = vi.hoisted(() => ({ value: undefined as unknown }));
vi.mock('./capability-release-approvals.js', () => ({
  get COMPILED_CAPABILITY_APPROVALS() {
    return release.value;
  },
}));

const RESOURCE = 'https://mcp.application.example.test/mcp';
const ORIGIN = 'https://project.application.example.test';
const ISSUER = `${ORIGIN}/auth/v1`;
const REDIRECT = 'http://127.0.0.1:8788/oauth/downstream/callback';
const PUBLISHABLE = 'sb_publishable_application_synthetic';
const A_CLIENT = 'synthetic-ingress-client';
const B_CLIENT = 'synthetic-data-client';
const AGENT = 'synthetic-application-agent';
const PEOPLE = [
  {
    sub: '11111111-1111-4111-8111-111111111111',
    source: '22222222-2222-4222-8222-222222222222',
    session: '33333333-3333-4333-8333-333333333333',
  },
  {
    sub: '55555555-5555-4555-8555-555555555555',
    source: '66666666-6666-4666-8666-666666666666',
    session: '77777777-7777-4777-8777-777777777777',
  },
] as const;
const DECOY = '44444444-4444-4444-8444-444444444444';

function rpcRequest(token: string, method: string, params: unknown): Request {
  return new Request(RESOURCE, {
    method: 'POST',
    headers: {
      accept: 'application/json, text/event-stream',
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      'mcp-protocol-version': '2025-06-18',
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
}

async function reply(response: Response) {
  const text = await response.text();
  const events = text.split('\n').filter((line) => line.startsWith('data: '));
  return JSON.parse(events.length ? (events.at(-1)?.slice(6) ?? '') : text) as {
    result?: { tools?: { name: string }[]; isError?: boolean; structuredContent?: unknown };
    error?: unknown;
  };
}

async function fixture() {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  const token = (sub: string, audience: string, claims: Record<string, unknown>) =>
    new SignJWT(claims)
      .setProtectedHeader({ alg: 'ES256', kid: 'application-test', typ: 'JWT' })
      .setSubject(sub)
      .setIssuer(ISSUER)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime('2m')
      .sign(privateKey);
  const actors = await Promise.all(
    PEOPLE.map(async (person) => ({
      ...person,
      a: await token(person.sub, RESOURCE, {
        role: MCP_INGRESS_ROLE,
        client_id: A_CLIENT,
        agent_id: AGENT,
        session_id: DECOY,
        source_session_id: person.source,
      }),
      b: await token(person.sub, 'authenticated', {
        role: 'authenticated',
        client_id: B_CLIENT,
        app_metadata: { client_id: B_CLIENT },
        agent_id: AGENT,
        session_id: person.session,
      }),
    })),
  );
  const body: CapabilityDescriptorBody = {
    descriptorVersion: CAPABILITY_DESCRIPTOR_VERSION,
    name: 'app_isolation_lookup',
    title: 'Synthetic own lookup',
    description: 'Synthetic application composition fixture.',
    kind: 'read',
    rpc: { schema: 'app_synthetic', function: 'isolation_lookup' },
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['label'],
      properties: { label: { type: 'string', maxLength: 64 } },
    },
    limits: { maxResponseBytes: 4096, timeoutMs: 1000 },
  };
  const approval = { adr: 'ADR-0007', bodySha256: capabilityBodySha256(body) };
  release.value = {
    allowlistVersion: CAPABILITY_APPROVAL_ALLOWLIST_VERSION,
    approvals: [approval],
  };
  const profile = createCapabilityRegistrationProfile({
    registry: { registryVersion: CAPABILITY_REGISTRY_VERSION, descriptors: [{ body, approval }] },
    adopterSchemas: ['app_synthetic'],
    composition: 'application',
    emitStartupEvent: () => undefined,
  });
  expect(profile.status).toBe('ready');
  expect(profile.toolNames).toEqual([body.name]);
  const revoked = new Set<string>();
  const requests: {
    url: string;
    method: string;
    authorization: string | null;
    headers: Headers;
    body: string;
  }[] = [];
  const fetcher: typeof fetch = async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    const text = request.method === 'GET' ? '' : await request.text();
    requests.push({
      url: request.url,
      method: request.method,
      authorization: request.headers.get('authorization'),
      headers: request.headers,
      body: text,
    });
    if (url.pathname === '/auth/v1/oauth/token') {
      const code = new URLSearchParams(text).get('code');
      const actor = actors.find((item) => item.sub === code);
      return actor
        ? Response.json({ access_token: actor.b, refresh_token: 'synthetic-discarded-refresh' })
        : Response.json({}, { status: 403 });
    }
    const actor = actors.find(
      (item) => request.headers.get('authorization') === `Bearer ${item.b}`,
    );
    if (!actor) return Response.json({}, { status: 403 });
    if (url.pathname === '/rest/v1/rpc/source_session_live_v1') {
      expect(JSON.parse(text)).toEqual({ source_session_id: actor.source, a_client_id: A_CLIENT });
      return Response.json(!revoked.has(actor.sub));
    }
    if (url.pathname === '/auth/v1/user')
      return Response.json({ id: actor.sub, aud: 'authenticated' });
    if (url.pathname === '/rest/v1/rpc/isolation_lookup') {
      // Fixture checks transport isolation; it does not claim real database RLS.
      return Response.json({
        result: {
          owner: actor.sub,
          label: JSON.parse(url.searchParams.get('input') ?? '{}').label,
        },
      });
    }
    return Response.json({}, { status: 500 });
  };
  const handler = createNativeUserMcpApplicationHandler({
    resourceServer: RESOURCE,
    supabaseUrl: ORIGIN,
    expectedClientId: A_CLIENT,
    expectedAgentId: AGENT,
    ingressRole: MCP_INGRESS_ROLE,
    publishableKey: PUBLISHABLE,
    jwks: { keys: [{ ...jwk, kid: 'application-test', alg: 'ES256', use: 'sig' }] },
    downstreamClientId: B_CLIENT,
    downstreamRedirectUri: REDIRECT,
    capabilityProfile: profile,
    fetch: fetcher,
  });
  const bind = async (actor: (typeof actors)[number]) => {
    const first = await handler(rpcRequest(actor.a, 'tools/list', {}));
    expect(first.status).toBe(403);
    const { handshake_id } = (await first.json()) as { handshake_id: string };
    expect(typeof handshake_id).toBe('string');
    const callback = await handler(
      new Request(`${REDIRECT}?code=${actor.sub}&state=${handshake_id}`, {
        headers: { host: '127.0.0.1:8788' },
      }),
    );
    expect(callback.status).toBe(200);
    expect(await callback.json()).toMatchObject({ bound: true });
  };
  return { actors, handler, bind, revoked, requests };
}

describe('native verified B to nonempty application registry composition', () => {
  it('lists and executes an approved capability with only B after the actual native callback', async () => {
    const f = await fixture();
    const actor = f.actors[0];
    if (!actor) throw Error('Missing fixture actor');
    await f.bind(actor);
    const listed = await reply(await f.handler(rpcRequest(actor.a, 'tools/list', {})));
    expect(listed.result?.tools?.map((tool) => tool.name)).toContain('app_isolation_lookup');
    const result = await reply(
      await f.handler(
        rpcRequest(actor.a, 'tools/call', {
          name: 'app_isolation_lookup',
          arguments: { label: 'my-result' },
        }),
      ),
    );
    expect(result.error).toBeUndefined();
    expect(result.result?.isError).toBe(false);
    expect(result.result?.structuredContent).toEqual({
      ok: true,
      result: { owner: actor.sub, label: 'my-result' },
      contentTrust: 'untrusted',
    });
    const data = f.requests.filter(
      (request) => new URL(request.url).pathname === '/rest/v1/rpc/isolation_lookup',
    );
    expect(data).toHaveLength(1);
    expect(data[0]?.method).toBe('GET');
    expect(data[0]?.headers.get('accept-profile')).toBe('app_synthetic');
    expect(data[0]?.headers.get('apikey')).toBe(PUBLISHABLE);
    expect(data[0]?.authorization).toBe(`Bearer ${actor.b}`);
    expect(data[0]?.body).toBe('');
    expect(
      f.requests.every(
        (request) => !f.actors.some((item) => request.authorization === `Bearer ${item.a}`),
      ),
    ).toBe(true);
    expect(JSON.stringify(result)).not.toContain(actor.a);
    expect(JSON.stringify(result)).not.toContain(actor.b);
  });

  it('keeps two native bindings separate and denies a revoked actor before another capability read', async () => {
    const f = await fixture();
    for (const actor of f.actors) await f.bind(actor);
    const results = await Promise.all(
      f.actors.map(async (actor) =>
        reply(
          await f.handler(
            rpcRequest(actor.a, 'tools/call', {
              name: 'app_isolation_lookup',
              arguments: { label: actor.sub },
            }),
          ),
        ),
      ),
    );
    for (let index = 0; index < f.actors.length; index += 1) {
      const actor = f.actors[index];
      if (!actor) throw Error('Missing fixture actor');
      expect(results[index]?.result?.structuredContent).toEqual({
        ok: true,
        result: { owner: actor.sub, label: actor.sub },
        contentTrust: 'untrusted',
      });
    }
    const actor = f.actors[0];
    if (!actor) throw Error('Missing fixture actor');
    const before = f.requests.filter(
      (request) => new URL(request.url).pathname === '/rest/v1/rpc/isolation_lookup',
    ).length;
    f.revoked.add(actor.sub);
    const denied = await f.handler(
      rpcRequest(actor.a, 'tools/call', {
        name: 'app_isolation_lookup',
        arguments: { label: 'after-revocation' },
      }),
    );
    expect(denied.status).toBe(403);
    expect(await denied.json()).toMatchObject({
      error: 'downstream_credential_unresolved',
      stage: 'liveness',
    });
    expect(
      f.requests.filter(
        (request) => new URL(request.url).pathname === '/rest/v1/rpc/isolation_lookup',
      ),
    ).toHaveLength(before);
  });
});
