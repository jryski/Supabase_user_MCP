import { Client } from '@modelcontextprotocol/client';
import { McpServer } from '@modelcontextprotocol/server';
import { StreamTransport } from '@supabase/mcp-utils';
import {
  CAPABILITY_APPROVAL_ALLOWLIST_VERSION,
  CAPABILITY_DESCRIPTOR_VERSION,
  CAPABILITY_REGISTRY_VERSION,
  type CapabilityDescriptorBody,
  capabilityBodySha256,
  createReadToolError,
} from '@supabase-user-mcp/contracts';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  createCapabilityRegistrationProfile,
  type CapabilityCurrentCredential,
  type CapabilityRegistrationConfig,
  prepareCapabilityMcpRegistration,
} from './capability-mcp-registration.js';

// Synthetic release build only. Production has no approvals; no test seam is exported.
const release = vi.hoisted(() => ({ value: undefined as unknown }));
vi.mock('./capability-release-approvals.js', () => ({
  get COMPILED_CAPABILITY_APPROVALS() {
    return release.value;
  },
}));

const HUMAN_A = '1a1a1a1a-0000-4000-8000-000000000001';
const HUMAN_B = '2b2b2b2b-0000-4000-8000-000000000002';
const B_CLIENT = 'synthetic-data-client';
const ORIGIN = 'https://synthetic.example';
const TOKEN_EXPIRY = Math.floor(Date.now() / 1_000) + 3_600;
const identity = (principalId = HUMAN_A) => ({ principalId, clientId: B_CLIENT });

function body(overrides: Partial<CapabilityDescriptorBody> = {}): CapabilityDescriptorBody {
  return {
    descriptorVersion: CAPABILITY_DESCRIPTOR_VERSION,
    name: 'app_example_lookup',
    title: 'Example lookup',
    description: 'Synthetic capability.',
    kind: 'read',
    rpc: { schema: 'app_synthetic', function: 'example_lookup' },
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['label'],
      properties: {
        label: { type: 'string', maxLength: 64 },
        limit: { type: 'integer', minimum: 1, maximum: 10 },
        active: { type: 'boolean' },
      },
    },
    limits: { maxResponseBytes: 8_192, timeoutMs: 200 },
    ...overrides,
  };
}

function approvals(bodies: CapabilityDescriptorBody[]) {
  return {
    allowlistVersion: CAPABILITY_APPROVAL_ALLOWLIST_VERSION,
    approvals: bodies.map((item) => ({ adr: 'ADR-0007', bodySha256: capabilityBodySha256(item) })),
  };
}

function registry(bodies: CapabilityDescriptorBody[]) {
  return {
    registryVersion: CAPABILITY_REGISTRY_VERSION,
    descriptors: bodies.map((item) => ({
      body: item,
      approval: { adr: 'ADR-0007', bodySha256: capabilityBodySha256(item) },
    })),
  };
}

function token(principalId = HUMAN_A, generation = 1, extra: Record<string, unknown> = {}) {
  return [
    Buffer.from('{}').toString('base64url'),
    Buffer.from(
      JSON.stringify({
        sub: principalId,
        role: 'authenticated',
        exp: TOKEN_EXPIRY,
        app_metadata: { client_id: B_CLIENT },
        iss: `${ORIGIN}/auth/v1`,
        aud: 'authenticated',
        generation,
        ...extra,
      }),
    ).toString('base64url'),
    'synthetic',
  ].join('.');
}

function current(principalId = HUMAN_A, generation = 1): CapabilityCurrentCredential {
  return {
    identity: identity(principalId),
    credentials: {
      projectPublishableKey: 'sb_publishable_synthetic',
      userAccessToken: token(principalId, generation),
    },
  };
}

function setup(
  bodies = [body()],
  overrides: Partial<CapabilityRegistrationConfig> = {},
  principalId = HUMAN_A,
) {
  release.value = approvals(bodies);
  const composition = bodies.some((item) => item.kind === 'proposal') ? 'application' : 'read-only';
  const profile = createCapabilityRegistrationProfile({
    registry: registry(bodies),
    adopterSchemas: ['app_synthetic'],
    composition,
    emitStartupEvent: () => undefined,
  });
  const fetcher = vi.fn<typeof fetch>(async () =>
    Response.json({ result: { value: 'synthetic' } }),
  );
  const credential = vi.fn(async () => current(principalId));
  const config: CapabilityRegistrationConfig = {
    profile,
    origin: ORIGIN,
    expectedDataClientId: B_CLIENT,
    currentCredential: credential,
    fetch: fetcher,
    governance: { maxRequestsPerWindow: 10_000 },
    ...overrides,
  };
  return {
    prepared: prepareCapabilityMcpRegistration(config, identity(principalId), composition),
    profile,
    config,
    fetcher,
    credential,
  };
}

beforeEach(() => {
  release.value = approvals([]);
});
afterEach(() => {
  vi.useRealTimers();
});

describe('release approval and startup profile', () => {
  it('rejects self-attested/unapproved edits atomically and never reloads a startup snapshot', () => {
    const first = body();
    release.value = approvals([first]);
    const input = registry([first]);
    const profile = createCapabilityRegistrationProfile({
      registry: input,
      adopterSchemas: ['app_synthetic'],
      composition: 'read-only',
      emitStartupEvent: () => undefined,
    });
    first.rpc.function = 'edited_later';
    input.descriptors.length = 0;
    expect(profile.status).toBe('ready');
    expect(profile.toolNames).toEqual(['app_example_lookup']);
    const edited = body({
      name: 'app_other_lookup',
      rpc: { schema: 'app_synthetic', function: 'other_lookup' },
    });
    const rejected = createCapabilityRegistrationProfile({
      registry: registry([body(), edited]),
      adopterSchemas: ['app_synthetic'],
      composition: 'read-only',
      emitStartupEvent: () => undefined,
    });
    expect(rejected.status).toBe('unavailable');
    expect(rejected.toolNames).toEqual([]);
  });

  it('rejects a caller-forged profile and a proposal in a read-only composition', () => {
    const { config } = setup([body({ kind: 'proposal' })]);
    expect(prepareCapabilityMcpRegistration(config, identity(), 'read-only').status).toBe(
      'unavailable',
    );
    expect(
      prepareCapabilityMcpRegistration(
        { ...config, profile: { ...config.profile } },
        identity(),
        'application',
      ).status,
    ).toBe('unavailable');
  });

  it('fails closed on malformed release data, forbidden schemas and logging failure', () => {
    for (const schema of ['public', 'auth', 'storage', 'pg_catalog']) {
      const item = body({ rpc: { schema, function: 'example_lookup' } });
      release.value = approvals([item]);
      expect(
        createCapabilityRegistrationProfile({
          registry: registry([item]),
          adopterSchemas: [schema],
          composition: 'read-only',
          emitStartupEvent: () => undefined,
        }).status,
      ).toBe('unavailable');
    }
    release.value = { allowlistVersion: 'wrong', approvals: [] };
    expect(
      createCapabilityRegistrationProfile({ adopterSchemas: [], composition: 'read-only' }).status,
    ).toBe('unavailable');
    release.value = approvals([]);
    expect(
      createCapabilityRegistrationProfile({
        adopterSchemas: [],
        composition: 'read-only',
        emitStartupEvent: () => {
          throw new Error('private');
        },
      }).status,
    ).toBe('unavailable');
  });
});

describe('fixed caller-scoped transport', () => {
  it('uses fixed GET/read profile and scalar argument envelope, with no caller routing', async () => {
    const { prepared, fetcher } = setup();
    expect(
      await prepared.execute('app_example_lookup', { label: 'one', active: true, limit: 3 }),
    ).toEqual({
      ok: true,
      result: { value: 'synthetic' },
      contentTrust: 'untrusted',
    });
    const [url, init] = fetcher.mock.calls[0] ?? [];
    expect(String(url)).toBe(
      `${ORIGIN}/rest/v1/rpc/example_lookup?input=%7B%22label%22%3A%22one%22%2C%22limit%22%3A3%2C%22active%22%3Atrue%7D`,
    );
    expect(init).toMatchObject({
      method: 'GET',
      redirect: 'error',
      headers: {
        Authorization: `Bearer ${token()}`,
        apikey: 'sb_publishable_synthetic',
        'Accept-Profile': 'app_synthetic',
        'Cache-Control': 'no-store',
      },
    });
    expect(init?.body).toBeUndefined();
    expect(new Headers(init?.headers).has('content-profile')).toBe(false);
  });

  it('uses only fixed POST/input envelope for explicit application proposals', async () => {
    const { prepared, fetcher } = setup([body({ kind: 'proposal' })]);
    await prepared.execute('app_example_lookup', { label: 'one' });
    const [url, init] = fetcher.mock.calls[0] ?? [];
    expect(url).toBe(`${ORIGIN}/rest/v1/rpc/example_lookup`);
    expect(init).toMatchObject({
      method: 'POST',
      body: '{"input":{"label":"one"}}',
      headers: { 'Content-Profile': 'app_synthetic' },
    });
  });

  it('denies forged fields, wrong types, unknown names and pre-cancelled calls before credentials/network', async () => {
    const { prepared, credential, fetcher } = setup();
    for (const input of [
      { label: 'one', schema: 'auth' },
      { label: 'one', user_id: HUMAN_B },
      { label: 'one', limit: 11 },
      { label: {} },
    ]) {
      expect(await prepared.execute('app_example_lookup', input)).toEqual(
        createReadToolError('INVALID_REQUEST'),
      );
    }
    expect(await prepared.execute('__proto__', { label: 'one' })).toEqual(
      createReadToolError('RESOURCE_UNAVAILABLE'),
    );
    expect(
      await prepared.execute(
        'app_example_lookup',
        { label: 'one' },
        { signal: AbortSignal.abort() },
      ),
    ).toEqual(createReadToolError('DEADLINE_EXCEEDED'));
    expect(credential).not.toHaveBeenCalled();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('reads refreshed credentials on each call and keeps concurrent users isolated', async () => {
    let generation = 1;
    const fetcher = vi.fn<typeof fetch>(async (_url, init) => {
      const auth = new Headers(init?.headers).get('authorization') ?? '';
      return Response.json({ result: { marker: auth.endsWith(token(HUMAN_B)) ? 'b' : 'a' } });
    });
    const a = setup([body()], {
      fetch: fetcher,
      currentCredential: async () => current(HUMAN_A, generation),
    });
    const b = setup([body()], { profile: a.profile, fetch: fetcher }, HUMAN_B);
    const outputs = await Promise.all([
      a.prepared.execute('app_example_lookup', { label: 'one' }),
      b.prepared.execute('app_example_lookup', { label: 'one' }),
    ]);
    expect(outputs).toMatchObject([{ result: { marker: 'a' } }, { result: { marker: 'b' } }]);
    generation = 2;
    await a.prepared.execute('app_example_lookup', { label: 'two' });
    expect(new Headers(fetcher.mock.calls[2]?.[1]?.headers).get('authorization')).toBe(
      `Bearer ${token(HUMAN_A, 2)}`,
    );
  });

  it('rejects provider identity, client, token role/sub/client and expired credential mismatches', async () => {
    const bad: CapabilityCurrentCredential[] = [
      { ...current(), identity: identity(HUMAN_B) },
      { ...current(), identity: { ...identity(), clientId: 'wrong-client' } },
      { ...current(), credentials: { ...current().credentials, userAccessToken: token(HUMAN_B) } },
      {
        ...current(),
        credentials: {
          ...current().credentials,
          userAccessToken: token(HUMAN_A, 1, { role: 'mcp_ingress' }),
        },
      },
      {
        ...current(),
        credentials: {
          ...current().credentials,
          userAccessToken: token(HUMAN_A, 1, { app_metadata: { client_id: 'wrong-client' } }),
        },
      },
      {
        ...current(),
        credentials: { ...current().credentials, userAccessToken: token(HUMAN_A, 1, { exp: 1 }) },
      },
      {
        ...current(),
        credentials: {
          ...current().credentials,
          userAccessToken: token(HUMAN_A, 1, { aud: 'wrong-audience' }),
        },
      },
      {
        ...current(),
        credentials: {
          ...current().credentials,
          userAccessToken: token(HUMAN_A, 1, { iss: 'https://wrong.example/auth/v1' }),
        },
      },
      {
        ...current(),
        credentials: {
          ...current().credentials,
          userAccessToken: token(HUMAN_A, 1, { client_id: 'wrong-client' }),
        },
      },
      {
        ...current(),
        credentials: {
          ...current().credentials,
          userAccessToken: token(HUMAN_A, 1, { app_metadata: {}, client_id: B_CLIENT }),
        },
      },
      {
        ...current(),
        credentials: { ...current().credentials, projectPublishableKey: 'not-publishable' },
      },
    ];
    for (const candidate of bad) {
      const { prepared, fetcher } = setup([body()], { currentCredential: async () => candidate });
      expect(await prepared.execute('app_example_lookup', { label: 'one' })).toEqual(
        createReadToolError('RESOURCE_UNAVAILABLE'),
      );
      expect(fetcher).not.toHaveBeenCalled();
    }
  });

  it('rechecks database revocation on every dispatch and sanitizes upstream errors', async () => {
    const { prepared, fetcher } = setup();
    expect((await prepared.execute('app_example_lookup', { label: 'one' })).ok).toBe(true);
    fetcher.mockResolvedValueOnce(
      new Response('private schema, token and raw SQL error', { status: 403 }),
    );
    expect(await prepared.execute('app_example_lookup', { label: 'one' })).toEqual(
      createReadToolError('RESOURCE_UNAVAILABLE'),
    );
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it('refuses malformed, non-object, extra-key, deep and prototype-bearing JSON envelopes', async () => {
    const deep = `${'{"nested":'.repeat(20)}null${'}'.repeat(20)}`;
    const values = [
      '[]',
      'null',
      '{"result":[]}',
      '{"result":{},"approval":true}',
      '{"result":{"__proto__":{}}}',
      `{"result":${deep}}`,
      '{',
    ];
    for (const text of values) {
      const { prepared } = setup([body()], {
        fetch: async () => new Response(text, { headers: { 'content-type': 'application/json' } }),
      });
      expect(await prepared.execute('app_example_lookup', { label: 'one' })).toEqual(
        createReadToolError('INTERNAL_ERROR'),
      );
    }
  });

  it('bounds streamed bytes and final MCP wire bytes', async () => {
    for (const [maximum, size] of [
      [2_000, 4_000],
      [2_000, 1_400],
    ] as const) {
      const { prepared } = setup(
        [body({ limits: { maxResponseBytes: maximum, timeoutMs: 200 } })],
        {
          fetch: async () => Response.json({ result: { text: 'x'.repeat(size) } }),
        },
      );
      expect(await prepared.execute('app_example_lookup', { label: 'one' })).toEqual(
        createReadToolError('RESPONSE_LIMIT_EXCEEDED'),
      );
    }
  });

  it('returns on deadline even if credential resolution ignores abort, and never dispatches late', async () => {
    vi.useFakeTimers();
    let resolveCredential: (value: CapabilityCurrentCredential) => void = () => undefined;
    const provider = vi
      .fn(async () => current())
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveCredential = resolve;
          }),
      );
    const { prepared, fetcher } = setup(
      [body({ limits: { maxResponseBytes: 8_192, timeoutMs: 20 } })],
      {
        currentCredential: provider,
        governance: { maxConcurrentExecutions: 1, maxRequestsPerWindow: 100 },
      },
    );
    const pending = prepared.execute('app_example_lookup', { label: 'one' });
    await vi.advanceTimersByTimeAsync(21);
    expect(await pending).toEqual(createReadToolError('DEADLINE_EXCEEDED'));
    expect(await prepared.execute('app_example_lookup', { label: 'one' })).toEqual(
      createReadToolError('RESOURCE_UNAVAILABLE'),
    );
    expect(provider).toHaveBeenCalledTimes(1);
    resolveCredential(current());
    await vi.advanceTimersByTimeAsync(0);
    expect(fetcher).not.toHaveBeenCalled();
    expect((await prepared.execute('app_example_lookup', { label: 'after-settlement' })).ok).toBe(
      true,
    );
  });

  it('suppresses late transport success after caller cancellation', async () => {
    let resolveFetch: (value: Response) => void = () => undefined;
    let called: () => void = () => undefined;
    const started = new Promise<void>((resolve) => {
      called = resolve;
    });
    const { prepared } = setup([body()], {
      fetch: () =>
        new Promise((resolve) => {
          resolveFetch = resolve;
          called();
        }),
    });
    const controller = new AbortController();
    const pending = prepared.execute(
      'app_example_lookup',
      { label: 'one' },
      { signal: controller.signal },
    );
    await started;
    controller.abort();
    expect(await pending).toEqual(createReadToolError('DEADLINE_EXCEEDED'));
    const cancelled = vi.fn();
    resolveFetch(
      new Response(new ReadableStream({ cancel: cancelled }), {
        headers: { 'content-type': 'application/json' },
      }),
    );
    await vi.waitFor(() => expect(cancelled).toHaveBeenCalledTimes(1));
  });
});

describe('MCP SDK integration', () => {
  it('lists and calls the approved tool over a real SDK transport with untrusted framing', async () => {
    const { prepared } = setup();
    const server = new McpServer({ name: 'synthetic-capability-server', version: '0.0.0' });
    prepared.register(server, (requestId, signal) => ({ requestId, signal }));
    expect(() => prepared.register(server, () => ({}))).toThrow('only once');
    const clientTransport = new StreamTransport();
    const serverTransport = new StreamTransport();
    const pipes = [
      clientTransport.readable.pipeTo(serverTransport.writable).catch(() => undefined),
      serverTransport.readable.pipeTo(clientTransport.writable).catch(() => undefined),
    ];
    const client = new Client(
      { name: 'synthetic-capability-client', version: '0.0.0' },
      { capabilities: {} },
    );
    try {
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const tools = await client.listTools();
      expect(tools.tools.map((tool) => tool.name)).toEqual(['app_example_lookup']);
      const result = await client.callTool({
        name: 'app_example_lookup',
        arguments: { label: 'one' },
      });
      expect(result.structuredContent).toEqual({
        ok: true,
        result: { value: 'synthetic' },
        contentTrust: 'untrusted',
      });
      expect(result.content).toMatchObject([
        { type: 'text', text: expect.stringMatching(/^SECURITY BOUNDARY:/u) },
      ]);
    } finally {
      await Promise.allSettled([client.close(), server.close()]);
      await Promise.all(pipes);
    }
  });
});
