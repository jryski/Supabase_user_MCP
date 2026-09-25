import { Client } from '@modelcontextprotocol/client';
import type { JSONRPCMessage, Transport } from '@modelcontextprotocol/server';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import type { AddressInfo } from 'node:net';
import { createServer as createNetServer } from 'node:net';

import {
  DOWNSTREAM_CREDENTIAL_UNRESOLVED,
  LOCAL_DISPATCH_TTL_MS,
  LOCAL_LAB_MCP_RESOURCE_URI,
} from '@supabase-user-mcp/contracts';
import { jwtVerify, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import { createAuthorizationServerMetadata } from './authorization-server-metadata.js';
import {
  createLabDualGrantBroker,
  LAB_DUAL_GRANT_FIXTURE_TRANSPORT,
  LAB_DUAL_GRANT_STATE_MACHINE,
  type LabDualGrantBroker,
  LabDualGrantError,
  type LabUpstreamOAuth,
  listenLabOAuthCallback,
} from './lab-dual-grant-broker.js';
import { SERVER_NAME, SERVER_VERSION } from './server.js';
import { generateS256PkceChallenge } from './local-oauth-pkce-client.js';
import { containsSecretMaterial, createRemoteHttpProfile } from './remote-http-profile.js';
import {
  createRemoteHttpHandlerFromEnvironment,
  LAB_DUAL_GRANT_ENV,
} from './remote-http-startup.js';
import {
  mintSyntheticAccessToken,
  SYNTHETIC_OAUTH_HMAC_SECRET,
  SyntheticOAuthLab,
} from './synthetic-oauth-lab.js';

const RESOURCE = LOCAL_LAB_MCP_RESOURCE_URI;
const UPSTREAM_ISSUER = 'http://127.0.0.1:54321/auth/v1';
const UPSTREAM_RESOURCE = 'http://127.0.0.1:54321/rest/v1';
const DATA_ORIGIN = 'http://127.0.0.1:54321';
const MCP_CLIENT = 'smp-lab-mcp-client';
const UPSTREAM_CLIENT = 'smp-lab-upstream-client';
const OTHER_CLIENT = 'smp-lab-other-client';
const PUBLISHABLE = 'sb_publishable_lab_dual_grant';
const CLIENT_NAME = 'lab-maintained-mcp';
const CLIENT_VERSION = 'r2-test-9f3a';
const ALICE_MEMORY = 'mem_ALICE_LAB_NOTE_00000001';
const BOB_MEMORY = 'mem_BOB_LAB_NOTE_0000000001';

interface MemoryRow {
  readonly id: string;
  readonly title: string;
  readonly content: string;
  readonly createdAt: string;
  readonly provenanceSummary: string;
  readonly owner: string;
}

function principal(): string {
  return randomUUID();
}

function memory(owner: string, id: string): MemoryRow {
  return {
    id,
    title: 'Synthetic note',
    content: 'loopback fixture',
    createdAt: '2026-09-22T12:00:00.000Z',
    provenanceSummary: 'lab',
    owner,
  };
}

function publicRow(row: MemoryRow): Omit<MemoryRow, 'owner'> {
  return {
    id: row.id,
    title: row.title,
    content: row.content,
    createdAt: row.createdAt,
    provenanceSummary: row.provenanceSummary,
  };
}

function scriptedFetch(
  rows: readonly MemoryRow[],
  observed: string[],
  paths: string[],
): typeof globalThis.fetch {
  return async (input, init) => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
    paths.push(url.pathname);
    const headers = new Headers(init?.headers);
    const authorization = headers.get('authorization') ?? '';
    observed.push(authorization);
    const token = authorization.slice('Bearer '.length);
    const payload = JSON.parse(
      Buffer.from(token.split('.')[1] ?? '', 'base64url').toString('utf8'),
    ) as {
      sub?: string;
    };
    const sub = payload.sub ?? '';
    if (url.pathname === '/auth/v1/user') {
      return Response.json({ id: sub, aud: 'authenticated' });
    }
    const owned = rows.filter((row) => row.owner === sub);
    if (url.pathname.endsWith('/authorized_memory_get_v1')) {
      const body = JSON.parse(String(init?.body ?? '{}')) as { id?: string };
      const found = owned.find((row) => row.id === body.id);
      return Response.json({ record: found ? publicRow(found) : null });
    }
    if (url.pathname.endsWith('/authorized_memory_search_v1')) {
      return Response.json({
        rows: owned.slice(0, 1).map((row) => ({ ...publicRow(row), rank: 1 })),
      });
    }
    if (url.pathname.endsWith('/authorized_memory_list_recent_v1')) {
      return Response.json({ rows: owned.slice(0, 1).map((row) => publicRow(row)) });
    }
    return Response.json({ error: 'not_found' }, { status: 404 });
  };
}

function adapt(
  lab: SyntheticOAuthLab,
  hooks?: {
    readonly exchange?: LabUpstreamOAuth['exchangeAuthorizationCode'];
    readonly refresh?: LabUpstreamOAuth['refresh'];
    readonly onRevoke?: () => void;
  },
): LabUpstreamOAuth {
  return {
    startAuthorization: (request) => lab.startAuthorization(request),
    approveAuthorization: (id) => lab.approveAuthorization(id),
    denyAuthorization: (id) => lab.denyAuthorization(id),
    exchangeAuthorizationCode: (input) =>
      hooks?.exchange ? hooks.exchange(input) : lab.exchangeAuthorizationCode(input),
    refresh: (input) => (hooks?.refresh ? hooks.refresh(input) : lab.refresh(input)),
    revokeGrant: (refreshToken) => {
      hooks?.onRevoke?.();
      lab.revokeGrant(refreshToken);
    },
  };
}

async function createBroker(input: {
  readonly upstream: LabUpstreamOAuth;
  readonly fetchImpl: typeof globalThis.fetch;
  readonly now?: () => number;
  readonly optIn?: boolean;
  readonly port?: number;
  readonly maintainedClientName?: string;
  readonly maintainedClientVersion?: string;
}): Promise<LabDualGrantBroker> {
  const port = input.port ?? 8765;
  return createLabDualGrantBroker({
    optIn: input.optIn ?? true,
    mcpIssuer: `http://127.0.0.1:${port}`,
    mcpClientId: MCP_CLIENT,
    mcpResourceUri: RESOURCE,
    upstreamIssuer: UPSTREAM_ISSUER,
    upstreamClientId: UPSTREAM_CLIENT,
    upstreamResourceUri: UPSTREAM_RESOURCE,
    exactRedirectUri: `http://127.0.0.1:${port}/lab/oauth/callback`,
    mcpClientRedirectUri: `http://127.0.0.1:${port}/lab/mcp/callback`,
    dataApiOrigin: DATA_ORIGIN,
    publishableKey: PUBLISHABLE,
    maintainedClientName: input.maintainedClientName ?? CLIENT_NAME,
    maintainedClientVersion: input.maintainedClientVersion ?? CLIENT_VERSION,
    upstream: input.upstream,
    fetch: input.fetchImpl,
    ...(input.now === undefined ? {} : { now: input.now }),
  });
}

function labFor(port: number, now?: () => number): SyntheticOAuthLab {
  return new SyntheticOAuthLab({
    issuer: UPSTREAM_ISSUER,
    resourceUri: UPSTREAM_RESOURCE,
    client: {
      clientId: UPSTREAM_CLIENT,
      redirectUri: `http://127.0.0.1:${port}/lab/oauth/callback`,
      tokenEndpointAuthMethod: 'none',
    },
    ...(now === undefined ? {} : { now }),
  });
}

async function login(broker: LabDualGrantBroker, who: string, port = 8765): Promise<string> {
  const sessionId = broker.openLoginSession(who);
  const pkce = generateS256PkceChallenge();
  const flowId = broker.beginMcpAuthorization({
    loginSessionId: sessionId,
    clientId: MCP_CLIENT,
    redirectUri: `http://127.0.0.1:${port}/lab/mcp/callback`,
    codeChallenge: pkce.codeChallenge,
    codeChallengeMethod: 'S256',
    state: randomBytes(16).toString('base64url'),
    resource: RESOURCE,
  });
  const mcpRedirect = broker.approveMcpConsent(flowId);
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
  const issued = await broker.exchangeMcpAuthorizationCode({
    grantType: 'authorization_code',
    code: mcpRedirect.searchParams.get('code') ?? '',
    clientId: MCP_CLIENT,
    redirectUri: `http://127.0.0.1:${port}/lab/mcp/callback`,
    codeVerifier: pkce.codeVerifier,
    resource: RESOURCE,
  });
  return issued.accessToken;
}

class LabHttpClientTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;
  readonly sent: JSONRPCMessage[] = [];
  readonly statuses: number[] = [];

  constructor(
    private readonly handler: (request: Request) => Promise<Response>,
    private readonly token: string,
  ) {}

  async start(): Promise<void> {}

  async send(message: JSONRPCMessage): Promise<void> {
    this.sent.push(message);
    const response = await this.handler(
      new Request(RESOURCE, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.token}`,
          Accept: 'application/json',
          'content-type': 'application/json',
        },
        body: JSON.stringify(message),
      }),
    );
    this.statuses.push(response.status);
    if (!('id' in message)) return;
    if (!response.ok) {
      throw new Error(`lab http ${response.status}`);
    }
    this.onmessage?.((await response.json()) as JSONRPCMessage);
  }

  async close(): Promise<void> {
    this.onclose?.();
  }
}

function toolRequest(
  token: string,
  name: string,
  args: unknown,
  extra?: Record<string, unknown>,
): Request {
  return new Request(RESOURCE, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name, arguments: args, ...extra },
    }),
  });
}

function profile(broker: LabDualGrantBroker, lab: SyntheticOAuthLab) {
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

async function structured(
  response: Response,
): Promise<{ ok?: boolean; record?: { id?: string }; error?: { code?: string } }> {
  const body = (await response.json()) as {
    result?: {
      structuredContent?: { ok?: boolean; record?: { id?: string }; error?: { code?: string } };
    };
    error?: string;
  };
  return body.result?.structuredContent ?? {};
}

describe('lab dual-grant broker r2', () => {
  it('keeps the ordinary profile fail-closed when the opt-in is off', async () => {
    const observed: string[] = [];
    const paths: string[] = [];
    const lab = labFor(8765);
    const broker = await createBroker({
      upstream: adapt(lab),
      fetchImpl: scriptedFetch([], observed, paths),
      optIn: false,
    });
    expect(broker.profileHook.enabled).toBe(false);
    expect(LAB_DUAL_GRANT_STATE_MACHINE.restart.provesProviderRevoke).toBe(false);
    expect(LAB_DUAL_GRANT_STATE_MACHINE.disconnect).toBe('cancels_request_only');
    const handler = createRemoteHttpProfile({
      resourceUri: RESOURCE,
      issuer: UPSTREAM_ISSUER,
      expectedClientId: UPSTREAM_CLIENT,
      signingKey: { kind: 'hmac', secret: SYNTHETIC_OAUTH_HMAC_SECRET },
      revocationAuthority: { inspectAccessToken: async () => 'active' },
      authorizationServerMetadata: createAuthorizationServerMetadata(UPSTREAM_ISSUER),
      allowInsecureIssuer: true,
      labDualGrant: broker.profileHook,
    });
    const token = await mintSyntheticAccessToken({
      issuer: UPSTREAM_ISSUER,
      resourceUri: RESOURCE,
      principalId: principal(),
      clientId: UPSTREAM_CLIENT,
      sessionId: randomUUID(),
    });
    const response = await handler(toolRequest(token, 'memory_get', { id: ALICE_MEMORY }));
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: DOWNSTREAM_CREDENTIAL_UNRESOLVED });
    expect(paths.filter((path) => path.startsWith('/rest/v1'))).toEqual([]);
    const callback = await handler(
      new Request(`${RESOURCE.replace(/\/mcp$/, '')}/lab/oauth/callback`),
    );
    expect(callback.status).toBe(404);
  });

  it('runs the opt-in read path and records the configured client identity', async () => {
    const who = principal();
    const observed: string[] = [];
    const paths: string[] = [];
    const lab = labFor(8765);
    const broker = await createBroker({
      upstream: adapt(lab),
      fetchImpl: scriptedFetch([memory(who, ALICE_MEMORY)], observed, paths),
      maintainedClientVersion: CLIENT_VERSION,
    });
    const handler = profile(broker, lab);
    const token = await login(broker, who);
    const listed = await handler(
      new Request(RESOURCE, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
      }),
    );
    expect(listed.status).toBe(200);
    expect(paths).toEqual([]);
    const response = await handler(toolRequest(token, 'memory_get', { id: ALICE_MEMORY }));
    expect(response.status).toBe(200);
    expect(await structured(response)).toMatchObject({ ok: true, record: { id: ALICE_MEMORY } });
    expect(observed.every((value) => value.startsWith('Bearer ') && !value.includes(token))).toBe(
      true,
    );
    expect(paths.some((path) => path.startsWith('/rest/v1'))).toBe(true);
    expect(paths.some((path) => path === '/auth/v1/user')).toBe(true);
    const receipt = broker.buildLabReceipt();
    expect(receipt.maintainedClientName).toBe(CLIENT_NAME);
    expect(receipt.maintainedClientVersion).toBe(CLIENT_VERSION);
    expect(receipt.custody).toBe('memory-only');
    expect(JSON.stringify(receipt)).not.toContain('eyJ');
    expect(containsSecretMaterial(receipt, [token, ...observed])).toBe(false);
  });

  it('completes initialize, tools/list, and tools/call through the MCP client SDK', async () => {
    const sdkName = 'lab-sdk-mcp-client';
    const sdkVersion = '0.0.0-lab-sdk';
    const who = principal();
    const observed: string[] = [];
    const paths: string[] = [];
    const lab = labFor(8765);
    const broker = await createBroker({
      upstream: adapt(lab),
      fetchImpl: scriptedFetch([memory(who, ALICE_MEMORY)], observed, paths),
      maintainedClientName: sdkName,
      maintainedClientVersion: sdkVersion,
    });
    const handler = profile(broker, lab);
    const token = await login(broker, who);
    const transport = new LabHttpClientTransport(handler, token);
    const client = new Client({ name: sdkName, version: sdkVersion });
    await client.connect(transport);
    expect(client.getServerVersion()).toEqual({ name: SERVER_NAME, version: SERVER_VERSION });
    expect(client.getInstructions()).toContain('three declared memory tools');
    const listing = await client.listTools();
    expect(listing.tools.map((tool) => tool.name).toSorted()).toEqual([
      'memory_get',
      'memory_list_recent',
      'memory_search',
    ]);
    for (const tool of listing.tools) {
      expect(tool.inputSchema.type).toBe('object');
      expect(tool.inputSchema.additionalProperties).toBe(false);
      expect(tool.outputSchema).toBeDefined();
      expect(Object.keys(tool.inputSchema.properties ?? {}).length).toBeGreaterThan(0);
    }
    const called = await client.callTool({
      name: 'memory_get',
      arguments: { id: ALICE_MEMORY },
    });
    expect(called.structuredContent).toMatchObject({ ok: true, record: { id: ALICE_MEMORY } });
    const initialize = transport.sent.find(
      (message) => 'method' in message && message.method === 'initialize',
    );
    expect(initialize).toMatchObject({
      params: { clientInfo: { name: sdkName, version: sdkVersion } },
    });
    const receipt = broker.buildLabReceipt();
    expect(receipt.maintainedClientName).toBe(sdkName);
    expect(receipt.maintainedClientVersion).toBe(sdkVersion);
    expect(paths.some((path) => path === '/auth/v1/user')).toBe(true);
    expect(paths.some((path) => path.startsWith('/rest/v1'))).toBe(true);
    expect(observed.every((value) => value.startsWith('Bearer ') && !value.includes(token))).toBe(
      true,
    );
    await client.close();

    const closedPaths: string[] = [];
    const closed = createRemoteHttpProfile({
      resourceUri: RESOURCE,
      issuer: UPSTREAM_ISSUER,
      expectedClientId: UPSTREAM_CLIENT,
      signingKey: { kind: 'hmac', secret: SYNTHETIC_OAUTH_HMAC_SECRET },
      revocationAuthority: { inspectAccessToken: async () => 'active' },
      authorizationServerMetadata: createAuthorizationServerMetadata(UPSTREAM_ISSUER),
      allowInsecureIssuer: true,
      fetch: async (input) => {
        const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
        closedPaths.push(url.pathname);
        return new Response(null, { status: 599 });
      },
    });
    const ordinaryToken = await mintSyntheticAccessToken({
      issuer: UPSTREAM_ISSUER,
      resourceUri: RESOURCE,
      principalId: principal(),
      clientId: UPSTREAM_CLIENT,
      sessionId: randomUUID(),
    });
    const closedTransport = new LabHttpClientTransport(closed, ordinaryToken);
    const closedClient = new Client({ name: sdkName, version: sdkVersion });
    await expect(closedClient.connect(closedTransport)).rejects.toThrow(/lab http 403/);
    expect(closedTransport.statuses).toContain(403);
    expect(closedPaths).toEqual([]);
    await closedClient.close();
  });

  it('isolates two synthetic principals and denies the other row', async () => {
    const alice = principal();
    const bob = principal();
    const observed: string[] = [];
    const paths: string[] = [];
    const lab = labFor(8765);
    const broker = await createBroker({
      upstream: adapt(lab),
      fetchImpl: scriptedFetch(
        [memory(alice, ALICE_MEMORY), memory(bob, BOB_MEMORY)],
        observed,
        paths,
      ),
    });
    const handler = profile(broker, lab);
    const aliceToken = await login(broker, alice);
    const bobToken = await login(broker, bob);
    const [aliceResponse, bobResponse, crossed] = await Promise.all([
      handler(toolRequest(aliceToken, 'memory_get', { id: ALICE_MEMORY })),
      handler(toolRequest(bobToken, 'memory_search', { query: 'note', limit: 1 })),
      handler(toolRequest(aliceToken, 'memory_get', { id: BOB_MEMORY }, { principalId: bob })),
    ]);
    expect((await structured(aliceResponse)).record?.id).toBe(ALICE_MEMORY);
    const bobBody = (await bobResponse.json()) as {
      result?: { structuredContent?: { ok?: boolean; items?: { id?: string }[] } };
    };
    expect(bobBody.result?.structuredContent?.items?.[0]?.id).toBe(BOB_MEMORY);
    expect((await structured(crossed)).error?.code).toBe('RESOURCE_UNAVAILABLE');
    expect(
      observed.every((value) => !value.includes(aliceToken) && !value.includes(bobToken)),
    ).toBe(true);
    const subjects = observed.map((value) => {
      const token = value.slice('Bearer '.length);
      return JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64url').toString('utf8'))
        .sub as string;
    });
    expect(subjects).toContain(alice);
    expect(subjects).toContain(bob);
  });

  it('denies a wrong MCP client and a substituted upstream client', async () => {
    const who = principal();
    const observed: string[] = [];
    const paths: string[] = [];
    const lab = labFor(8765);
    const broker = await createBroker({
      upstream: adapt(lab, {
        exchange: async () => ({
          accessToken: await mintSyntheticAccessToken({
            issuer: UPSTREAM_ISSUER,
            resourceUri: UPSTREAM_RESOURCE,
            principalId: who,
            clientId: OTHER_CLIENT,
            sessionId: randomUUID(),
          }),
          refreshToken: 'rt_wrong_client',
          expiresIn: 60,
        }),
      }),
      fetchImpl: scriptedFetch([], observed, paths),
    });
    const sessionId = broker.openLoginSession(who);
    expect(() =>
      broker.beginMcpAuthorization({
        loginSessionId: sessionId,
        clientId: OTHER_CLIENT,
        redirectUri: 'http://127.0.0.1:8765/lab/mcp/callback',
        codeChallenge: generateS256PkceChallenge().codeChallenge,
        codeChallengeMethod: 'S256',
        state: randomBytes(16).toString('base64url'),
        resource: RESOURCE,
      }),
    ).toThrowError(expect.objectContaining({ code: 'wrong_client' }));
    const pkce = generateS256PkceChallenge();
    const flowId = broker.beginMcpAuthorization({
      loginSessionId: sessionId,
      clientId: MCP_CLIENT,
      redirectUri: 'http://127.0.0.1:8765/lab/mcp/callback',
      codeChallenge: pkce.codeChallenge,
      codeChallengeMethod: 'S256',
      state: randomBytes(16).toString('base64url'),
      resource: RESOURCE,
    });
    broker.approveMcpConsent(flowId);
    const upstream = broker.beginUpstreamAuthorization({
      parentFlowId: flowId,
      loginSessionId: sessionId,
    });
    const approved = broker.approveUpstreamConsent(upstream.flowId);
    await expect(
      broker.consumeUpstreamCallback({
        state: approved.searchParams.get('state') ?? '',
        iss: UPSTREAM_ISSUER,
        code: 'code_ignored',
      }),
    ).rejects.toMatchObject({ code: 'wrong_client' });
    expect(broker.describeUpstreamGrant(who)).toBeUndefined();
    expect(paths).toEqual([]);
  });

  it('rejects caller mapping keys and user_metadata client ids', async () => {
    const alice = principal();
    const bob = principal();
    let starts = 0;
    const lab = labFor(8765);
    const broker = await createBroker({
      upstream: {
        ...adapt(lab),
        startAuthorization: (request) => {
          starts += 1;
          return lab.startAuthorization(request);
        },
      },
      fetchImpl: scriptedFetch([], [], []),
    });
    const sessionId = broker.openLoginSession(alice);
    const pkce = generateS256PkceChallenge();
    const flowId = broker.beginMcpAuthorization({
      loginSessionId: sessionId,
      clientId: MCP_CLIENT,
      redirectUri: 'http://127.0.0.1:8765/lab/mcp/callback',
      codeChallenge: pkce.codeChallenge,
      codeChallengeMethod: 'S256',
      state: randomBytes(16).toString('base64url'),
      resource: RESOURCE,
    });
    broker.approveMcpConsent(flowId);
    expect(() =>
      broker.beginUpstreamAuthorization({
        parentFlowId: flowId,
        loginSessionId: sessionId,
        expectedPrincipalId: bob,
      }),
    ).toThrowError(expect.objectContaining({ code: 'caller_mapping_rejected' }));
    expect(starts).toBe(0);
    const metadataOnly = await new SignJWT({
      role: 'authenticated',
      aud: 'authenticated',
      user_metadata: { client_id: UPSTREAM_CLIENT },
      session_id: randomUUID(),
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuer(UPSTREAM_ISSUER)
      .setSubject(alice)
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(SYNTHETIC_OAUTH_HMAC_SECRET);
    const forged = await createBroker({
      upstream: adapt(lab, {
        exchange: async () => ({
          accessToken: metadataOnly,
          refreshToken: 'rt_metadata',
          expiresIn: 60,
        }),
      }),
      fetchImpl: scriptedFetch([], [], []),
    });
    const forgedSession = forged.openLoginSession(alice);
    const forgedPkce = generateS256PkceChallenge();
    const forgedFlow = forged.beginMcpAuthorization({
      loginSessionId: forgedSession,
      clientId: MCP_CLIENT,
      redirectUri: 'http://127.0.0.1:8765/lab/mcp/callback',
      codeChallenge: forgedPkce.codeChallenge,
      codeChallengeMethod: 'S256',
      state: randomBytes(16).toString('base64url'),
      resource: RESOURCE,
    });
    forged.approveMcpConsent(forgedFlow);
    const forgedUpstream = forged.beginUpstreamAuthorization({
      parentFlowId: forgedFlow,
      loginSessionId: forgedSession,
    });
    forged.approveUpstreamConsent(forgedUpstream.flowId);
    await expect(
      forged.consumeUpstreamCallback({
        state: forgedUpstream.state,
        iss: UPSTREAM_ISSUER,
        code: 'forged',
      }),
    ).rejects.toMatchObject({ code: 'user_metadata_rejected' });
    expect(forged.custodyCounts().grants).toBe(0);

    const appMetadataToken = await new SignJWT({
      role: 'authenticated',
      aud: 'authenticated',
      app_metadata: { client_id: UPSTREAM_CLIENT },
      session_id: randomUUID(),
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuer(UPSTREAM_ISSUER)
      .setSubject(alice)
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(SYNTHETIC_OAUTH_HMAC_SECRET);
    const appBroker = await createBroker({
      upstream: adapt(labFor(8765), {
        exchange: async () => ({
          accessToken: appMetadataToken,
          refreshToken: 'rt_app_metadata',
          expiresIn: 3600,
        }),
      }),
      fetchImpl: scriptedFetch([memory(alice, ALICE_MEMORY)], [], []),
    });
    const appSession = appBroker.openLoginSession(alice);
    const appPkce = generateS256PkceChallenge();
    const appFlow = appBroker.beginMcpAuthorization({
      loginSessionId: appSession,
      clientId: MCP_CLIENT,
      redirectUri: 'http://127.0.0.1:8765/lab/mcp/callback',
      codeChallenge: appPkce.codeChallenge,
      codeChallengeMethod: 'S256',
      state: randomBytes(16).toString('base64url'),
      resource: RESOURCE,
    });
    const appRedirect = appBroker.approveMcpConsent(appFlow);
    const appUpstream = appBroker.beginUpstreamAuthorization({
      parentFlowId: appFlow,
      loginSessionId: appSession,
    });
    appBroker.approveUpstreamConsent(appUpstream.flowId);
    await appBroker.consumeUpstreamCallback({
      state: appUpstream.state,
      iss: UPSTREAM_ISSUER,
      code: 'app',
    });
    const appToken = await appBroker.exchangeMcpAuthorizationCode({
      grantType: 'authorization_code',
      code: appRedirect.searchParams.get('code') ?? '',
      clientId: MCP_CLIENT,
      redirectUri: 'http://127.0.0.1:8765/lab/mcp/callback',
      codeVerifier: appPkce.codeVerifier,
      resource: RESOURCE,
    });
    const appResponse = await profile(
      appBroker,
      lab,
    )(toolRequest(appToken.accessToken, 'memory_get', { id: ALICE_MEMORY }));
    expect(appResponse.status).toBe(200);
    expect(appBroker.describeUpstreamGrant(alice)?.upstreamClientId).toBe(UPSTREAM_CLIENT);
  });

  it('denies callback replay, code replay, mix-up, and stale flows', async () => {
    let now = Date.now();
    const clock = () => now;
    const who = principal();
    const lab = labFor(8765, clock);
    const broker = await createBroker({
      upstream: adapt(lab),
      fetchImpl: scriptedFetch([], [], []),
      now: clock,
    });
    const sessionId = broker.openLoginSession(who);
    const firstPkce = generateS256PkceChallenge();
    const firstFlow = broker.beginMcpAuthorization({
      loginSessionId: sessionId,
      clientId: MCP_CLIENT,
      redirectUri: 'http://127.0.0.1:8765/lab/mcp/callback',
      codeChallenge: firstPkce.codeChallenge,
      codeChallengeMethod: 'S256',
      state: randomBytes(16).toString('base64url'),
      resource: RESOURCE,
    });
    const mcpRedirect = broker.approveMcpConsent(firstFlow);
    const upstream = broker.beginUpstreamAuthorization({
      parentFlowId: firstFlow,
      loginSessionId: sessionId,
    });
    const approved = broker.approveUpstreamConsent(upstream.flowId);
    const callback = {
      state: approved.searchParams.get('state') ?? '',
      iss: approved.searchParams.get('iss') ?? '',
      code: approved.searchParams.get('code') ?? '',
    };
    await broker.consumeUpstreamCallback(callback);
    await expect(broker.consumeUpstreamCallback(callback)).rejects.toMatchObject({
      code: 'replay',
    });
    const issued = await broker.exchangeMcpAuthorizationCode({
      grantType: 'authorization_code',
      code: mcpRedirect.searchParams.get('code') ?? '',
      clientId: MCP_CLIENT,
      redirectUri: 'http://127.0.0.1:8765/lab/mcp/callback',
      codeVerifier: firstPkce.codeVerifier,
      resource: RESOURCE,
    });
    await expect(
      broker.exchangeMcpAuthorizationCode({
        grantType: 'authorization_code',
        code: mcpRedirect.searchParams.get('code') ?? '',
        clientId: MCP_CLIENT,
        redirectUri: 'http://127.0.0.1:8765/lab/mcp/callback',
        codeVerifier: firstPkce.codeVerifier,
        resource: RESOURCE,
      }),
    ).rejects.toMatchObject({ code: 'replay' });
    expect(issued.accessToken.split('.')).toHaveLength(3);

    const secondPkce = generateS256PkceChallenge();
    const secondFlow = broker.beginMcpAuthorization({
      loginSessionId: sessionId,
      clientId: MCP_CLIENT,
      redirectUri: 'http://127.0.0.1:8765/lab/mcp/callback',
      codeChallenge: secondPkce.codeChallenge,
      codeChallengeMethod: 'S256',
      state: randomBytes(16).toString('base64url'),
      resource: RESOURCE,
    });
    broker.approveMcpConsent(secondFlow);
    const mixed = broker.beginUpstreamAuthorization({
      parentFlowId: secondFlow,
      loginSessionId: sessionId,
    });
    const mixedUrl = broker.approveUpstreamConsent(mixed.flowId);
    await expect(
      broker.consumeUpstreamCallback({
        state: mixedUrl.searchParams.get('state') ?? '',
        iss: `http://127.0.0.1:8765`,
        code: mixedUrl.searchParams.get('code') ?? '',
      }),
    ).rejects.toMatchObject({ code: 'mixup' });

    const thirdPkce = generateS256PkceChallenge();
    const thirdFlow = broker.beginMcpAuthorization({
      loginSessionId: sessionId,
      clientId: MCP_CLIENT,
      redirectUri: 'http://127.0.0.1:8765/lab/mcp/callback',
      codeChallenge: thirdPkce.codeChallenge,
      codeChallengeMethod: 'S256',
      state: randomBytes(16).toString('base64url'),
      resource: RESOURCE,
    });
    broker.approveMcpConsent(thirdFlow);
    const stale = broker.beginUpstreamAuthorization({
      parentFlowId: thirdFlow,
      loginSessionId: sessionId,
    });
    const staleUrl = broker.approveUpstreamConsent(stale.flowId);
    now += 10 * 60 * 1000 + 1;
    await expect(
      broker.consumeUpstreamCallback({
        state: staleUrl.searchParams.get('state') ?? '',
        iss: staleUrl.searchParams.get('iss') ?? '',
        code: staleUrl.searchParams.get('code') ?? '',
      }),
    ).rejects.toMatchObject({ code: 'stale' });
  });

  it('does not overwrite an existing grant family', async () => {
    const who = principal();
    const lab = labFor(8765);
    const broker = await createBroker({
      upstream: adapt(lab),
      fetchImpl: scriptedFetch([memory(who, ALICE_MEMORY)], [], []),
    });
    await login(broker, who);
    const first = broker.describeUpstreamGrant(who);
    const sessionId = broker.openLoginSession(who);
    const pkce = generateS256PkceChallenge();
    const flowId = broker.beginMcpAuthorization({
      loginSessionId: sessionId,
      clientId: MCP_CLIENT,
      redirectUri: 'http://127.0.0.1:8765/lab/mcp/callback',
      codeChallenge: pkce.codeChallenge,
      codeChallengeMethod: 'S256',
      state: randomBytes(16).toString('base64url'),
      resource: RESOURCE,
    });
    broker.approveMcpConsent(flowId);
    const upstream = broker.beginUpstreamAuthorization({
      parentFlowId: flowId,
      loginSessionId: sessionId,
    });
    const approved = broker.approveUpstreamConsent(upstream.flowId);
    await expect(
      broker.consumeUpstreamCallback({
        state: approved.searchParams.get('state') ?? '',
        iss: approved.searchParams.get('iss') ?? '',
        code: approved.searchParams.get('code') ?? '',
      }),
    ).rejects.toMatchObject({ code: 'grant_family_conflict' });
    expect(broker.describeUpstreamGrant(who)).toEqual(first);
  });

  it('refreshes once inside the local window and stops at the local deadline', async () => {
    let now = Date.now();
    const clock = () => now;
    const who = principal();
    let refreshCalls = 0;
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const lab = labFor(8765, clock);
    const broker = await createBroker({
      upstream: adapt(lab, {
        exchange: async (input) => {
          const issued = await lab.exchangeAuthorizationCode(input);
          return {
            ...issued,
            accessToken: await mintSyntheticAccessToken({
              issuer: UPSTREAM_ISSUER,
              resourceUri: UPSTREAM_RESOURCE,
              principalId: who,
              clientId: UPSTREAM_CLIENT,
              sessionId: randomUUID(),
              expiresInSec: 2,
              now: clock,
            }),
          };
        },
        refresh: async (input) => {
          refreshCalls += 1;
          await gate;
          return lab.refresh(input);
        },
      }),
      fetchImpl: scriptedFetch([memory(who, ALICE_MEMORY)], [], []),
      now: clock,
    });
    const handler = profile(broker, lab);
    const token = await login(broker, who);
    now += 3_000;
    const first = handler(toolRequest(token, 'memory_get', { id: ALICE_MEMORY }));
    const second = handler(toolRequest(token, 'memory_list_recent', { limit: 1 }));
    for (let attempt = 0; attempt < 40 && refreshCalls < 1; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
    release?.();
    const [left, right] = await Promise.all([first, second]);
    expect(left.status).toBe(200);
    expect(right.status).toBe(200);
    expect(refreshCalls).toBe(1);
    expect(broker.describeUpstreamGrant(who)?.generation).toBe(2);

    now += LOCAL_DISPATCH_TTL_MS;
    const blocked = await handler(toolRequest(token, 'memory_get', { id: ALICE_MEMORY }));
    expect(blocked.status).toBe(403);
    expect(await blocked.json()).toEqual({ error: 'local_dispatch_deadline' });
    expect(refreshCalls).toBe(1);
  });

  it('keeps broker revoke and provider revoke on separate clocks', async () => {
    const source = await readFile(new URL('./lab-dual-grant-broker.ts', import.meta.url), 'utf8');
    expect(source).not.toContain('ACCESS_TOKEN_REVOCATION_LATENCY_BOUND_MS');
    expect(source).not.toContain('urn:ietf:params:oauth:grant-type:token-exchange');
    expect(source).not.toContain("alg: 'HS256'");
    expect(source).not.toContain('Function.prototype.toString');
    expect(source).not.toContain('[native code]');
    const who = principal();
    const paths: string[] = [];
    const lab = labFor(8765);
    let providerCalls = 0;
    const broker = await createBroker({
      upstream: adapt(lab, {
        onRevoke: () => {
          providerCalls += 1;
        },
      }),
      fetchImpl: async (input, _init) => {
        const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
        paths.push(url.pathname);
        if (url.pathname === '/auth/v1/user') return Response.json({}, { status: 401 });
        return Response.json({ record: null });
      },
    });
    const handler = profile(broker, lab);
    const token = await login(broker, who);
    broker.revokeLocal(who);
    const local = await handler(toolRequest(token, 'memory_get', { id: ALICE_MEMORY }));
    expect(local.status).toBe(403);
    expect(providerCalls).toBe(0);
    expect(broker.providerRevocationCount()).toBe(0);
    expect(paths.filter((path) => path.startsWith('/rest/v1'))).toEqual([]);
  });

  it('denies the next call when the provider rejects the upstream token', async () => {
    const who = principal();
    const paths: string[] = [];
    const observed: string[] = [];
    const lab = labFor(8765);
    const broker = await createBroker({
      upstream: adapt(lab),
      fetchImpl: async (input, init) => {
        const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
        paths.push(url.pathname);
        observed.push(new Headers(init?.headers).get('authorization') ?? '');
        if (url.pathname === '/auth/v1/user') return Response.json({}, { status: 401 });
        return Response.json({ record: null });
      },
    });
    const handler = profile(broker, lab);
    const token = await login(broker, who);
    const denied = await handler(toolRequest(token, 'memory_get', { id: ALICE_MEMORY }));
    expect(denied.status).toBe(403);
    expect(await denied.json()).toEqual({ error: 'upstream_revoked' });
    expect(paths.filter((path) => path.startsWith('/rest/v1'))).toEqual([]);
    expect(observed.every((value) => !value.includes(token))).toBe(true);
    expect(broker.providerRevocationCount()).toBe(0);
    const again = await handler(toolRequest(token, 'memory_get', { id: ALICE_MEMORY }));
    expect(again.status).toBe(403);
    expect(await again.json()).toEqual({ error: 'reauth_required' });
  });

  it('cancels one request without dropping the grant and restart does not revoke upstream', async () => {
    const who = principal();
    const lab = labFor(8765);
    let capturedRefresh = '';
    const broker = await createBroker({
      upstream: adapt(lab, {
        exchange: async (input) => {
          const issued = await lab.exchangeAuthorizationCode(input);
          capturedRefresh = issued.refreshToken;
          return issued;
        },
      }),
      fetchImpl: scriptedFetch([memory(who, ALICE_MEMORY)], [], []),
    });
    const handler = profile(broker, lab);
    const token = await login(broker, who);
    const controller = new AbortController();
    controller.abort();
    const cancelled = await handler(
      new Request(RESOURCE, {
        method: 'POST',
        signal: controller.signal,
        headers: {
          Authorization: `Bearer ${token}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: 'memory_get', arguments: { id: ALICE_MEMORY } },
        }),
      }),
    );
    expect(cancelled.status).toBe(499);
    expect(broker.custodyCounts().grants).toBe(1);
    const again = await handler(toolRequest(token, 'memory_get', { id: ALICE_MEMORY }));
    expect(again.status).toBe(200);
    expect(broker.providerRevocationCount()).toBe(0);
    await broker.discardMemoryCustody();
    expect(broker.custodyCounts()).toEqual({
      grants: 0,
      pendingFlows: 0,
      loginSessions: 0,
      mappings: 0,
    });
    expect(broker.providerRevocationCount()).toBe(0);
    await expect(
      lab.refresh({
        grantType: 'refresh_token',
        refreshToken: capturedRefresh,
        clientId: UPSTREAM_CLIENT,
        resource: UPSTREAM_RESOURCE,
      }),
    ).resolves.toEqual(expect.objectContaining({ tokenType: 'Bearer' }));
    const wiped = await handler(toolRequest(token, 'memory_get', { id: ALICE_MEMORY }));
    expect(wiped.status).toBe(401);
    const rebound = await login(broker, who);
    const restored = await handler(toolRequest(rebound, 'memory_get', { id: ALICE_MEMORY }));
    expect(restored.status).toBe(200);
    await broker.cleanup();
    expect(broker.buildLabReceipt().activeGrants).toBe(0);
    expect(
      containsSecretMaterial(broker.buildLabReceipt(), [token, capturedRefresh, rebound]),
    ).toBe(false);
  });

  it('uses distinct MCP signing keys and never the synthetic upstream HMAC', async () => {
    const who = principal();
    const lab = labFor(8765);
    const broker = await createBroker({
      upstream: adapt(lab),
      fetchImpl: scriptedFetch([memory(who, ALICE_MEMORY)], [], []),
    });
    const token = await login(broker, who);
    const header = JSON.parse(
      Buffer.from(token.split('.')[0] ?? '', 'base64url').toString('utf8'),
    ) as {
      alg?: string;
    };
    expect(header.alg).toBe('ES256');
    await expect(jwtVerify(token, SYNTHETIC_OAUTH_HMAC_SECRET)).rejects.toThrow();
    const receipt = broker.buildLabReceipt();
    expect(receipt.mcpSigningAlg).toBe('ES256');
    expect(receipt.mcpPublicJwkThumbprint.length).toBeGreaterThan(10);
    expect(receipt.optInDefault).toBe(false);
    await expect(
      createLabDualGrantBroker({
        optIn: true,
        mcpIssuer: 'http://127.0.0.1:8765',
        mcpClientId: MCP_CLIENT,
        mcpResourceUri: RESOURCE,
        upstreamIssuer: UPSTREAM_ISSUER,
        upstreamClientId: UPSTREAM_CLIENT,
        upstreamResourceUri: UPSTREAM_RESOURCE,
        exactRedirectUri: 'http://127.0.0.1:8765/lab/oauth/callback',
        mcpClientRedirectUri: 'http://127.0.0.1:8765/lab/mcp/callback',
        dataApiOrigin: DATA_ORIGIN,
        publishableKey: 'service_role_key',
        maintainedClientName: CLIENT_NAME,
        maintainedClientVersion: CLIENT_VERSION,
        upstream: adapt(lab),
        fetch: scriptedFetch([], [], []),
      }),
    ).rejects.toBeInstanceOf(LabDualGrantError);
  });

  it('serves the upstream callback only on 127.0.0.1 and denies replay', async () => {
    const port = await new Promise<number>((resolve, reject) => {
      const probe = createNetServer();
      probe.once('error', reject);
      probe.listen(0, '127.0.0.1', () => {
        const address = probe.address() as AddressInfo;
        probe.close(() => resolve(address.port));
      });
    });
    const who = principal();
    const lab = labFor(port);
    const broker = await createBroker({
      upstream: adapt(lab),
      fetchImpl: scriptedFetch([], [], []),
      port,
    });
    const server = listenLabOAuthCallback(broker, port);
    await new Promise<void>((resolve) => server.once('listening', () => resolve()));
    const address = server.address() as AddressInfo;
    expect(address.address).toBe('127.0.0.1');
    const sessionId = broker.openLoginSession(who);
    const pkce = generateS256PkceChallenge();
    const flowId = broker.beginMcpAuthorization({
      loginSessionId: sessionId,
      clientId: MCP_CLIENT,
      redirectUri: `http://127.0.0.1:${port}/lab/mcp/callback`,
      codeChallenge: pkce.codeChallenge,
      codeChallengeMethod: 'S256',
      state: randomBytes(16).toString('base64url'),
      resource: RESOURCE,
    });
    broker.approveMcpConsent(flowId);
    const upstream = broker.beginUpstreamAuthorization({
      parentFlowId: flowId,
      loginSessionId: sessionId,
    });
    const approved = broker.approveUpstreamConsent(upstream.flowId);
    const first = await fetch(approved);
    const second = await fetch(approved);
    expect(first.status).toBe(200);
    expect(second.status).toBe(400);
    expect(await second.json()).toEqual({ error: 'replay' });
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  });

  it('requires the startup flag before the lab hook can dispatch', async () => {
    const who = principal();
    const observed: string[] = [];
    const paths: string[] = [];
    const lab = labFor(8765);
    const broker = await createBroker({
      upstream: adapt(lab),
      fetchImpl: scriptedFetch([memory(who, ALICE_MEMORY)], observed, paths),
    });
    const token = await login(broker, who);
    const baseEnv = {
      SUPABASE_USER_MCP_RESOURCE_URI: RESOURCE,
      SUPABASE_USER_MCP_AUTHORIZATION_SERVER: 'http://127.0.0.1:62421/auth/v1',
      SUPABASE_USER_MCP_ORIGIN: 'https://data.loopback.invalid',
      SUPABASE_USER_MCP_PUBLISHABLE_KEY: PUBLISHABLE,
      SUPABASE_USER_MCP_OAUTH_CLIENT_ID: UPSTREAM_CLIENT,
    };
    const metadata = createAuthorizationServerMetadata('http://127.0.0.1:62421/auth/v1');
    const closed = createRemoteHttpHandlerFromEnvironment({
      env: baseEnv,
      revocationAuthority: lab,
      authorizationServerMetadata: metadata,
      labDualGrant: broker.profileHook,
    });
    const denied = await closed(toolRequest(token, 'memory_get', { id: ALICE_MEMORY }));
    expect(denied.status).toBe(401);
    const open = createRemoteHttpHandlerFromEnvironment({
      env: { ...baseEnv, [LAB_DUAL_GRANT_ENV]: '1' },
      revocationAuthority: lab,
      authorizationServerMetadata: metadata,
      labDualGrant: broker.profileHook,
    });
    const allowed = await open(toolRequest(token, 'memory_get', { id: ALICE_MEMORY }));
    expect(allowed.status).toBe(200);
    const flaggedWithoutHook = createRemoteHttpHandlerFromEnvironment({
      env: { ...baseEnv, [LAB_DUAL_GRANT_ENV]: '1' },
      revocationAuthority: lab,
      authorizationServerMetadata: metadata,
    });
    const absent = await flaggedWithoutHook(
      new Request('http://127.0.0.1:62421/lab/oauth/callback'),
    );
    expect([400, 404]).toContain(absent.status);
    expect(paths.every((path) => !path.includes('admin'))).toBe(true);
  });

  it('rechecks authority after identity and before /rest/v1', async () => {
    for (const mode of ['revoke', 'deadline', 'cleanup'] as const) {
      let now = Date.now();
      const who = principal();
      const paths: string[] = [];
      let release: (() => void) | undefined;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      const lab = labFor(8765, () => now);
      const broker = await createBroker({
        upstream: adapt(lab),
        now: () => now,
        fetchImpl: async (input) => {
          const url = new URL(
            typeof input === 'string' || input instanceof URL ? input : input.url,
          );
          paths.push(url.pathname);
          if (url.pathname === '/auth/v1/user') {
            if (mode === 'revoke') broker.revokeLocal(who);
            if (mode === 'deadline') now += LOCAL_DISPATCH_TTL_MS + 1;
            if (mode === 'cleanup') await broker.cleanup();
            await gate;
            return Response.json({ id: who, aud: 'authenticated' });
          }
          return Response.json({ record: null });
        },
      });
      const handler = profile(broker, lab);
      const token = await login(broker, who, 8765);
      const pending = handler(toolRequest(token, 'memory_get', { id: ALICE_MEMORY }));
      for (let attempt = 0; attempt < 40 && !paths.includes('/auth/v1/user'); attempt += 1) {
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
      release?.();
      const response = await pending;
      expect([mode, response.status]).not.toEqual([mode, 200]);
      expect(paths.filter((path) => path.startsWith('/rest/v1'))).toEqual([]);
      if (mode === 'cleanup') {
        expect(broker.custodyCounts()).toEqual({
          grants: 0,
          pendingFlows: 0,
          loginSessions: 0,
          mappings: 0,
        });
      }
      await broker.cleanup();
    }
  });

  it('does not dispatch a stale generation after refresh replaces the grant', async () => {
    let now = Date.now();
    const who = principal();
    const paths: string[] = [];
    const identityTokens: string[] = [];
    const restTokens: string[] = [];
    let releaseIdentity: (() => void) | undefined;
    const identityGate = new Promise<void>((resolve) => {
      releaseIdentity = resolve;
    });
    const lab = labFor(8765, () => now);
    const broker = await createBroker({
      upstream: adapt(lab, {
        exchange: async (input) => {
          const issued = await lab.exchangeAuthorizationCode(input);
          return {
            ...issued,
            accessToken: await mintSyntheticAccessToken({
              issuer: UPSTREAM_ISSUER,
              resourceUri: UPSTREAM_RESOURCE,
              principalId: who,
              clientId: UPSTREAM_CLIENT,
              sessionId: randomUUID(),
              expiresInSec: 2,
              now: () => now,
            }),
          };
        },
      }),
      now: () => now,
      fetchImpl: async (input, init) => {
        const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
        paths.push(url.pathname);
        const authorization = new Headers(init?.headers).get('authorization') ?? '';
        if (url.pathname.startsWith('/rest/v1')) restTokens.push(authorization);
        if (url.pathname === '/auth/v1/user') {
          identityTokens.push(authorization);
          await identityGate;
          return Response.json({ id: who, aud: 'authenticated' });
        }
        return Response.json({ record: null });
      },
    });
    const handler = profile(broker, lab);
    const token = await login(broker, who);
    const original = broker.describeUpstreamGrant(who);
    const stale = handler(toolRequest(token, 'memory_get', { id: ALICE_MEMORY }));
    for (let attempt = 0; attempt < 40 && !paths.includes('/auth/v1/user'); attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    now += 3_000;
    const fresh = handler(toolRequest(token, 'memory_get', { id: ALICE_MEMORY }));
    for (let attempt = 0; attempt < 40; attempt += 1) {
      if (broker.describeUpstreamGrant(who)?.generation === 2) break;
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    expect(broker.describeUpstreamGrant(who)?.generation).toBe(2);
    expect(broker.describeUpstreamGrant(who)?.grantFamily).toBe(original?.grantFamily);
    releaseIdentity?.();
    const [staleResponse, freshResponse] = await Promise.all([stale, fresh]);
    expect(staleResponse.status).toBe(403);
    expect(await staleResponse.json()).toEqual({ error: 'reauth_required' });
    expect(freshResponse.status).toBe(200);
    expect(paths.filter((path) => path.startsWith('/rest/v1'))).toHaveLength(1);
    expect(identityTokens.length).toBeGreaterThanOrEqual(2);
    expect(restTokens).toEqual([identityTokens[1]]);
    expect(restTokens[0]).not.toBe(identityTokens[0]);
  });

  it('does not restore custody after cleanup during exchange, signing, or refresh', async () => {
    const who = principal();
    const lab = labFor(8765);
    let releaseExchange: (() => void) | undefined;
    const exchangeGate = new Promise<void>((resolve) => {
      releaseExchange = resolve;
    });
    let exchangeEntered: (() => void) | undefined;
    const exchangeEnteredPromise = new Promise<void>((resolve) => {
      exchangeEntered = resolve;
    });
    const exchangeBroker = await createBroker({
      upstream: adapt(lab, {
        exchange: async (input) => {
          const tokens = await lab.exchangeAuthorizationCode(input);
          exchangeEntered?.();
          await exchangeGate;
          return tokens;
        },
      }),
      fetchImpl: scriptedFetch([], [], []),
    });
    const sessionId = exchangeBroker.openLoginSession(who);
    const pkce = generateS256PkceChallenge();
    const flowId = exchangeBroker.beginMcpAuthorization({
      loginSessionId: sessionId,
      clientId: MCP_CLIENT,
      redirectUri: 'http://127.0.0.1:8765/lab/mcp/callback',
      codeChallenge: pkce.codeChallenge,
      codeChallengeMethod: 'S256',
      state: randomBytes(16).toString('base64url'),
      resource: RESOURCE,
    });
    exchangeBroker.approveMcpConsent(flowId);
    const upstream = exchangeBroker.beginUpstreamAuthorization({
      parentFlowId: flowId,
      loginSessionId: sessionId,
    });
    const approved = exchangeBroker.approveUpstreamConsent(upstream.flowId);
    const inFlight = exchangeBroker.consumeUpstreamCallback({
      state: approved.searchParams.get('state') ?? '',
      iss: approved.searchParams.get('iss') ?? '',
      code: approved.searchParams.get('code') ?? '',
    });
    await exchangeEnteredPromise;
    await exchangeBroker.cleanup();
    expect(exchangeBroker.custodyCounts().grants).toBe(0);
    releaseExchange?.();
    await inFlight;
    expect(exchangeBroker.custodyCounts()).toEqual({
      grants: 0,
      pendingFlows: 0,
      loginSessions: 0,
      mappings: 0,
    });

    let releaseAdmit: (() => void) | undefined;
    const admitGate = new Promise<void>((resolve) => {
      releaseAdmit = resolve;
    });
    let admitEntered: (() => void) | undefined;
    const admitEnteredPromise = new Promise<void>((resolve) => {
      admitEntered = resolve;
    });
    const signingLab = labFor(8766);
    const signingBroker = await createLabDualGrantBroker({
      optIn: true,
      mcpIssuer: 'http://127.0.0.1:8766',
      mcpClientId: MCP_CLIENT,
      mcpResourceUri: RESOURCE,
      upstreamIssuer: UPSTREAM_ISSUER,
      upstreamClientId: UPSTREAM_CLIENT,
      upstreamResourceUri: UPSTREAM_RESOURCE,
      exactRedirectUri: 'http://127.0.0.1:8766/lab/oauth/callback',
      mcpClientRedirectUri: 'http://127.0.0.1:8766/lab/mcp/callback',
      dataApiOrigin: DATA_ORIGIN,
      publishableKey: PUBLISHABLE,
      maintainedClientName: CLIENT_NAME,
      maintainedClientVersion: CLIENT_VERSION,
      upstream: adapt(signingLab),
      fetch: scriptedFetch([], [], []),
      beforeAdmitMcpToken: async () => {
        admitEntered?.();
        await admitGate;
      },
    });
    const signingSession = signingBroker.openLoginSession(who);
    const signingPkce = generateS256PkceChallenge();
    const signingFlow = signingBroker.beginMcpAuthorization({
      loginSessionId: signingSession,
      clientId: MCP_CLIENT,
      redirectUri: 'http://127.0.0.1:8766/lab/mcp/callback',
      codeChallenge: signingPkce.codeChallenge,
      codeChallengeMethod: 'S256',
      state: randomBytes(16).toString('base64url'),
      resource: RESOURCE,
    });
    const mcpRedirect = signingBroker.approveMcpConsent(signingFlow);
    const signingUpstream = signingBroker.beginUpstreamAuthorization({
      parentFlowId: signingFlow,
      loginSessionId: signingSession,
    });
    const signingApproved = signingBroker.approveUpstreamConsent(signingUpstream.flowId);
    await signingBroker.consumeUpstreamCallback({
      state: signingApproved.searchParams.get('state') ?? '',
      iss: signingApproved.searchParams.get('iss') ?? '',
      code: signingApproved.searchParams.get('code') ?? '',
    });
    const signing = signingBroker.exchangeMcpAuthorizationCode({
      grantType: 'authorization_code',
      code: mcpRedirect.searchParams.get('code') ?? '',
      clientId: MCP_CLIENT,
      redirectUri: 'http://127.0.0.1:8766/lab/mcp/callback',
      codeVerifier: signingPkce.codeVerifier,
      resource: RESOURCE,
    });
    await admitEnteredPromise;
    await signingBroker.cleanup();
    releaseAdmit?.();
    await expect(signing).rejects.toMatchObject({ code: 'reauth_required' });
    expect(signingBroker.custodyCounts().mappings).toBe(0);
    expect(signingBroker.custodyCounts().grants).toBe(0);

    let now = Date.now();
    let releaseRefresh: (() => void) | undefined;
    const refreshGate = new Promise<void>((resolve) => {
      releaseRefresh = resolve;
    });
    let refreshEntered: (() => void) | undefined;
    const refreshEnteredPromise = new Promise<void>((resolve) => {
      refreshEntered = resolve;
    });
    const refreshLab = labFor(8767, () => now);
    const refreshBroker = await createBroker({
      port: 8767,
      now: () => now,
      upstream: adapt(refreshLab, {
        exchange: async (input) => {
          const issued = await refreshLab.exchangeAuthorizationCode(input);
          return {
            ...issued,
            accessToken: await mintSyntheticAccessToken({
              issuer: UPSTREAM_ISSUER,
              resourceUri: UPSTREAM_RESOURCE,
              principalId: who,
              clientId: UPSTREAM_CLIENT,
              sessionId: randomUUID(),
              expiresInSec: 2,
              now: () => now,
            }),
          };
        },
        refresh: async (input) => {
          refreshEntered?.();
          await refreshGate;
          return refreshLab.refresh(input);
        },
      }),
      fetchImpl: scriptedFetch([memory(who, ALICE_MEMORY)], [], []),
    });
    const refreshHandler = profile(refreshBroker, refreshLab);
    const refreshToken = await login(refreshBroker, who, 8767);
    now += 3_000;
    const refreshed = refreshHandler(toolRequest(refreshToken, 'memory_get', { id: ALICE_MEMORY }));
    await refreshEnteredPromise;
    await refreshBroker.cleanup();
    releaseRefresh?.();
    const blocked = await refreshed;
    expect(blocked.status).toBe(403);
    expect(refreshBroker.custodyCounts().grants).toBe(0);
    expect(refreshBroker.custodyCounts().mappings).toBe(0);
  });

  it('rejects attacker-shaped loopback coordinates without a network call', async () => {
    const lab = labFor(8765);
    const base = {
      optIn: true,
      mcpIssuer: 'http://127.0.0.1:8765',
      mcpClientId: MCP_CLIENT,
      mcpResourceUri: RESOURCE,
      upstreamIssuer: UPSTREAM_ISSUER,
      upstreamClientId: UPSTREAM_CLIENT,
      upstreamResourceUri: UPSTREAM_RESOURCE,
      exactRedirectUri: 'http://127.0.0.1:8765/lab/oauth/callback',
      mcpClientRedirectUri: 'http://127.0.0.1:8765/lab/mcp/callback',
      dataApiOrigin: DATA_ORIGIN,
      publishableKey: PUBLISHABLE,
      maintainedClientName: CLIENT_NAME,
      maintainedClientVersion: CLIENT_VERSION,
      upstream: adapt(lab),
      fetch: scriptedFetch([], [], []),
    };
    const rejected = [
      { mcpIssuer: 'http://127.0.0.1.attacker.invalid:8765' },
      { mcpIssuer: 'http://user:pass@127.0.0.1:8765' },
      { mcpIssuer: 'http://localhost:8765' },
      { mcpIssuer: 'https://127.0.0.1:8765' },
      { dataApiOrigin: 'https://remote.example' },
      { dataApiOrigin: 'https://remote.example.invalid' },
      { exactRedirectUri: 'http://127.0.0.1:9999/lab/oauth/callback' },
      { upstreamIssuer: 'https://auth.example/auth/v1' },
      {
        mcpIssuer: 'http://127.0.0.1.attacker.invalid:8765',
        dataApiOrigin: 'https://remote.example.invalid',
      },
    ];
    for (const override of rejected) {
      await expect(createLabDualGrantBroker({ ...base, ...override })).rejects.toBeInstanceOf(
        LabDualGrantError,
      );
    }
    const loopback = await createLabDualGrantBroker({
      ...base,
      upstreamIssuer: 'http://127.0.0.1:9/auth/v1',
      upstreamResourceUri: 'http://127.0.0.1:9/rest/v1',
      dataApiOrigin: 'http://127.0.0.1:9',
    });
    expect(loopback.profileHook.allowInsecureIssuer).toBe(true);
    await loopback.cleanup();
  });

  it('rejects a thin global fetch wrapper for invalid fixtures', async () => {
    const fixtureIssuer = 'https://auth.remote.example.invalid/auth/v1';
    const fixtureResource = 'https://data.remote.example.invalid/rest/v1';
    const fixtureOrigin = 'https://data.remote.example.invalid';
    const lab = new SyntheticOAuthLab({
      issuer: fixtureIssuer,
      resourceUri: fixtureResource,
      client: {
        clientId: UPSTREAM_CLIENT,
        redirectUri: 'http://127.0.0.1:8765/lab/oauth/callback',
        tokenEndpointAuthMethod: 'none',
      },
    });
    const remoteFixture = {
      optIn: true,
      mcpIssuer: 'http://127.0.0.1:8765',
      mcpClientId: MCP_CLIENT,
      mcpResourceUri: RESOURCE,
      upstreamIssuer: fixtureIssuer,
      upstreamClientId: UPSTREAM_CLIENT,
      upstreamResourceUri: fixtureResource,
      exactRedirectUri: 'http://127.0.0.1:8765/lab/oauth/callback',
      mcpClientRedirectUri: 'http://127.0.0.1:8765/lab/mcp/callback',
      dataApiOrigin: fixtureOrigin,
      publishableKey: PUBLISHABLE,
      maintainedClientName: CLIENT_NAME,
      maintainedClientVersion: CLIENT_VERSION,
      upstream: adapt(lab),
    };
    let calls = 0;
    const wrapper: typeof globalThis.fetch = async (input, init) => {
      calls += 1;
      return globalThis.fetch(input, init);
    };
    const rejected = [
      { fetch: wrapper },
      { fetch: globalThis.fetch },
      { fetch: globalThis.fetch.bind(globalThis) },
      {},
      { fetch: wrapper, fixtureTransport: LAB_DUAL_GRANT_FIXTURE_TRANSPORT },
      {
        fetch: async () => new Response(null, { status: 599 }),
      },
    ] as const;
    for (const override of rejected) {
      await expect(
        createLabDualGrantBroker({ ...remoteFixture, ...override }),
      ).rejects.toMatchObject({ code: 'contract_fixture_not_a_network_target' });
    }
    expect(calls).toBe(0);
    await expect(
      createLabDualGrantBroker({
        ...remoteFixture,
        upstreamIssuer: UPSTREAM_ISSUER,
        upstreamResourceUri: UPSTREAM_RESOURCE,
        dataApiOrigin: DATA_ORIGIN,
        fixtureTransport: LAB_DUAL_GRANT_FIXTURE_TRANSPORT,
      }),
    ).rejects.toMatchObject({ code: 'contract_fixture_not_a_network_target' });
    await expect(
      createLabDualGrantBroker({
        ...remoteFixture,
        upstreamResourceUri: UPSTREAM_RESOURCE,
        dataApiOrigin: DATA_ORIGIN,
        fixtureTransport: LAB_DUAL_GRANT_FIXTURE_TRANSPORT,
      }),
    ).rejects.toMatchObject({ code: 'contract_fixture_not_a_network_target' });

    const originalFetch = globalThis.fetch;
    let networkCalls = 0;
    globalThis.fetch = async (input, init) => {
      networkCalls += 1;
      return originalFetch(input, init);
    };
    try {
      const broker = await createLabDualGrantBroker({
        ...remoteFixture,
        fixtureTransport: LAB_DUAL_GRANT_FIXTURE_TRANSPORT,
      });
      const who = principal();
      const handler = createRemoteHttpProfile({
        resourceUri: RESOURCE,
        issuer: fixtureIssuer,
        expectedClientId: UPSTREAM_CLIENT,
        signingKey: { kind: 'hmac', secret: SYNTHETIC_OAUTH_HMAC_SECRET },
        revocationAuthority: lab,
        authorizationServerMetadata: createAuthorizationServerMetadata(fixtureIssuer),
        allowInsecureIssuer: true,
        labDualGrant: broker.profileHook,
      });
      const token = await login(broker, who);
      const response = await handler(toolRequest(token, 'memory_get', { id: ALICE_MEMORY }));
      expect(response.status).toBe(200);
      expect(await structured(response)).toMatchObject({ ok: false });
      expect(calls).toBe(0);
      expect(networkCalls).toBe(0);
      await broker.cleanup();
    } finally {
      globalThis.fetch = originalFetch;
    }

    const loopbackNetwork = await createLabDualGrantBroker({
      ...remoteFixture,
      upstreamIssuer: 'http://127.0.0.1:9/auth/v1',
      upstreamResourceUri: 'http://127.0.0.1:9/rest/v1',
      dataApiOrigin: 'http://127.0.0.1:9',
      fetch: globalThis.fetch,
    });
    expect(loopbackNetwork.profileHook.enabled).toBe(true);
    await loopbackNetwork.cleanup();
  });

  it('handles refresh rejection on every waiter without an unhandled rejection', async () => {
    const seen: Array<{ name: string | undefined; message: string | undefined }> = [];
    const capture = (error: unknown): void => {
      const value = error as { name?: string; message?: string };
      seen.push({ name: value.name, message: value.message });
    };
    process.on('unhandledRejection', capture);
    try {
      let now = Date.now();
      const who = principal();
      const lab = labFor(8765, () => now);
      let refreshCalls = 0;
      let releaseRefresh: (() => void) | undefined;
      const refreshGate = new Promise<void>((resolve) => {
        releaseRefresh = resolve;
      });
      const broker = await createBroker({
        upstream: adapt(lab, {
          exchange: async (input) => {
            const issued = await lab.exchangeAuthorizationCode(input);
            return {
              ...issued,
              accessToken: await mintSyntheticAccessToken({
                issuer: UPSTREAM_ISSUER,
                resourceUri: UPSTREAM_RESOURCE,
                principalId: who,
                clientId: UPSTREAM_CLIENT,
                sessionId: randomUUID(),
                expiresInSec: 2,
                now: () => now,
              }),
            };
          },
          refresh: async () => {
            refreshCalls += 1;
            await refreshGate;
            throw new Error('synthetic-refresh-failure');
          },
        }),
        now: () => now,
        fetchImpl: scriptedFetch([memory(who, ALICE_MEMORY)], [], []),
      });
      const handler = profile(broker, lab);
      const token = await login(broker, who);
      now += 3_000;
      const leftPending = handler(toolRequest(token, 'memory_get', { id: ALICE_MEMORY }));
      const rightPending = handler(toolRequest(token, 'memory_list_recent', { limit: 1 }));
      for (let attempt = 0; attempt < 40 && refreshCalls < 1; attempt += 1) {
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
      await new Promise((resolve) => setTimeout(resolve, 20));
      releaseRefresh?.();
      const [left, right] = await Promise.all([leftPending, rightPending]);
      await new Promise((resolve) => setTimeout(resolve, 25));
      expect(seen).toEqual([]);
      expect(refreshCalls).toBe(1);
      expect(left.status).toBe(403);
      expect(right.status).toBe(403);
      expect(await left.json()).toEqual({ error: 'upstream_refresh_failed' });
      expect(await right.json()).toEqual({ error: 'upstream_refresh_failed' });

      let release: (() => void) | undefined;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      let entered: (() => void) | undefined;
      const enteredPromise = new Promise<void>((resolve) => {
        entered = resolve;
      });
      const revokeLab = labFor(8768, () => now);
      const revokeBroker = await createBroker({
        port: 8768,
        now: () => now,
        upstream: adapt(revokeLab, {
          exchange: async (input) => {
            const issued = await revokeLab.exchangeAuthorizationCode(input);
            return {
              ...issued,
              accessToken: await mintSyntheticAccessToken({
                issuer: UPSTREAM_ISSUER,
                resourceUri: UPSTREAM_RESOURCE,
                principalId: who,
                clientId: UPSTREAM_CLIENT,
                sessionId: randomUUID(),
                expiresInSec: 2,
                now: () => now,
              }),
            };
          },
          refresh: async (input) => {
            entered?.();
            await gate;
            return revokeLab.refresh(input);
          },
        }),
        fetchImpl: scriptedFetch([memory(who, ALICE_MEMORY)], [], []),
      });
      const revokeHandler = profile(revokeBroker, revokeLab);
      const revokeToken = await login(revokeBroker, who, 8768);
      now += 3_000;
      const pending = revokeHandler(toolRequest(revokeToken, 'memory_get', { id: ALICE_MEMORY }));
      await enteredPromise;
      revokeBroker.revokeLocal(who);
      release?.();
      const revoked = await pending;
      expect(revoked.status).toBe(403);
      expect(revokeBroker.describeUpstreamGrant(who)?.generation).toBe(1);
      expect(seen).toEqual([]);
      await broker.cleanup();
      await revokeBroker.cleanup();
    } finally {
      process.off('unhandledRejection', capture);
    }
  });
});
