import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createServer as createNetServer } from 'node:net';
import type { AddressInfo } from 'node:net';

import { Client } from '@modelcontextprotocol/client';
import type { JSONRPCMessage, Transport } from '@modelcontextprotocol/server';
import {
  DOWNSTREAM_CREDENTIAL_UNRESOLVED,
  LOCAL_LAB_MCP_RESOURCE_URI,
} from '@supabase-user-mcp/contracts';
import { describe, expect, it } from 'vitest';

import { createAuthorizationServerMetadata } from './authorization-server-metadata.js';
import { createGoTrueSessionRevocationAuthority } from './gotrue-revocation-authority.js';
import {
  createLabDualGrantBroker,
  type LabDualGrantBroker,
  listenLabOAuthCallback,
} from './lab-dual-grant-broker.js';
import {
  buildLabDualGrantM4Receipt,
  createLiveGoTrueLabUpstream,
} from './live-gotrue-lab-upstream.js';
import {
  approveLocalAuthorization,
  exchangeLocalAuthorizationCode,
  generateS256PkceChallenge,
  startLocalAuthorization,
} from './local-oauth-pkce-client.js';
import { containsSecretMaterial, createRemoteHttpProfile } from './remote-http-profile.js';
import {
  AUTHORIZATION_SERVER_ENV,
  LAB_DUAL_GRANT_ENV,
  OAUTH_CLIENT_ID_ENV,
  PUBLISHABLE_KEY_ENV,
  RESOURCE_URI_ENV,
  SUPABASE_ORIGIN_ENV,
  createRemoteHttpHandlerFromEnvironment,
} from './remote-http-startup.js';
import { SERVER_NAME, SERVER_VERSION } from './server.js';

const requiredEnvironment = [
  'M4_SUPABASE_URL',
  'M4_PUBLISHABLE_KEY',
  'M4_SERVICE_ROLE_KEY',
  'M4_ALICE_TOKEN',
  'M4_BOB_TOKEN',
  'M4_DB_URL',
] as const;

const enabled = requiredEnvironment.every((key) => (process.env[key] ?? '').length > 0);
const liveDescribe = enabled ? describe : describe.skip;
const RESOURCE = LOCAL_LAB_MCP_RESOURCE_URI;
const MCP_CLIENT = 'lab-dual-grant-mcp';
const ALICE = '11111111-1111-4111-9111-111111111111';
const BOB = '22222222-2222-4222-9222-222222222222';
const ALICE_MEMORY = 'mem_01JTESTALPHA000000000001';
const BOB_MEMORY = 'mem_01JTESTBETA0000000000001';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function env(name: (typeof requiredEnvironment)[number]): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}

function loopbackOrigin(value: string): URL {
  const url = new URL(value);
  if (
    url.protocol !== 'http:' ||
    url.hostname !== '127.0.0.1' ||
    url.username !== '' ||
    url.password !== ''
  ) {
    throw new Error('non_loopback_origin');
  }
  return url;
}

async function freeLoopbackPort(): Promise<number> {
  const server = createNetServer();
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address() as AddressInfo;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
  return address.port;
}

function seedUpstreamClient(dbUrl: string, clientId: string): void {
  if (!UUID.test(clientId)) throw new Error('client id must be a uuid');
  execFileSync(
    'psql',
    [
      dbUrl,
      '-v',
      'ON_ERROR_STOP=1',
      '-c',
      `insert into policy_lab.clients (client_id, state, valid_until)
       values ('${clientId}', 'active', '2099-01-01')
       on conflict (client_id) do update set state = excluded.state, valid_until = excluded.valid_until;
       insert into policy_lab.memberships (principal_id, client_id, workspace_id, state, valid_until)
       values
         ('${ALICE}', '${clientId}', 'workspace-mcp-alpha', 'active', '2099-01-01'),
         ('${BOB}', '${clientId}', 'workspace-mcp-beta', 'active', '2099-01-01')
       on conflict (principal_id, client_id, workspace_id) do update
         set state = excluded.state, valid_until = excluded.valid_until;
       insert into policy_lab.capability_grants
         (principal_id, client_id, workspace_id, capability, state, valid_until)
       values
         ('${ALICE}', '${clientId}', 'workspace-mcp-alpha', 'memory:read', 'active', '2099-01-01'),
         ('${ALICE}', '${clientId}', 'workspace-mcp-alpha', 'memory:search', 'active', '2099-01-01'),
         ('${BOB}', '${clientId}', 'workspace-mcp-beta', 'memory:read', 'active', '2099-01-01'),
         ('${BOB}', '${clientId}', 'workspace-mcp-beta', 'memory:search', 'active', '2099-01-01')
       on conflict (principal_id, client_id, workspace_id, capability) do update
         set state = excluded.state, valid_until = excluded.valid_until;`,
    ],
    { stdio: 'pipe' },
  );
}

async function approvedCode(input: {
  readonly authOrigin: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly resource: string;
  readonly userAccessToken: string;
  readonly publishableKey: string;
}): Promise<{ readonly code: string; readonly verifier: string }> {
  const pkce = generateS256PkceChallenge();
  const started = await startLocalAuthorization({
    authOrigin: input.authOrigin,
    clientId: input.clientId,
    redirectUri: input.redirectUri,
    resource: input.resource,
    codeChallenge: pkce.codeChallenge,
    state: randomUUID(),
    projectPublishableKey: input.publishableKey,
  });
  const approved = await approveLocalAuthorization({
    authOrigin: input.authOrigin,
    authorizationId: started.authorizationId,
    userAccessToken: input.userAccessToken,
    projectPublishableKey: input.publishableKey,
  });
  return { code: approved.code, verifier: pkce.codeVerifier };
}

async function exchangeCode(input: {
  readonly authOrigin: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly resource: string;
  readonly publishableKey: string;
  readonly code: string;
  readonly verifier: string;
}): Promise<string> {
  const tokens = await exchangeLocalAuthorizationCode({
    authOrigin: input.authOrigin,
    clientId: input.clientId,
    redirectUri: input.redirectUri,
    code: input.code,
    codeVerifier: input.verifier,
    resource: input.resource,
    projectPublishableKey: input.publishableKey,
  });
  return tokens.accessToken;
}

class LabHttpClientTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  constructor(
    private readonly handler: (request: Request) => Promise<Response>,
    private readonly token: string,
  ) {}

  async start(): Promise<void> {}

  async send(message: JSONRPCMessage): Promise<void> {
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
    if (!('id' in message)) return;
    if (!response.ok) throw new Error(`lab http ${response.status}`);
    this.onmessage?.((await response.json()) as JSONRPCMessage);
  }

  async close(): Promise<void> {
    this.onclose?.();
  }
}

function toolRequest(token: string, name: string, args: unknown): Request {
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
      params: { name, arguments: args },
    }),
  });
}

async function login(
  broker: LabDualGrantBroker,
  principalId: string,
  port: number,
): Promise<string> {
  const sessionId = broker.openLoginSession(principalId);
  const pkce = generateS256PkceChallenge();
  const flowId = broker.beginMcpAuthorization({
    loginSessionId: sessionId,
    clientId: MCP_CLIENT,
    redirectUri: `http://127.0.0.1:${port}/lab/mcp/callback`,
    codeChallenge: pkce.codeChallenge,
    codeChallengeMethod: 'S256',
    state: randomUUID(),
    resource: RESOURCE,
  });
  const mcpRedirect = broker.approveMcpConsent(flowId);
  const upstreamFlow = broker.beginUpstreamAuthorization({
    parentFlowId: flowId,
    loginSessionId: sessionId,
  });
  const approved = broker.approveUpstreamConsent(upstreamFlow.flowId);
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

async function readMemory(
  handler: (request: Request) => Promise<Response>,
  token: string,
  memoryId: string,
  name: string,
  version: string,
): Promise<{ ok?: boolean; record?: { id?: string }; error?: { code?: string } }> {
  const transport = new LabHttpClientTransport(handler, token);
  const client = new Client({ name, version });
  await client.connect(transport);
  expect(client.getServerVersion()).toEqual({ name: SERVER_NAME, version: SERVER_VERSION });
  const called = await client.callTool({ name: 'memory_get', arguments: { id: memoryId } });
  await client.close();
  return (called.structuredContent ?? {}) as {
    ok?: boolean;
    record?: { id?: string };
    error?: { code?: string };
  };
}

liveDescribe('lab dual-grant disposable GoTrue M4', () => {
  it('exercises the broker on loopback GoTrue and Postgres RLS', async () => {
    const authOrigin = loopbackOrigin(env('M4_SUPABASE_URL')).origin;
    const publishableKey = env('M4_PUBLISHABLE_KEY');
    const serviceRoleKey = env('M4_SERVICE_ROLE_KEY');
    const dbUrl = env('M4_DB_URL');
    loopbackOrigin(dbUrl);
    if (publishableKey.split('.').length === 3 || publishableKey.includes('service_role')) {
      throw new Error('publishable key is not a lab publishable key');
    }
    const port = await freeLoopbackPort();
    const redirectUri = `http://127.0.0.1:${port}/lab/oauth/callback`;
    const mcpRedirectUri = `http://127.0.0.1:${port}/lab/mcp/callback`;
    const restPaths: string[] = [];
    const guardedFetch: typeof fetch = async (input, init) => {
      const requested = new URL(
        typeof input === 'string' || input instanceof URL ? input : input.url,
      );
      if (requested.protocol !== 'http:' || requested.hostname !== '127.0.0.1') {
        throw new Error('non_loopback_fetch');
      }
      const headers = new Headers(init?.headers);
      const authorization = headers.get('authorization') ?? '';
      const apikey = headers.get('apikey') ?? '';
      if (authorization.includes(serviceRoleKey) || apikey === serviceRoleKey) {
        throw new Error('service_role_on_request_path');
      }
      if (requested.pathname.startsWith('/rest/v1')) restPaths.push(requested.pathname);
      return globalThis.fetch(input, init);
    };
    const sdk = createRequire(import.meta.url)('@modelcontextprotocol/client/package.json') as {
      name: string;
      version: string;
    };
    const upstream = await createLiveGoTrueLabUpstream({
      authOrigin,
      publishableKey,
      serviceRoleKey,
      exactRedirectUri: redirectUri,
      principals: [
        { principalId: ALICE, userAccessToken: env('M4_ALICE_TOKEN') },
        { principalId: BOB, userAccessToken: env('M4_BOB_TOKEN') },
      ],
    });
    let broker: LabDualGrantBroker | undefined;
    let listener: ReturnType<typeof listenLabOAuthCallback> | undefined;
    try {
      seedUpstreamClient(dbUrl, upstream.upstreamClientId);
      broker = await createLabDualGrantBroker({
        optIn: true,
        mcpIssuer: `http://127.0.0.1:${port}`,
        mcpClientId: MCP_CLIENT,
        mcpResourceUri: RESOURCE,
        upstreamIssuer: upstream.upstreamIssuer,
        upstreamClientId: upstream.upstreamClientId,
        upstreamResourceUri: upstream.upstreamResourceUri,
        exactRedirectUri: redirectUri,
        mcpClientRedirectUri: mcpRedirectUri,
        dataApiOrigin: upstream.dataApiOrigin,
        publishableKey,
        maintainedClientName: 'modelcontextprotocol-client',
        maintainedClientVersion: sdk.version,
        upstream,
        fetch: guardedFetch,
      });
      listener = listenLabOAuthCallback(broker, port);
      const metadata = createAuthorizationServerMetadata(upstream.upstreamIssuer);
      const revocationAuthority = createGoTrueSessionRevocationAuthority({
        origin: authOrigin,
        publishableKey,
        fetch: guardedFetch,
      });
      const startupBase = {
        [RESOURCE_URI_ENV]: RESOURCE,
        [AUTHORIZATION_SERVER_ENV]: upstream.upstreamIssuer,
        [SUPABASE_ORIGIN_ENV]: upstream.dataApiOrigin,
        [PUBLISHABLE_KEY_ENV]: publishableKey,
        [OAUTH_CLIENT_ID_ENV]: upstream.upstreamClientId,
      };
      const ordinaryToken = await exchangeCode({
        authOrigin,
        clientId: upstream.upstreamClientId,
        redirectUri,
        resource: RESOURCE,
        publishableKey,
        ...(await approvedCode({
          authOrigin,
          clientId: upstream.upstreamClientId,
          redirectUri,
          resource: RESOURCE,
          userAccessToken: env('M4_ALICE_TOKEN'),
          publishableKey,
        })),
      });
      const ordinary = createRemoteHttpProfile({
        resourceUri: RESOURCE,
        issuer: upstream.upstreamIssuer,
        expectedClientId: upstream.upstreamClientId,
        signingKey: {
          kind: 'jwks',
          jwksUrl: new URL(`${upstream.upstreamIssuer}/.well-known/jwks.json`),
        },
        revocationAuthority,
        authorizationServerMetadata: metadata,
        allowInsecureIssuer: true,
        fetch: guardedFetch,
      });
      const closed = await ordinary(
        new Request(RESOURCE, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${ordinaryToken}`,
            Accept: 'application/json',
            'content-type': 'application/json',
          },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
        }),
      );
      expect(closed.status).toBe(403);
      expect(await closed.json()).toEqual({ error: DOWNSTREAM_CREDENTIAL_UNRESOLVED });
      const flagOnly = createRemoteHttpHandlerFromEnvironment({
        env: { ...startupBase, [LAB_DUAL_GRANT_ENV]: '1' },
        revocationAuthority,
        authorizationServerMetadata: metadata,
        fetch: guardedFetch,
      });
      const flagOnlyResponse = await flagOnly(
        new Request(RESOURCE, {
          method: 'POST',
          headers: { Authorization: `Bearer ${ordinaryToken}`, Accept: 'application/json' },
          body: '{}',
        }),
      );
      expect(flagOnlyResponse.status).toBe(403);
      const hookOnly = createRemoteHttpHandlerFromEnvironment({
        env: startupBase,
        revocationAuthority,
        authorizationServerMetadata: metadata,
        fetch: guardedFetch,
        labDualGrant: broker.profileHook,
      });
      const hookOnlyResponse = await hookOnly(
        new Request(RESOURCE, {
          method: 'POST',
          headers: { Authorization: `Bearer ${ordinaryToken}`, Accept: 'application/json' },
          body: '{}',
        }),
      );
      expect(hookOnlyResponse.status).toBe(403);
      expect(restPaths).toEqual([]);

      const wrongCode = await approvedCode({
        authOrigin,
        clientId: upstream.wrongClientId,
        redirectUri,
        resource: upstream.upstreamResourceUri,
        userAccessToken: env('M4_ALICE_TOKEN'),
        publishableKey,
      });
      await expect(
        exchangeLocalAuthorizationCode({
          authOrigin,
          clientId: upstream.upstreamClientId,
          redirectUri,
          code: wrongCode.code,
          codeVerifier: wrongCode.verifier,
          resource: upstream.upstreamResourceUri,
          projectPublishableKey: publishableKey,
        }),
      ).rejects.toThrow(/token exchange failed/);
      const wrongAccess = await exchangeCode({
        authOrigin,
        clientId: upstream.wrongClientId,
        redirectUri,
        resource: upstream.upstreamResourceUri,
        publishableKey,
        ...(await approvedCode({
          authOrigin,
          clientId: upstream.wrongClientId,
          redirectUri,
          resource: upstream.upstreamResourceUri,
          userAccessToken: env('M4_ALICE_TOKEN'),
          publishableKey,
        })),
      });
      const wrongProfile = await ordinary(
        new Request(RESOURCE, {
          method: 'POST',
          headers: { Authorization: `Bearer ${wrongAccess}`, Accept: 'application/json' },
          body: '{}',
        }),
      );
      expect(wrongProfile.status).toBe(401);
      const wrongRow = await probeMemory({
        origin: authOrigin,
        publishableKey,
        token: wrongAccess,
        memoryId: ALICE_MEMORY,
      });
      expect(wrongRow.recordVisible).toBe(false);
      const substituted = await approvedCode({
        authOrigin,
        clientId: upstream.wrongClientId,
        redirectUri,
        resource: upstream.upstreamResourceUri,
        userAccessToken: env('M4_ALICE_TOKEN'),
        publishableKey,
      });
      const sessionId = broker.openLoginSession(ALICE);
      const pkce = generateS256PkceChallenge();
      const flowId = broker.beginMcpAuthorization({
        loginSessionId: sessionId,
        clientId: MCP_CLIENT,
        redirectUri: mcpRedirectUri,
        codeChallenge: pkce.codeChallenge,
        codeChallengeMethod: 'S256',
        state: randomUUID(),
        resource: RESOURCE,
      });
      broker.approveMcpConsent(flowId);
      const pending = broker.beginUpstreamAuthorization({
        parentFlowId: flowId,
        loginSessionId: sessionId,
      });
      const approved = broker.approveUpstreamConsent(pending.flowId);
      await expect(
        broker.consumeUpstreamCallback({
          state: approved.searchParams.get('state') ?? '',
          iss: approved.searchParams.get('iss') ?? '',
          code: substituted.code,
        }),
      ).rejects.toThrow();
      expect(broker.custodyCounts().grants).toBe(0);
      expect(restPaths).toEqual([]);

      const handler = createRemoteHttpHandlerFromEnvironment({
        env: { ...startupBase, [LAB_DUAL_GRANT_ENV]: '1' },
        revocationAuthority,
        authorizationServerMetadata: metadata,
        fetch: guardedFetch,
        labDualGrant: broker.profileHook,
      });
      const aliceToken = await login(broker, ALICE, port);
      const aliceTransport = new LabHttpClientTransport(handler, aliceToken);
      const aliceClient = new Client({
        name: 'modelcontextprotocol-client',
        version: sdk.version,
      });
      await aliceClient.connect(aliceTransport);
      expect(aliceClient.getServerVersion()).toEqual({
        name: SERVER_NAME,
        version: SERVER_VERSION,
      });
      const listing = await aliceClient.listTools();
      expect(listing.tools.map((tool) => tool.name).toSorted()).toEqual([
        'memory_get',
        'memory_list_recent',
        'memory_search',
      ]);
      const aliceAlpha = await aliceClient.callTool({
        name: 'memory_get',
        arguments: { id: ALICE_MEMORY },
      });
      expect(aliceAlpha.structuredContent).toMatchObject({
        ok: true,
        record: { id: ALICE_MEMORY },
      });
      expect(restPaths.some((path) => path.startsWith('/rest/v1'))).toBe(true);
      const aliceBeta = await readMemory(
        handler,
        aliceToken,
        BOB_MEMORY,
        'modelcontextprotocol-client',
        sdk.version,
      );
      expect(aliceBeta).toMatchObject({ ok: false, error: { code: 'RESOURCE_UNAVAILABLE' } });
      const bobToken = await login(broker, BOB, port);
      const bobAlpha = await readMemory(
        handler,
        bobToken,
        ALICE_MEMORY,
        'modelcontextprotocol-client',
        sdk.version,
      );
      expect(bobAlpha).toMatchObject({ ok: false, error: { code: 'RESOURCE_UNAVAILABLE' } });
      const bobBeta = await readMemory(
        handler,
        bobToken,
        BOB_MEMORY,
        'modelcontextprotocol-client',
        sdk.version,
      );
      expect(bobBeta).toMatchObject({ ok: true, record: { id: BOB_MEMORY } });
      await aliceClient.close();

      broker.revokeLocal(ALICE);
      const localDeny = await handler(toolRequest(aliceToken, 'memory_get', { id: ALICE_MEMORY }));
      expect(localDeny.status).toBe(403);
      expect(await localDeny.json()).toEqual({ error: 'reauth_required' });
      expect(broker.providerRevocationCount()).toBe(0);
      expect(upstream.lastProviderRevokeMeasurement()).toBeUndefined();
      const bobAccess = upstream.upstreamAccessTokenForProbe(BOB);
      broker.revokeAtProvider(BOB);
      const provider = upstream.lastProviderRevokeMeasurement();
      if (!provider?.refreshDenied) throw new Error('provider refresh was not denied');
      expect(broker.providerRevocationCount()).toBe(1);
      const providerDeny = await handler(toolRequest(bobToken, 'memory_get', { id: BOB_MEMORY }));
      expect(providerDeny.status).toBe(403);
      const dataApiProbe = await probeMemory({
        origin: authOrigin,
        publishableKey,
        token: bobAccess,
        memoryId: BOB_MEMORY,
      });
      expect(Number.isFinite(dataApiProbe.latencyMs)).toBe(true);

      const beforeCleanup = broker.buildLabReceipt().mcpPublicJwkThumbprint;
      await broker.cleanup();
      expect(broker.custodyCounts()).toEqual({
        grants: 0,
        pendingFlows: 0,
        loginSessions: 0,
        mappings: 0,
      });
      expect(broker.buildLabReceipt().activeGrants).toBe(0);
      expect(broker.buildLabReceipt().encryptedRefreshAtRest).toBe(false);
      expect(broker.buildLabReceipt().mcpPublicJwkThumbprint).not.toBe(beforeCleanup);
      const afterCleanup = await handler(toolRequest(bobToken, 'memory_get', { id: BOB_MEMORY }));
      expect(afterCleanup.status).toBe(401);

      const receipt = buildLabDualGrantM4Receipt({
        repositorySha: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
        treeSha: execFileSync('git', ['rev-parse', 'HEAD^{tree}'], { encoding: 'utf8' }).trim(),
        node: process.version,
        npm: execFileSync('npm', ['--version'], { encoding: 'utf8' }).trim(),
        supabase: execFileSync('supabase', ['--version'], { encoding: 'utf8' }).trim(),
        providerAuthorizationRedirectIncludesIss: upstream.providerRedirectIncludedIss() === true,
        mcpSdkPackageName: sdk.name,
        mcpSdkVersion: sdk.version,
        t10ProviderRevoke: provider,
        t10DataApiProbe: dataApiProbe,
        forbiddenSubstrings: [
          serviceRoleKey,
          publishableKey,
          dbUrl,
          env('M4_ALICE_TOKEN'),
          env('M4_BOB_TOKEN'),
          ordinaryToken,
          wrongAccess,
          aliceToken,
          bobToken,
          bobAccess,
          ...upstream.secretMaterial(),
        ],
      });
      expect(receipt.result).toBe('pass');
      expect(containsSecretMaterial(receipt, upstream.secretMaterial())).toBe(false);
      const receiptPath = process.env.LAB_DUAL_GRANT_M4_RECEIPT_PATH;
      if (receiptPath) writeFileSync(receiptPath, `${JSON.stringify(receipt)}\n`);
      process.stdout.write(`${JSON.stringify(receipt)}\n`);
    } finally {
      if (listener) {
        await new Promise<void>((resolve) => {
          listener?.close(() => resolve());
        });
      }
      await broker?.cleanup();
      await upstream.close();
    }
  }, 180_000);
});

async function probeMemory(input: {
  readonly origin: string;
  readonly publishableKey: string;
  readonly token: string;
  readonly memoryId: string;
}): Promise<{
  readonly latencyMs: number;
  readonly httpStatus: number;
  readonly accessJwtRejected: boolean;
  readonly recordVisible: boolean;
  readonly slaClaimed: false;
}> {
  const started = performance.now();
  const response = await fetch(new URL('/rest/v1/rpc/authorized_memory_get_v1', input.origin), {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${input.token}`,
      apikey: input.publishableKey,
      Accept: 'application/json',
      'Accept-Profile': 'memory',
      'Content-Type': 'application/json',
      'Content-Profile': 'memory',
    },
    body: JSON.stringify({ id: input.memoryId }),
  });
  const latencyMs = Math.round(performance.now() - started);
  const text = await response.text();
  let recordVisible = false;
  try {
    const body = JSON.parse(text) as { record?: { id?: string } | null };
    recordVisible = body.record?.id === input.memoryId;
  } catch {
    recordVisible = false;
  }
  return {
    latencyMs,
    httpStatus: response.status,
    accessJwtRejected: response.status === 401 || response.status === 403,
    recordVisible,
    slaClaimed: false,
  };
}
