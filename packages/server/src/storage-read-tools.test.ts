import { Client } from '@modelcontextprotocol/client';
import type { JSONRPCMessage } from '@modelcontextprotocol/server';
import { StreamTransport } from '@supabase/mcp-utils';
import {
  MAX_RESPONSE_BYTES,
  readToolWireResponseByteLength,
  STORAGE_MAX_INLINE_BYTES,
  STORAGE_MAX_OBJECT_BYTES,
  STORAGE_SIGNED_URL_TTL_SECONDS,
} from '@supabase-user-mcp/contracts';
import { beforeEach, describe, expect, it } from 'vitest';

import type { VerifiedFixedSupabaseClient } from './fixed-supabase-client.js';
import { createReadOnlyServer } from './server.js';
import {
  createPathPrefixStoragePrincipalResolver,
  type StoragePrincipalResolver,
} from './storage-principal.js';
import {
  createStorageReadTools,
  encodeStorageListCursor,
  prepareStorageMcpRegistration,
} from './storage-read-tools.js';
import type {
  StorageListEntry,
  StorageListPage,
  StorageObjectInfo,
  UserScopedStorageClient,
} from './user-scoped-storage-client.js';

/** Synthetic principals only: two humans and one delegated agent per human. */
export const USER_1 = '1a1a1a1a-0000-4000-8000-000000000001';
export const USER_2 = '2b2b2b2b-0000-4000-8000-000000000002';
export const AGENT_1 = '3c3c3c3c-0000-4000-8000-000000000003';
export const AGENT_2 = '4d4d4d4d-0000-4000-8000-000000000004';
export const UPDATED_AT = '2026-10-01T00:00:00.000Z';

interface StoredObject {
  readonly bytes: Uint8Array;
  readonly mimeType: string;
}

/**
 * In-memory stand-in for Storage plus RLS option A. Each session client acts as
 * one `auth.uid()`; visibility requires an active `storage:read` grant and an
 * object key under `storage_principal()/`, mirroring the planned S4 policy.
 */
export class SyntheticStorage {
  readonly objects = new Map<string, StoredObject>();
  readonly grants = new Map<string, Set<string>>();
  readonly delegations = new Map<string, string>([
    [AGENT_1, USER_1],
    [AGENT_2, USER_2],
  ]);
  readonly calls: string[] = [];

  put(objectKey: string, content: string | Uint8Array, mimeType: string): void {
    const bytes = typeof content === 'string' ? new TextEncoder().encode(content) : content;
    this.objects.set(objectKey, { bytes, mimeType });
  }

  grant(uid: string, ...capabilities: string[]): void {
    this.grants.set(uid, new Set(capabilities));
  }

  revoke(uid: string): void {
    this.grants.delete(uid);
  }

  storagePrincipal(uid: string): string {
    return this.delegations.get(uid) ?? uid;
  }

  private visible(uid: string, objectKey: string): boolean {
    return (
      this.grants.get(uid)?.has('storage:read') === true &&
      objectKey.startsWith(`${this.storagePrincipal(uid)}/`)
    );
  }

  private info(objectKey: string, object: StoredObject): StorageObjectInfo {
    return {
      objectKey,
      size: object.bytes.byteLength,
      mimeType: object.mimeType,
      updatedAt: UPDATED_AT,
    };
  }

  /** Session client for `uid`. `bypassPolicy` simulates a broken policy layer. */
  sessionClient(uid: string, options: { bypassPolicy?: boolean } = {}): UserScopedStorageClient {
    const visible = (key: string) => options.bypassPolicy === true || this.visible(uid, key);
    return {
      fetchStorageGrants: async () => {
        this.calls.push('grants');
        return [...(this.grants.get(uid) ?? [])];
      },
      fetchStoragePrincipal: async () => {
        this.calls.push('principal');
        return this.storagePrincipal(uid);
      },
      listObjects: async ({ folder, limit, offset }): Promise<StorageListPage> => {
        this.calls.push(`list:${folder}`);
        const children = new Map<string, StorageListEntry>();
        for (const [key, object] of [...this.objects].toSorted(([a], [b]) => a.localeCompare(b))) {
          if (!visible(key) || !key.startsWith(`${folder}/`)) continue;
          const rest = key.slice(folder.length + 1);
          const slash = rest.indexOf('/');
          if (slash === -1) {
            children.set(rest, { kind: 'object', ...this.info(key, object) });
          } else {
            const name = rest.slice(0, slash);
            children.set(name, { kind: 'folder', objectPrefix: `${folder}/${name}` });
          }
        }
        const all = [...children.values()];
        return {
          entries: all.slice(offset, offset + limit),
          hasMore: all.length > offset + limit,
        };
      },
      getObjectInfo: async (objectKey) => {
        this.calls.push(`info:${objectKey}`);
        const object = this.objects.get(objectKey);
        return object !== undefined && visible(objectKey) ? this.info(objectKey, object) : null;
      },
      downloadObject: async (objectKey, maxBytes) => {
        this.calls.push(`download:${objectKey}:${maxBytes}`);
        const object = this.objects.get(objectKey);
        return object !== undefined && visible(objectKey) ? object.bytes : null;
      },
      createSignedDownloadUrl: async (objectKey, expiresInSeconds) => {
        this.calls.push(`sign:${objectKey}:${expiresInSeconds}`);
        const object = this.objects.get(objectKey);
        if (object === undefined || !visible(objectKey)) return null;
        return `https://storage.example.test/storage/v1/object/sign/user-files/${objectKey}?token=synthetic`;
      },
    };
  }
}

async function withClient(
  server: ReturnType<typeof createReadOnlyServer>,
  run: (client: Client) => Promise<void>,
  capturedServerMessages: JSONRPCMessage[] = [],
): Promise<void> {
  const clientTransport = new StreamTransport();
  const serverTransport = new StreamTransport();
  const pipes = [
    clientTransport.readable.pipeTo(serverTransport.writable).catch(() => undefined),
    serverTransport.readable
      .pipeThrough(
        new TransformStream<JSONRPCMessage, JSONRPCMessage>({
          transform: (message, controller) => {
            capturedServerMessages.push(message);
            controller.enqueue(message);
          },
        }),
      )
      .pipeTo(clientTransport.writable)
      .catch(() => undefined),
  ];
  const client = new Client(
    { name: 'read-only-registration-test', version: '0.0.0' },
    { capabilities: {} },
  );
  const resolvedServer = await server;
  try {
    await resolvedServer.connect(serverTransport);
    await client.connect(clientTransport);
    await run(client);
  } finally {
    await Promise.allSettled([client.close(), resolvedServer.close()]);
    await Promise.all(pipes);
  }
}

const NOW = Date.parse('2026-10-27T16:00:00.000Z');
const STORAGE_TOOLS = ['storage_capabilities', 'storage_get', 'storage_list'];
const MEMORY_TOOLS = ['memory_get', 'memory_list_recent', 'memory_search'];
let sequence = 0;

function memoryClient(principalId: string): VerifiedFixedSupabaseClient {
  return {
    verifyUserIdentity: async () => ({ principalId }),
    listMemoryRows: async () => [],
    searchMemoryRows: async () => ({ rows: [] }),
    getMemoryRow: async () => null,
    listRecentMemoryRows: async () => ({ rows: [] }),
  };
}

/** Distinct governor scope per test so the process-global rate limiter never interferes. */
function freshIdentity(): { principalId: string } {
  sequence += 1;
  return { principalId: `9e9e9e9e-0000-4000-8000-${sequence.toString().padStart(12, '0')}` };
}

async function tools(
  storage: SyntheticStorage,
  uid: string,
  options: { bypassPolicy?: boolean; resolver?: StoragePrincipalResolver } = {},
) {
  const client = storage.sessionClient(uid, { bypassPolicy: options.bypassPolicy ?? false });
  const resolver =
    options.resolver ?? createPathPrefixStoragePrincipalResolver(client.fetchStoragePrincipal);
  const scope = await resolver.resolve({ principalId: uid }, new AbortController().signal);
  const built = createStorageReadTools({
    client,
    scope,
    capabilities: ['storage:read'],
    toolNames: STORAGE_TOOLS,
    now: () => NOW,
  });
  const context = { ...freshIdentity(), now: () => NOW };
  return {
    list: (input: unknown) => built.list(input, context),
    get: (input: unknown) => built.get(input, context),
    capabilities: () => built.capabilities({}, context),
  };
}

function errorCode(output: unknown): string | undefined {
  const value = output as { ok: boolean; error?: { code: string } };
  return value.ok ? undefined : value.error?.code;
}

function seed(storage: SyntheticStorage): void {
  for (const uid of [USER_1, USER_2, AGENT_1, AGENT_2]) storage.grant(uid, 'storage:read');
  storage.put(`${USER_1}/notes/one.md`, '# user one', 'text/markdown');
  storage.put(`${USER_1}/notes/deep/two.txt`, 'two', 'text/plain');
  storage.put(`${USER_1}/data.json`, '{"a":1}', 'application/json');
  storage.put(`${USER_2}/notes/secret.md`, '# user two', 'text/markdown');
  storage.put(`${USER_2}/data.json`, '{"b":2}', 'application/json');
}

describe('storage read tools: synthetic 2 users + 2 agents matrix (RLS option A)', () => {
  let storage: SyntheticStorage;
  beforeEach(() => {
    storage = new SyntheticStorage();
    seed(storage);
  });

  it.each([
    ['user 1', USER_1, '{"a":1}'],
    ['agent of user 1', AGENT_1, '{"a":1}'],
    ['user 2', USER_2, '{"b":2}'],
    ['agent of user 2', AGENT_2, '{"b":2}'],
  ])('%s reads its own objects', async (_label, uid, expected) => {
    const session = await tools(storage, uid);
    const output = (await session.get({ key: 'data.json' })) as {
      ok: true;
      record: { delivery: string; contentBase64: string; contentTrust: string };
    };
    expect(output.ok).toBe(true);
    expect(output.record.delivery).toBe('inline');
    expect(output.record.contentTrust).toBe('untrusted');
    expect(Buffer.from(output.record.contentBase64, 'base64').toString()).toBe(expected);
  });

  it.each([
    ['user 1', USER_1, ['data.json', 'notes']],
    ['agent of user 1', AGENT_1, ['data.json', 'notes']],
    ['user 2', USER_2, ['data.json', 'notes']],
  ])('%s lists only its own scope', async (_label, uid, expected) => {
    const session = await tools(storage, uid);
    const output = (await session.list({})) as { ok: true; items: Array<{ key: string }> };
    expect(output.ok).toBe(true);
    expect(output.items.map((item) => item.key)).toEqual(expected);
    const notes = (await session.list({ prefix: 'notes' })) as {
      items: Array<{ key: string }>;
    };
    expect(notes.items.map((item) => item.key)).toEqual(
      uid === USER_2 ? ['notes/secret.md'] : ['notes/deep', 'notes/one.md'],
    );
  });

  it('cross-principal get is denied: another principal id inside a relative key stays in scope', async () => {
    const session = await tools(storage, USER_1);
    expect(errorCode(await session.get({ key: `${USER_2}/data.json` }))).toBe(
      'RESOURCE_UNAVAILABLE',
    );
    expect(storage.calls).toContain(`info:${USER_1}/${USER_2}/data.json`);
    expect(storage.calls.some((call) => call.startsWith(`info:${USER_2}/`))).toBe(false);
  });

  it('cross-principal list is denied: another principal id as prefix lists nothing', async () => {
    const session = await tools(storage, AGENT_1);
    const output = (await session.list({ prefix: USER_2 })) as { ok: true; items: unknown[] };
    expect(output).toEqual({ ok: true, items: [] });
    expect(storage.calls).toContain(`list:${USER_1}/${USER_2}`);
  });

  it('a wrong-scope resolver is still denied by the policy layer', async () => {
    const hostile: StoragePrincipalResolver = createPathPrefixStoragePrincipalResolver(
      async () => USER_2,
    );
    const session = await tools(storage, USER_1, { resolver: hostile });
    expect(errorCode(await session.get({ key: 'data.json' }))).toBe('RESOURCE_UNAVAILABLE');
    expect(await session.list({})).toEqual({ ok: true, items: [] });
  });

  it('fails closed when the policy layer returns out-of-scope entries', async () => {
    const client = storage.sessionClient(USER_1, { bypassPolicy: true });
    const leaking: UserScopedStorageClient = {
      ...client,
      listObjects: async () => ({
        entries: [
          {
            kind: 'object',
            objectKey: `${USER_2}/data.json`,
            size: 7,
            mimeType: 'application/json',
            updatedAt: UPDATED_AT,
          },
        ],
        hasMore: false,
      }),
      getObjectInfo: async () => ({
        objectKey: `${USER_2}/data.json`,
        size: 7,
        mimeType: 'application/json',
        updatedAt: UPDATED_AT,
      }),
    };
    const scope = await createPathPrefixStoragePrincipalResolver(async () => USER_1).resolve(
      { principalId: USER_1 },
      new AbortController().signal,
    );
    const built = createStorageReadTools({
      client: leaking,
      scope,
      capabilities: ['storage:read'],
      toolNames: STORAGE_TOOLS,
    });
    expect(errorCode(await built.list({}, freshIdentity()))).toBe('INTERNAL_ERROR');
    expect(errorCode(await built.get({ key: 'data.json' }, freshIdentity()))).toBe(
      'RESOURCE_UNAVAILABLE',
    );
  });

  it('revoked grant: an open session is denied and a new session has no storage tools', async () => {
    const session = await tools(storage, USER_1);
    storage.revoke(USER_1);
    expect(errorCode(await session.get({ key: 'data.json' }))).toBe('RESOURCE_UNAVAILABLE');
    expect(await session.list({})).toEqual({ ok: true, items: [] });
    const prepared = await prepareStorageMcpRegistration(
      { client: storage.sessionClient(USER_1) },
      { principalId: USER_1 },
    );
    expect(prepared.status).toBe('not_granted');
    expect(prepared.toolNames).toEqual([]);
  });

  it('revoking an agent grant removes its storage tools while the human keeps them', async () => {
    storage.revoke(AGENT_1);
    const prepared = await prepareStorageMcpRegistration(
      { client: storage.sessionClient(AGENT_1) },
      { principalId: AGENT_1 },
    );
    expect(prepared.toolNames).toEqual([]);
    const human = await prepareStorageMcpRegistration(
      { client: storage.sessionClient(USER_1) },
      { principalId: USER_1 },
    );
    expect(human.status).toBe('registered');
  });
});

describe('storage read tools: bounds', () => {
  let storage: SyntheticStorage;
  beforeEach(() => {
    storage = new SyntheticStorage();
    seed(storage);
  });

  it.each([
    '../data.json',
    `../${USER_2}/data.json`,
    '/data.json',
    'a\\b.json',
    'notes/./one.md',
    'notes//one.md',
    'run.exe',
    'index.html',
    `${'x'.repeat(600)}.txt`,
  ])('rejects path escape or disallowed key %s before any storage call', async (key) => {
    const session = await tools(storage, USER_1);
    const before = storage.calls.length;
    expect(errorCode(await session.get({ key }))).toBe('INVALID_REQUEST');
    expect(storage.calls.length).toBe(before);
  });

  it('rejects list prefix escapes', async () => {
    const session = await tools(storage, USER_1);
    for (const prefix of ['..', '../x', '/x', 'notes/', 'a\\b']) {
      expect(errorCode(await session.list({ prefix }))).toBe('INVALID_REQUEST');
    }
  });

  it('refuses objects whose stored type disagrees with the key extension', async () => {
    storage.put(`${USER_1}/fake.txt`, '<script>', 'text/html');
    storage.put(`${USER_1}/mismatch.png`, 'not png', 'text/plain');
    const session = await tools(storage, USER_1);
    expect(errorCode(await session.get({ key: 'fake.txt' }))).toBe('RESOURCE_UNAVAILABLE');
    expect(errorCode(await session.get({ key: 'mismatch.png' }))).toBe('RESOURCE_UNAVAILABLE');
    const listed = (await session.list({})) as { items: Array<{ key: string }> };
    expect(listed.items.map((item) => item.key)).not.toContain('fake.txt');
    expect(listed.items.map((item) => item.key)).not.toContain('mismatch.png');
  });

  it('serves the largest inline object within the wire budget', async () => {
    storage.put(
      `${USER_1}/max.txt`,
      new Uint8Array(STORAGE_MAX_INLINE_BYTES).fill(0x41),
      'text/plain',
    );
    const session = await tools(storage, USER_1);
    const output = await session.get({ key: 'max.txt' });
    expect((output as { record: { delivery: string } }).record.delivery).toBe('inline');
    expect(readToolWireResponseByteLength('request-id', output)).toBeLessThanOrEqual(
      MAX_RESPONSE_BYTES,
    );
  });

  it('switches to a 60 s signed URL above the inline limit and refuses forced inline', async () => {
    storage.put(
      `${USER_1}/big.pdf`,
      new Uint8Array(STORAGE_MAX_INLINE_BYTES + 1),
      'application/pdf',
    );
    const session = await tools(storage, USER_1);
    const output = (await session.get({ key: 'big.pdf' })) as {
      ok: true;
      record: { delivery: string; signedUrl: string; expiresAt: string };
    };
    expect(output.record.delivery).toBe('signed_url');
    expect(Date.parse(output.record.expiresAt) - NOW).toBe(STORAGE_SIGNED_URL_TTL_SECONDS * 1000);
    expect(storage.calls).toContain(`sign:${USER_1}/big.pdf:${STORAGE_SIGNED_URL_TTL_SECONDS}`);
    expect(storage.calls.some((call) => call.startsWith('download:'))).toBe(false);
    expect(errorCode(await session.get({ key: 'big.pdf', delivery: 'inline' }))).toBe(
      'RESPONSE_LIMIT_EXCEEDED',
    );
  });

  it('signed_url delivery works for small objects too', async () => {
    const session = await tools(storage, USER_1);
    const output = (await session.get({ key: 'data.json', delivery: 'signed_url' })) as {
      record: { delivery: string };
    };
    expect(output.record.delivery).toBe('signed_url');
  });

  it('rejects oversized objects without downloading or signing', async () => {
    storage.put(
      `${USER_1}/huge.pdf`,
      new Uint8Array(STORAGE_MAX_OBJECT_BYTES + 1),
      'application/pdf',
    );
    const session = await tools(storage, USER_1);
    expect(errorCode(await session.get({ key: 'huge.pdf' }))).toBe('RESPONSE_LIMIT_EXCEEDED');
    expect(storage.calls.some((call) => /^(download|sign):/.test(call))).toBe(false);
  });

  it('rejects a signed URL that does not point at the requested object', async () => {
    storage.put(
      `${USER_1}/big.pdf`,
      new Uint8Array(STORAGE_MAX_INLINE_BYTES + 1),
      'application/pdf',
    );
    const client = storage.sessionClient(USER_1);
    const scope = await createPathPrefixStoragePrincipalResolver(
      client.fetchStoragePrincipal,
    ).resolve({ principalId: USER_1 }, new AbortController().signal);
    for (const url of [
      `https://storage.example.test/storage/v1/object/sign/user-files/${USER_2}/big.pdf?token=t`,
      `http://storage.example.test/storage/v1/object/sign/user-files/${USER_1}/big.pdf?token=t`,
      `https://storage.example.test/storage/v1/object/sign/user-files/${USER_1}/big.pdf`,
    ]) {
      const built = createStorageReadTools({
        client: { ...client, createSignedDownloadUrl: async () => url },
        scope,
        capabilities: ['storage:read'],
        toolNames: STORAGE_TOOLS,
      });
      expect(errorCode(await built.get({ key: 'big.pdf' }, freshIdentity()))).toBe(
        'INTERNAL_ERROR',
      );
    }
  });

  it('paginates with prefix-bound opaque cursors', async () => {
    for (let index = 0; index < 5; index += 1) {
      storage.put(`${USER_1}/page/item-${index}.txt`, `${index}`, 'text/plain');
    }
    const session = await tools(storage, USER_1);
    const first = (await session.list({ prefix: 'page', limit: 2 })) as {
      items: Array<{ key: string }>;
      nextCursor: string;
    };
    expect(first.items.map((item) => item.key)).toEqual(['page/item-0.txt', 'page/item-1.txt']);
    const second = (await session.list({ prefix: 'page', limit: 2, cursor: first.nextCursor })) as {
      items: Array<{ key: string }>;
    };
    expect(second.items.map((item) => item.key)).toEqual(['page/item-2.txt', 'page/item-3.txt']);
    expect(
      errorCode(await session.list({ prefix: 'notes', limit: 2, cursor: first.nextCursor })),
    ).toBe('INVALID_REQUEST');
    expect(
      errorCode(
        await session.list({ prefix: 'page', cursor: encodeStorageListCursor('page', 20_000) }),
      ),
    ).toBe('INVALID_REQUEST');
    expect(errorCode(await session.list({ prefix: 'page', cursor: `cur_${'A'.repeat(30)}` }))).toBe(
      'INVALID_REQUEST',
    );
  });

  it('reports capabilities and bounds', async () => {
    const session = await tools(storage, USER_1);
    expect(await session.capabilities()).toMatchObject({
      ok: true,
      capabilities: ['storage:read'],
      tools: STORAGE_TOOLS,
      limits: { maxInlineBytes: STORAGE_MAX_INLINE_BYTES, signedUrlTtlSeconds: 60 },
    });
  });
});

describe('storage tool registration is grant-gated', () => {
  const listTools = async (
    storage: SyntheticStorage,
    uid: string,
    client?: UserScopedStorageClient,
  ) => {
    let names: string[] = [];
    let instructions = '';
    await withClient(
      createReadOnlyServer({
        client: memoryClient(uid),
        storageRegistration: { client: client ?? storage.sessionClient(uid) },
      }),
      async (mcp) => {
        names = (await mcp.listTools()).tools.map((tool) => tool.name).toSorted();
        instructions = mcp.getInstructions() ?? '';
      },
    );
    return { names, instructions };
  };

  it('storage:read sessions get exactly the three read tools, read-only annotated', async () => {
    const storage = new SyntheticStorage();
    storage.grant(USER_1, 'storage:read');
    let tools: Awaited<ReturnType<Client['listTools']>>['tools'] = [];
    await withClient(
      createReadOnlyServer({
        client: memoryClient(USER_1),
        storageRegistration: { client: storage.sessionClient(USER_1) },
      }),
      async (mcp) => {
        tools = (await mcp.listTools()).tools;
      },
    );
    expect(tools.map((tool) => tool.name).toSorted()).toEqual(
      [...MEMORY_TOOLS, ...STORAGE_TOOLS].toSorted(),
    );
    for (const tool of tools.filter((entry) => entry.name.startsWith('storage_'))) {
      expect(tool.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false });
      expect(JSON.stringify(tool.inputSchema)).not.toMatch(/bucket|principal|token|owner/i);
    }
  });

  it('no grant, write-only grant, or setup failure registers no storage tools', async () => {
    const none = new SyntheticStorage();
    const writeOnly = new SyntheticStorage();
    writeOnly.grant(USER_1, 'storage:write');
    const memoryOnly = new SyntheticStorage();
    memoryOnly.grant(USER_1, 'memory:read', 'memory:search');
    const failing = new SyntheticStorage();
    failing.grant(USER_1, 'storage:read');
    const broken: UserScopedStorageClient = {
      ...failing.sessionClient(USER_1),
      fetchStoragePrincipal: async () => 'not-a-uuid',
    };
    const failingGrants: UserScopedStorageClient = {
      ...failing.sessionClient(USER_1),
      fetchStorageGrants: async () => {
        throw new Error('synthetic outage');
      },
    };
    for (const result of [
      await listTools(none, USER_1),
      await listTools(writeOnly, USER_1),
      await listTools(memoryOnly, USER_1),
      await listTools(failing, USER_1, broken),
      await listTools(failing, USER_1, failingGrants),
    ]) {
      expect(result.names).toEqual(MEMORY_TOOLS);
      expect(result.instructions).not.toMatch(/storage/);
    }
  });

  it('prepare reports status and does not resolve the principal without a read grant', async () => {
    const storage = new SyntheticStorage();
    storage.grant(USER_1, 'storage:write');
    const prepared = await prepareStorageMcpRegistration(
      { client: storage.sessionClient(USER_1) },
      { principalId: USER_1 },
    );
    expect(prepared).toMatchObject({ status: 'not_granted', capabilities: ['storage:write'] });
    expect(storage.calls).toEqual(['grants']);
  });

  it('serves storage_get end to end over an MCP session with the untrusted prefix', async () => {
    const storage = new SyntheticStorage();
    seed(storage);
    let result: { structuredContent?: unknown; content?: Array<{ text?: string }> } = {};
    await withClient(
      createReadOnlyServer({
        client: memoryClient(AGENT_1),
        storageRegistration: { client: storage.sessionClient(AGENT_1) },
      }),
      async (mcp) => {
        result = (await mcp.callTool({
          name: 'storage_get',
          arguments: { key: 'notes/one.md' },
        })) as typeof result;
      },
    );
    expect(result.structuredContent).toMatchObject({
      ok: true,
      record: { key: 'notes/one.md', delivery: 'inline', contentTrust: 'untrusted' },
    });
    expect(result.content?.[0]?.text).toMatch(/^SECURITY BOUNDARY:/);
    expect(JSON.stringify(result)).not.toContain(USER_1);
  });
});
