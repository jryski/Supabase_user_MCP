import { createHash } from 'node:crypto';

import type { McpServer } from '@modelcontextprotocol/server';
import {
  checkStorageInlineBase64,
  checkStorageMimeType,
  createReadToolError,
  createReadToolMcpResult,
  parseStorageRelativeKey,
  type ReadToolErrorCode,
  STORAGE_ALLOWED_MIME_TYPES,
  STORAGE_CAPABILITIES,
  STORAGE_CAPABILITIES_TOOL,
  STORAGE_DELETE_TOOL,
  STORAGE_GET_TOOL,
  STORAGE_LIST_TOOL,
  STORAGE_MAX_INLINE_BYTES,
  STORAGE_MAX_LIST_ITEMS,
  STORAGE_MAX_OBJECT_BYTES,
  STORAGE_PUT_TOOL,
  STORAGE_SIGNED_URL_TTL_SECONDS,
  type StorageCapability,
  type StorageDeleteInput,
  type StorageGetInput,
  type StorageListInput,
  type StorageListItem,
  type StoragePutInput,
} from '@supabase-user-mcp/contracts';

import type { VerifiedUserIdentity } from './fixed-supabase-client.js';
import {
  createReadToolExecutor,
  type ReadToolExecutionContext,
  type ReadToolGovernancePolicy,
} from './read-tool-governor.js';
import {
  createPathPrefixStoragePrincipalResolver,
  type StorageKeyScope,
  type StoragePrincipalResolver,
} from './storage-principal.js';
import { StorageClientError, type UserScopedStorageClient } from './user-scoped-storage-client.js';

const MAX_LIST_OFFSET = 10_000;
const SETUP_TIMEOUT_MS = 2_000;

const STORAGE_READ_ANNOTATIONS = Object.freeze({
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
});

const STORAGE_TOOL_METADATA = Object.freeze({
  [STORAGE_CAPABILITIES_TOOL.name]: Object.freeze({
    title: 'Storage capabilities',
    description: 'Reports the storage capabilities and bounds granted to this session.',
  }),
  [STORAGE_LIST_TOOL.name]: Object.freeze({
    title: 'List storage objects',
    description: "Lists the caller's own storage objects under a bounded relative prefix.",
  }),
  [STORAGE_GET_TOOL.name]: Object.freeze({
    title: 'Get storage object',
    description:
      "Returns one of the caller's own storage objects inline (small) or as a short-lived signed URL.",
  }),
  [STORAGE_PUT_TOOL.name]: Object.freeze({
    title: 'Create storage object',
    description:
      "Creates one new small object under the caller's own storage. Never overwrites an existing key.",
  }),
  [STORAGE_DELETE_TOOL.name]: Object.freeze({
    title: 'Delete storage object',
    description:
      "Deletes one of the caller's own storage objects. Signed URLs already issued stay valid until they expire.",
  }),
});

const STORAGE_PUT_ANNOTATIONS = Object.freeze({
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: false,
});

const STORAGE_DELETE_ANNOTATIONS = Object.freeze({
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: false,
  openWorldHint: false,
});

class StorageToolFailure extends Error {
  constructor(readonly code: ReadToolErrorCode) {
    super(code);
  }
}

function fail(code: ReadToolErrorCode): never {
  throw new StorageToolFailure(code);
}

/**
 * Maps storage tool failures to typed read-tool errors. Exported for tests.
 * Only a caller or deadline abort is rethrown, so the governor reports it as
 * a deadline; every other failure is returned here, never thrown.
 */
export async function guardStorageToolRun(
  signal: AbortSignal,
  run: () => Promise<unknown>,
): Promise<unknown> {
  try {
    return await run();
  } catch (error) {
    if (signal.aborted) throw error;
    if (error instanceof StorageToolFailure) return createReadToolError(error.code);
    if (error instanceof StorageClientError && error.code === 'STORAGE_CLIENT_RESPONSE_TOO_LARGE') {
      return createReadToolError('RESPONSE_LIMIT_EXCEEDED');
    }
    return createReadToolError('INTERNAL_ERROR');
  }
}

function prefixDigest(prefix: string): string {
  return createHash('sha256').update(prefix).digest('hex').slice(0, 16);
}

export function encodeStorageListCursor(prefix: string, offset: number): string {
  return `cur_${Buffer.from(`v1.${offset}.${prefixDigest(prefix)}`).toString('base64url')}`;
}

function decodeStorageListCursor(prefix: string, cursor: string | undefined): number {
  if (cursor === undefined) return 0;
  const decoded = Buffer.from(cursor.slice(4), 'base64url').toString('utf8');
  const match = /^v1\.(0|[1-9][0-9]{0,4})\.([0-9a-f]{16})$/.exec(decoded);
  if (match === null || match[2] !== prefixDigest(prefix)) fail('INVALID_REQUEST');
  const offset = Number(match[1]);
  if (offset > MAX_LIST_OFFSET) fail('INVALID_REQUEST');
  return offset;
}

function isSignedUrlFor(url: string, objectKey: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  const encodedKey = objectKey.split('/').map(encodeURIComponent).join('/');
  return (
    parsed.protocol === 'https:' &&
    parsed.username === '' &&
    parsed.password === '' &&
    parsed.pathname.startsWith('/storage/v1/object/sign/') &&
    parsed.pathname.endsWith(`/${encodedKey}`) &&
    (parsed.searchParams.get('token') ?? '') !== ''
  );
}

export interface StorageReadToolDependencies {
  readonly client: UserScopedStorageClient;
  readonly scope: StorageKeyScope;
  readonly capabilities: ReadonlyArray<StorageCapability>;
  readonly toolNames: ReadonlyArray<string>;
  readonly governance?: ReadToolGovernancePolicy;
  readonly now?: () => number;
}

export function createStorageReadTools(dependencies: StorageReadToolDependencies) {
  const { client, scope } = dependencies;
  const now = dependencies.now ?? (() => Date.now());
  const governance = dependencies.governance ?? {};

  const capabilities = createReadToolExecutor(
    STORAGE_CAPABILITIES_TOOL,
    async () => ({
      ok: true as const,
      capabilities: [...dependencies.capabilities],
      tools: [...dependencies.toolNames],
      limits: {
        maxInlineBytes: STORAGE_MAX_INLINE_BYTES,
        maxObjectBytes: STORAGE_MAX_OBJECT_BYTES,
        maxListItems: STORAGE_MAX_LIST_ITEMS,
        signedUrlTtlSeconds: STORAGE_SIGNED_URL_TTL_SECONDS,
        allowedMimeTypes: [...STORAGE_ALLOWED_MIME_TYPES],
      },
    }),
    governance,
  );

  const list = createReadToolExecutor(
    STORAGE_LIST_TOOL,
    (input: StorageListInput, signal) =>
      guardStorageToolRun(signal, async () => {
        const offset = decodeStorageListCursor(input.prefix, input.cursor);
        const page = await client.listObjects(
          { folder: scope.toListPrefix(input.prefix), limit: input.limit, offset },
          signal,
        );
        const items: StorageListItem[] = [];
        for (const entry of page.entries) {
          const upstreamKey = entry.kind === 'object' ? entry.objectKey : entry.objectPrefix;
          // An entry outside the caller's scope means the policy layer leaked; fail closed.
          if (!scope.contains(upstreamKey)) fail('INTERNAL_ERROR');
          if (entry.kind === 'folder') {
            const key = scope.toRelativePrefix(entry.objectPrefix);
            if (key !== undefined) items.push({ kind: 'folder', key });
            continue;
          }
          const key = scope.toRelativeKey(entry.objectKey);
          const parsed = key === undefined ? undefined : parseStorageRelativeKey(key);
          // In-scope objects whose names or types fall outside S1 bounds are not exposed.
          if (key === undefined || parsed === undefined || !parsed.ok) continue;
          if (!checkStorageMimeType(parsed.value, entry.mimeType).ok) continue;
          if (entry.size > STORAGE_MAX_OBJECT_BYTES) continue;
          items.push({
            kind: 'object',
            key,
            size: entry.size,
            mimeType: entry.mimeType,
            updatedAt: entry.updatedAt,
          });
        }
        const nextOffset = offset + input.limit;
        return {
          ok: true as const,
          items,
          ...(page.hasMore && nextOffset <= MAX_LIST_OFFSET
            ? { nextCursor: encodeStorageListCursor(input.prefix, nextOffset) }
            : {}),
        };
      }),
    governance,
  );

  const get = createReadToolExecutor(
    STORAGE_GET_TOOL,
    (input: StorageGetInput, signal) =>
      guardStorageToolRun(signal, async () => {
        const parsed = parseStorageRelativeKey(input.key);
        if (!parsed.ok) fail('INVALID_REQUEST');
        const objectKey = scope.toObjectKey(parsed.value.key);
        const info = await client.getObjectInfo(objectKey, signal);
        // Missing, cross-principal and revoked are deliberately the same answer.
        if (info === null || info.objectKey !== objectKey) fail('RESOURCE_UNAVAILABLE');
        if (!checkStorageMimeType(parsed.value, info.mimeType).ok) fail('RESOURCE_UNAVAILABLE');
        if (info.size > STORAGE_MAX_OBJECT_BYTES) fail('RESPONSE_LIMIT_EXCEEDED');
        const inline =
          input.delivery === 'inline' ||
          (input.delivery === 'auto' && info.size <= STORAGE_MAX_INLINE_BYTES);
        const base = {
          key: parsed.value.key,
          size: info.size,
          mimeType: info.mimeType,
          updatedAt: info.updatedAt,
          contentTrust: 'untrusted' as const,
        };
        if (inline) {
          if (info.size > STORAGE_MAX_INLINE_BYTES) fail('RESPONSE_LIMIT_EXCEEDED');
          const bytes = await client.downloadObject(objectKey, STORAGE_MAX_INLINE_BYTES, signal);
          if (bytes === null) fail('RESOURCE_UNAVAILABLE');
          if (bytes.byteLength !== info.size) fail('INTERNAL_ERROR');
          return {
            ok: true as const,
            record: {
              ...base,
              delivery: 'inline' as const,
              contentBase64: Buffer.from(bytes).toString('base64'),
            },
          };
        }
        const issuedAt = now();
        const signedUrl = await client.createSignedDownloadUrl(
          objectKey,
          STORAGE_SIGNED_URL_TTL_SECONDS,
          signal,
        );
        if (signedUrl === null) fail('RESOURCE_UNAVAILABLE');
        if (!isSignedUrlFor(signedUrl, objectKey)) fail('INTERNAL_ERROR');
        return {
          ok: true as const,
          record: {
            ...base,
            delivery: 'signed_url' as const,
            signedUrl,
            expiresAt: new Date(issuedAt + STORAGE_SIGNED_URL_TTL_SECONDS * 1000).toISOString(),
          },
        };
      }),
    governance,
  );

  // Writes go through the same scope seam as reads: the object key is always
  // `<storage principal>/<relative key>`, where the database names the
  // principal. For a delegated agent that is the human's prefix.
  const put = createReadToolExecutor(
    STORAGE_PUT_TOOL,
    (input: StoragePutInput, signal) =>
      guardStorageToolRun(signal, async () => {
        if (!dependencies.capabilities.includes('storage:write')) fail('RESOURCE_UNAVAILABLE');
        const parsed = parseStorageRelativeKey(input.key);
        if (!parsed.ok) fail('INVALID_REQUEST');
        if (!checkStorageMimeType(parsed.value, input.mimeType).ok) fail('INVALID_REQUEST');
        const size = checkStorageInlineBase64(input.contentBase64);
        if (!size.ok) fail('INVALID_REQUEST');
        const bytes = new Uint8Array(Buffer.from(input.contentBase64, 'base64'));
        if (bytes.byteLength !== size.value) fail('INVALID_REQUEST');
        const objectKey = scope.toObjectKey(parsed.value.key);
        // Not permitted, already exists and revoked are deliberately the same answer.
        if (!(await client.uploadObject(objectKey, bytes, input.mimeType, signal))) {
          fail('RESOURCE_UNAVAILABLE');
        }
        return {
          ok: true as const,
          record: { key: parsed.value.key, size: bytes.byteLength, mimeType: input.mimeType },
        };
      }),
    governance,
  );

  const remove = createReadToolExecutor(
    STORAGE_DELETE_TOOL,
    (input: StorageDeleteInput, signal) =>
      guardStorageToolRun(signal, async () => {
        if (!dependencies.capabilities.includes('storage:write')) fail('RESOURCE_UNAVAILABLE');
        const parsed = parseStorageRelativeKey(input.key);
        if (!parsed.ok) fail('INVALID_REQUEST');
        const objectKey = scope.toObjectKey(parsed.value.key);
        if (!(await client.deleteObject(objectKey, signal))) fail('RESOURCE_UNAVAILABLE');
        return { ok: true as const, deleted: { key: parsed.value.key } };
      }),
    governance,
  );

  return Object.freeze({ capabilities, list, get, put, delete: remove });
}

export interface StorageRegistrationConfig {
  readonly client: UserScopedStorageClient;
  /** Defaults to RLS option A (path prefix) backed by `client.fetchStoragePrincipal`. */
  readonly principalResolver?: StoragePrincipalResolver;
  readonly governance?: ReadToolGovernancePolicy;
  readonly now?: () => number;
  /**
   * Read-only surfaces (the remote pilot). A `storage:write` grant is ignored:
   * `storage_put` and `storage_delete` are never registered and
   * `storage_capabilities` reports `storage:read` only. Off by default.
   */
  readonly readOnly?: boolean;
}

export type StorageRegistrationStatus = 'registered' | 'not_granted' | 'unavailable';

export interface PreparedStorageRegistration {
  readonly status: StorageRegistrationStatus;
  readonly capabilities: ReadonlyArray<StorageCapability>;
  readonly toolNames: ReadonlyArray<string>;
  register(
    server: McpServer,
    executionContext: (requestId: string | number, signal: AbortSignal) => ReadToolExecutionContext,
  ): void;
}

function unregistered(
  status: Exclude<StorageRegistrationStatus, 'registered'>,
  capabilities: ReadonlyArray<StorageCapability> = [],
): PreparedStorageRegistration {
  return Object.freeze({
    status,
    capabilities: Object.freeze([...capabilities]),
    toolNames: Object.freeze([]),
    register: () => undefined,
  });
}

/**
 * Resolves the session's storage grant and principal scope once, before tool
 * registration. Storage tools exist only when the database reports
 * `storage:read`; any setup failure registers no storage tools (fail closed)
 * without affecting the memory tools.
 */
export async function prepareStorageMcpRegistration(
  config: StorageRegistrationConfig,
  identity: VerifiedUserIdentity,
): Promise<PreparedStorageRegistration> {
  // The storage client's user token must belong to the verified caller.
  if (
    typeof config.client.tokenSubject !== 'string' ||
    config.client.tokenSubject !== identity.principalId
  ) {
    return unregistered('unavailable');
  }
  const signal = AbortSignal.timeout(SETUP_TIMEOUT_MS);
  let capabilities: StorageCapability[];
  try {
    const grants = new Set(await config.client.fetchStorageGrants(signal));
    capabilities = STORAGE_CAPABILITIES.filter(
      (capability) =>
        grants.has(capability) && !(config.readOnly === true && capability === 'storage:write'),
    );
  } catch {
    return unregistered('unavailable');
  }
  if (!capabilities.includes('storage:read')) return unregistered('not_granted', capabilities);

  const resolver =
    config.principalResolver ??
    createPathPrefixStoragePrincipalResolver(
      config.client.fetchStoragePrincipal,
      config.client.tokenSubject,
    );
  let scope: StorageKeyScope;
  try {
    scope = await resolver.resolve(identity, signal);
  } catch {
    return unregistered('unavailable', capabilities);
  }

  const writable = capabilities.includes('storage:write');
  const toolNames = Object.freeze([
    STORAGE_CAPABILITIES_TOOL.name,
    STORAGE_LIST_TOOL.name,
    STORAGE_GET_TOOL.name,
    ...(writable ? [STORAGE_PUT_TOOL.name, STORAGE_DELETE_TOOL.name] : []),
  ]);
  const tools = createStorageReadTools({
    client: config.client,
    scope,
    capabilities,
    toolNames,
    ...(config.governance === undefined ? {} : { governance: config.governance }),
    ...(config.now === undefined ? {} : { now: config.now }),
  });
  let registered = false;

  const prepared: PreparedStorageRegistration = {
    status: 'registered',
    capabilities: Object.freeze(capabilities),
    toolNames,
    register(server, executionContext) {
      if (registered) throw new TypeError('Storage tool registration may run only once.');
      registered = true;
      server.registerTool(
        STORAGE_CAPABILITIES_TOOL.name,
        {
          ...STORAGE_TOOL_METADATA[STORAGE_CAPABILITIES_TOOL.name],
          inputSchema: STORAGE_CAPABILITIES_TOOL.inputSchema,
          outputSchema: STORAGE_CAPABILITIES_TOOL.outputSchema,
          annotations: STORAGE_READ_ANNOTATIONS,
        },
        async (input, context) =>
          createReadToolMcpResult(
            await tools.capabilities(
              input,
              executionContext(context.mcpReq.id, context.mcpReq.signal),
            ),
          ),
      );
      server.registerTool(
        STORAGE_LIST_TOOL.name,
        {
          ...STORAGE_TOOL_METADATA[STORAGE_LIST_TOOL.name],
          inputSchema: STORAGE_LIST_TOOL.inputSchema,
          outputSchema: STORAGE_LIST_TOOL.outputSchema,
          annotations: STORAGE_READ_ANNOTATIONS,
        },
        async (input, context) =>
          createReadToolMcpResult(
            await tools.list(input, executionContext(context.mcpReq.id, context.mcpReq.signal)),
          ),
      );
      server.registerTool(
        STORAGE_GET_TOOL.name,
        {
          ...STORAGE_TOOL_METADATA[STORAGE_GET_TOOL.name],
          inputSchema: STORAGE_GET_TOOL.inputSchema,
          outputSchema: STORAGE_GET_TOOL.outputSchema,
          annotations: STORAGE_READ_ANNOTATIONS,
        },
        async (input, context) =>
          createReadToolMcpResult(
            await tools.get(input, executionContext(context.mcpReq.id, context.mcpReq.signal)),
          ),
      );
      if (!writable) return;
      server.registerTool(
        STORAGE_PUT_TOOL.name,
        {
          ...STORAGE_TOOL_METADATA[STORAGE_PUT_TOOL.name],
          inputSchema: STORAGE_PUT_TOOL.inputSchema,
          outputSchema: STORAGE_PUT_TOOL.outputSchema,
          annotations: STORAGE_PUT_ANNOTATIONS,
        },
        async (input, context) =>
          createReadToolMcpResult(
            await tools.put(input, executionContext(context.mcpReq.id, context.mcpReq.signal)),
          ),
      );
      server.registerTool(
        STORAGE_DELETE_TOOL.name,
        {
          ...STORAGE_TOOL_METADATA[STORAGE_DELETE_TOOL.name],
          inputSchema: STORAGE_DELETE_TOOL.inputSchema,
          outputSchema: STORAGE_DELETE_TOOL.outputSchema,
          annotations: STORAGE_DELETE_ANNOTATIONS,
        },
        async (input, context) =>
          createReadToolMcpResult(
            await tools.delete(input, executionContext(context.mcpReq.id, context.mcpReq.signal)),
          ),
      );
    },
  };
  return Object.freeze(prepared);
}
