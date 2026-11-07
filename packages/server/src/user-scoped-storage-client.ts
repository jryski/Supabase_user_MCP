import { checkStorageBucketId, STORAGE_MAX_LIST_ITEMS } from '@supabase-user-mcp/contracts';

import type { LocalCredentials } from './local-credential-loader.js';

/**
 * Issue #123 S2: storage client that acts only as the calling user.
 *
 * Every request carries the caller's own user access token plus the project
 * publishable key. There is no privileged-key input, no bucket or origin
 * override per call, and object keys arrive already scoped by the
 * {@link import('./storage-principal.js').StorageKeyScope} seam.
 */

export type StorageClientErrorCode =
  | 'STORAGE_CLIENT_INVALID_CONFIG'
  | 'STORAGE_CLIENT_RESPONSE_TOO_LARGE'
  | 'STORAGE_CLIENT_MALFORMED_RESPONSE'
  | 'STORAGE_CLIENT_UPSTREAM_ERROR';

export class StorageClientError extends Error {
  constructor(readonly code: StorageClientErrorCode) {
    super('Storage request could not be completed.');
    this.name = 'StorageClientError';
  }
}

export interface StorageObjectInfo {
  readonly objectKey: string;
  readonly size: number;
  readonly mimeType: string;
  readonly updatedAt: string;
}

export type StorageListEntry =
  | ({ readonly kind: 'object' } & StorageObjectInfo)
  | { readonly kind: 'folder'; readonly objectPrefix: string };

export interface StorageListPage {
  readonly entries: ReadonlyArray<StorageListEntry>;
  readonly hasMore: boolean;
}

export interface UserScopedStorageClient {
  /**
   * `sub` claim of the user access token this client sends (decoded, not
   * verified). Registration requires it to equal the verified caller identity.
   */
  readonly tokenSubject: string;
  /** Active storage capabilities for this session, as reported by the database. */
  readonly fetchStorageGrants: (signal: AbortSignal) => Promise<ReadonlyArray<string>>;
  /** Result of the DB `storage_principal()` function for the calling user. */
  readonly fetchStoragePrincipal: (signal: AbortSignal) => Promise<string>;
  readonly listObjects: (
    input: { readonly folder: string; readonly limit: number; readonly offset: number },
    signal: AbortSignal,
  ) => Promise<StorageListPage>;
  readonly getObjectInfo: (
    objectKey: string,
    signal: AbortSignal,
  ) => Promise<StorageObjectInfo | null>;
  readonly downloadObject: (
    objectKey: string,
    maxBytes: number,
    signal: AbortSignal,
  ) => Promise<Uint8Array | null>;
  readonly createSignedDownloadUrl: (
    objectKey: string,
    expiresInSeconds: number,
    signal: AbortSignal,
  ) => Promise<string | null>;
}

export interface UserScopedStorageClientConfig {
  readonly origin: string;
  readonly bucket: string;
  readonly credentials: LocalCredentials;
  readonly fetch?: typeof globalThis.fetch;
}

/** Schema of the S4 session RPCs (`storage_principal`, `storage_session_capabilities`). */
export const STORAGE_RPC_SCHEMA = 'policy_lab';
const MAX_JSON_BYTES = 256 * 1024;
const MAX_SIGNED_URL_BYTES = 2048;

/** Only publishable project keys are accepted; every other key shape is refused. */
const PUBLISHABLE_KEY_PATTERN = /^sb_publishable_[A-Za-z0-9_-]+$/;
const SECRET_KEY_PATTERN = /^sb_secret_/i;
const JWT_SEGMENT_PATTERN = /^[A-Za-z0-9_-]+$/;
const TOKEN_SUBJECT_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const USER_TOKEN_ROLE = 'authenticated';

function invalidConfig(): never {
  throw new StorageClientError('STORAGE_CLIENT_INVALID_CONFIG');
}

function malformed(): never {
  throw new StorageClientError('STORAGE_CLIENT_MALFORMED_RESPONSE');
}

function encodeObjectPath(objectKey: string): string {
  return objectKey.split('/').map(encodeURIComponent).join('/');
}

async function readBounded(response: Response, maximum: number): Promise<Uint8Array> {
  const advertised = response.headers.get('content-length');
  if (advertised !== null && Number(advertised) > maximum) {
    await response.body?.cancel();
    throw new StorageClientError('STORAGE_CLIENT_RESPONSE_TOO_LARGE');
  }
  if (response.body === null) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  while (true) {
    const result = await reader.read();
    if (result.done) break;
    length += result.value.byteLength;
    if (length > maximum) {
      await reader.cancel();
      throw new StorageClientError('STORAGE_CLIENT_RESPONSE_TOO_LARGE');
    }
    chunks.push(result.value);
  }
  return new Uint8Array(Buffer.concat(chunks, length));
}

async function readJson(response: Response): Promise<unknown> {
  const bytes = await readBounded(response, MAX_JSON_BYTES);
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    malformed();
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Missing and not-permitted are indistinguishable to the caller by design. */
function isDenied(status: number): boolean {
  return status === 400 || status === 401 || status === 403 || status === 404;
}

/**
 * Decodes the user access token payload WITHOUT verifying its signature and
 * returns its `sub`. Signature and expiry verification stay with the upstream
 * identity check; this only refuses tokens that are plainly not a signed-in
 * user's (for example `role: service_role`) before they are ever sent.
 */
function userTokenSubject(token: string): string {
  const parts = token.split('.');
  if (parts.length !== 3 || !parts.every((part) => JWT_SEGMENT_PATTERN.test(part))) {
    invalidConfig();
  }
  let payload: unknown;
  try {
    payload = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(parts[1] ?? '', 'base64url')),
    );
  } catch {
    invalidConfig();
  }
  if (
    !isRecord(payload) ||
    payload.role !== USER_TOKEN_ROLE ||
    typeof payload.sub !== 'string' ||
    !TOKEN_SUBJECT_PATTERN.test(payload.sub)
  ) {
    invalidConfig();
  }
  return payload.sub;
}

function toIso(value: unknown): string {
  if (typeof value !== 'string') malformed();
  const time = Date.parse(value);
  if (!Number.isFinite(time)) malformed();
  return new Date(time).toISOString();
}

export function createUserScopedStorageClient(
  config: UserScopedStorageClientConfig,
): UserScopedStorageClient {
  let origin: URL;
  try {
    origin = new URL(config.origin);
  } catch {
    invalidConfig();
  }
  if (
    origin.protocol !== 'https:' ||
    origin.origin !== config.origin ||
    origin.username !== '' ||
    origin.password !== ''
  ) {
    invalidConfig();
  }
  if (!checkStorageBucketId(config.bucket).ok) invalidConfig();
  const key = config.credentials.projectPublishableKey?.trim();
  const token = config.credentials.userAccessToken?.trim();
  // Only an `sb_publishable_` key may fill the key slot. Secret keys (any case)
  // and JWT-shaped keys (for example a legacy privileged project key) are refused.
  if (!key || !token || key === token) invalidConfig();
  if (SECRET_KEY_PATTERN.test(key)) invalidConfig();
  if (!PUBLISHABLE_KEY_PATTERN.test(key)) invalidConfig();
  if (key.split('.').length === 3) invalidConfig();
  // The user token must be a JWT whose (unverified) role is `authenticated`.
  const tokenSubject = userTokenSubject(token);
  const fetchImplementation = config.fetch ?? globalThis.fetch;
  const bucket = config.bucket;
  const baseHeaders = Object.freeze({ Authorization: `Bearer ${token}`, apikey: key });

  const request = (path: string, init: RequestInit, signal: AbortSignal) =>
    fetchImplementation(`${origin.origin}${path}`, {
      ...init,
      headers: { ...baseHeaders, ...(init.headers as Record<string, string> | undefined) },
      redirect: 'error',
      signal,
    });

  const rpc = async (name: string, signal: AbortSignal): Promise<unknown> => {
    const response = await request(
      `/rest/v1/rpc/${name}`,
      {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'Content-Profile': STORAGE_RPC_SCHEMA,
          'Accept-Profile': STORAGE_RPC_SCHEMA,
        },
        body: '{}',
      },
      signal,
    );
    if (!response.ok) {
      await response.body?.cancel();
      throw new StorageClientError('STORAGE_CLIENT_UPSTREAM_ERROR');
    }
    return readJson(response);
  };

  const client: UserScopedStorageClient = {
    tokenSubject,
    async fetchStorageGrants(signal: AbortSignal) {
      const value = await rpc('storage_session_capabilities', signal);
      if (!Array.isArray(value) || value.length > 8) malformed();
      if (!value.every((entry) => typeof entry === 'string')) malformed();
      return Object.freeze([...value] as string[]);
    },

    async fetchStoragePrincipal(signal: AbortSignal) {
      const value = await rpc('storage_principal', signal);
      if (typeof value !== 'string') malformed();
      return value;
    },

    async listObjects(input, signal) {
      if (
        !Number.isSafeInteger(input.limit) ||
        input.limit < 1 ||
        input.limit > STORAGE_MAX_LIST_ITEMS ||
        !Number.isSafeInteger(input.offset) ||
        input.offset < 0
      ) {
        invalidConfig();
      }
      const response = await request(
        `/storage/v1/object/list/${encodeURIComponent(bucket)}`,
        {
          method: 'POST',
          headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
          body: JSON.stringify({
            prefix: input.folder,
            limit: input.limit + 1,
            offset: input.offset,
            sortBy: { column: 'name', order: 'asc' },
          }),
        },
        signal,
      );
      if (isDenied(response.status)) {
        await response.body?.cancel();
        return Object.freeze({ entries: Object.freeze([]), hasMore: false });
      }
      if (!response.ok) {
        await response.body?.cancel();
        throw new StorageClientError('STORAGE_CLIENT_UPSTREAM_ERROR');
      }
      const value = await readJson(response);
      if (!Array.isArray(value) || value.length > input.limit + 1) malformed();
      const entries: StorageListEntry[] = value.slice(0, input.limit).map((row: unknown) => {
        if (!isRecord(row) || typeof row.name !== 'string' || row.name.includes('/')) malformed();
        const path = `${input.folder}/${row.name}`;
        if (row.id === null) return Object.freeze({ kind: 'folder' as const, objectPrefix: path });
        const metadata = row.metadata;
        if (!isRecord(metadata) || typeof metadata.mimetype !== 'string') malformed();
        if (typeof metadata.size !== 'number') malformed();
        return Object.freeze({
          kind: 'object' as const,
          objectKey: path,
          size: metadata.size,
          mimeType: metadata.mimetype,
          updatedAt: toIso(row.updated_at),
        });
      });
      return Object.freeze({
        entries: Object.freeze(entries),
        hasMore: value.length > input.limit,
      });
    },

    async getObjectInfo(objectKey, signal) {
      const response = await request(
        `/storage/v1/object/authenticated/${encodeURIComponent(bucket)}/${encodeObjectPath(objectKey)}`,
        { method: 'HEAD' },
        signal,
      );
      await response.body?.cancel();
      if (isDenied(response.status)) return null;
      if (!response.ok) throw new StorageClientError('STORAGE_CLIENT_UPSTREAM_ERROR');
      const size = Number(response.headers.get('content-length'));
      const mimeType = response.headers.get('content-type');
      if (!Number.isSafeInteger(size) || size < 0 || mimeType === null) malformed();
      return Object.freeze({
        objectKey,
        size,
        mimeType,
        updatedAt: toIso(response.headers.get('last-modified')),
      });
    },

    async downloadObject(objectKey, maxBytes, signal) {
      const response = await request(
        `/storage/v1/object/authenticated/${encodeURIComponent(bucket)}/${encodeObjectPath(objectKey)}`,
        { method: 'GET' },
        signal,
      );
      if (isDenied(response.status)) {
        await response.body?.cancel();
        return null;
      }
      if (!response.ok) {
        await response.body?.cancel();
        throw new StorageClientError('STORAGE_CLIENT_UPSTREAM_ERROR');
      }
      return readBounded(response, maxBytes);
    },

    async createSignedDownloadUrl(objectKey, expiresInSeconds, signal) {
      const response = await request(
        `/storage/v1/object/sign/${encodeURIComponent(bucket)}/${encodeObjectPath(objectKey)}`,
        {
          method: 'POST',
          headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
          body: JSON.stringify({ expiresIn: expiresInSeconds }),
        },
        signal,
      );
      if (isDenied(response.status)) {
        await response.body?.cancel();
        return null;
      }
      if (!response.ok) {
        await response.body?.cancel();
        throw new StorageClientError('STORAGE_CLIENT_UPSTREAM_ERROR');
      }
      const value = await readJson(response);
      if (!isRecord(value) || typeof value.signedURL !== 'string') malformed();
      if (value.signedURL.length > MAX_SIGNED_URL_BYTES) malformed();
      return `${origin.origin}/storage/v1${value.signedURL.startsWith('/') ? '' : '/'}${value.signedURL}`;
    },
  };
  return Object.freeze(client);
}
