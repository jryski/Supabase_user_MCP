import type { LocalCredentials } from './local-credential-loader.js';
import {
  MemoryGetInputSchema,
  type MemoryGetInput,
  MemoryListRecentInputSchema,
  type MemoryListRecentInput,
  MemorySearchInputSchema,
  type MemorySearchInput,
} from '@supabase-user-mcp/contracts';

const FIXED_PATH = '/rest/v1/memories?select=id%2Ccontent&limit=100';
const FIXED_SCHEMA = 'memory';
const FIXED_SEARCH_PATH = '/rest/v1/rpc/authorized_memory_search_v1';
const FIXED_GET_PATH = '/rest/v1/rpc/authorized_memory_get_v1';
const FIXED_LIST_RECENT_PATH = '/rest/v1/rpc/authorized_memory_list_recent_v1';
const DEFAULT_TIMEOUT_MS = 5_000;
const MAX_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const OPAQUE_CURSOR = /^cur_[A-Za-z0-9_-]{16,1020}$/;

const ALLOWED_MEMORY_ROW_FIELDS = Object.freeze([
  'id',
  'title',
  'content',
  'createdAt',
  'provenanceSummary',
] as const);

export type FixedMemoryRecordField = (typeof ALLOWED_MEMORY_ROW_FIELDS)[number];

export type FixedSupabaseClientErrorCode =
  | 'FIXED_CLIENT_INVALID_CREDENTIAL'
  | 'FIXED_CLIENT_INVALID_REQUEST'
  | 'FIXED_CLIENT_INVALID_CURSOR'
  | 'FIXED_CLIENT_TIMEOUT'
  | 'FIXED_CLIENT_NETWORK_FAILURE'
  | 'FIXED_CLIENT_MALFORMED_RESPONSE'
  | 'FIXED_CLIENT_UPSTREAM_STATUS'
  | 'FIXED_CLIENT_RESPONSE_TOO_LARGE';

export class FixedSupabaseClientError extends Error {
  readonly code: FixedSupabaseClientErrorCode;

  constructor(code: FixedSupabaseClientErrorCode) {
    super(code);
    this.name = 'FixedSupabaseClientError';
    this.code = code;
  }
}

export interface FixedSupabaseClientConfig {
  readonly origin: string;
  readonly credentials: LocalCredentials;
  readonly fetch?: typeof globalThis.fetch;
  readonly timeoutMs?: number;
  readonly maxResponseBytes?: number;
}

export interface FixedMemoryGetRow {
  readonly id: string;
  readonly title: string;
  readonly content: string;
  readonly createdAt: string;
  readonly provenanceSummary: string;
}

export interface FixedMemoryListRecentResult {
  readonly rows: ReadonlyArray<FixedMemoryGetRow>;
  readonly nextCursor?: string;
}

export interface FixedSupabaseClient {
  readonly listMemoryRows: () => Promise<ReadonlyArray<Readonly<Record<string, unknown>>>>;
  readonly searchMemoryRows: (
    input: MemorySearchInput,
    signal?: AbortSignal,
  ) => Promise<FixedMemorySearchResult>;
  readonly getMemoryRow: (
    input: MemoryGetInput,
    signal?: AbortSignal,
  ) => Promise<FixedMemoryGetRow | null>;
  readonly listRecentMemoryRows: (
    input: MemoryListRecentInput,
    signal?: AbortSignal,
  ) => Promise<FixedMemoryListRecentResult>;
}

export interface FixedMemorySearchRow extends FixedMemoryGetRow {
  readonly rank: number;
}

export interface FixedMemorySearchResult {
  readonly rows: ReadonlyArray<FixedMemorySearchRow>;
  readonly nextCursor?: string;
}

function invalid(): never {
  throw new FixedSupabaseClientError('FIXED_CLIENT_INVALID_CREDENTIAL');
}

function boundedInteger(value: number, maximum: number): boolean {
  return Number.isSafeInteger(value) && value > 0 && value <= maximum;
}

function hasAllowedKeys(
  record: Readonly<Record<string, unknown>>,
  allowed: readonly string[],
): boolean {
  const keys = Object.keys(record);
  if (keys.length !== allowed.length) return false;
  for (const key of keys) {
    if (!allowed.includes(key)) return false;
  }
  return true;
}

function hasRequiredStringFields(
  record: Readonly<Record<string, unknown>>,
  fields: readonly string[],
): boolean {
  return (
    hasAllowedKeys(record, fields) && fields.every((field) => typeof record[field] === 'string')
  );
}

async function readBoundedBody(response: Response, maximum: number): Promise<string> {
  if (response.body === null) return '';
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      length += result.value.byteLength;
      if (length > maximum) {
        await reader.cancel();
        throw new FixedSupabaseClientError('FIXED_CLIENT_RESPONSE_TOO_LARGE');
      }
      chunks.push(result.value);
    }
  } catch (error) {
    if (error instanceof FixedSupabaseClientError) throw error;
    throw error;
  }
  return Buffer.concat(chunks, length).toString('utf8');
}

function parseGetRow(value: unknown, code: FixedSupabaseClientErrorCode): FixedMemoryGetRow {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new FixedSupabaseClientError(code);
  }
  if (
    !hasRequiredStringFields(value as Readonly<Record<string, unknown>>, ALLOWED_MEMORY_ROW_FIELDS)
  ) {
    throw new FixedSupabaseClientError(code);
  }
  return Object.freeze({
    id: (value as Record<string, unknown>).id as string,
    title: (value as Record<string, unknown>).title as string,
    content: (value as Record<string, unknown>).content as string,
    createdAt: (value as Record<string, unknown>).createdAt as string,
    provenanceSummary: (value as Record<string, unknown>).provenanceSummary as string,
  });
}

function parseMemoryGetPayload(value: unknown): FixedMemoryGetRow | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new FixedSupabaseClientError('FIXED_CLIENT_MALFORMED_RESPONSE');
  }
  const envelope = value as Readonly<Record<string, unknown>>;
  const keys = Object.keys(envelope);
  if (keys.length !== 1 || keys[0] !== 'record') {
    throw new FixedSupabaseClientError('FIXED_CLIENT_MALFORMED_RESPONSE');
  }
  if (envelope.record === null) return null;
  return parseGetRow(envelope.record, 'FIXED_CLIENT_MALFORMED_RESPONSE');
}

function parseMemoryListPayload(value: unknown): FixedMemoryListRecentResult {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new FixedSupabaseClientError('FIXED_CLIENT_MALFORMED_RESPONSE');
  }
  const envelope = value as Readonly<Record<string, unknown>>;
  const keys = Object.keys(envelope).sort();
  if (keys.length < 1 || keys.length > 2) {
    throw new FixedSupabaseClientError('FIXED_CLIENT_MALFORMED_RESPONSE');
  }
  const allowed = ['nextCursor', 'rows'];
  if (!keys.every((key) => allowed.includes(key))) {
    throw new FixedSupabaseClientError('FIXED_CLIENT_MALFORMED_RESPONSE');
  }
  const rawRows = envelope.rows;
  if (!Array.isArray(rawRows)) {
    throw new FixedSupabaseClientError('FIXED_CLIENT_MALFORMED_RESPONSE');
  }
  const rows = rawRows.map((value) => parseGetRow(value, 'FIXED_CLIENT_MALFORMED_RESPONSE'));
  if (envelope.nextCursor !== undefined) {
    if (typeof envelope.nextCursor !== 'string' || !OPAQUE_CURSOR.test(envelope.nextCursor)) {
      throw new FixedSupabaseClientError('FIXED_CLIENT_INVALID_CURSOR');
    }
  }
  return Object.freeze({
    rows,
    ...(envelope.nextCursor === undefined ? {} : { nextCursor: envelope.nextCursor }),
  });
}

function parseMemorySearchPayload(value: unknown, limit: number): FixedMemorySearchResult {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new FixedSupabaseClientError('FIXED_CLIENT_MALFORMED_RESPONSE');
  }
  const envelope = value as Readonly<Record<string, unknown>>;
  const keys = Object.keys(envelope).sort();
  if (
    keys.length < 1 ||
    keys.length > 2 ||
    !keys.every((key) => key === 'rows' || key === 'nextCursor') ||
    !Array.isArray(envelope.rows) ||
    envelope.rows.length > limit
  ) {
    throw new FixedSupabaseClientError('FIXED_CLIENT_MALFORMED_RESPONSE');
  }
  const rows = envelope.rows.map((candidate) => {
    if (typeof candidate !== 'object' || candidate === null || Array.isArray(candidate)) {
      throw new FixedSupabaseClientError('FIXED_CLIENT_MALFORMED_RESPONSE');
    }
    const record = candidate as Readonly<Record<string, unknown>>;
    const rowKeys = Object.keys(record);
    const allowed = [...ALLOWED_MEMORY_ROW_FIELDS, 'rank'];
    if (
      rowKeys.length !== allowed.length ||
      !rowKeys.every((key) => allowed.includes(key as FixedMemoryRecordField | 'rank')) ||
      typeof record.rank !== 'number' ||
      !Number.isFinite(record.rank) ||
      record.rank < 0 ||
      record.rank > 1
    ) {
      throw new FixedSupabaseClientError('FIXED_CLIENT_MALFORMED_RESPONSE');
    }
    const baseRow = Object.fromEntries(
      ALLOWED_MEMORY_ROW_FIELDS.map((field) => [field, record[field]]),
    );
    return Object.freeze({
      ...parseGetRow(baseRow, 'FIXED_CLIENT_MALFORMED_RESPONSE'),
      rank: record.rank,
    });
  });
  if (
    envelope.nextCursor !== undefined &&
    (typeof envelope.nextCursor !== 'string' || !OPAQUE_CURSOR.test(envelope.nextCursor))
  ) {
    throw new FixedSupabaseClientError('FIXED_CLIENT_INVALID_CURSOR');
  }
  return Object.freeze({
    rows,
    ...(envelope.nextCursor === undefined ? {} : { nextCursor: envelope.nextCursor }),
  });
}

export function createFixedSupabaseClient(config: FixedSupabaseClientConfig): FixedSupabaseClient {
  let parsedOrigin: URL;
  try {
    parsedOrigin = new URL(config.origin);
  } catch {
    invalid();
  }
  if (
    parsedOrigin.protocol !== 'https:' ||
    parsedOrigin.origin !== config.origin ||
    parsedOrigin.username !== '' ||
    parsedOrigin.password !== ''
  ) {
    invalid();
  }
  const key = config.credentials.projectPublishableKey?.trim();
  const token = config.credentials.userAccessToken?.trim();
  if (
    !key ||
    !token ||
    key === token ||
    key.split('.').length === 3 ||
    token.split('.').length !== 3
  ) {
    invalid();
  }
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxResponseBytes = config.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  if (
    !boundedInteger(timeoutMs, MAX_TIMEOUT_MS) ||
    !boundedInteger(maxResponseBytes, MAX_RESPONSE_BYTES)
  ) {
    invalid();
  }
  const fetchImplementation = config.fetch ?? globalThis.fetch;
  const listHeaders = Object.freeze({
    Accept: 'application/json',
    'Accept-Profile': FIXED_SCHEMA,
    Authorization: `Bearer ${token}`,
    apikey: key,
  });

  const postHeaders = Object.freeze({
    ...listHeaders,
    'Content-Type': 'application/json',
    'Content-Profile': FIXED_SCHEMA,
  });

  const listMemoryRows = async (): Promise<ReadonlyArray<Readonly<Record<string, unknown>>>> => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const upstream = await fetchImplementation(`${parsedOrigin.origin}${FIXED_PATH}`, {
        method: 'GET',
        headers: listHeaders,
        signal: controller.signal,
      });
      if (!upstream.ok) throw new FixedSupabaseClientError('FIXED_CLIENT_UPSTREAM_STATUS');
      const advertisedLength = upstream.headers.get('content-length');
      if (advertisedLength !== null && Number(advertisedLength) > maxResponseBytes) {
        throw new FixedSupabaseClientError('FIXED_CLIENT_RESPONSE_TOO_LARGE');
      }
      const body = await readBoundedBody(upstream, maxResponseBytes);
      let parsed: unknown;
      try {
        parsed = JSON.parse(body);
      } catch {
        throw new FixedSupabaseClientError('FIXED_CLIENT_MALFORMED_RESPONSE');
      }
      if (
        !Array.isArray(parsed) ||
        parsed.some((row) => typeof row !== 'object' || row === null || Array.isArray(row))
      ) {
        throw new FixedSupabaseClientError('FIXED_CLIENT_MALFORMED_RESPONSE');
      }
      return parsed as ReadonlyArray<Readonly<Record<string, unknown>>>;
    } catch (error) {
      if (error instanceof FixedSupabaseClientError) throw error;
      if (controller.signal.aborted) throw new FixedSupabaseClientError('FIXED_CLIENT_TIMEOUT');
      throw new FixedSupabaseClientError('FIXED_CLIENT_NETWORK_FAILURE');
    } finally {
      clearTimeout(timer);
    }
  };

  const requestMemoryRpc = async <TInput>(
    path: string,
    input: TInput,
    callerSignal?: AbortSignal,
  ): Promise<unknown> => {
    const parsedInput = JSON.parse(JSON.stringify(input));
    const controller = new AbortController();
    const cancel = () => controller.abort();
    callerSignal?.addEventListener('abort', cancel, { once: true });
    if (callerSignal?.aborted) controller.abort();
    const timer = setTimeout(cancel, timeoutMs);
    try {
      const upstream = await fetchImplementation(`${parsedOrigin.origin}${path}`, {
        method: 'POST',
        headers: postHeaders,
        body: JSON.stringify(parsedInput),
        signal: controller.signal,
      });
      if (!upstream.ok) {
        throw new FixedSupabaseClientError(
          upstream.status === 400 ? 'FIXED_CLIENT_INVALID_CURSOR' : 'FIXED_CLIENT_UPSTREAM_STATUS',
        );
      }
      const advertisedLength = upstream.headers.get('content-length');
      if (advertisedLength !== null && Number(advertisedLength) > maxResponseBytes) {
        throw new FixedSupabaseClientError('FIXED_CLIENT_RESPONSE_TOO_LARGE');
      }
      const body = await readBoundedBody(upstream, maxResponseBytes);
      let value: unknown;
      try {
        value = JSON.parse(body);
      } catch {
        throw new FixedSupabaseClientError('FIXED_CLIENT_MALFORMED_RESPONSE');
      }
      return value;
    } catch (error) {
      if (error instanceof FixedSupabaseClientError) throw error;
      if (controller.signal.aborted) throw new FixedSupabaseClientError('FIXED_CLIENT_TIMEOUT');
      throw new FixedSupabaseClientError('FIXED_CLIENT_NETWORK_FAILURE');
    } finally {
      clearTimeout(timer);
      callerSignal?.removeEventListener('abort', cancel);
    }
  };

  const getMemoryRow = async (
    unsafeInput: MemoryGetInput,
    callerSignal?: AbortSignal,
  ): Promise<FixedMemoryGetRow | null> => {
    const parsedInput = MemoryGetInputSchema.safeParse(unsafeInput);
    if (!parsedInput.success) {
      throw new FixedSupabaseClientError('FIXED_CLIENT_INVALID_REQUEST');
    }
    const payload = await requestMemoryRpc(FIXED_GET_PATH, parsedInput.data, callerSignal);
    return parseMemoryGetPayload(payload);
  };

  const searchMemoryRows = async (
    unsafeInput: MemorySearchInput,
    callerSignal?: AbortSignal,
  ): Promise<FixedMemorySearchResult> => {
    const parsedInput = MemorySearchInputSchema.safeParse(unsafeInput);
    if (!parsedInput.success) {
      throw new FixedSupabaseClientError('FIXED_CLIENT_INVALID_REQUEST');
    }
    const payload = await requestMemoryRpc(FIXED_SEARCH_PATH, parsedInput.data, callerSignal);
    return parseMemorySearchPayload(payload, parsedInput.data.limit);
  };

  const listRecentMemoryRows = async (
    unsafeInput: MemoryListRecentInput,
    callerSignal?: AbortSignal,
  ): Promise<FixedMemoryListRecentResult> => {
    const parsedInput = MemoryListRecentInputSchema.safeParse(unsafeInput);
    if (!parsedInput.success) {
      throw new FixedSupabaseClientError('FIXED_CLIENT_INVALID_REQUEST');
    }
    const payload = await requestMemoryRpc(FIXED_LIST_RECENT_PATH, parsedInput.data, callerSignal);
    const result = parseMemoryListPayload(payload);
    if (result.rows.length > parsedInput.data.limit) {
      throw new FixedSupabaseClientError('FIXED_CLIENT_MALFORMED_RESPONSE');
    }
    return result;
  };

  return Object.freeze({
    listMemoryRows,
    searchMemoryRows,
    getMemoryRow,
    listRecentMemoryRows,
  });
}
