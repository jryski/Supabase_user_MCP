import type { LocalCredentials } from './local-credential-loader.js';
import { MemorySearchInputSchema, type MemorySearchInput } from '@supabase-user-mcp/contracts';

const FIXED_PATH = '/rest/v1/memories?select=id%2Ccontent&limit=100';
const FIXED_SCHEMA = 'memory';
const FIXED_SEARCH_PATH = '/rest/v1/rpc/authorized_memory_search_v1';
const DEFAULT_TIMEOUT_MS = 5_000;
const MAX_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_RESPONSE_BYTES = 1024 * 1024;

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

export interface FixedSupabaseClient {
  readonly listMemoryRows: () => Promise<ReadonlyArray<Readonly<Record<string, unknown>>>>;
  readonly searchMemoryRows: (
    input: MemorySearchInput,
    signal?: AbortSignal,
  ) => Promise<FixedMemorySearchResult>;
}

export interface FixedMemorySearchRow {
  readonly id: string;
  readonly title: string;
  readonly content: string;
  readonly createdAt: string;
  readonly provenanceSummary: string;
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
    throw new FixedSupabaseClientError('FIXED_CLIENT_NETWORK_FAILURE');
  }
  return Buffer.concat(chunks, length).toString('utf8');
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
  const url = `${parsedOrigin.origin}${FIXED_PATH}`;
  const headers = Object.freeze({
    Accept: 'application/json',
    'Accept-Profile': FIXED_SCHEMA,
    Authorization: `Bearer ${token}`,
    apikey: key,
  });

  const listMemoryRows = async (): Promise<ReadonlyArray<Readonly<Record<string, unknown>>>> => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let upstream: Response;
    try {
      upstream = await fetchImplementation(url, {
        method: 'GET',
        headers,
        signal: controller.signal,
      });
    } catch {
      if (controller.signal.aborted) throw new FixedSupabaseClientError('FIXED_CLIENT_TIMEOUT');
      throw new FixedSupabaseClientError('FIXED_CLIENT_NETWORK_FAILURE');
    } finally {
      clearTimeout(timer);
    }
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
  };

  const searchMemoryRows = async (
    unsafeInput: MemorySearchInput,
    callerSignal?: AbortSignal,
  ): Promise<FixedMemorySearchResult> => {
    const parsedInput = MemorySearchInputSchema.safeParse(unsafeInput);
    if (!parsedInput.success) {
      throw new FixedSupabaseClientError('FIXED_CLIENT_INVALID_REQUEST');
    }
    const controller = new AbortController();
    const cancel = () => controller.abort();
    callerSignal?.addEventListener('abort', cancel, { once: true });
    if (callerSignal?.aborted) controller.abort();
    const timer = setTimeout(cancel, timeoutMs);
    let upstream: Response;
    try {
      upstream = await fetchImplementation(`${parsedOrigin.origin}${FIXED_SEARCH_PATH}`, {
        method: 'POST',
        headers: {
          ...headers,
          'Content-Type': 'application/json',
          'Content-Profile': FIXED_SCHEMA,
        },
        body: JSON.stringify(parsedInput.data),
        signal: controller.signal,
      });
    } catch {
      if (controller.signal.aborted) throw new FixedSupabaseClientError('FIXED_CLIENT_TIMEOUT');
      throw new FixedSupabaseClientError('FIXED_CLIENT_NETWORK_FAILURE');
    } finally {
      clearTimeout(timer);
      callerSignal?.removeEventListener('abort', cancel);
    }
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
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      throw new FixedSupabaseClientError('FIXED_CLIENT_MALFORMED_RESPONSE');
    }
    const envelope = value as Record<string, unknown>;
    const envelopeKeys = Object.keys(envelope);
    if (
      !envelopeKeys.every((key) => key === 'rows' || key === 'nextCursor') ||
      !Array.isArray(envelope.rows) ||
      envelope.rows.length > parsedInput.data.limit ||
      (envelope.nextCursor !== undefined && typeof envelope.nextCursor !== 'string')
    ) {
      throw new FixedSupabaseClientError('FIXED_CLIENT_MALFORMED_RESPONSE');
    }
    const allowed = ['id', 'title', 'content', 'createdAt', 'provenanceSummary', 'rank'];
    if (
      envelope.rows.some((candidate) => {
        if (typeof candidate !== 'object' || candidate === null || Array.isArray(candidate))
          return true;
        const candidateRecord = candidate as Record<string, unknown>;
        return (
          Object.keys(candidateRecord).length !== allowed.length ||
          !Object.keys(candidateRecord).every((key) => allowed.includes(key))
        );
      })
    ) {
      throw new FixedSupabaseClientError('FIXED_CLIENT_MALFORMED_RESPONSE');
    }
    return Object.freeze({
      rows: envelope.rows as FixedMemorySearchRow[],
      ...(envelope.nextCursor === undefined ? {} : { nextCursor: envelope.nextCursor as string }),
    });
  };

  return Object.freeze({ listMemoryRows, searchMemoryRows });
}
