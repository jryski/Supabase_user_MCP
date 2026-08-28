import {
  MAX_RESPONSE_BYTES,
  MAX_TOOL_EXECUTION_MS,
  MEMORY_LIST_RECENT_TOOL,
  MemoryListRecentOutputSchema,
  readToolWireResponseByteLength,
  type MemoryListRecentOutput,
} from '@supabase-user-mcp/contracts';
import {
  FixedSupabaseClientError,
  type FixedMemoryGetRow,
  type FixedSupabaseClient,
} from './fixed-supabase-client.js';
import {
  createReadToolExecutor,
  normalizeReadToolExecutionContext,
  type ReadToolGovernancePolicy,
  type ReadToolInvocationContext,
} from './read-tool-governor.js';

function error(
  code: 'INVALID_REQUEST' | 'RESPONSE_LIMIT_EXCEEDED' | 'DEADLINE_EXCEEDED' | 'INTERNAL_ERROR',
): MemoryListRecentOutput {
  switch (code) {
    case 'INVALID_REQUEST':
      return { ok: false, error: { code, message: 'Request is invalid.', retryable: false } };
    case 'RESPONSE_LIMIT_EXCEEDED':
      return { ok: false, error: { code, message: 'Response limit exceeded.', retryable: false } };
    case 'DEADLINE_EXCEEDED':
      return {
        ok: false,
        error: { code, message: 'Request deadline exceeded.', retryable: false },
      };
    case 'INTERNAL_ERROR':
      return {
        ok: false,
        error: { code, message: 'Request could not be completed.', retryable: false },
      };
  }
}

function mapClientError(
  code?: unknown,
): 'INVALID_REQUEST' | 'RESPONSE_LIMIT_EXCEEDED' | 'DEADLINE_EXCEEDED' | 'INTERNAL_ERROR' {
  if (code === 'FIXED_CLIENT_TIMEOUT') return 'DEADLINE_EXCEEDED';
  if (code === 'FIXED_CLIENT_RESPONSE_TOO_LARGE') return 'RESPONSE_LIMIT_EXCEEDED';
  if (code === 'FIXED_CLIENT_INVALID_REQUEST' || code === 'FIXED_CLIENT_INVALID_CURSOR') {
    return 'INVALID_REQUEST';
  }
  return 'INTERNAL_ERROR';
}

function mapRows(rows: ReadonlyArray<FixedMemoryGetRow>) {
  return rows.map((row) => ({
    ...row,
    contentTrust: 'untrusted' as const,
  }));
}

function normalizeError(cause: unknown, aborted: boolean): MemoryListRecentOutput {
  if (aborted) return error('DEADLINE_EXCEEDED');
  if (
    cause instanceof FixedSupabaseClientError ||
    (typeof cause === 'object' && cause !== null && 'code' in cause)
  ) {
    return error(mapClientError((cause as { code?: unknown }).code));
  }
  return error('INTERNAL_ERROR');
}

export interface MemoryListRecentOptions {
  readonly timeoutMs?: number;
  readonly governance?: ReadToolGovernancePolicy;
}

export function createMemoryListRecent(
  client: FixedSupabaseClient,
  options: MemoryListRecentOptions = {},
) {
  const timeoutMs = options.timeoutMs ?? MAX_TOOL_EXECUTION_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TOOL_EXECUTION_MS) {
    throw new TypeError('Invalid memory_list_recent timeout.');
  }

  const executeRaw = async (
    unsafeInput: unknown,
    callerSignal?: AbortSignal,
  ): Promise<MemoryListRecentOutput> => {
    const input = MEMORY_LIST_RECENT_TOOL.inputSchema.safeParse(unsafeInput);
    if (!input.success) return error('INVALID_REQUEST');

    const controller = new AbortController();
    const cancel = () => controller.abort();
    callerSignal?.addEventListener('abort', cancel, { once: true });
    if (callerSignal?.aborted) controller.abort();
    const timer = setTimeout(cancel, timeoutMs);

    try {
      const result = await client.listRecentMemoryRows(input.data, controller.signal);
      const isOrdered = result.rows.every((current, index, rows) => {
        if (index === 0) return true;
        const previous = rows[index - 1];
        if (previous === undefined) return false;
        return (
          previous.createdAt > current.createdAt ||
          (previous.createdAt === current.createdAt && previous.id >= current.id)
        );
      });
      if (!isOrdered) return error('INTERNAL_ERROR');
      const candidate = {
        ok: true as const,
        items: mapRows(result.rows),
        ...(result.nextCursor === undefined ? {} : { nextCursor: result.nextCursor }),
      };
      const validated = MemoryListRecentOutputSchema.safeParse(candidate);
      if (!validated.success) {
        return readToolWireResponseByteLength(null, candidate) > MAX_RESPONSE_BYTES
          ? error('RESPONSE_LIMIT_EXCEEDED')
          : error('INTERNAL_ERROR');
      }
      return validated.data;
    } catch (cause) {
      return normalizeError(cause, controller.signal.aborted);
    } finally {
      clearTimeout(timer);
      callerSignal?.removeEventListener('abort', cancel);
    }
  };
  const execute = createReadToolExecutor(
    MEMORY_LIST_RECENT_TOOL,
    (input, signal) => executeRaw(input, signal),
    options.governance,
  );
  return (unsafeInput: unknown, context?: ReadToolInvocationContext) =>
    execute(unsafeInput, normalizeReadToolExecutionContext(context));
}
