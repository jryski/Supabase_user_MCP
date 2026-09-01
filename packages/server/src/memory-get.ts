import {
  MAX_RESPONSE_BYTES,
  MAX_TOOL_EXECUTION_MS,
  MEMORY_GET_TOOL,
  MemoryGetOutputSchema,
  publicMemoryGetUnavailable,
  readToolWireResponseByteLength,
  type MemoryGetOutput,
} from '@supabase-user-mcp/contracts';
import {
  FixedSupabaseClientError,
  type FixedSupabaseClient,
  type FixedMemoryGetRow,
} from './fixed-supabase-client.js';
import {
  createReadToolExecutor,
  normalizeReadToolExecutionContext,
  type ReadToolGovernancePolicy,
  type ReadToolInvocationContext,
} from './read-tool-governor.js';

function error(
  code: 'INVALID_REQUEST' | 'RESPONSE_LIMIT_EXCEEDED' | 'DEADLINE_EXCEEDED' | 'INTERNAL_ERROR',
): MemoryGetOutput {
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

function mapRow(record: FixedMemoryGetRow) {
  return {
    ...record,
    contentTrust: 'untrusted' as const,
  };
}

function normalizeError(cause: unknown, aborted: boolean): MemoryGetOutput {
  if (aborted) return error('DEADLINE_EXCEEDED');
  if (
    cause instanceof FixedSupabaseClientError ||
    (typeof cause === 'object' && cause !== null && 'code' in cause)
  ) {
    return error(mapClientError((cause as { code?: unknown }).code));
  }
  return error('INTERNAL_ERROR');
}

export interface MemoryGetOptions {
  readonly timeoutMs?: number;
  readonly governance?: ReadToolGovernancePolicy;
}

export function createMemoryGet(client: FixedSupabaseClient, options: MemoryGetOptions = {}) {
  const timeoutMs = options.timeoutMs ?? MAX_TOOL_EXECUTION_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TOOL_EXECUTION_MS) {
    throw new TypeError('Invalid memory_get timeout.');
  }

  const executeRaw = async (
    unsafeInput: unknown,
    callerSignal?: AbortSignal,
  ): Promise<MemoryGetOutput> => {
    const input = MEMORY_GET_TOOL.inputSchema.safeParse(unsafeInput);
    if (!input.success) return error('INVALID_REQUEST');

    const controller = new AbortController();
    const cancel = () => controller.abort();
    callerSignal?.addEventListener('abort', cancel, { once: true });
    if (callerSignal?.aborted) controller.abort();
    const timer = setTimeout(cancel, timeoutMs);

    try {
      const record = await client.getMemoryRow(input.data, controller.signal);
      if (record === null) return publicMemoryGetUnavailable('missing');
      const candidate = {
        ok: true as const,
        record: mapRow(record),
      };
      const validated = MemoryGetOutputSchema.safeParse(candidate);
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
    MEMORY_GET_TOOL,
    (input, signal) => executeRaw(input, signal),
    options.governance,
  );
  return (unsafeInput: unknown, context?: ReadToolInvocationContext) =>
    execute(unsafeInput, normalizeReadToolExecutionContext(context));
}
