import {
  MAX_RESPONSE_BYTES,
  MAX_TOOL_EXECUTION_MS,
  MEMORY_SEARCH_TOOL,
  MemorySearchInputSchema,
  MemorySearchOutputSchema,
  readToolWireResponseByteLength,
  type MemorySearchOutput,
} from '@supabase-user-mcp/contracts';
import { FixedSupabaseClientError, type FixedSupabaseClient } from './fixed-supabase-client.js';
import {
  createReadToolExecutor,
  normalizeReadToolExecutionContext,
  type ReadToolGovernancePolicy,
  type ReadToolInvocationContext,
} from './read-tool-governor.js';

function error(
  code: 'INVALID_REQUEST' | 'RESPONSE_LIMIT_EXCEEDED' | 'DEADLINE_EXCEEDED' | 'INTERNAL_ERROR',
): MemorySearchOutput {
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

export interface MemorySearchOptions {
  readonly timeoutMs?: number;
  readonly governance?: ReadToolGovernancePolicy;
}

export function createMemorySearch(client: FixedSupabaseClient, options: MemorySearchOptions = {}) {
  const timeoutMs = options.timeoutMs ?? MAX_TOOL_EXECUTION_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TOOL_EXECUTION_MS) {
    throw new TypeError('Invalid memory search timeout.');
  }
  const executeRaw = async (
    unsafeInput: unknown,
    callerSignal?: AbortSignal,
  ): Promise<MemorySearchOutput> => {
    const input = MemorySearchInputSchema.safeParse(unsafeInput);
    if (!input.success) return error('INVALID_REQUEST');
    const controller = new AbortController();
    const cancel = () => controller.abort();
    callerSignal?.addEventListener('abort', cancel, { once: true });
    if (callerSignal?.aborted) controller.abort();
    const timer = setTimeout(cancel, timeoutMs);
    try {
      const result = await client.searchMemoryRows(input.data, controller.signal);
      const candidate = {
        ok: true as const,
        items: result.rows.map((row) => ({ ...row, contentTrust: 'untrusted' as const })),
        ...(result.nextCursor === undefined ? {} : { nextCursor: result.nextCursor }),
      };
      if (readToolWireResponseByteLength(null, candidate) > MAX_RESPONSE_BYTES) {
        return error('RESPONSE_LIMIT_EXCEEDED');
      }
      const validated = MemorySearchOutputSchema.safeParse(candidate);
      if (!validated.success) {
        return error('INTERNAL_ERROR');
      }
      return validated.data;
    } catch (cause) {
      if (controller.signal.aborted) return error('DEADLINE_EXCEEDED');
      if (
        cause instanceof FixedSupabaseClientError ||
        (typeof cause === 'object' && cause !== null && 'code' in cause)
      ) {
        const code = (cause as { code?: unknown }).code;
        if (code === 'FIXED_CLIENT_TIMEOUT') return error('DEADLINE_EXCEEDED');
        if (code === 'FIXED_CLIENT_RESPONSE_TOO_LARGE') return error('RESPONSE_LIMIT_EXCEEDED');
        if (code === 'FIXED_CLIENT_INVALID_REQUEST' || code === 'FIXED_CLIENT_INVALID_CURSOR')
          return error('INVALID_REQUEST');
      }
      return error('INTERNAL_ERROR');
    } finally {
      clearTimeout(timer);
      callerSignal?.removeEventListener('abort', cancel);
    }
  };
  const execute = createReadToolExecutor(
    MEMORY_SEARCH_TOOL,
    (input, signal) => executeRaw(input, signal),
    options.governance,
  );
  return (unsafeInput: unknown, context?: ReadToolInvocationContext) =>
    execute(unsafeInput, normalizeReadToolExecutionContext(context));
}
