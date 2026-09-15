import {
  MAX_REQUEST_ID_BYTES,
  MAX_RESPONSE_BYTES,
  MAX_TOOL_EXECUTION_MS,
  MEMORY_SEARCH_TOOL,
  type MemoryGetOutput,
  type MemorySearchOutput,
  readToolWireResponseByteLength,
} from '@supabase-user-mcp/contracts';
import type { FixedSupabaseClient } from './fixed-supabase-client.js';
import { createMemoryGet } from './memory-get.js';
import { createMemorySearch } from './memory-search.js';
import {
  normalizeReadToolExecutionContext,
  type ReadToolInvocationContext,
} from './read-tool-governor.js';

type Outcome = 'found' | 'ambiguous' | 'partial' | 'no-match-within-searched-scope' | 'error';
export interface DefensiveRetrievalOutput {
  outcome: Outcome;
  completeness: 'unknown';
  result: MemorySearchOutput | MemoryGetOutput;
  lastSearchQuery: string;
}

// Opt-in composition only: no new registered capability or authority.
export function createDefensiveRetrieval(
  client: FixedSupabaseClient,
  timeoutMs = MAX_TOOL_EXECUTION_MS,
) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TOOL_EXECUTION_MS)
    throw new TypeError('Invalid retrieval timeout.');
  const search = createMemorySearch(client, { ungoverned: true });
  const get = createMemoryGet(client, { ungoverned: true });
  return async (
    unsafeInput: unknown,
    invocation?: ReadToolInvocationContext,
  ): Promise<DefensiveRetrievalOutput> => {
    const context = { ...normalizeReadToolExecutionContext(invocation) };
    // Invocation precondition, before dispatch or error-envelope construction.
    // Reject invalid IDs rather than truncating or reflecting them into a reply.
    // Accepted IDs: absent/null, finite JSON numbers, or <=1024 UTF-8 bytes.
    const requestId = context.requestId;
    if (typeof requestId === 'string') {
      if (new TextEncoder().encode(requestId).byteLength > MAX_REQUEST_ID_BYTES) {
        throw new RangeError('Request ID exceeds the UTF-8 byte limit.');
      }
    } else if (
      requestId !== undefined &&
      requestId !== null &&
      (typeof requestId !== 'number' || !Number.isFinite(requestId))
    ) {
      throw new TypeError('Request ID must be a string, finite number, null, or absent.');
    }
    const controller = new AbortController();
    const abort = () => controller.abort();
    context.signal?.addEventListener('abort', abort, { once: true });
    if (context.signal?.aborted) abort();
    const timer = setTimeout(abort, timeoutMs);
    const failure = (
      code: 'DEADLINE_EXCEEDED' | 'INVALID_REQUEST' | 'INTERNAL_ERROR' | 'RESPONSE_LIMIT_EXCEEDED',
    ): DefensiveRetrievalOutput => ({
      outcome: 'error',
      completeness: 'unknown',
      lastSearchQuery: '',
      result: {
        ok: false,
        error: (
          {
            DEADLINE_EXCEEDED: {
              code: 'DEADLINE_EXCEEDED',
              message: 'Request deadline exceeded.',
              retryable: false,
            },
            INVALID_REQUEST: {
              code: 'INVALID_REQUEST',
              message: 'Request is invalid.',
              retryable: false,
            },
            INTERNAL_ERROR: {
              code: 'INTERNAL_ERROR',
              message: 'Request could not be completed.',
              retryable: false,
            },
            RESPONSE_LIMIT_EXCEEDED: {
              code: 'RESPONSE_LIMIT_EXCEEDED',
              message: 'Response limit exceeded.',
              retryable: false,
            },
          } as const
        )[code],
      },
    });
    const finish = (
      outcome: Outcome,
      result: MemorySearchOutput | MemoryGetOutput,
      lastSearchQuery: string,
    ): DefensiveRetrievalOutput => {
      const output: DefensiveRetrievalOutput = {
        outcome,
        completeness: 'unknown',
        result,
        lastSearchQuery,
      };
      return readToolWireResponseByteLength(context.requestId ?? null, output) <= MAX_RESPONSE_BYTES
        ? output
        : failure('RESPONSE_LIMIT_EXCEEDED');
    };
    const executionContext = { ...context, signal: controller.signal };
    const run = async (): Promise<DefensiveRetrievalOutput> => {
      if (controller.signal.aborted) return failure('DEADLINE_EXCEEDED');
      const input = MEMORY_SEARCH_TOOL.inputSchema.safeParse(unsafeInput);
      if (!input.success) return failure('INVALID_REQUEST');
      let lastSearchQuery = input.data.query;
      let result = await search(input.data, executionContext);
      if (controller.signal.aborted) return failure('DEADLINE_EXCEEDED');
      if (!result.ok) return finish('error', result, lastSearchQuery);
      const normalized = input.data.query.replace(/\s+/gu, ' ').trim();
      // Never reinterpret a continuation cursor under a different query.
      if (
        result.items.length === 0 &&
        result.nextCursor === undefined &&
        input.data.cursor === undefined &&
        normalized !== input.data.query
      ) {
        lastSearchQuery = normalized;
        result = await search({ ...input.data, query: normalized }, executionContext);
        if (controller.signal.aborted) return failure('DEADLINE_EXCEEDED');
        if (!result.ok) return finish('error', result, lastSearchQuery);
      }
      if (result.nextCursor !== undefined) return finish('partial', result, lastSearchQuery);
      if (result.items.length === 0)
        return finish('no-match-within-searched-scope', result, lastSearchQuery);
      if (result.items.length !== 1) return finish('ambiguous', result, lastSearchQuery);
      const candidate = result.items[0];
      if (candidate === undefined) return failure('INTERNAL_ERROR');
      const exact = await get({ id: candidate.id }, executionContext);
      if (controller.signal.aborted) return failure('DEADLINE_EXCEEDED');
      if (exact.ok && exact.record.id !== candidate.id) return failure('INTERNAL_ERROR');
      return finish(exact.ok ? 'found' : 'error', exact, lastSearchQuery);
    };
    let onAbort: (() => void) | undefined;
    try {
      const cancelled = new Promise<DefensiveRetrievalOutput>((resolve) => {
        onAbort = () => resolve(failure('DEADLINE_EXCEEDED'));
        controller.signal.addEventListener('abort', onAbort, { once: true });
        if (controller.signal.aborted) onAbort();
      });
      return await Promise.race([run(), cancelled]);
    } catch {
      return failure(controller.signal.aborted ? 'DEADLINE_EXCEEDED' : 'INTERNAL_ERROR');
    } finally {
      clearTimeout(timer);
      context.signal?.removeEventListener('abort', abort);
      if (onAbort) controller.signal.removeEventListener('abort', onAbort);
    }
  };
}
