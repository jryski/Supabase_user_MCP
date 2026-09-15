import {
  createReadToolError,
  MEMORY_RETRIEVE_TOOL,
  type MemoryRetrieveOutput,
} from '@supabase-user-mcp/contracts';
import type { DefensiveRetrievalOutput } from './defensive-retrieval.js';
import { createDefensiveRetrieval } from './defensive-retrieval.js';
import type { FixedSupabaseClient } from './fixed-supabase-client.js';
import {
  createReadToolExecutor,
  normalizeReadToolExecutionContext,
  type ReadToolGovernancePolicy,
  type ReadToolInvocationContext,
} from './read-tool-governor.js';

function retrievalContext(queryLastExecuted: string) {
  return {
    strategy: 'defensive_search_then_get_v1' as const,
    query_last_executed: queryLastExecuted,
    scope_semantics: 'authorized_scope_only' as const,
    snapshot_semantics: 'no_server_snapshot_v1' as const,
    provenance_currentness: 'unknown' as const,
  };
}

function boundedMemoryRetrieveError(
  code: 'INVALID_REQUEST' | 'INTERNAL_ERROR' | 'RESPONSE_LIMIT_EXCEEDED' | 'DEADLINE_EXCEEDED',
): MemoryRetrieveOutput {
  return createReadToolError(code) as MemoryRetrieveOutput;
}

function finalizeMemoryRetrieveOutput(candidate: unknown): MemoryRetrieveOutput {
  const parsed = MEMORY_RETRIEVE_TOOL.outputSchema.safeParse(candidate);
  if (!parsed.success) {
    return boundedMemoryRetrieveError('INTERNAL_ERROR');
  }
  return parsed.data;
}

export function mapDefensiveRetrievalToMemoryRetrieveOutput(
  internal: DefensiveRetrievalOutput,
): MemoryRetrieveOutput {
  const context = retrievalContext(internal.lastSearchQuery);

  if (internal.outcome === 'error') {
    if (!internal.result.ok) {
      return finalizeMemoryRetrieveOutput(internal.result);
    }
    return boundedMemoryRetrieveError('INTERNAL_ERROR');
  }

  if (internal.outcome === 'found') {
    if (!internal.result.ok || !('record' in internal.result)) {
      return boundedMemoryRetrieveError('INTERNAL_ERROR');
    }
    return finalizeMemoryRetrieveOutput({
      ok: true,
      outcome: 'found',
      completeness: 'unknown',
      retrieval: context,
      result: internal.result,
    });
  }

  if (internal.outcome === 'no-match-within-searched-scope') {
    if (!internal.result.ok || !('items' in internal.result)) {
      return boundedMemoryRetrieveError('INTERNAL_ERROR');
    }
    if (internal.result.items.length > 0 || internal.result.nextCursor !== undefined) {
      return boundedMemoryRetrieveError('INTERNAL_ERROR');
    }
    return finalizeMemoryRetrieveOutput({
      ok: true,
      outcome: 'scoped_no_match',
      completeness: 'unknown',
      retrieval: context,
      result: { ok: true, items: [] },
    });
  }

  if (internal.outcome === 'ambiguous') {
    if (!internal.result.ok || !('items' in internal.result)) {
      return boundedMemoryRetrieveError('INTERNAL_ERROR');
    }
    if (internal.result.items.length < 2 || internal.result.nextCursor !== undefined) {
      return boundedMemoryRetrieveError('INTERNAL_ERROR');
    }
    return finalizeMemoryRetrieveOutput({
      ok: true,
      outcome: 'ambiguous',
      completeness: 'unknown',
      retrieval: context,
      result: internal.result,
    });
  }

  if (internal.outcome === 'partial') {
    if (
      !internal.result.ok ||
      !('items' in internal.result) ||
      internal.result.nextCursor === undefined
    ) {
      return boundedMemoryRetrieveError('INTERNAL_ERROR');
    }
    return finalizeMemoryRetrieveOutput({
      ok: true,
      outcome: 'partial',
      completeness: 'unknown',
      retrieval: context,
      result: internal.result,
    });
  }

  return boundedMemoryRetrieveError('INTERNAL_ERROR');
}

export interface MemoryRetrieveOptions {
  readonly governance?: ReadToolGovernancePolicy;
}

export function createMemoryRetrieve(
  client: FixedSupabaseClient,
  options: MemoryRetrieveOptions = {},
) {
  const retrieve = createDefensiveRetrieval(client);
  return (unsafeInput: unknown, invocation?: ReadToolInvocationContext) => {
    const context = normalizeReadToolExecutionContext(invocation);
    const execute = createReadToolExecutor(
      MEMORY_RETRIEVE_TOOL,
      async (input, signal) => {
        const internal = await retrieve(input, { ...context, signal });
        return mapDefensiveRetrievalToMemoryRetrieveOutput(internal);
      },
      options.governance,
    );
    return execute(unsafeInput, context);
  };
}
