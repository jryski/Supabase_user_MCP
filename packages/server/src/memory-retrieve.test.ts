import {
  MAX_RESPONSE_BYTES,
  MemorySearchOutputSchema,
  readToolWireResponseByteLength,
} from '@supabase-user-mcp/contracts';
import { expect, it } from 'vitest';
import type { DefensiveRetrievalOutput } from './defensive-retrieval.js';
import { mapDefensiveRetrievalToMemoryRetrieveOutput } from './memory-retrieve.js';

it('reports a response limit when only the public retrieval wrapper exceeds the byte budget', () => {
  const internal: DefensiveRetrievalOutput = {
    outcome: 'ambiguous',
    completeness: 'unknown',
    lastSearchQuery: 'x',
    result: {
      ok: true,
      items: Array.from({ length: 4 }, (_, index) => ({
        id: `mem_${String(index).padStart(24, '0')}`,
        title: 't',
        content: 'x'.repeat(7909),
        contentTrust: 'untrusted',
        createdAt: '2026-08-23T12:00:00.000Z',
        provenanceSummary: 'p',
        rank: 0.5,
      })),
    },
  };
  const publicCandidate = {
    ok: true,
    outcome: 'ambiguous',
    completeness: 'unknown',
    retrieval: {
      strategy: 'defensive_search_then_get_v1',
      query_last_executed: 'x',
      scope_semantics: 'authorized_scope_only',
      snapshot_semantics: 'no_server_snapshot_v1',
      provenance_currentness: 'unknown',
    },
    result: internal.result,
  };

  expect(MemorySearchOutputSchema.safeParse(internal.result).success).toBe(true);
  expect(readToolWireResponseByteLength(null, internal)).toBeLessThanOrEqual(MAX_RESPONSE_BYTES);
  expect(readToolWireResponseByteLength(null, publicCandidate)).toBeGreaterThan(MAX_RESPONSE_BYTES);
  const output = mapDefensiveRetrievalToMemoryRetrieveOutput(internal);
  expect(output).toEqual({
    ok: false,
    error: {
      code: 'RESPONSE_LIMIT_EXCEEDED',
      message: 'Response limit exceeded.',
      retryable: false,
    },
  });
  expect(readToolWireResponseByteLength(null, output)).toBeLessThanOrEqual(MAX_RESPONSE_BYTES);
});

it('rejects contradictory scoped no-match search payloads', () => {
  const output = mapDefensiveRetrievalToMemoryRetrieveOutput({
    outcome: 'no-match-within-searched-scope',
    completeness: 'unknown',
    lastSearchQuery: 'x',
    result: {
      ok: true,
      items: [
        {
          id: 'mem_1234567890123456789012',
          title: 't',
          content: 'c',
          contentTrust: 'untrusted',
          createdAt: '2026-08-23T12:00:00.000Z',
          provenanceSummary: 'p',
          rank: 0.5,
        },
      ],
    },
  });
  expect(output).toEqual({
    ok: false,
    error: {
      code: 'INTERNAL_ERROR',
      message: 'Request could not be completed.',
      retryable: false,
    },
  });
});
