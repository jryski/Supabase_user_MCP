import { expect, it } from 'vitest';
import { mapDefensiveRetrievalToMemoryRetrieveOutput } from './memory-retrieve.js';

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
