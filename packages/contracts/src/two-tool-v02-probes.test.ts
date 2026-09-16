import { describe, expect, it } from 'vitest';

import {
  MemoryRetrieveInputSchema,
  MemoryRetrieveOutputSchema,
  SESSION_CAPABILITIES_READ_SEMANTICS_DIGEST,
  SessionCapabilitiesGetOutputSchema,
  createReadToolMcpResult,
} from './read-tools.js';

const memoryId = 'mem_AAAAAAAAAAAAAAAAAAAAAA';
const cursor = 'cur_AAAAAAAAAAAAAAAA';

const retrievalBase = {
  strategy: 'defensive_search_then_get_v1',
  query_last_executed: 'synthetic',
  scope_semantics: 'authorized_scope_only',
  snapshot_semantics: 'no_server_snapshot_v1',
  provenance_currentness: 'unknown',
} as const;

const record = {
  id: memoryId,
  title: 'Synthetic title',
  content: 'Synthetic stored text.',
  contentTrust: 'untrusted',
  createdAt: '2026-08-20T00:00:00.000Z',
  provenanceSummary: 'synthetic test fixture',
} as const;

const searchItem = { ...record, rank: 0.75 };

describe('ari v0.2 independent probe regressions (executable Zod)', () => {
  it.each([
    ['blank_query', { query: '   ' }],
    ['blank_tag', { query: 'test', filters: { tags: ['  '] } }],
    [
      'seven_filters',
      {
        query: 'test',
        filters: {
          tags: ['a', 'b', 'c', 'd', 'e'],
          createdAfter: '2026-01-01T00:00:00Z',
          createdBefore: '2026-09-01T00:00:00Z',
        },
      },
    ],
    [
      'reversed_dates',
      {
        query: 'test',
        filters: {
          createdAfter: '2026-09-01T00:00:00Z',
          createdBefore: '2026-01-01T00:00:00Z',
        },
      },
    ],
  ] as const)('rejects memory_retrieve input probe %s', (_name, payload) => {
    expect(MemoryRetrieveInputSchema.safeParse(payload).success).toBe(false);
  });

  it('rejects catalog_input_sketch compatibility profile (strict input)', () => {
    expect(
      MemoryRetrieveInputSchema.safeParse({
        query: 'catalog sketch path',
        compatibility_profile: 'catalog_input_sketch_0_1',
        filters: { tags: ['v01'] },
      }).success,
    ).toBe(false);
  });

  it('rejects found_but_legacy_no_match (legacy duplicate payload)', () => {
    expect(
      MemoryRetrieveOutputSchema.safeParse({
        ok: true,
        outcome: 'found',
        completeness: 'unknown',
        retrieval: retrievalBase,
        result: { ok: true, record },
        legacy: {
          profile: 'legacy_read_tools_v1',
          payload: { ok: true, items: [] },
        },
      }).success,
    ).toBe(false);
  });

  it('rejects no_match_with_next_page', () => {
    expect(
      MemoryRetrieveOutputSchema.safeParse({
        ok: true,
        outcome: 'scoped_no_match',
        completeness: 'unknown',
        retrieval: retrievalBase,
        result: { ok: true, items: [], nextCursor: cursor },
      }).success,
    ).toBe(false);
  });

  it('rejects different_continuation_cursors (duplicate continuation projection)', () => {
    expect(
      MemoryRetrieveOutputSchema.safeParse({
        ok: true,
        outcome: 'partial',
        completeness: 'unknown',
        retrieval: {
          ...retrievalBase,
          continuation: {
            cursor: 'cur_different000000001',
            binds: ['query', 'mode', 'filters', 'limit'],
          },
        },
        result: { ok: true, items: [searchItem], nextCursor: cursor },
      }).success,
    ).toBe(false);
  });

  it('rejects partial_without_source_cursor', () => {
    expect(
      MemoryRetrieveOutputSchema.safeParse({
        ok: true,
        outcome: 'partial',
        completeness: 'unknown',
        retrieval: retrievalBase,
        result: { ok: true, items: [searchItem] },
      }).success,
    ).toBe(false);
  });

  it('rejects wrong_error_message_for_code', () => {
    expect(
      MemoryRetrieveOutputSchema.safeParse({
        ok: false,
        error: {
          code: 'INVALID_REQUEST',
          message: 'Record is unavailable.',
          retryable: false,
        },
      }).success,
    ).toBe(false);
  });

  it('rejects unavailable_with_invalid_request (success envelope around tool error)', () => {
    expect(
      MemoryRetrieveOutputSchema.safeParse({
        ok: true,
        outcome: 'unavailable',
        completeness: 'unknown',
        retrieval: retrievalBase,
        result: {
          ok: false,
          error: {
            code: 'INVALID_REQUEST',
            message: 'Request is invalid.',
            retryable: false,
          },
        },
      }).success,
    ).toBe(false);
  });

  it('rejects expiry_before_observation on session_capabilities_get', () => {
    expect(
      SessionCapabilitiesGetOutputSchema.safeParse({
        ok: true,
        discovery: {
          profile: 'session_capabilities_minimal_draft_0_2',
          schema_version: 'draft-0.2',
          tools_list: { method: 'tools/list', permission_authority: false },
          status: 'DRAFT; supplements tools/list only; no runtime authority',
          observed_at: '2026-09-15T16:00:00+00:00',
          expires_at: '2000-01-01T00:00:00Z',
          assurance: {
            tools_list_is_permission_authority: false,
            catalog_provenance_currentness: 'unknown',
            effective_grants: 'unknown',
          },
        },
        session: {
          wire: {
            max_request_id_utf8_bytes: 1024,
            max_complete_response_utf8_bytes: 65536,
            default_deadline_ms: 2000,
            automatic_retries: 0,
          },
          read_semantics_digest: SESSION_CAPABILITIES_READ_SEMANTICS_DIGEST,
        },
        visible_tools: [],
      }).success,
    ).toBe(false);
  });
});

describe('memory_retrieve and session_capabilities_get valid shapes', () => {
  it('accepts discriminated success and bare error envelopes', () => {
    expect(
      MemoryRetrieveOutputSchema.parse({
        ok: true,
        outcome: 'found',
        completeness: 'unknown',
        retrieval: retrievalBase,
        result: { ok: true, record },
      }),
    ).toMatchObject({ outcome: 'found' });

    const errorEnvelope = MemoryRetrieveOutputSchema.parse({
      ok: false,
      error: {
        code: 'DEADLINE_EXCEEDED',
        message: 'Request deadline exceeded.',
        retryable: false,
      },
    });
    expect(createReadToolMcpResult(errorEnvelope).isError).toBe(true);
  });

  it('marks tool errors isError and keeps success non-error', () => {
    const unavailable = MemoryRetrieveOutputSchema.parse({
      ok: false,
      error: {
        code: 'RESOURCE_UNAVAILABLE',
        message: 'Record is unavailable.',
        retryable: false,
      },
    });
    expect(createReadToolMcpResult(unavailable).isError).toBe(true);
    const found = MemoryRetrieveOutputSchema.parse({
      ok: true,
      outcome: 'scoped_no_match',
      completeness: 'unknown',
      retrieval: retrievalBase,
      result: { ok: true, items: [] },
    });
    expect(createReadToolMcpResult(found).isError).toBe(false);
  });
});
