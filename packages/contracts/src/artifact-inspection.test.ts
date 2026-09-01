import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  ANALYZER_PROFILE_IDS,
  ARTIFACT_INSPECTION_DESCRIPTOR_IS_NOT_PERMISSION,
  ARTIFACT_INSPECTION_ERROR_CODES,
  ARTIFACT_INSPECTION_OPERATIONS,
  ARTIFACT_INSPECTION_RECEIPT_IS_NOT_AUTHORIZATION,
  ARTIFACT_INSPECTION_RECEIPT_SCHEMA_VERSION,
  ARTIFACT_INSPECTION_TOOLS,
  ARTIFACT_INSPECTION_UNTRUSTED_CONTENT_PREFIX,
  ARTIFACT_READ_HEADING_TOOL,
  ARTIFACT_READ_LINES_TOOL,
  ARTIFACT_READ_RANGE_TOOL,
  ARTIFACT_SEARCH_EXACT_TOOL,
  ARTIFACT_STAT_TOOL,
  AnalyzerProfileIdSchema,
  ArtifactDerivationInputRefSchema,
  ArtifactDerivationWithInputsSchema,
  ArtifactInspectionErrorOutputSchema,
  ArtifactInspectionOperationSchema,
  ArtifactInspectionReceiptSchema,
  ArtifactReadHeadingInputSchema,
  ArtifactReadHeadingOutputSchema,
  ArtifactReadLinesInputSchema,
  ArtifactReadLinesOutputSchema,
  ArtifactReadRangeInputSchema,
  ArtifactReadRangeOutputSchema,
  ArtifactSearchExactInputSchema,
  ArtifactSearchExactOutputSchema,
  ArtifactStatInputSchema,
  ArtifactStatOutputSchema,
  DerivationTypeSchema,
  MAX_ARTIFACT_BYTE_OFFSET,
  MAX_ARTIFACT_ID_LENGTH,
  MAX_ARTIFACT_REQUEST_ID_BYTES,
  MAX_ARTIFACT_RESPONSE_BYTES,
  MAX_ARTIFACT_TOOL_EXECUTION_MS,
  MAX_HEADING_ID_LENGTH,
  MAX_LINE_COUNT,
  MAX_RANGE_BYTES,
  MAX_SEARCH_HITS,
  MAX_SEARCH_QUERY_LENGTH,
  MAX_VERIFIED_CHUNKS_PER_READ,
  MIN_ARTIFACT_ID_LENGTH,
  PARTIAL_READ_INTEGRITY_STATEMENT,
  PartialReadIntegritySchema,
  SEMANTIC_ANALYSIS_POLICY,
  SourceIntegrityMetadataSchema,
  artifactInspectionRequestIdByteLength,
  artifactInspectionResponseByteLength,
  createArtifactInspectionError,
  createArtifactInspectionMcpResult,
  isArtifactExpired,
  isArtifactInspectionDeadlineExceeded,
  publicArtifactInspectionUnavailable,
  serializeArtifactInspectionResponse,
} from './artifact-inspection.js';

function sha256Hex(text: string): string {
  return createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
}

function utf8Length(text: string): number {
  return new TextEncoder().encode(text).byteLength;
}

const artifactId = 'art_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const otherArtifactId = 'art_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';
const sha256 = 'a1'.repeat(32);
const otherSha256 = 'b2'.repeat(32);
const merkleRoot = 'c3'.repeat(32);
const objectVersionRef = 'ov_AAAAAAAAAAAAAAAAAAAAAAAA';
const gitCoordinate = 'd'.repeat(40);
const nowIso = '2026-09-01T00:00:00.000Z';
const pastIso = '2026-01-01T00:00:00.000Z';
const futureIso = '2027-01-01T00:00:00.000Z';

function validSourceIntegrityMetadata(overrides: Record<string, unknown> = {}) {
  return {
    artifactId,
    objectVersionRef,
    sourceSha256: sha256,
    byteLength: 4096,
    chunkSize: 1024,
    chunkCount: 4,
    chunkHashes: { kind: 'inline', hashes: [sha256, sha256, sha256, sha256] },
    merkleRoot,
    mediaType: 'text/markdown',
    analyzerProfileSupport: 'text/markdown',
    createdAt: nowIso,
    expiresAt: undefined as string | undefined,
    ...overrides,
  };
}

/** A single valid verified chunk, structural only (no cryptographic binding
 * to real returned content) -- for testing `PartialReadIntegritySchema` in
 * isolation. */
function singleValidChunk(overrides: Record<string, unknown> = {}) {
  return {
    chunkIndex: 0,
    byteStart: 0,
    byteLength: 10,
    chunkSha256: sha256,
    merkleProof: [] as unknown[],
    ...overrides,
  };
}

type VerifiedChunkFixture = {
  chunkIndex: number;
  byteStart: number;
  byteLength: number;
  chunkSha256: string;
  merkleProof: Array<{ siblingPosition: 'left' | 'right'; siblingSha256: string }>;
};

/** Narrows an in-bounds array-index read (under `noUncheckedIndexedAccess`)
 * without a non-null assertion, mirroring the same helper in the module
 * under test. */
function definedAt<T>(value: T | undefined): T {
  if (value === undefined) {
    throw new Error('Expected a defined value at a proven in-bounds array index.');
  }
  return value;
}

/** Two contiguous, sequential, hash-non-empty-proof chunks -- for testing the
 * multi-chunk covering-range rules in isolation from real content hashing.
 * Returned as a tuple so `chunks[0]`/`chunks[1]` never need an assertion. */
function twoValidChunks(): [VerifiedChunkFixture, VerifiedChunkFixture] {
  return [
    {
      chunkIndex: 0,
      byteStart: 0,
      byteLength: 10,
      chunkSha256: sha256,
      merkleProof: [{ siblingPosition: 'right', siblingSha256: otherSha256 }],
    },
    {
      chunkIndex: 1,
      byteStart: 10,
      byteLength: 10,
      chunkSha256: otherSha256,
      merkleProof: [{ siblingPosition: 'left', siblingSha256: sha256 }],
    },
  ];
}

/** Structurally valid, single-chunk `PartialReadIntegrity` -- for testing the
 * schema's own shape (required fields, covering-range order, etc.) without
 * needing hash-bound real content. */
function validPartialReadIntegrity(overrides: Record<string, unknown> = {}) {
  return {
    requestedRange: { kind: 'byte_range', offset: 0, length: 10 },
    verifiedCoveringChunkRange: { startChunkIndex: 0, endChunkIndex: 0 },
    returnedRange: { offset: 0, length: 10 },
    chunkSize: 10,
    chunkCount: 1,
    verifiedChunks: [singleValidChunk()],
    merkleRoot,
    returnedByteSha256: sha256,
    sourceSha256: sha256,
    contentTrust: 'untrusted',
    ...overrides,
  };
}

/** Structurally valid, two-chunk `PartialReadIntegrity` covering bytes 0-20
 * -- the base fixture for repair-2's multi-chunk covering-range tests. */
function validTwoChunkIntegrity(overrides: Record<string, unknown> = {}) {
  return {
    requestedRange: { kind: 'byte_range', offset: 0, length: 20 },
    verifiedCoveringChunkRange: { startChunkIndex: 0, endChunkIndex: 1 },
    returnedRange: { offset: 0, length: 20 },
    chunkSize: 10,
    chunkCount: 2,
    verifiedChunks: twoValidChunks(),
    merkleRoot,
    returnedByteSha256: sha256,
    sourceSha256: sha256,
    contentTrust: 'untrusted',
    ...overrides,
  };
}

/** A single-chunk `PartialReadIntegrity` cryptographically bound to `data`:
 * `returnedByteSha256` and the sole chunk's `chunkSha256` are the real
 * SHA-256 of `data`'s UTF-8 bytes, and `returnedRange.length` is `data`'s
 * real UTF-8 byte length -- for testing repair-7's output/integrity binding
 * and the "every accepted operation" happy path. */
function boundIntegrityForData(data: string, requestedRange: Record<string, unknown>) {
  const length = utf8Length(data);
  const hash = sha256Hex(data);
  return {
    requestedRange,
    verifiedCoveringChunkRange: { startChunkIndex: 0, endChunkIndex: 0 },
    returnedRange: { offset: 0, length },
    chunkSize: length,
    chunkCount: 1,
    verifiedChunks: [
      { chunkIndex: 0, byteStart: 0, byteLength: length, chunkSha256: hash, merkleProof: [] },
    ],
    merkleRoot,
    returnedByteSha256: hash,
    sourceSha256: sha256,
    contentTrust: 'untrusted',
  };
}

/** A single search hit whose snippet range starts at `snippetOffset`,
 * cryptographically bound (`snippetSha256`, byte lengths) to `snippet`'s
 * real UTF-8 bytes, with a match sub-range inside the snippet. */
function boundSearchHit(
  snippet: string,
  snippetOffset: number,
  matchOffsetWithinSnippet: number,
  matchLength: number,
) {
  const snippetLength = utf8Length(snippet);
  return {
    matchRange: { offset: snippetOffset + matchOffsetWithinSnippet, length: matchLength },
    snippetRange: { offset: snippetOffset, length: snippetLength },
    snippetSha256: sha256Hex(snippet),
    lineNumber: 1,
    snippet,
    contentTrust: 'untrusted' as const,
  };
}

function boundIntegrityForHits(totalLength: number) {
  return {
    requestedRange: { kind: 'search_exact', queryLength: 6 },
    verifiedCoveringChunkRange: { startChunkIndex: 0, endChunkIndex: 0 },
    returnedRange: { offset: 0, length: totalLength },
    chunkSize: totalLength,
    chunkCount: 1,
    verifiedChunks: [
      {
        chunkIndex: 0,
        byteStart: 0,
        byteLength: totalLength,
        chunkSha256: sha256,
        merkleProof: [],
      },
    ],
    merkleRoot,
    returnedByteSha256: sha256,
    sourceSha256: sha256,
    contentTrust: 'untrusted',
  };
}

function validReceipt(overrides: Record<string, unknown> = {}) {
  return {
    receiptSchemaVersion: ARTIFACT_INSPECTION_RECEIPT_SCHEMA_VERSION,
    verifierAudience: 'verifier-1',
    principalRef: 'principal-1',
    principalBinding: 'session_derived',
    inspectorClientRef: 'smp-lab-inspector',
    inspectorClientBinding: 'approved',
    inspectorCapabilityRef: { capability: 'artifact:inspect', ref: 'grant-1' },
    artifactId,
    objectVersionRef,
    sourceSha256: sha256,
    merkleRoot,
    analyzerProfileId: 'text/markdown',
    analyzerProfileVersion: 'markdown-1',
    policyVersion: 'policy-1',
    inspectorDeploymentGitCoordinate: gitCoordinate,
    recordedAt: nowIso,
    operationDetail: { operation: 'artifact_stat' },
    resultOrErrorClass: { kind: 'result' },
    ...overrides,
  };
}

const rangeOperationDetail = {
  operation: 'artifact_read_range',
  requestedRange: { offset: 0, length: 10 },
  returnedRange: { offset: 0, length: 10 },
  returnedByteSha256: sha256,
};
const linesOperationDetail = {
  operation: 'artifact_read_lines',
  requestedLineRange: { startLine: 1, count: 5 },
  returnedRange: { offset: 0, length: 18 },
  returnedByteSha256: sha256,
};
const headingOperationDetail = {
  operation: 'artifact_read_heading',
  requestedHeadingId: 'intro-section',
  returnedRange: { offset: 0, length: 15 },
  returnedByteSha256: sha256,
};
const searchOperationDetail = {
  operation: 'artifact_search_exact',
  queryLength: 6,
  maxHits: 10,
  returnedHits: [{ returnedRange: { offset: 0, length: 6 }, returnedByteSha256: sha256 }],
};

describe('opaque artifact identifier', () => {
  it('accepts only the opaque art_ handle, never a caller-chosen path', () => {
    expect(ArtifactStatInputSchema.safeParse({ artifactId }).success).toBe(true);
    expect(ArtifactStatInputSchema.safeParse({ artifactId: 'private/secret.txt' }).success).toBe(
      false,
    );
    expect(ArtifactStatInputSchema.safeParse({ artifactId: '../etc/passwd' }).success).toBe(false);
  });

  it('enforces the exact artifact-ID length ceiling and rejects one-over', () => {
    const atMin = `art_${'A'.repeat(MIN_ARTIFACT_ID_LENGTH - 4)}`;
    const underMin = `art_${'A'.repeat(MIN_ARTIFACT_ID_LENGTH - 5)}`;
    const atMax = `art_${'A'.repeat(MAX_ARTIFACT_ID_LENGTH - 4)}`;
    const overMax = `art_${'A'.repeat(MAX_ARTIFACT_ID_LENGTH - 3)}`;
    expect(atMin).toHaveLength(MIN_ARTIFACT_ID_LENGTH);
    expect(atMax).toHaveLength(MAX_ARTIFACT_ID_LENGTH);
    expect(ArtifactStatInputSchema.safeParse({ artifactId: atMin }).success).toBe(true);
    expect(ArtifactStatInputSchema.safeParse({ artifactId: underMin }).success).toBe(false);
    expect(ArtifactStatInputSchema.safeParse({ artifactId: atMax }).success).toBe(true);
    expect(ArtifactStatInputSchema.safeParse({ artifactId: overMax }).success).toBe(false);
  });
});

describe('every accepted operation', () => {
  it('artifact_stat: accepts a bounded request and a well-formed success output', () => {
    expect(ArtifactStatInputSchema.parse({ artifactId })).toEqual({ artifactId });
    expect(
      ArtifactStatOutputSchema.safeParse({ ok: true, artifact: validSourceIntegrityMetadata() })
        .success,
    ).toBe(true);
  });

  it('artifact_read_range: accepts a bounded request and a well-formed, hash-bound success output', () => {
    expect(ArtifactReadRangeInputSchema.parse({ artifactId, offset: 0, length: 10 })).toMatchObject(
      { offset: 0, length: 10 },
    );
    const data = 'hello text';
    expect(
      ArtifactReadRangeOutputSchema.safeParse({
        ok: true,
        data,
        contentTrust: 'untrusted',
        integrity: boundIntegrityForData(data, { kind: 'byte_range', offset: 0, length: 10 }),
      }).success,
    ).toBe(true);
  });

  it('artifact_read_lines: accepts a bounded request and a well-formed, hash-bound success output', () => {
    expect(
      ArtifactReadLinesInputSchema.parse({ artifactId, startLine: 1, count: 5 }),
    ).toMatchObject({ startLine: 1, count: 5 });
    const data = 'line one\nline two';
    expect(
      ArtifactReadLinesOutputSchema.safeParse({
        ok: true,
        data,
        returnedLineCount: 2,
        contentTrust: 'untrusted',
        integrity: boundIntegrityForData(data, { kind: 'line_range', startLine: 1, count: 5 }),
      }).success,
    ).toBe(true);
  });

  it('artifact_read_heading: accepts a bounded request and a well-formed, hash-bound success output', () => {
    expect(
      ArtifactReadHeadingInputSchema.parse({ artifactId, headingId: 'intro-section' }),
    ).toMatchObject({ headingId: 'intro-section' });
    const data = '## Intro\n\nbody';
    expect(
      ArtifactReadHeadingOutputSchema.safeParse({
        ok: true,
        headingId: 'intro-section',
        data,
        contentTrust: 'untrusted',
        integrity: boundIntegrityForData(data, { kind: 'heading', headingId: 'intro-section' }),
      }).success,
    ).toBe(true);
  });

  it('artifact_search_exact: accepts a bounded request and a well-formed, hash-bound success output', () => {
    expect(
      ArtifactSearchExactInputSchema.parse({ artifactId, query: 'needle', maxHits: 10 }),
    ).toMatchObject({ query: 'needle', maxHits: 10 });
    const snippet = 'needle in a haystack';
    const hit = boundSearchHit(snippet, 0, 0, 6);
    expect(
      ArtifactSearchExactOutputSchema.safeParse({
        ok: true,
        hits: [hit],
        integrity: boundIntegrityForHits(utf8Length(snippet)),
      }).success,
    ).toBe(true);
  });
});

describe('unknown operation denial', () => {
  it('rejects any operation name outside the exact proposed five', () => {
    expect(ARTIFACT_INSPECTION_OPERATIONS).toHaveLength(5);
    expect(ArtifactInspectionOperationSchema.safeParse('artifact_stat').success).toBe(true);
    expect(ArtifactInspectionOperationSchema.safeParse('artifact_delete').success).toBe(false);
    expect(ArtifactInspectionOperationSchema.safeParse('artifact_read_all').success).toBe(false);
    expect(ArtifactInspectionOperationSchema.safeParse('').success).toBe(false);
  });
});

describe('caller-selected path/origin/schema/RPC/method fields are denied on every operation', () => {
  const forbiddenExtraFields: Record<string, unknown> = {
    bucket: 'artifact-lab',
    objectPath: 'private/secret.txt',
    objectKey: 'private/secret.txt',
    url: 'https://example.com/object',
    origin: 'https://example.com',
    schema: 'public',
    table: 'artifact_registry',
    rpc: 'some_rpc',
    httpMethod: 'GET',
    signedUrl: 'https://signed.example.com/x?token=abc',
    serviceRoleKey: 'service_role_secret',
    serviceRole: true,
    parser: 'custom-parser',
    parserProfile: 'custom-parser',
    profile: 'custom-profile',
  };

  const operations: Array<{
    name: string;
    schema: { safeParse: (v: unknown) => { success: boolean } };
    base: Record<string, unknown>;
  }> = [
    { name: 'artifact_stat', schema: ArtifactStatInputSchema, base: { artifactId } },
    {
      name: 'artifact_read_range',
      schema: ArtifactReadRangeInputSchema,
      base: { artifactId, offset: 0, length: 10 },
    },
    {
      name: 'artifact_read_lines',
      schema: ArtifactReadLinesInputSchema,
      base: { artifactId, startLine: 1, count: 5 },
    },
    {
      name: 'artifact_read_heading',
      schema: ArtifactReadHeadingInputSchema,
      base: { artifactId, headingId: 'intro-section' },
    },
    {
      name: 'artifact_search_exact',
      schema: ArtifactSearchExactInputSchema,
      base: { artifactId, query: 'needle', maxHits: 10 },
    },
  ];

  for (const operation of operations) {
    it(`${operation.name} rejects the base fixture as a control`, () => {
      expect(operation.schema.safeParse(operation.base).success).toBe(true);
    });

    for (const [field, value] of Object.entries(forbiddenExtraFields)) {
      it(`${operation.name} rejects an unexpected "${field}" property`, () => {
        expect(operation.schema.safeParse({ ...operation.base, [field]: value }).success).toBe(
          false,
        );
      });
    }
  }
});

describe('exact ceiling and one-over cases', () => {
  it('byte-range length: exact ceiling accepted, one-over rejected', () => {
    expect(
      ArtifactReadRangeInputSchema.safeParse({ artifactId, offset: 0, length: MAX_RANGE_BYTES })
        .success,
    ).toBe(true);
    expect(
      ArtifactReadRangeInputSchema.safeParse({
        artifactId,
        offset: 0,
        length: MAX_RANGE_BYTES + 1,
      }).success,
    ).toBe(false);
  });

  it('byte offset: exact ceiling accepted, one-over rejected', () => {
    expect(
      ArtifactReadRangeInputSchema.safeParse({
        artifactId,
        offset: MAX_ARTIFACT_BYTE_OFFSET,
        length: 1,
      }).success,
    ).toBe(true);
    expect(
      ArtifactReadRangeInputSchema.safeParse({
        artifactId,
        offset: MAX_ARTIFACT_BYTE_OFFSET + 1,
        length: 1,
      }).success,
    ).toBe(false);
  });

  it('line count: exact ceiling accepted, one-over rejected', () => {
    expect(
      ArtifactReadLinesInputSchema.safeParse({ artifactId, startLine: 1, count: MAX_LINE_COUNT })
        .success,
    ).toBe(true);
    expect(
      ArtifactReadLinesInputSchema.safeParse({
        artifactId,
        startLine: 1,
        count: MAX_LINE_COUNT + 1,
      }).success,
    ).toBe(false);
  });

  it('heading-ID length: exact ceiling accepted, one-over rejected', () => {
    const atMax = `h${'a'.repeat(MAX_HEADING_ID_LENGTH - 1)}`;
    const overMax = `h${'a'.repeat(MAX_HEADING_ID_LENGTH)}`;
    expect(atMax).toHaveLength(MAX_HEADING_ID_LENGTH);
    expect(ArtifactReadHeadingInputSchema.safeParse({ artifactId, headingId: atMax }).success).toBe(
      true,
    );
    expect(
      ArtifactReadHeadingInputSchema.safeParse({ artifactId, headingId: overMax }).success,
    ).toBe(false);
  });

  it('exact-search query length: exact ceiling accepted, one-over rejected', () => {
    const atMax = 'q'.repeat(MAX_SEARCH_QUERY_LENGTH);
    const overMax = 'q'.repeat(MAX_SEARCH_QUERY_LENGTH + 1);
    expect(ArtifactSearchExactInputSchema.safeParse({ artifactId, query: atMax }).success).toBe(
      true,
    );
    expect(ArtifactSearchExactInputSchema.safeParse({ artifactId, query: overMax }).success).toBe(
      false,
    );
  });

  it('exact-search hit count: exact ceiling accepted on request and response, one-over rejected', () => {
    expect(
      ArtifactSearchExactInputSchema.safeParse({ artifactId, query: 'x', maxHits: MAX_SEARCH_HITS })
        .success,
    ).toBe(true);
    expect(
      ArtifactSearchExactInputSchema.safeParse({
        artifactId,
        query: 'x',
        maxHits: MAX_SEARCH_HITS + 1,
      }).success,
    ).toBe(false);

    // Non-overlapping, ascending, hash-bound hits so the ceiling test isn't
    // accidentally caught by the disjoint-overlap/duplicate-range rule.
    const snippet = 'xxxx';
    const snippetLength = utf8Length(snippet);
    const hits = Array.from({ length: MAX_SEARCH_HITS }, (_, i) =>
      boundSearchHit(snippet, i * snippetLength, 0, snippetLength),
    );
    const totalLength = MAX_SEARCH_HITS * snippetLength;
    const integrity = boundIntegrityForHits(totalLength);

    expect(ArtifactSearchExactOutputSchema.safeParse({ ok: true, hits, integrity }).success).toBe(
      true,
    );
    expect(
      ArtifactSearchExactOutputSchema.safeParse({
        ok: true,
        hits: [...hits, boundSearchHit(snippet, totalLength, 0, snippetLength)],
        integrity: boundIntegrityForHits(totalLength + snippetLength),
      }).success,
    ).toBe(false);
  });

  it('execution time: exact ceiling not exceeded, one-over exceeded', () => {
    expect(isArtifactInspectionDeadlineExceeded(MAX_ARTIFACT_TOOL_EXECUTION_MS)).toBe(false);
    expect(isArtifactInspectionDeadlineExceeded(MAX_ARTIFACT_TOOL_EXECUTION_MS + 1)).toBe(true);
  });
});

describe('complete JSON-RPC/MCP wire envelope budget', () => {
  it('measures the complete wire response, not the bare output JSON', () => {
    const output = { a: 'x'.repeat(40_000) };
    const plainJsonBytes = utf8Length(JSON.stringify(output));
    expect(plainJsonBytes).toBeLessThan(MAX_ARTIFACT_RESPONSE_BYTES);

    const wireBytes = artifactInspectionResponseByteLength(null, output);
    expect(wireBytes).toBeGreaterThan(MAX_ARTIFACT_RESPONSE_BYTES);
    expect(() => serializeArtifactInspectionResponse(null, output)).toThrow(RangeError);
  });

  it('complete wire envelope: exact ceiling accepted, one byte over rejected', () => {
    // Coarse phase: grow the output body (duplicated across content.text and
    // structuredContent, so ~2 bytes per added character) to just under the
    // ceiling, leaving a small headroom well inside the independent
    // request-ID budget for exact fine-tuning.
    const safetyMargin = 64;
    const target = MAX_ARTIFACT_RESPONSE_BYTES - safetyMargin;
    let low = 0;
    let high = MAX_ARTIFACT_RESPONSE_BYTES;
    while (low < high) {
      const mid = Math.ceil((low + high) / 2);
      const size = artifactInspectionResponseByteLength('', { a: 'x'.repeat(mid) });
      if (size <= target) low = mid;
      else high = mid - 1;
    }
    const coarseOutput = { a: 'x'.repeat(low) };
    const baseSize = artifactInspectionResponseByteLength('', coarseOutput);
    const gap = MAX_ARTIFACT_RESPONSE_BYTES - baseSize;
    expect(gap).toBeGreaterThan(0);
    expect(gap).toBeLessThan(MAX_ARTIFACT_REQUEST_ID_BYTES - 8);

    // Fine phase: the request ID contributes exactly its own JSON-encoded
    // byte length to the envelope (never duplicated), so scanning its length
    // closes the exact remaining gap.
    let atLimitRequestId: string | undefined;
    for (let k = 0; k <= gap + 4; k++) {
      const candidate = 'i'.repeat(k);
      if (
        artifactInspectionResponseByteLength(candidate, coarseOutput) ===
        MAX_ARTIFACT_RESPONSE_BYTES
      ) {
        atLimitRequestId = candidate;
        break;
      }
    }
    expect(atLimitRequestId).toBeDefined();
    const requestId = atLimitRequestId as string;

    expect(artifactInspectionResponseByteLength(requestId, coarseOutput)).toBe(
      MAX_ARTIFACT_RESPONSE_BYTES,
    );
    expect(() => serializeArtifactInspectionResponse(requestId, coarseOutput)).not.toThrow();

    const overRequestId = `${requestId}i`;
    expect(artifactInspectionRequestIdByteLength(overRequestId)).toBeLessThanOrEqual(
      MAX_ARTIFACT_REQUEST_ID_BYTES,
    );
    expect(artifactInspectionResponseByteLength(overRequestId, coarseOutput)).toBe(
      MAX_ARTIFACT_RESPONSE_BYTES + 1,
    );
    expect(() => serializeArtifactInspectionResponse(overRequestId, coarseOutput)).toThrow(
      RangeError,
    );
  });

  it('response envelope byte counting is UTF-8 aware, not JS string-length aware', () => {
    const multiByte = { data: 'é'.repeat(10) };
    expect(artifactInspectionResponseByteLength(null, multiByte)).toBeGreaterThan(
      JSON.stringify(multiByte).length,
    );
  });

  it('request-ID budget: exact ceiling accepted, one byte over rejected, independent of output size', () => {
    const atMaxId = 'i'.repeat(MAX_ARTIFACT_REQUEST_ID_BYTES - 2);
    const overMaxId = 'i'.repeat(MAX_ARTIFACT_REQUEST_ID_BYTES - 1);
    expect(artifactInspectionRequestIdByteLength(atMaxId)).toBe(MAX_ARTIFACT_REQUEST_ID_BYTES);
    expect(() => serializeArtifactInspectionResponse(atMaxId, { ok: true })).not.toThrow();
    expect(artifactInspectionRequestIdByteLength(overMaxId)).toBe(
      MAX_ARTIFACT_REQUEST_ID_BYTES + 1,
    );
    expect(() => serializeArtifactInspectionResponse(overMaxId, { ok: true })).toThrow(RangeError);
  });

  it('structuredContent and model-visible text encode the same output', () => {
    const output = { ok: true, foo: 'bar', n: 5 };
    const result = createArtifactInspectionMcpResult(output);
    expect(result.structuredContent).toEqual(output);
    const textContent = definedAt(result.content[0]).text;
    expect(textContent.startsWith(ARTIFACT_INSPECTION_UNTRUSTED_CONTENT_PREFIX)).toBe(true);
    const embedded = textContent.slice(ARTIFACT_INSPECTION_UNTRUSTED_CONTENT_PREFIX.length);
    expect(JSON.parse(embedded)).toEqual(output);
  });

  it('always marks stored artifact content untrusted with an explicit security prefix', () => {
    const result = createArtifactInspectionMcpResult({ anything: 'goes here' });
    expect(definedAt(result.content[0]).text.startsWith('SECURITY BOUNDARY:')).toBe(true);
    expect(ARTIFACT_INSPECTION_UNTRUSTED_CONTENT_PREFIX).toMatch(/untrusted/);
  });

  it('sets isError from output.ok: true for errors, false for success', () => {
    expect(
      createArtifactInspectionMcpResult(createArtifactInspectionError('INVALID_REQUEST')).isError,
    ).toBe(true);
    expect(
      createArtifactInspectionMcpResult({ ok: true, artifact: validSourceIntegrityMetadata() })
        .isError,
    ).toBe(false);
  });
});

describe('missing versus unauthorized byte-identical output', () => {
  it('produces the exact same frozen result for both reasons', () => {
    const missing = publicArtifactInspectionUnavailable('missing');
    const unauthorized = publicArtifactInspectionUnavailable('unauthorized');
    expect(missing).toBe(unauthorized);
    expect(JSON.stringify(missing)).toBe(JSON.stringify(unauthorized));
    expect(missing).toEqual(createArtifactInspectionError('RESOURCE_UNAVAILABLE'));
    expect(Object.isFrozen(missing)).toBe(true);
    expect(ArtifactInspectionErrorOutputSchema.safeParse(missing).success).toBe(true);
  });
});

describe('unsupported media type', () => {
  it('accepts only the two S0 analyzer profiles, nothing else', () => {
    expect(ANALYZER_PROFILE_IDS).toEqual(['text/plain', 'text/markdown']);
    expect(AnalyzerProfileIdSchema.safeParse('text/markdown').success).toBe(true);
    expect(AnalyzerProfileIdSchema.safeParse('application/pdf').success).toBe(false);
    expect(AnalyzerProfileIdSchema.safeParse('text/csv').success).toBe(false);
  });

  it('stat metadata can classify an unsupported profile explicitly rather than fabricate one', () => {
    expect(
      SourceIntegrityMetadataSchema.safeParse(
        validSourceIntegrityMetadata({
          mediaType: 'application/pdf',
          analyzerProfileSupport: 'unsupported',
        }),
      ).success,
    ).toBe(true);
    expect(
      SourceIntegrityMetadataSchema.safeParse(
        validSourceIntegrityMetadata({ analyzerProfileSupport: 'application/pdf' }),
      ).success,
    ).toBe(false);
  });

  it('the UNSUPPORTED error class exists and is byte-stable', () => {
    expect(createArtifactInspectionError('UNSUPPORTED')).toEqual({
      ok: false,
      error: {
        code: 'UNSUPPORTED',
        message: 'Artifact content profile is not supported.',
        retryable: false,
      },
    });
  });
});

describe('verified chunk and Merkle-inclusion evidence', () => {
  it('accepts a valid single-chunk integrity object with an empty proof (chunk count 1)', () => {
    expect(PartialReadIntegritySchema.safeParse(validPartialReadIntegrity()).success).toBe(true);
  });

  it('accepts a valid two-chunk integrity object with non-empty proofs', () => {
    expect(PartialReadIntegritySchema.safeParse(validTwoChunkIntegrity()).success).toBe(true);
  });

  it('a whole-object source SHA-256 alone does not satisfy the schema', () => {
    expect(
      PartialReadIntegritySchema.safeParse({ sourceSha256: sha256, contentTrust: 'untrusted' })
        .success,
    ).toBe(false);
  });

  const requiredFields = [
    'requestedRange',
    'verifiedCoveringChunkRange',
    'returnedRange',
    'chunkSize',
    'chunkCount',
    'verifiedChunks',
    'merkleRoot',
    'returnedByteSha256',
    'sourceSha256',
    'contentTrust',
  ];
  for (const field of requiredFields) {
    it(`rejects an integrity object missing "${field}"`, () => {
      const integrity = validPartialReadIntegrity() as Record<string, unknown>;
      delete integrity[field];
      expect(PartialReadIntegritySchema.safeParse(integrity).success).toBe(false);
    });
  }

  const chunkFields = ['chunkIndex', 'byteStart', 'byteLength', 'chunkSha256', 'merkleProof'];
  for (const field of chunkFields) {
    it(`rejects a verified chunk missing "${field}"`, () => {
      const chunk = singleValidChunk() as Record<string, unknown>;
      delete chunk[field];
      expect(
        PartialReadIntegritySchema.safeParse(validPartialReadIntegrity({ verifiedChunks: [chunk] }))
          .success,
      ).toBe(false);
    });
  }

  const proofNodeFields = ['siblingPosition', 'siblingSha256'];
  for (const field of proofNodeFields) {
    it(`rejects a Merkle proof node missing "${field}"`, () => {
      const chunks = twoValidChunks();
      const proofNode = { ...definedAt(chunks[0].merkleProof[0]) } as Record<string, unknown>;
      delete proofNode[field];
      chunks[0] = { ...chunks[0], merkleProof: [proofNode] as VerifiedChunkFixture['merkleProof'] };
      expect(
        PartialReadIntegritySchema.safeParse(validTwoChunkIntegrity({ verifiedChunks: chunks }))
          .success,
      ).toBe(false);
    });
  }

  it('rejects a covering chunk range that ends before it starts', () => {
    expect(
      PartialReadIntegritySchema.safeParse(
        validPartialReadIntegrity({
          verifiedCoveringChunkRange: { startChunkIndex: 3, endChunkIndex: 1 },
        }),
      ).success,
    ).toBe(false);
  });

  it('rejects duplicate chunk indexes', () => {
    const chunks = twoValidChunks();
    chunks[1] = { ...chunks[1], chunkIndex: 0, byteStart: 10 };
    expect(
      PartialReadIntegritySchema.safeParse(validTwoChunkIntegrity({ verifiedChunks: chunks }))
        .success,
    ).toBe(false);
  });

  it('rejects out-of-order chunk indexes', () => {
    const chunks = twoValidChunks();
    const reversed = [chunks[1], chunks[0]];
    expect(
      PartialReadIntegritySchema.safeParse(validTwoChunkIntegrity({ verifiedChunks: reversed }))
        .success,
    ).toBe(false);
  });

  it('rejects a gap between covering chunk indexes', () => {
    const chunks = twoValidChunks();
    chunks[1] = { ...chunks[1], chunkIndex: 2 };
    expect(
      PartialReadIntegritySchema.safeParse(
        validTwoChunkIntegrity({
          chunkCount: 3,
          verifiedCoveringChunkRange: { startChunkIndex: 0, endChunkIndex: 2 },
          verifiedChunks: chunks,
        }),
      ).success,
    ).toBe(false);
  });

  it('rejects overlapping chunk byte ranges', () => {
    const chunks = twoValidChunks();
    chunks[1] = { ...chunks[1], byteStart: 5 };
    expect(
      PartialReadIntegritySchema.safeParse(validTwoChunkIntegrity({ verifiedChunks: chunks }))
        .success,
    ).toBe(false);
  });

  it('rejects a chunk index outside the declared total chunk count', () => {
    const chunks = twoValidChunks();
    chunks[1] = { ...chunks[1], chunkIndex: 5 };
    expect(
      PartialReadIntegritySchema.safeParse(validTwoChunkIntegrity({ verifiedChunks: chunks }))
        .success,
    ).toBe(false);
  });

  it('rejects when the first or last verified chunk does not match the covering range', () => {
    expect(
      PartialReadIntegritySchema.safeParse(
        validTwoChunkIntegrity({
          verifiedCoveringChunkRange: { startChunkIndex: 0, endChunkIndex: 0 },
        }),
      ).success,
    ).toBe(false);
  });

  it('rejects a requested/returned range outside the verified chunk byte coverage', () => {
    expect(
      PartialReadIntegritySchema.safeParse(
        validPartialReadIntegrity({ returnedRange: { offset: 5, length: 10 } }),
      ).success,
    ).toBe(false);
    expect(
      PartialReadIntegritySchema.safeParse(
        validPartialReadIntegrity({
          requestedRange: { kind: 'byte_range', offset: 5, length: 10 },
        }),
      ).success,
    ).toBe(false);
  });

  it('rejects a multi-chunk tree with an absent inclusion proof on any chunk', () => {
    const chunks = twoValidChunks();
    chunks[0] = { ...chunks[0], merkleProof: [] };
    expect(
      PartialReadIntegritySchema.safeParse(validTwoChunkIntegrity({ verifiedChunks: chunks }))
        .success,
    ).toBe(false);
  });

  it('allows an empty proof only when the total chunk count is exactly one', () => {
    expect(
      PartialReadIntegritySchema.safeParse(
        validPartialReadIntegrity({ verifiedChunks: [singleValidChunk({ merkleProof: [] })] }),
      ).success,
    ).toBe(true);
  });

  it('rejects covering ranges that exceed the maximum verified-chunk ceiling', () => {
    const chunkCount = MAX_VERIFIED_CHUNKS_PER_READ + 1;
    const chunks = Array.from({ length: chunkCount }, (_, i) => ({
      chunkIndex: i,
      byteStart: i * 10,
      byteLength: 10,
      chunkSha256: sha256,
      merkleProof: [{ siblingPosition: 'left' as const, siblingSha256: otherSha256 }],
    }));
    expect(
      PartialReadIntegritySchema.safeParse({
        requestedRange: { kind: 'byte_range', offset: 0, length: chunkCount * 10 },
        verifiedCoveringChunkRange: { startChunkIndex: 0, endChunkIndex: chunkCount - 1 },
        returnedRange: { offset: 0, length: chunkCount * 10 },
        chunkSize: 10,
        chunkCount,
        verifiedChunks: chunks,
        merkleRoot,
        returnedByteSha256: sha256,
        sourceSha256: sha256,
        contentTrust: 'untrusted',
      }).success,
    ).toBe(false);
  });

  it('states plainly that a whole-object hash cannot stand in for partial-read integrity', () => {
    expect(PARTIAL_READ_INTEGRITY_STATEMENT).toMatch(/does not by itself prove/);
  });
});

describe('bind returned content to integrity metadata', () => {
  it('accepts range/lines/heading output whose data matches its declared integrity', () => {
    const data = 'hello text';
    expect(
      ArtifactReadRangeOutputSchema.safeParse({
        ok: true,
        data,
        contentTrust: 'untrusted',
        integrity: boundIntegrityForData(data, { kind: 'byte_range', offset: 0, length: 10 }),
      }).success,
    ).toBe(true);
  });

  it('rejects modified data with unchanged integrity metadata', () => {
    const data = 'hello text';
    const integrity = boundIntegrityForData(data, { kind: 'byte_range', offset: 0, length: 10 });
    expect(
      ArtifactReadRangeOutputSchema.safeParse({
        ok: true,
        data: 'HELLO TEXT',
        contentTrust: 'untrusted',
        integrity,
      }).success,
    ).toBe(false);
  });

  it('rejects a modified returned range with unchanged data/hash', () => {
    const data = 'hello text';
    const integrity = boundIntegrityForData(data, { kind: 'byte_range', offset: 0, length: 10 });
    expect(
      ArtifactReadRangeOutputSchema.safeParse({
        ok: true,
        data,
        contentTrust: 'untrusted',
        integrity: {
          ...integrity,
          returnedRange: { offset: 0, length: 9 },
        },
      }).success,
    ).toBe(false);
  });

  it('applies the same binding to artifact_read_lines and artifact_read_heading', () => {
    const linesData = 'line one\nline two';
    expect(
      ArtifactReadLinesOutputSchema.safeParse({
        ok: true,
        data: 'tampered',
        returnedLineCount: 2,
        contentTrust: 'untrusted',
        integrity: boundIntegrityForData(linesData, { kind: 'line_range', startLine: 1, count: 5 }),
      }).success,
    ).toBe(false);

    const headingData = '## Intro\n\nbody';
    expect(
      ArtifactReadHeadingOutputSchema.safeParse({
        ok: true,
        headingId: 'intro-section',
        data: 'tampered',
        contentTrust: 'untrusted',
        integrity: boundIntegrityForData(headingData, {
          kind: 'heading',
          headingId: 'intro-section',
        }),
      }).success,
    ).toBe(false);
  });

  it('binds each search hit snippet to its own returned range and SHA-256', () => {
    const snippet = 'needle in a haystack';
    const validHit = boundSearchHit(snippet, 0, 0, 6);
    const integrity = boundIntegrityForHits(utf8Length(snippet));
    expect(
      ArtifactSearchExactOutputSchema.safeParse({ ok: true, hits: [validHit], integrity }).success,
    ).toBe(true);

    const tamperedHit = { ...validHit, snippet: 'TAMPERED SNIPPET TEXT' };
    expect(
      ArtifactSearchExactOutputSchema.safeParse({ ok: true, hits: [tamperedHit], integrity })
        .success,
    ).toBe(false);
  });

  it('rejects a match range that lies outside its own returned snippet range', () => {
    const snippet = 'needle in a haystack';
    const hit = boundSearchHit(snippet, 0, 0, 6);
    const brokenHit = { ...hit, matchRange: { offset: 100, length: 6 } };
    expect(
      ArtifactSearchExactOutputSchema.safeParse({
        ok: true,
        hits: [brokenHit],
        integrity: boundIntegrityForHits(utf8Length(snippet)),
      }).success,
    ).toBe(false);
  });

  it('rejects disjoint hits sharing one fabricated zero-length returned range', () => {
    const snippet = 'needle';
    const fabricated = {
      matchRange: { offset: 0, length: 0 },
      snippetRange: { offset: 0, length: 0 },
      snippetSha256: sha256,
      lineNumber: 1,
      snippet: '',
      contentTrust: 'untrusted' as const,
    };
    expect(
      ArtifactSearchExactOutputSchema.safeParse({
        ok: true,
        hits: [fabricated, fabricated],
        integrity: boundIntegrityForHits(utf8Length(snippet)),
      }).success,
    ).toBe(false);
  });

  it('rejects hits outside the verified chunk coverage', () => {
    const snippet = 'needle';
    const hit = boundSearchHit(snippet, 0, 0, 6);
    expect(
      ArtifactSearchExactOutputSchema.safeParse({
        ok: true,
        hits: [hit],
        integrity: boundIntegrityForHits(2), // coverage shorter than the hit's own range
      }).success,
    ).toBe(false);
  });
});

describe('inspection receipt', () => {
  it('accepts a well-formed artifact_stat receipt', () => {
    expect(ArtifactInspectionReceiptSchema.safeParse(validReceipt()).success).toBe(true);
  });

  it('accepts a well-formed receipt for each of the other four operations', () => {
    for (const operationDetail of [
      rangeOperationDetail,
      linesOperationDetail,
      headingOperationDetail,
      searchOperationDetail,
    ]) {
      expect(
        ArtifactInspectionReceiptSchema.safeParse(validReceipt({ operationDetail })).success,
      ).toBe(true);
    }
  });

  it('rejects an incomplete receipt audience', () => {
    const receipt = validReceipt() as Record<string, unknown>;
    delete receipt.verifierAudience;
    expect(ArtifactInspectionReceiptSchema.safeParse(receipt).success).toBe(false);

    expect(
      ArtifactInspectionReceiptSchema.safeParse(validReceipt({ verifierAudience: '' })).success,
    ).toBe(false);
  });

  const forbiddenReceiptFields: Record<string, unknown> = {
    jwt: 'eyJhbGciOiJIUzI1NiJ9.x.y',
    authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.x.y',
    authorizationHeader: 'Bearer x',
    serviceRole: true,
    serviceRoleKey: 'service_role_secret',
    storagePath: 'artifact-lab/private/secret.txt',
    payloadBytes: 'aGVsbG8=',
    queryText: 'needle',
    secret: 'top-secret-metadata',
  };

  for (const [field, value] of Object.entries(forbiddenReceiptFields)) {
    it(`rejects a receipt carrying a forbidden "${field}" field`, () => {
      expect(
        ArtifactInspectionReceiptSchema.safeParse({ ...validReceipt(), [field]: value }).success,
      ).toBe(false);
    });
  }

  it('never carries exact-search query text, only its length, even for a search operation', () => {
    const searchReceipt = validReceipt({ operationDetail: searchOperationDetail });
    expect(ArtifactInspectionReceiptSchema.safeParse(searchReceipt).success).toBe(true);
    expect(
      ArtifactInspectionReceiptSchema.safeParse({
        ...searchReceipt,
        operationDetail: { ...searchOperationDetail, queryText: 'needle' },
      }).success,
    ).toBe(false);
  });

  it('states plainly that a receipt is evidence, not bearer authorization', () => {
    expect(ARTIFACT_INSPECTION_RECEIPT_IS_NOT_AUTHORIZATION).toMatch(/not bearer authorization/);
  });

  it('does not allow a Merkle root alone to stand in for immutable source identity', () => {
    const receipt = validReceipt() as Record<string, unknown>;
    delete receipt.objectVersionRef;
    delete receipt.sourceSha256;
    expect(ArtifactInspectionReceiptSchema.safeParse(receipt).success).toBe(false);
  });
});

describe('operation-specific receipt semantics', () => {
  it('rejects artifact_read_range without requested/returned ranges', () => {
    expect(
      ArtifactInspectionReceiptSchema.safeParse(
        validReceipt({ operationDetail: { operation: 'artifact_read_range' } }),
      ).success,
    ).toBe(false);
  });

  it('rejects artifact_stat carrying any range', () => {
    expect(
      ArtifactInspectionReceiptSchema.safeParse(
        validReceipt({
          operationDetail: { operation: 'artifact_stat', returnedRange: { offset: 0, length: 1 } },
        }),
      ).success,
    ).toBe(false);
  });

  it("each operation rejects another operation's receipt-detail shape", () => {
    const details = [
      { operation: 'artifact_stat' },
      rangeOperationDetail,
      linesOperationDetail,
      headingOperationDetail,
      searchOperationDetail,
    ];
    for (const own of details) {
      for (const foreign of details) {
        if (foreign.operation === own.operation) continue;
        const mixed = { ...foreign, operation: own.operation };
        expect(
          ArtifactInspectionReceiptSchema.safeParse(validReceipt({ operationDetail: mixed }))
            .success,
        ).toBe(false);
      }
    }
  });

  it('rejects a missing session-derived principal binding', () => {
    const receipt = validReceipt() as Record<string, unknown>;
    delete receipt.principalBinding;
    expect(ArtifactInspectionReceiptSchema.safeParse(receipt).success).toBe(false);
    expect(
      ArtifactInspectionReceiptSchema.safeParse(validReceipt({ principalBinding: 'manual' }))
        .success,
    ).toBe(false);
  });

  it('rejects a missing approved-client binding', () => {
    const receipt = validReceipt() as Record<string, unknown>;
    delete receipt.inspectorClientBinding;
    expect(ArtifactInspectionReceiptSchema.safeParse(receipt).success).toBe(false);
    expect(
      ArtifactInspectionReceiptSchema.safeParse(validReceipt({ inspectorClientBinding: 'manual' }))
        .success,
    ).toBe(false);
  });

  it('rejects a missing or mis-bound capability reference', () => {
    const receipt = validReceipt() as Record<string, unknown>;
    delete receipt.inspectorCapabilityRef;
    expect(ArtifactInspectionReceiptSchema.safeParse(receipt).success).toBe(false);
    expect(
      ArtifactInspectionReceiptSchema.safeParse(
        validReceipt({ inspectorCapabilityRef: { capability: 'memory:read', ref: 'grant-1' } }),
      ).success,
    ).toBe(false);
  });

  const requiredIdentityFields = [
    'objectVersionRef',
    'sourceSha256',
    'merkleRoot',
    'analyzerProfileId',
    'analyzerProfileVersion',
  ];
  for (const field of requiredIdentityFields) {
    it(`rejects a receipt missing "${field}"`, () => {
      const receipt = validReceipt() as Record<string, unknown>;
      delete receipt[field];
      expect(ArtifactInspectionReceiptSchema.safeParse(receipt).success).toBe(false);
    });
  }

  it('rejects search receipts carrying an unrelated or over-ceiling returned-range set', () => {
    const tooManyHits = Array.from({ length: MAX_SEARCH_HITS + 1 }, (_, i) => ({
      returnedRange: { offset: i * 4, length: 4 },
      returnedByteSha256: sha256,
    }));
    expect(
      ArtifactInspectionReceiptSchema.safeParse(
        validReceipt({
          operationDetail: { ...searchOperationDetail, returnedHits: tooManyHits },
        }),
      ).success,
    ).toBe(false);

    const duplicateRangeHits = [
      { returnedRange: { offset: 0, length: 4 }, returnedByteSha256: sha256 },
      { returnedRange: { offset: 0, length: 4 }, returnedByteSha256: sha256 },
    ];
    expect(
      ArtifactInspectionReceiptSchema.safeParse(
        validReceipt({
          operationDetail: { ...searchOperationDetail, returnedHits: duplicateRangeHits },
        }),
      ).success,
    ).toBe(false);
  });

  it('rejects search receipts carrying a zero-length returned range', () => {
    expect(
      ArtifactInspectionReceiptSchema.safeParse(
        validReceipt({
          operationDetail: {
            ...searchOperationDetail,
            returnedHits: [{ returnedRange: { offset: 0, length: 0 }, returnedByteSha256: sha256 }],
          },
        }),
      ).success,
    ).toBe(false);
  });
});

describe('source-manifest cross-field consistency', () => {
  it('accepts a valid zero-byte artifact', () => {
    expect(
      SourceIntegrityMetadataSchema.safeParse(
        validSourceIntegrityMetadata({
          byteLength: 0,
          chunkCount: 0,
          chunkHashes: { kind: 'inline', hashes: [] },
        }),
      ).success,
    ).toBe(true);
  });

  it('rejects a zero-byte artifact declaring nonzero chunks', () => {
    expect(
      SourceIntegrityMetadataSchema.safeParse(
        validSourceIntegrityMetadata({ byteLength: 0, chunkCount: 1 }),
      ).success,
    ).toBe(false);
  });

  it('accepts an exact-multiple byte length', () => {
    expect(
      SourceIntegrityMetadataSchema.safeParse(
        validSourceIntegrityMetadata({ byteLength: 4096, chunkSize: 1024, chunkCount: 4 }),
      ).success,
    ).toBe(true);
  });

  it('accepts a short final chunk', () => {
    expect(
      SourceIntegrityMetadataSchema.safeParse(
        validSourceIntegrityMetadata({
          byteLength: 3100,
          chunkSize: 1024,
          chunkCount: 4,
        }),
      ).success,
    ).toBe(true);
  });

  it('rejects a mismatched inline hash count', () => {
    expect(
      SourceIntegrityMetadataSchema.safeParse(
        validSourceIntegrityMetadata({
          chunkHashes: { kind: 'inline', hashes: [sha256, sha256, sha256] },
        }),
      ).success,
    ).toBe(false);
  });

  it('rejects an impossible byte length for the declared chunk size and count', () => {
    expect(
      SourceIntegrityMetadataSchema.safeParse(
        validSourceIntegrityMetadata({ byteLength: 5000, chunkSize: 1024, chunkCount: 4 }),
      ).success,
    ).toBe(false);
    expect(
      SourceIntegrityMetadataSchema.safeParse(
        validSourceIntegrityMetadata({ byteLength: 3000, chunkSize: 1024, chunkCount: 4 }),
      ).success,
    ).toBe(false);
  });

  it('rejects a one-over inline hash count', () => {
    expect(
      SourceIntegrityMetadataSchema.safeParse(
        validSourceIntegrityMetadata({
          chunkHashes: { kind: 'inline', hashes: [sha256, sha256, sha256, sha256, sha256] },
        }),
      ).success,
    ).toBe(false);
  });

  it('allows reference-mode chunk hashes for manifests exceeding the inline ceiling', () => {
    expect(
      SourceIntegrityMetadataSchema.safeParse(
        validSourceIntegrityMetadata({
          byteLength: 1024 * 100,
          chunkSize: 1024,
          chunkCount: 100,
          chunkHashes: { kind: 'reference', ref: 'chr_AAAAAAAAAAAAAAAAAAAA' },
        }),
      ).success,
    ).toBe(true);
  });
});

describe('source expiry versus historical manifest durability', () => {
  it('denies future access once expired', () => {
    expect(isArtifactExpired(pastIso, nowIso)).toBe(true);
    expect(isArtifactExpired(futureIso, nowIso)).toBe(false);
    expect(isArtifactExpired(undefined, nowIso)).toBe(false);
  });

  it('still parses the full immutable manifest for an expired artifact', () => {
    const expired = validSourceIntegrityMetadata({ expiresAt: pastIso });
    expect(isArtifactExpired(expired.expiresAt as string, nowIso)).toBe(true);
    const parsed = SourceIntegrityMetadataSchema.safeParse(expired);
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.sourceSha256).toBe(sha256);
      expect(parsed.data.merkleRoot).toBe(merkleRoot);
      expect(parsed.data.byteLength).toBe(4096);
    }
  });

  it('still parses a historical receipt referencing an expired artifact', () => {
    expect(ArtifactInspectionReceiptSchema.safeParse(validReceipt()).success).toBe(true);
  });
});

describe('semantic analysis prohibited', () => {
  it('is disabled and, when it exists, is worker-only, never Edge', () => {
    expect(SEMANTIC_ANALYSIS_POLICY.enabled).toBe(false);
    expect(SEMANTIC_ANALYSIS_POLICY.executionClass).toBe('local_worker_only');
    expect(Object.isFrozen(SEMANTIC_ANALYSIS_POLICY)).toBe(true);
  });

  it('excludes semantic_summary from the S0 deterministic derivation-type contract', () => {
    expect(DerivationTypeSchema.safeParse('text_extraction').success).toBe(true);
    expect(DerivationTypeSchema.safeParse('semantic_summary').success).toBe(false);
  });
});

describe('many-source derivation contract', () => {
  const baseDerivation = {
    derivationId: 'drv_AAAAAAAAAAAAAAAAAAAA',
    derivedArtifactId: otherArtifactId,
    derivationType: 'text_extraction',
    profileId: 'text/markdown',
    profileVersion: 'markdown-1',
    scope: 'full-document',
    createdAt: nowIso,
  };

  it('supports two inputs, each binding its own exact source SHA', () => {
    const inputs = [
      {
        derivationId: baseDerivation.derivationId,
        sourceArtifactId: artifactId,
        sourceSha256: sha256,
      },
      {
        derivationId: baseDerivation.derivationId,
        sourceArtifactId: otherArtifactId,
        sourceSha256: otherSha256,
      },
    ];
    expect(inputs.every((input) => ArtifactDerivationInputRefSchema.safeParse(input).success)).toBe(
      true,
    );
    expect(
      ArtifactDerivationWithInputsSchema.safeParse({ derivation: baseDerivation, inputs }).success,
    ).toBe(true);
  });

  it('rejects an input bound to a different derivation', () => {
    const inputs = [
      {
        derivationId: 'drv_BBBBBBBBBBBBBBBBBBBB',
        sourceArtifactId: artifactId,
        sourceSha256: sha256,
      },
    ];
    expect(
      ArtifactDerivationWithInputsSchema.safeParse({ derivation: baseDerivation, inputs }).success,
    ).toBe(false);
  });

  it('rejects a duplicate sourceArtifactId within the same derivation', () => {
    const inputs = [
      {
        derivationId: baseDerivation.derivationId,
        sourceArtifactId: artifactId,
        sourceSha256: sha256,
      },
      {
        derivationId: baseDerivation.derivationId,
        sourceArtifactId: artifactId,
        sourceSha256: otherSha256,
      },
    ];
    expect(
      ArtifactDerivationWithInputsSchema.safeParse({ derivation: baseDerivation, inputs }).success,
    ).toBe(false);
  });
});

describe('capability descriptor not granting authority', () => {
  it('declares that current authorization is still required and grants nothing itself', () => {
    for (const tool of ARTIFACT_INSPECTION_TOOLS) {
      expect(tool.authorizationRequired).toBe(true);
      expect('grant' in tool).toBe(false);
      expect('bypassAuthorization' in tool).toBe(false);
      expect('authority' in tool).toBe(false);
    }
    expect(ARTIFACT_INSPECTION_DESCRIPTOR_IS_NOT_PERMISSION).toMatch(/does not itself grant/);
  });

  it('marks every descriptor idempotent and non-retrying (independent of read-only)', () => {
    for (const tool of ARTIFACT_INSPECTION_TOOLS) {
      expect(tool.idempotency).toBe('idempotent');
      expect(tool.retry).toEqual({ maxAttempts: 1, policy: 'none' });
      expect(tool.contentTrust).toBe('untrusted');
    }
  });
});

describe('explicit read-only descriptors', () => {
  it('every descriptor states readOnly: true explicitly', () => {
    for (const tool of ARTIFACT_INSPECTION_TOOLS) {
      expect(tool.readOnly).toBe(true);
    }
  });

  it('idempotency does not stand in for read-only in this contract', () => {
    for (const tool of ARTIFACT_INSPECTION_TOOLS) {
      expect(tool).toHaveProperty('readOnly');
      expect(tool).toHaveProperty('idempotency');
      // Two independent claims: neither key derives the other's presence.
      expect(typeof tool.readOnly).toBe('boolean');
    }
  });
});

describe('all exported descriptors and nested policy objects are frozen', () => {
  it('freezes every tool descriptor and its nested limits/retry/errorMapping', () => {
    for (const descriptor of [
      ARTIFACT_STAT_TOOL,
      ARTIFACT_READ_RANGE_TOOL,
      ARTIFACT_READ_LINES_TOOL,
      ARTIFACT_READ_HEADING_TOOL,
      ARTIFACT_SEARCH_EXACT_TOOL,
    ]) {
      expect(Object.isFrozen(descriptor)).toBe(true);
      expect(Object.isFrozen(descriptor.limits)).toBe(true);
      expect(Object.isFrozen(descriptor.retry)).toBe(true);
      expect(Object.isFrozen(descriptor.errorMapping)).toBe(true);
    }
    expect(Object.isFrozen(ARTIFACT_INSPECTION_TOOLS)).toBe(true);
  });

  it('freezes the analyzer/derivation policy constants', () => {
    expect(Object.isFrozen(ANALYZER_PROFILE_IDS)).toBe(true);
    expect(Object.isFrozen(ARTIFACT_INSPECTION_OPERATIONS)).toBe(true);
    expect(Object.isFrozen(ARTIFACT_INSPECTION_ERROR_CODES)).toBe(true);
    expect(Object.isFrozen(SEMANTIC_ANALYSIS_POLICY)).toBe(true);
  });
});
