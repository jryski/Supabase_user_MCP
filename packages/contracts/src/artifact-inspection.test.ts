import { describe, expect, it } from 'vitest';

import {
  ANALYZER_PROFILE_IDS,
  ARTIFACT_INSPECTION_DESCRIPTOR_IS_NOT_PERMISSION,
  ARTIFACT_INSPECTION_ERROR_CODES,
  ARTIFACT_INSPECTION_OPERATIONS,
  ARTIFACT_INSPECTION_RECEIPT_IS_NOT_AUTHORIZATION,
  ARTIFACT_INSPECTION_RECEIPT_SCHEMA_VERSION,
  ARTIFACT_INSPECTION_TOOLS,
  ARTIFACT_READ_HEADING_TOOL,
  ARTIFACT_READ_LINES_TOOL,
  ARTIFACT_READ_RANGE_TOOL,
  ARTIFACT_SEARCH_EXACT_TOOL,
  ARTIFACT_STAT_TOOL,
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
  AnalyzerProfileIdSchema,
  DerivationTypeSchema,
  MAX_ARTIFACT_BYTE_OFFSET,
  MAX_ARTIFACT_ID_LENGTH,
  MAX_ARTIFACT_RESPONSE_BYTES,
  MAX_ARTIFACT_TOOL_EXECUTION_MS,
  MAX_HEADING_ID_LENGTH,
  MAX_LINE_COUNT,
  MAX_RANGE_BYTES,
  MAX_SEARCH_HITS,
  MAX_SEARCH_QUERY_LENGTH,
  MIN_ARTIFACT_ID_LENGTH,
  PARTIAL_READ_INTEGRITY_STATEMENT,
  PartialReadIntegritySchema,
  SEMANTIC_ANALYSIS_POLICY,
  SourceIntegrityMetadataSchema,
  artifactInspectionResponseByteLength,
  createArtifactInspectionError,
  isArtifactExpired,
  isArtifactInspectionDeadlineExceeded,
  publicArtifactInspectionUnavailable,
  serializeArtifactInspectionResponse,
} from './artifact-inspection.js';

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

function validPartialReadIntegrity(overrides: Record<string, unknown> = {}) {
  return {
    requestedRange: { kind: 'byte_range', offset: 0, length: 10 },
    verifiedCoveringChunkRange: { startChunkIndex: 0, endChunkIndex: 0 },
    returnedRange: { offset: 0, length: 10 },
    merkleRoot,
    returnedByteSha256: sha256,
    sourceSha256: sha256,
    contentTrust: 'untrusted',
    ...overrides,
  };
}

function validReceipt(overrides: Record<string, unknown> = {}) {
  return {
    receiptSchemaVersion: ARTIFACT_INSPECTION_RECEIPT_SCHEMA_VERSION,
    verifierAudience: 'verifier-1',
    principalRef: 'principal-1',
    inspectorClientRef: 'smp-lab-inspector',
    artifactId,
    sourceIdentity: { kind: 'merkle_root', merkleRoot },
    operation: 'artifact_stat',
    returnedByteHash: sha256,
    policyVersion: 'policy-1',
    analyzerProfileVersion: 'markdown-1',
    inspectorDeploymentGitCoordinate: gitCoordinate,
    recordedAt: nowIso,
    resultOrErrorClass: { kind: 'result' },
    ...overrides,
  };
}

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

  it('artifact_read_range: accepts a bounded request and a well-formed success output', () => {
    expect(ArtifactReadRangeInputSchema.parse({ artifactId, offset: 0, length: 10 })).toMatchObject(
      { offset: 0, length: 10 },
    );
    expect(
      ArtifactReadRangeOutputSchema.safeParse({
        ok: true,
        data: 'hello text',
        contentTrust: 'untrusted',
        integrity: validPartialReadIntegrity(),
      }).success,
    ).toBe(true);
  });

  it('artifact_read_lines: accepts a bounded request and a well-formed success output', () => {
    expect(
      ArtifactReadLinesInputSchema.parse({ artifactId, startLine: 1, count: 5 }),
    ).toMatchObject({ startLine: 1, count: 5 });
    expect(
      ArtifactReadLinesOutputSchema.safeParse({
        ok: true,
        data: 'line one\nline two',
        returnedLineCount: 2,
        contentTrust: 'untrusted',
        integrity: validPartialReadIntegrity({
          requestedRange: { kind: 'line_range', startLine: 1, count: 5 },
        }),
      }).success,
    ).toBe(true);
  });

  it('artifact_read_heading: accepts a bounded request and a well-formed success output', () => {
    expect(
      ArtifactReadHeadingInputSchema.parse({ artifactId, headingId: 'intro-section' }),
    ).toMatchObject({ headingId: 'intro-section' });
    expect(
      ArtifactReadHeadingOutputSchema.safeParse({
        ok: true,
        headingId: 'intro-section',
        data: '## Intro\n\nbody',
        contentTrust: 'untrusted',
        integrity: validPartialReadIntegrity({
          requestedRange: { kind: 'heading', headingId: 'intro-section' },
        }),
      }).success,
    ).toBe(true);
  });

  it('artifact_search_exact: accepts a bounded request and a well-formed success output', () => {
    expect(
      ArtifactSearchExactInputSchema.parse({ artifactId, query: 'needle', maxHits: 10 }),
    ).toMatchObject({ query: 'needle', maxHits: 10 });
    expect(
      ArtifactSearchExactOutputSchema.safeParse({
        ok: true,
        hits: [
          {
            byteOffset: 0,
            length: 6,
            lineNumber: 1,
            snippet: 'needle in a haystack',
            contentTrust: 'untrusted',
          },
        ],
        integrity: validPartialReadIntegrity({
          requestedRange: { kind: 'search_exact', queryLength: 6 },
        }),
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

    const hit = {
      byteOffset: 0,
      length: 1,
      lineNumber: 1,
      snippet: 'x',
      contentTrust: 'untrusted' as const,
    };
    const integrity = validPartialReadIntegrity({
      requestedRange: { kind: 'search_exact', queryLength: 1 },
    });
    expect(
      ArtifactSearchExactOutputSchema.safeParse({
        ok: true,
        hits: Array.from({ length: MAX_SEARCH_HITS }, () => hit),
        integrity,
      }).success,
    ).toBe(true);
    expect(
      ArtifactSearchExactOutputSchema.safeParse({
        ok: true,
        hits: Array.from({ length: MAX_SEARCH_HITS + 1 }, () => hit),
        integrity,
      }).success,
    ).toBe(false);
  });

  it('execution time: exact ceiling not exceeded, one-over exceeded', () => {
    expect(isArtifactInspectionDeadlineExceeded(MAX_ARTIFACT_TOOL_EXECUTION_MS)).toBe(false);
    expect(isArtifactInspectionDeadlineExceeded(MAX_ARTIFACT_TOOL_EXECUTION_MS + 1)).toBe(true);
  });

  it('complete UTF-8 response envelope: exact ceiling accepted, one-over rejected', () => {
    const overhead = artifactInspectionResponseByteLength({ a: '' });
    const fillLength = MAX_ARTIFACT_RESPONSE_BYTES - overhead;
    const atLimit = { a: 'x'.repeat(fillLength) };
    const overLimit = { a: 'x'.repeat(fillLength + 1) };

    expect(artifactInspectionResponseByteLength(atLimit)).toBe(MAX_ARTIFACT_RESPONSE_BYTES);
    expect(() => serializeArtifactInspectionResponse(atLimit)).not.toThrow();

    expect(artifactInspectionResponseByteLength(overLimit)).toBe(MAX_ARTIFACT_RESPONSE_BYTES + 1);
    expect(() => serializeArtifactInspectionResponse(overLimit)).toThrow(RangeError);
  });

  it('response envelope byte counting is UTF-8 aware, not JS string-length aware', () => {
    const multiByte = { data: 'é'.repeat(10) };
    expect(artifactInspectionResponseByteLength(multiByte)).toBeGreaterThan(
      JSON.stringify(multiByte).length,
    );
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

describe('inspection receipt', () => {
  it('accepts a well-formed receipt', () => {
    expect(ArtifactInspectionReceiptSchema.safeParse(validReceipt()).success).toBe(true);
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
    objectKey: 'private/secret.txt',
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
    const searchReceipt = validReceipt({
      operation: 'artifact_search_exact',
      requestedRange: { kind: 'search_exact', queryLength: 6 },
    });
    expect(ArtifactInspectionReceiptSchema.safeParse(searchReceipt).success).toBe(true);
    expect(
      ArtifactInspectionReceiptSchema.safeParse({
        ...searchReceipt,
        requestedRange: { kind: 'search_exact', queryLength: 6, query: 'needle' },
      }).success,
    ).toBe(false);
  });

  it('states plainly that a receipt is evidence, not bearer authorization', () => {
    expect(ARTIFACT_INSPECTION_RECEIPT_IS_NOT_AUTHORIZATION).toMatch(/not bearer authorization/);
  });
});

describe('partial-read integrity fields', () => {
  it('accepts a fully populated integrity object', () => {
    expect(PartialReadIntegritySchema.safeParse(validPartialReadIntegrity()).success).toBe(true);
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

  it('rejects a covering chunk range that ends before it starts', () => {
    expect(
      PartialReadIntegritySchema.safeParse(
        validPartialReadIntegrity({
          verifiedCoveringChunkRange: { startChunkIndex: 3, endChunkIndex: 1 },
        }),
      ).success,
    ).toBe(false);
  });

  it('states plainly that a whole-object hash cannot stand in for partial-read integrity', () => {
    expect(PARTIAL_READ_INTEGRITY_STATEMENT).toMatch(/does not by itself prove/);
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
    expect(
      ArtifactInspectionReceiptSchema.safeParse(
        validReceipt({ sourceIdentity: { kind: 'merkle_root', merkleRoot } }),
      ).success,
    ).toBe(true);
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
  it('supports two inputs, each binding its own exact source SHA', () => {
    const derivation = {
      derivationId: 'drv_AAAAAAAAAAAAAAAAAAAA',
      derivedArtifactId: otherArtifactId,
      derivationType: 'text_extraction',
      profileId: 'text/markdown',
      profileVersion: 'markdown-1',
      scope: 'full-document',
      createdAt: nowIso,
    };
    const inputs = [
      { derivationId: derivation.derivationId, sourceArtifactId: artifactId, sourceSha256: sha256 },
      {
        derivationId: derivation.derivationId,
        sourceArtifactId: otherArtifactId,
        sourceSha256: otherSha256,
      },
    ];
    expect(inputs.every((input) => ArtifactDerivationInputRefSchema.safeParse(input).success)).toBe(
      true,
    );
    expect(ArtifactDerivationWithInputsSchema.safeParse({ derivation, inputs }).success).toBe(true);
  });

  it('rejects an input bound to a different derivation', () => {
    const derivation = {
      derivationId: 'drv_AAAAAAAAAAAAAAAAAAAA',
      derivedArtifactId: otherArtifactId,
      derivationType: 'text_extraction',
      profileId: 'text/markdown',
      profileVersion: 'markdown-1',
      scope: 'full-document',
      createdAt: nowIso,
    };
    const inputs = [
      {
        derivationId: 'drv_BBBBBBBBBBBBBBBBBBBB',
        sourceArtifactId: artifactId,
        sourceSha256: sha256,
      },
    ];
    expect(ArtifactDerivationWithInputsSchema.safeParse({ derivation, inputs }).success).toBe(
      false,
    );
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

  it('marks every descriptor read-only, idempotent, and non-retrying', () => {
    for (const tool of ARTIFACT_INSPECTION_TOOLS) {
      expect(tool.idempotency).toBe('idempotent');
      expect(tool.retry).toEqual({ maxAttempts: 1, policy: 'none' });
      expect(tool.contentTrust).toBe('untrusted');
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
