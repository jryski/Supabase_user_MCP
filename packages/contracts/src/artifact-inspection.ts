import * as z from 'zod/v4';

import { AuthorizationIdentifierSchema } from './authorization.js';

/**
 * S0 candidate contract for GitHub issue #34 (Governed Artifact Inspection).
 *
 * Scope boundary, restated here so this file cannot be read as more than it is:
 *
 * - This module defines the MCP capability surface only: input/output shapes,
 *   the error vocabulary, source and partial-read integrity metadata, the
 *   inspection-receipt shape, and frozen tool descriptors.
 * - It is a candidate contract. Nothing here is accepted architecture until a
 *   maintainer says so.
 * - S1 already exists synthetically on `main`: the artifact registry, chunk,
 *   derivation, and derivation-input tables, plus the `storage.objects` RLS
 *   lab, live in `supabase/migrations/20260826000100_artifact_schema.sql` and
 *   `supabase/migrations/20260826000200_storage_object_policy.sql`. This file
 *   does not rebuild or modify that migration surface.
 * - This file adds no migration, Edge Function, MCP runtime registration,
 *   Storage deployment, semantic analysis, or hosted configuration.
 * - The deterministic inspector/Edge execution surface, Postgres/RLS
 *   authorization, Storage byte custody, ingest-time bounded worker hashing,
 *   and any future worker-only semantic derivation are separate authority
 *   surfaces from the MCP capability surface defined here. A tool descriptor
 *   below states scheduling/interface metadata; it does not itself grant
 *   access, and an inspection receipt is evidence of what occurred, not
 *   bearer authorization -- see the exported statements near the receipt
 *   schema.
 * - Source expiry (`expiresAt` on `SourceIntegrityMetadataSchema`) denies
 *   *future* access to a source artifact. It must not be read as erasing the
 *   immutable manifest fields (hashes, Merkle root, byte length) needed to
 *   verify a historical receipt issued before expiry -- see
 *   `isArtifactExpired` below, which is deliberately a pure predicate over a
 *   timestamp and carries no side effect on manifest data.
 */

// ---------------------------------------------------------------------------
// Exact ceilings
// ---------------------------------------------------------------------------

export const MIN_ARTIFACT_ID_LENGTH = 20;
export const MAX_ARTIFACT_ID_LENGTH = 128;
/** A sanity ceiling on requestable byte offsets (2^40 = 1 TiB). Not one of the
 * enumerated exact-boundary ceilings; bounded for schema safety only. */
export const MAX_ARTIFACT_BYTE_OFFSET = 1_099_511_627_776;
export const MAX_RANGE_BYTES = 8_192;
export const MAX_START_LINE = 1_000_000;
export const MAX_LINE_COUNT = 200;
export const MAX_HEADING_ID_LENGTH = 128;
export const MAX_SEARCH_QUERY_LENGTH = 256;
export const MAX_SEARCH_HITS = 50;
export const MAX_SEARCH_SNIPPET_LENGTH = 256;
export const MAX_ARTIFACT_TOOL_EXECUTION_MS = 2_000;
export const MAX_ARTIFACT_RESPONSE_BYTES = 65_536;
export const MAX_INLINE_CHUNK_HASHES = 64;
export const MAX_DERIVATION_INPUTS_PER_DERIVATION = 25;

// ---------------------------------------------------------------------------
// Opaque identifiers and shared primitives
// ---------------------------------------------------------------------------

/**
 * Callers identify artifacts only by this opaque handle. Resolution to a
 * bucket, object key, or any Storage-facing locator is a policy/registry
 * concern, never a caller-supplied value.
 */
export const ArtifactIdSchema = z
  .string()
  .min(MIN_ARTIFACT_ID_LENGTH)
  .max(MAX_ARTIFACT_ID_LENGTH)
  .regex(/^art_[A-Za-z0-9_-]+$/, 'Expected an opaque artifact identifier.');
export type ArtifactId = z.infer<typeof ArtifactIdSchema>;

const OpaqueObjectVersionRefSchema = z
  .string()
  .min(20)
  .max(256)
  .regex(/^ov_[A-Za-z0-9_-]+$/, 'Expected an opaque immutable object/version reference.');

const OpaqueChunkHashesRefSchema = z
  .string()
  .min(20)
  .max(256)
  .regex(/^chr_[A-Za-z0-9_-]+$/, 'Expected an opaque chunk-hashes reference.');

const OpaqueDerivationIdSchema = z
  .string()
  .min(20)
  .max(128)
  .regex(/^drv_[A-Za-z0-9_-]+$/, 'Expected an opaque derivation identifier.');

/** Hex-encoded on the wire; the registry stores the equivalent value as `bytea`. */
const Sha256HexSchema = z
  .string()
  .length(64)
  .regex(/^[0-9a-f]{64}$/, 'Expected a lowercase hex-encoded SHA-256 digest.');

const GitCommitCoordinateSchema = z
  .string()
  .regex(/^[0-9a-f]{40}$/, 'Expected an exact 40-hex-character Git commit SHA.');

const BoundedVersionStringSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/, 'Expected a bounded version identifier.');

const HeadingIdSchema = z
  .string()
  .min(1)
  .max(MAX_HEADING_ID_LENGTH)
  .regex(/^[A-Za-z0-9][A-Za-z0-9_-]*$/, 'Expected an opaque heading identifier.');

// ---------------------------------------------------------------------------
// Error vocabulary
// ---------------------------------------------------------------------------

export const ARTIFACT_INSPECTION_ERROR_CODES = Object.freeze([
  'INVALID_REQUEST',
  'RESOURCE_UNAVAILABLE',
  'UNSUPPORTED',
  'RESPONSE_LIMIT_EXCEEDED',
  'INTEGRITY_FAILURE',
  'DEADLINE_EXCEEDED',
  'INTERNAL_ERROR',
] as const);

export type ArtifactInspectionErrorCode = (typeof ARTIFACT_INSPECTION_ERROR_CODES)[number];

export const ArtifactInspectionErrorCodeSchema = z.enum(ARTIFACT_INSPECTION_ERROR_CODES);

export const ARTIFACT_INSPECTION_ERROR_MESSAGES: Record<ArtifactInspectionErrorCode, string> =
  Object.freeze({
    INVALID_REQUEST: 'Request is invalid.',
    RESOURCE_UNAVAILABLE: 'Artifact is unavailable.',
    UNSUPPORTED: 'Artifact content profile is not supported.',
    RESPONSE_LIMIT_EXCEEDED: 'Response limit exceeded.',
    INTEGRITY_FAILURE: 'Artifact integrity verification failed.',
    DEADLINE_EXCEEDED: 'Request deadline exceeded.',
    INTERNAL_ERROR: 'Request could not be completed.',
  } satisfies Record<ArtifactInspectionErrorCode, string>);

export const ArtifactInspectionErrorSchema = z.discriminatedUnion('code', [
  z
    .object({
      code: z.literal('INVALID_REQUEST'),
      message: z.literal(ARTIFACT_INSPECTION_ERROR_MESSAGES.INVALID_REQUEST),
      retryable: z.literal(false),
    })
    .strict(),
  z
    .object({
      code: z.literal('RESOURCE_UNAVAILABLE'),
      message: z.literal(ARTIFACT_INSPECTION_ERROR_MESSAGES.RESOURCE_UNAVAILABLE),
      retryable: z.literal(false),
    })
    .strict(),
  z
    .object({
      code: z.literal('UNSUPPORTED'),
      message: z.literal(ARTIFACT_INSPECTION_ERROR_MESSAGES.UNSUPPORTED),
      retryable: z.literal(false),
    })
    .strict(),
  z
    .object({
      code: z.literal('RESPONSE_LIMIT_EXCEEDED'),
      message: z.literal(ARTIFACT_INSPECTION_ERROR_MESSAGES.RESPONSE_LIMIT_EXCEEDED),
      retryable: z.literal(false),
    })
    .strict(),
  z
    .object({
      code: z.literal('INTEGRITY_FAILURE'),
      message: z.literal(ARTIFACT_INSPECTION_ERROR_MESSAGES.INTEGRITY_FAILURE),
      retryable: z.literal(false),
    })
    .strict(),
  z
    .object({
      code: z.literal('DEADLINE_EXCEEDED'),
      message: z.literal(ARTIFACT_INSPECTION_ERROR_MESSAGES.DEADLINE_EXCEEDED),
      retryable: z.literal(false),
    })
    .strict(),
  z
    .object({
      code: z.literal('INTERNAL_ERROR'),
      message: z.literal(ARTIFACT_INSPECTION_ERROR_MESSAGES.INTERNAL_ERROR),
      retryable: z.literal(false),
    })
    .strict(),
]);

export interface ArtifactInspectionError {
  code: ArtifactInspectionErrorCode;
  message: string;
  retryable: false;
}

export const ArtifactInspectionErrorOutputSchema = z
  .object({
    ok: z.literal(false),
    error: ArtifactInspectionErrorSchema,
  })
  .strict();

export interface ArtifactInspectionErrorOutput {
  ok: false;
  error: ArtifactInspectionError;
}

export function createArtifactInspectionError(
  code: ArtifactInspectionErrorCode,
): ArtifactInspectionErrorOutput {
  return Object.freeze({
    ok: false as const,
    error: Object.freeze({
      code,
      message: ARTIFACT_INSPECTION_ERROR_MESSAGES[code],
      retryable: false as const,
    }),
  });
}

const PUBLIC_ARTIFACT_UNAVAILABLE = createArtifactInspectionError('RESOURCE_UNAVAILABLE');

export type ArtifactUnavailableReason = 'missing' | 'unauthorized';

/**
 * Missing and unauthorized artifacts MUST produce this same frozen result.
 * `reason` exists only for the caller's internal telemetry; it is never read
 * to shape the public output, so a missing artifact and an artifact denied
 * by policy are byte-identical on the wire.
 */
export function publicArtifactInspectionUnavailable(
  reason: ArtifactUnavailableReason,
): typeof PUBLIC_ARTIFACT_UNAVAILABLE {
  void reason;
  return PUBLIC_ARTIFACT_UNAVAILABLE;
}

// ---------------------------------------------------------------------------
// Response envelope and deadline ceilings
// ---------------------------------------------------------------------------

export function artifactInspectionResponseByteLength(output: unknown): number {
  return new TextEncoder().encode(JSON.stringify(output)).byteLength;
}

export function serializeArtifactInspectionResponse(output: unknown): string {
  const serialized = JSON.stringify(output);
  if (new TextEncoder().encode(serialized).byteLength > MAX_ARTIFACT_RESPONSE_BYTES) {
    throw new RangeError(
      `Artifact inspection response must not exceed ${MAX_ARTIFACT_RESPONSE_BYTES} UTF-8 bytes.`,
    );
  }
  return serialized;
}

function withinArtifactInspectionResponseByteLimit(value: unknown): boolean {
  return artifactInspectionResponseByteLength(value) <= MAX_ARTIFACT_RESPONSE_BYTES;
}

export function isArtifactInspectionDeadlineExceeded(elapsedMs: number): boolean {
  return elapsedMs > MAX_ARTIFACT_TOOL_EXECUTION_MS;
}

/**
 * Pure predicate: does `expiresAt` deny access as of `nowIso`? This function
 * has no effect on, and takes no dependency on, the manifest fields required
 * to verify a historical receipt (hashes, Merkle root, byte length). Expiry
 * gates *future* access; it must never be read as license to drop those
 * fields from a previously issued receipt or from `SourceIntegrityMetadata`.
 */
export function isArtifactExpired(expiresAt: string | undefined, nowIso: string): boolean {
  if (expiresAt === undefined) return false;
  return Date.parse(expiresAt) <= Date.parse(nowIso);
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

export const ARTIFACT_INSPECTION_OPERATIONS = Object.freeze([
  'artifact_stat',
  'artifact_read_range',
  'artifact_read_lines',
  'artifact_read_heading',
  'artifact_search_exact',
] as const);

export type ArtifactInspectionOperation = (typeof ARTIFACT_INSPECTION_OPERATIONS)[number];

export const ArtifactInspectionOperationSchema = z.enum(ARTIFACT_INSPECTION_OPERATIONS);

// ---------------------------------------------------------------------------
// Input schemas -- opaque artifact ID plus bounded operation parameters only.
//
// Every schema below is `.strict()`. A caller-supplied bucket, object path or
// key, URL, origin, schema, table, RPC, HTTP method, signed URL, service-role
// material, or arbitrary parser/profile selection is rejected as an unknown
// property, not merely ignored.
// ---------------------------------------------------------------------------

export const ArtifactStatInputSchema = z.object({ artifactId: ArtifactIdSchema }).strict();
export type ArtifactStatInput = z.infer<typeof ArtifactStatInputSchema>;

export const ArtifactReadRangeInputSchema = z
  .object({
    artifactId: ArtifactIdSchema,
    offset: z.number().int().min(0).max(MAX_ARTIFACT_BYTE_OFFSET),
    length: z.number().int().min(1).max(MAX_RANGE_BYTES),
  })
  .strict();
export type ArtifactReadRangeInput = z.infer<typeof ArtifactReadRangeInputSchema>;

export const ArtifactReadLinesInputSchema = z
  .object({
    artifactId: ArtifactIdSchema,
    startLine: z.number().int().min(1).max(MAX_START_LINE),
    count: z.number().int().min(1).max(MAX_LINE_COUNT),
  })
  .strict();
export type ArtifactReadLinesInput = z.infer<typeof ArtifactReadLinesInputSchema>;

export const ArtifactReadHeadingInputSchema = z
  .object({
    artifactId: ArtifactIdSchema,
    headingId: HeadingIdSchema,
  })
  .strict();
export type ArtifactReadHeadingInput = z.infer<typeof ArtifactReadHeadingInputSchema>;

export const ArtifactSearchExactInputSchema = z
  .object({
    artifactId: ArtifactIdSchema,
    query: z.string().trim().min(1).max(MAX_SEARCH_QUERY_LENGTH),
    maxHits: z.number().int().min(1).max(MAX_SEARCH_HITS).default(MAX_SEARCH_HITS),
  })
  .strict();
export type ArtifactSearchExactInput = z.infer<typeof ArtifactSearchExactInputSchema>;

// ---------------------------------------------------------------------------
// Source-integrity metadata (artifact_stat)
// ---------------------------------------------------------------------------

const ChunkHashesSchema = z.discriminatedUnion('kind', [
  z
    .object({
      kind: z.literal('inline'),
      hashes: z.array(Sha256HexSchema).max(MAX_INLINE_CHUNK_HASHES),
    })
    .strict(),
  z
    .object({
      kind: z.literal('reference'),
      ref: OpaqueChunkHashesRefSchema,
    })
    .strict(),
]);

export const ANALYZER_PROFILE_IDS = Object.freeze(['text/plain', 'text/markdown'] as const);
export type AnalyzerProfileId = (typeof ANALYZER_PROFILE_IDS)[number];
export const AnalyzerProfileIdSchema = z.enum(ANALYZER_PROFILE_IDS);

/** Proposed next deterministic profile per issue #34. Not implemented in S0:
 * intentionally absent from `AnalyzerProfileIdSchema`. */
export const PROPOSED_NEXT_DETERMINISTIC_PROFILE_ID = 'text/csv' as const;

const AnalyzerProfileSupportSchema = z.enum([...ANALYZER_PROFILE_IDS, 'unsupported']);

export const SourceIntegrityMetadataSchema = z
  .object({
    artifactId: ArtifactIdSchema,
    objectVersionRef: OpaqueObjectVersionRefSchema,
    sourceSha256: Sha256HexSchema,
    byteLength: z.number().int().min(0),
    chunkSize: z.number().int().positive(),
    chunkCount: z.number().int().min(0),
    chunkHashes: ChunkHashesSchema,
    merkleRoot: Sha256HexSchema,
    mediaType: z.string().min(1).max(255),
    analyzerProfileSupport: AnalyzerProfileSupportSchema,
    createdAt: z.iso.datetime({ offset: true }),
    expiresAt: z.iso.datetime({ offset: true }).optional(),
  })
  .strict();
export type SourceIntegrityMetadata = z.infer<typeof SourceIntegrityMetadataSchema>;

// ---------------------------------------------------------------------------
// Partial-read integrity metadata (read_range / read_lines / read_heading /
// search_exact)
// ---------------------------------------------------------------------------

const RequestedRangeSchema = z.discriminatedUnion('kind', [
  z
    .object({
      kind: z.literal('byte_range'),
      offset: z.number().int().min(0).max(MAX_ARTIFACT_BYTE_OFFSET),
      length: z.number().int().min(1).max(MAX_RANGE_BYTES),
    })
    .strict(),
  z
    .object({
      kind: z.literal('line_range'),
      startLine: z.number().int().min(1).max(MAX_START_LINE),
      count: z.number().int().min(1).max(MAX_LINE_COUNT),
    })
    .strict(),
  z
    .object({
      kind: z.literal('heading'),
      headingId: HeadingIdSchema,
    })
    .strict(),
  z
    .object({
      // Deliberately excludes the query text itself -- see the receipt
      // schema below, which must not carry exact-search query text.
      kind: z.literal('search_exact'),
      queryLength: z.number().int().min(1).max(MAX_SEARCH_QUERY_LENGTH),
    })
    .strict(),
]);

const ReturnedRangeSchema = z
  .object({
    offset: z.number().int().min(0),
    length: z.number().int().min(0).max(MAX_RANGE_BYTES),
  })
  .strict();

const CoveringChunkRangeSchema = z
  .object({
    startChunkIndex: z.number().int().min(0),
    endChunkIndex: z.number().int().min(0),
  })
  .strict()
  .refine(
    (range) => range.endChunkIndex >= range.startChunkIndex,
    'endChunkIndex must not precede startChunkIndex.',
  );

/**
 * Every field here is required. A whole-object source SHA-256 does not, by
 * itself, prove the integrity of an arbitrary partial read -- this schema
 * makes that structurally impossible to assert: a caller cannot produce a
 * valid partial-read integrity object carrying only `sourceSha256` while
 * omitting the verified covering chunk range, the Merkle root, or the
 * returned-byte hash.
 */
export const PARTIAL_READ_INTEGRITY_STATEMENT: string =
  'A whole-object source SHA-256 does not by itself prove the integrity of an arbitrary ' +
  'partial read. Partial reads must carry their own verified covering chunk range, ' +
  'returned-range byte hash, and Merkle root.';

export const PartialReadIntegritySchema = z
  .object({
    requestedRange: RequestedRangeSchema,
    verifiedCoveringChunkRange: CoveringChunkRangeSchema,
    returnedRange: ReturnedRangeSchema,
    merkleRoot: Sha256HexSchema,
    returnedByteSha256: Sha256HexSchema,
    sourceSha256: Sha256HexSchema,
    contentTrust: z.literal('untrusted'),
  })
  .strict();
export type PartialReadIntegrity = z.infer<typeof PartialReadIntegritySchema>;

// ---------------------------------------------------------------------------
// Operation output schemas
// ---------------------------------------------------------------------------

const ArtifactStatSuccessSchema = z
  .object({
    ok: z.literal(true),
    artifact: SourceIntegrityMetadataSchema,
  })
  .strict();

export const ArtifactStatOutputSchema = z
  .union([ArtifactStatSuccessSchema, ArtifactInspectionErrorOutputSchema])
  .refine(
    withinArtifactInspectionResponseByteLimit,
    `Response must not exceed ${MAX_ARTIFACT_RESPONSE_BYTES} UTF-8 bytes.`,
  );
export type ArtifactStatOutput = z.infer<typeof ArtifactStatOutputSchema>;

const ArtifactReadRangeSuccessSchema = z
  .object({
    ok: z.literal(true),
    data: z.string(),
    contentTrust: z.literal('untrusted'),
    integrity: PartialReadIntegritySchema,
  })
  .strict();

export const ArtifactReadRangeOutputSchema = z
  .union([ArtifactReadRangeSuccessSchema, ArtifactInspectionErrorOutputSchema])
  .refine(
    withinArtifactInspectionResponseByteLimit,
    `Response must not exceed ${MAX_ARTIFACT_RESPONSE_BYTES} UTF-8 bytes.`,
  );
export type ArtifactReadRangeOutput = z.infer<typeof ArtifactReadRangeOutputSchema>;

const ArtifactReadLinesSuccessSchema = z
  .object({
    ok: z.literal(true),
    data: z.string(),
    returnedLineCount: z.number().int().min(0).max(MAX_LINE_COUNT),
    contentTrust: z.literal('untrusted'),
    integrity: PartialReadIntegritySchema,
  })
  .strict();

export const ArtifactReadLinesOutputSchema = z
  .union([ArtifactReadLinesSuccessSchema, ArtifactInspectionErrorOutputSchema])
  .refine(
    withinArtifactInspectionResponseByteLimit,
    `Response must not exceed ${MAX_ARTIFACT_RESPONSE_BYTES} UTF-8 bytes.`,
  );
export type ArtifactReadLinesOutput = z.infer<typeof ArtifactReadLinesOutputSchema>;

const ArtifactReadHeadingSuccessSchema = z
  .object({
    ok: z.literal(true),
    headingId: HeadingIdSchema,
    data: z.string(),
    contentTrust: z.literal('untrusted'),
    integrity: PartialReadIntegritySchema,
  })
  .strict();

export const ArtifactReadHeadingOutputSchema = z
  .union([ArtifactReadHeadingSuccessSchema, ArtifactInspectionErrorOutputSchema])
  .refine(
    withinArtifactInspectionResponseByteLimit,
    `Response must not exceed ${MAX_ARTIFACT_RESPONSE_BYTES} UTF-8 bytes.`,
  );
export type ArtifactReadHeadingOutput = z.infer<typeof ArtifactReadHeadingOutputSchema>;

const ArtifactSearchHitSchema = z
  .object({
    byteOffset: z.number().int().min(0),
    length: z.number().int().min(1).max(MAX_RANGE_BYTES),
    lineNumber: z.number().int().min(1).max(MAX_START_LINE),
    snippet: z.string().max(MAX_SEARCH_SNIPPET_LENGTH),
    contentTrust: z.literal('untrusted'),
  })
  .strict();
export type ArtifactSearchHit = z.infer<typeof ArtifactSearchHitSchema>;

const ArtifactSearchExactSuccessSchema = z
  .object({
    ok: z.literal(true),
    hits: z.array(ArtifactSearchHitSchema).max(MAX_SEARCH_HITS),
    integrity: PartialReadIntegritySchema,
  })
  .strict();

export const ArtifactSearchExactOutputSchema = z
  .union([ArtifactSearchExactSuccessSchema, ArtifactInspectionErrorOutputSchema])
  .refine(
    withinArtifactInspectionResponseByteLimit,
    `Response must not exceed ${MAX_ARTIFACT_RESPONSE_BYTES} UTF-8 bytes.`,
  );
export type ArtifactSearchExactOutput = z.infer<typeof ArtifactSearchExactOutputSchema>;

// ---------------------------------------------------------------------------
// Inspection receipt
//
// A receipt is evidence of what occurred. It is not bearer authorization and
// must never be accepted as a substitute for current policy evaluation.
// ---------------------------------------------------------------------------

export const ARTIFACT_INSPECTION_RECEIPT_IS_NOT_AUTHORIZATION: string =
  'An inspection receipt is evidence of what occurred; it is not bearer authorization and ' +
  'must not be accepted as a substitute for current policy evaluation.';

export const ARTIFACT_INSPECTION_RECEIPT_SCHEMA_VERSION =
  'artifact-inspection-receipt/0.1' as const;

const SourceIdentitySchema = z.discriminatedUnion('kind', [
  z
    .object({
      kind: z.literal('object_version_ref'),
      ref: OpaqueObjectVersionRefSchema,
    })
    .strict(),
  z
    .object({
      kind: z.literal('merkle_root'),
      merkleRoot: Sha256HexSchema,
    })
    .strict(),
]);

const ReceiptResultOrErrorSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('result') }).strict(),
  z
    .object({
      kind: z.literal('error'),
      errorClass: ArtifactInspectionErrorCodeSchema,
    })
    .strict(),
]);

export const ArtifactInspectionReceiptSchema = z
  .object({
    receiptSchemaVersion: z.literal(ARTIFACT_INSPECTION_RECEIPT_SCHEMA_VERSION),
    verifierAudience: AuthorizationIdentifierSchema,
    principalRef: AuthorizationIdentifierSchema,
    inspectorClientRef: AuthorizationIdentifierSchema,
    artifactId: ArtifactIdSchema,
    sourceIdentity: SourceIdentitySchema,
    operation: ArtifactInspectionOperationSchema,
    requestedRange: RequestedRangeSchema.optional(),
    returnedRange: ReturnedRangeSchema.optional(),
    returnedByteHash: Sha256HexSchema,
    policyVersion: BoundedVersionStringSchema,
    analyzerProfileVersion: BoundedVersionStringSchema,
    inspectorDeploymentGitCoordinate: GitCommitCoordinateSchema,
    recordedAt: z.iso.datetime({ offset: true }),
    resultOrErrorClass: ReceiptResultOrErrorSchema,
  })
  .strict();
export type ArtifactInspectionReceipt = z.infer<typeof ArtifactInspectionReceiptSchema>;

// ---------------------------------------------------------------------------
// Deterministic analyzer-profile and derivation contracts
//
// Semantic analysis is a separate, disabled, worker-only authority class in
// S0. Edge (and this MCP capability surface) remains deterministic-only.
// ---------------------------------------------------------------------------

export const SEMANTIC_ANALYSIS_POLICY = Object.freeze({
  enabled: false as const,
  executionClass: 'local_worker_only' as const,
  note:
    'Semantic analysis is disabled in S0. When enabled in a later prompt it is worker-only; ' +
    'Edge inspection and this MCP capability surface remain deterministic.',
});

export const EDGE_EXECUTION_CLASS = 'deterministic_edge_inline' as const;

/** Deterministic derivation types only. `semantic_summary` and other
 * model-derived types are intentionally excluded from S0's contract. */
export const S0_DETERMINISTIC_DERIVATION_TYPES = Object.freeze([
  'text_extraction',
  'structure_index',
  'chunk_map',
] as const);
export type S0DeterministicDerivationType = (typeof S0_DETERMINISTIC_DERIVATION_TYPES)[number];
export const DerivationTypeSchema = z.enum(S0_DETERMINISTIC_DERIVATION_TYPES);

export const ArtifactDerivationRefSchema = z
  .object({
    derivationId: OpaqueDerivationIdSchema,
    derivedArtifactId: ArtifactIdSchema,
    derivationType: DerivationTypeSchema,
    profileId: AnalyzerProfileIdSchema,
    profileVersion: BoundedVersionStringSchema,
    scope: z.string().trim().min(1).max(128),
    createdAt: z.iso.datetime({ offset: true }),
  })
  .strict();
export type ArtifactDerivationRef = z.infer<typeof ArtifactDerivationRefSchema>;

/** Every derivation input binds the exact source SHA used, per
 * `derivation_inputs.source_sha256` in the S1 migration. */
export const ArtifactDerivationInputRefSchema = z
  .object({
    derivationId: OpaqueDerivationIdSchema,
    sourceArtifactId: ArtifactIdSchema,
    sourceSha256: Sha256HexSchema,
  })
  .strict();
export type ArtifactDerivationInputRef = z.infer<typeof ArtifactDerivationInputRefSchema>;

/** Many-sources -> one-derivation, matching S1's `derivation_inputs` table. */
export const ArtifactDerivationWithInputsSchema = z
  .object({
    derivation: ArtifactDerivationRefSchema,
    inputs: z
      .array(ArtifactDerivationInputRefSchema)
      .min(1)
      .max(MAX_DERIVATION_INPUTS_PER_DERIVATION),
  })
  .strict()
  .refine(
    (value) => value.inputs.every((input) => input.derivationId === value.derivation.derivationId),
    'Every derivation input must reference its own derivation.',
  );
export type ArtifactDerivationWithInputs = z.infer<typeof ArtifactDerivationWithInputsSchema>;

// ---------------------------------------------------------------------------
// Frozen tool descriptors
//
// A capability descriptor is scheduling/interface metadata; it does not
// itself grant access. Current policy evaluation is required for every call
// regardless of descriptor shape.
// ---------------------------------------------------------------------------

export const ARTIFACT_INSPECTION_DESCRIPTOR_IS_NOT_PERMISSION: string =
  'A tool descriptor states scheduling and interface metadata; it does not itself grant ' +
  'access. Current policy evaluation is required for every call regardless of descriptor ' +
  'shape.';

const ARTIFACT_INSPECTION_BEHAVIOR = Object.freeze({
  retry: Object.freeze({ maxAttempts: 1, policy: 'none' as const }),
  idempotency: 'idempotent' as const,
  concurrency: 'parallel_safe' as const,
  approval: 'not_required' as const,
  authorizationRequired: true as const,
  contentTrust: 'untrusted' as const,
  audit: 'artifact_inspection_access' as const,
  errorMapping: Object.freeze({
    validation: 'INVALID_REQUEST' as const,
    unavailable: 'RESOURCE_UNAVAILABLE' as const,
    unsupported: 'UNSUPPORTED' as const,
    responseLimit: 'RESPONSE_LIMIT_EXCEEDED' as const,
    integrityFailure: 'INTEGRITY_FAILURE' as const,
    timeout: 'DEADLINE_EXCEEDED' as const,
    unexpected: 'INTERNAL_ERROR' as const,
  }),
});

const ARTIFACT_INSPECTION_SHARED_LIMITS = Object.freeze({
  maxResponseBytes: MAX_ARTIFACT_RESPONSE_BYTES,
  maxResponseBytesUnit: 'utf8_response_envelope' as const,
  maxExecutionMs: MAX_ARTIFACT_TOOL_EXECUTION_MS,
});

export const ARTIFACT_STAT_TOOL = Object.freeze({
  name: 'artifact_stat' as const,
  capability: 'artifact:inspect' as const,
  operation: 'artifact_stat_v1' as const,
  inputSchema: ArtifactStatInputSchema,
  outputSchema: ArtifactStatOutputSchema,
  ...ARTIFACT_INSPECTION_BEHAVIOR,
  limits: Object.freeze({
    maxArtifactIdLength: MAX_ARTIFACT_ID_LENGTH,
    ...ARTIFACT_INSPECTION_SHARED_LIMITS,
  }),
});

export const ARTIFACT_READ_RANGE_TOOL = Object.freeze({
  name: 'artifact_read_range' as const,
  capability: 'artifact:inspect' as const,
  operation: 'artifact_read_range_v1' as const,
  inputSchema: ArtifactReadRangeInputSchema,
  outputSchema: ArtifactReadRangeOutputSchema,
  ...ARTIFACT_INSPECTION_BEHAVIOR,
  limits: Object.freeze({
    maxArtifactIdLength: MAX_ARTIFACT_ID_LENGTH,
    maxRangeBytes: MAX_RANGE_BYTES,
    maxByteOffset: MAX_ARTIFACT_BYTE_OFFSET,
    ...ARTIFACT_INSPECTION_SHARED_LIMITS,
  }),
});

export const ARTIFACT_READ_LINES_TOOL = Object.freeze({
  name: 'artifact_read_lines' as const,
  capability: 'artifact:inspect' as const,
  operation: 'artifact_read_lines_v1' as const,
  inputSchema: ArtifactReadLinesInputSchema,
  outputSchema: ArtifactReadLinesOutputSchema,
  ...ARTIFACT_INSPECTION_BEHAVIOR,
  limits: Object.freeze({
    maxArtifactIdLength: MAX_ARTIFACT_ID_LENGTH,
    maxLineCount: MAX_LINE_COUNT,
    maxStartLine: MAX_START_LINE,
    ...ARTIFACT_INSPECTION_SHARED_LIMITS,
  }),
});

export const ARTIFACT_READ_HEADING_TOOL = Object.freeze({
  name: 'artifact_read_heading' as const,
  capability: 'artifact:inspect' as const,
  operation: 'artifact_read_heading_v1' as const,
  inputSchema: ArtifactReadHeadingInputSchema,
  outputSchema: ArtifactReadHeadingOutputSchema,
  ...ARTIFACT_INSPECTION_BEHAVIOR,
  limits: Object.freeze({
    maxArtifactIdLength: MAX_ARTIFACT_ID_LENGTH,
    maxHeadingIdLength: MAX_HEADING_ID_LENGTH,
    ...ARTIFACT_INSPECTION_SHARED_LIMITS,
  }),
});

export const ARTIFACT_SEARCH_EXACT_TOOL = Object.freeze({
  name: 'artifact_search_exact' as const,
  capability: 'artifact:inspect' as const,
  operation: 'artifact_search_exact_v1' as const,
  inputSchema: ArtifactSearchExactInputSchema,
  outputSchema: ArtifactSearchExactOutputSchema,
  ...ARTIFACT_INSPECTION_BEHAVIOR,
  limits: Object.freeze({
    maxArtifactIdLength: MAX_ARTIFACT_ID_LENGTH,
    maxQueryLength: MAX_SEARCH_QUERY_LENGTH,
    maxHits: MAX_SEARCH_HITS,
    ...ARTIFACT_INSPECTION_SHARED_LIMITS,
  }),
});

export const ARTIFACT_INSPECTION_TOOLS = Object.freeze([
  ARTIFACT_STAT_TOOL,
  ARTIFACT_READ_RANGE_TOOL,
  ARTIFACT_READ_LINES_TOOL,
  ARTIFACT_READ_HEADING_TOOL,
  ARTIFACT_SEARCH_EXACT_TOOL,
] as const);
