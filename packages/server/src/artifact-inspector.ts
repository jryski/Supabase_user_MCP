import { createHash } from 'node:crypto';

import {
  ARTIFACT_INSPECTION_RECEIPT_SCHEMA_VERSION,
  type ArtifactInspectionErrorCode,
  type ArtifactInspectionOperation,
  type ArtifactInspectionReceipt,
  ArtifactInspectionReceiptSchema,
  ArtifactReadLinesInputSchema,
  type ArtifactReadLinesOutput,
  ArtifactReadLinesOutputSchema,
  ArtifactReadRangeInputSchema,
  type ArtifactReadRangeOutput,
  ArtifactReadRangeOutputSchema,
  ArtifactStatInputSchema,
  type ArtifactStatOutput,
  ArtifactStatOutputSchema,
  AuthorizationIdentifierSchema,
  artifactInspectionResponseByteLength,
  createArtifactInspectionError,
  isArtifactExpired,
  MAX_ARTIFACT_RESPONSE_BYTES,
  MAX_INLINE_CHUNK_HASHES,
  MAX_RANGE_BYTES,
  MAX_VERIFIED_CHUNKS_PER_READ,
  publicArtifactInspectionUnavailable,
} from '@supabase-user-mcp/contracts';
import * as z from 'zod/v4';

import {
  ALLOWED_CHUNK_SIZES,
  type AllowedChunkSize,
  ARTIFACT_CHUNK_MERKLE_PROFILE_VERSION,
  type ArtifactChunkManifest,
  type ArtifactChunkManifestEntry,
  ArtifactChunkManifestError,
  type ArtifactChunkProof,
  buildArtifactChunkProof,
  EMPTY_ARTIFACT_MERKLE_ROOT,
  verifyArtifactChunkProof,
  verifyArtifactSourceManifest,
} from './artifact-chunk-manifest.js';

/**
 * Issue #34 S2: one fixed, synthetic/local, read-only artifact inspector
 * candidate.
 *
 * This module is a pure TypeScript implementation seam. It performs no
 * network, filesystem, Storage, database, or Edge access itself -- every
 * byte and every registry fact it uses comes through the two injected
 * dependencies (`resolveAuthorizedArtifact`, `readVersionedRange`) plus a
 * deterministic clock (`now`). It registers no MCP tool and deploys
 * nothing; see `docs/evidence/ISSUE_34_S2_FIXED_INSPECTOR.md` for the
 * complete claim-limits statement.
 *
 * Trusted context (`ArtifactInspectorTrustedContext`) is supplied by the
 * trusted server layer, never derived from tool input. The three operation
 * entry points (`artifactStat`, `artifactReadRange`, `artifactReadLines`)
 * each accept that context and the raw (untrusted) tool input as separate
 * parameters; unknown input fields and any caller-selected
 * principal/client/capability value are rejected by the accepted S0 input
 * schema before any dependency is called.
 *
 * Authorization is never derived from artifact content or caller input:
 * the injected `resolveAuthorizedArtifact` dependency stands in for the
 * current principal/client/RLS boundary, and every one of missing artifact,
 * wrong principal, wrong client, missing capability, expired artifact, and
 * "object version no longer available" collapses to the exact same frozen
 * `RESOURCE_UNAVAILABLE` output -- byte-identical, non-enumerating, and
 * never backed by an S0 inspection receipt (a receipt is only ever emitted
 * once a real, authorized registry record exists).
 */

// ---------------------------------------------------------------------------
// Local shape helpers -- narrow patterns this module needs but that are not
// exported by `@supabase-user-mcp/contracts` (they are private constants
// inside the S0 module). These duplicate only trivial regexes, never a
// second response-budget or hashing implementation -- the wire-ceiling
// check below reuses `artifactInspectionResponseByteLength` verbatim.
// ---------------------------------------------------------------------------

const GIT_COMMIT_COORDINATE_PATTERN = /^[0-9a-f]{40}$/;
const BOUNDED_VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const HEX64_PATTERN = /^[0-9a-f]{64}$/;

/** This module's own fixed deterministic-profile identity, bound into every
 * receipt's `analyzerProfileVersion`. S2 performs no semantic analysis and
 * defines no per-media-type analyzer version of its own. */
export const ARTIFACT_INSPECTOR_PROFILE_VERSION = 'artifact-inspector-s2-0.1' as const;

/** Fixed inspector deployment/execution ceilings, kept local because they
 * are S2-specific (not part of the S0 contract's own exported ceilings). */
export const MAX_COVERING_FETCH_BYTES = 16_384;
export const MAX_LINE_SOURCE_SCAN_BYTES = 262_144;

const SUPPORTED_LINE_MEDIA_TYPES = Object.freeze(['text/plain', 'text/markdown'] as const);
type SupportedLineMediaType = (typeof SUPPORTED_LINE_MEDIA_TYPES)[number];

function isSupportedLineMediaType(mediaType: string): mediaType is SupportedLineMediaType {
  return (SUPPORTED_LINE_MEDIA_TYPES as readonly string[]).includes(mediaType);
}

const EMPTY_BYTES_SHA256_HEX = createHash('sha256').update(Buffer.alloc(0)).digest('hex');

/** Narrows an in-bounds array-index read (under `noUncheckedIndexedAccess`)
 * without a non-null assertion, mirroring the pattern already used across
 * this repository's contracts and S1b modules. */
function definedAt<T>(value: T | undefined): T {
  if (value === undefined) {
    throw new Error('Expected a defined value at a proven in-bounds array index.');
  }
  return value;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && (typeof value === 'object' || typeof value === 'function')) {
    if (!Object.isFrozen(value)) {
      Object.freeze(value);
      for (const key of Object.getOwnPropertyNames(value)) {
        deepFreeze((value as Record<string, unknown>)[key]);
      }
    }
  }
  return value;
}

// ---------------------------------------------------------------------------
// Trusted request context
//
// Supplied by the trusted server layer only. Never accept this shape, or
// any of its individual fields, from tool input.
// ---------------------------------------------------------------------------

export const ArtifactInspectorTrustedContextSchema = z
  .object({
    principalRef: AuthorizationIdentifierSchema,
    inspectorClientRef: AuthorizationIdentifierSchema,
    inspectorCapabilityRef: z.literal('artifact:inspect'),
    verifierAudience: AuthorizationIdentifierSchema,
    policyVersion: z.string().min(1).max(64).regex(BOUNDED_VERSION_PATTERN),
    inspectorDeploymentGitCoordinate: z.string().regex(GIT_COMMIT_COORDINATE_PATTERN),
    requestCorrelationId: AuthorizationIdentifierSchema.optional(),
  })
  .strict();
export type ArtifactInspectorTrustedContext = z.infer<typeof ArtifactInspectorTrustedContextSchema>;

/** Validates and freezes a trusted context. Intended to be called once by
 * the trusted server layer per request, never from a tool-input path. */
export function createArtifactInspectorTrustedContext(
  input: unknown,
): ArtifactInspectorTrustedContext {
  const parsed = ArtifactInspectorTrustedContextSchema.parse(input);
  return Object.freeze({ ...parsed });
}

// ---------------------------------------------------------------------------
// Injected dependencies
// ---------------------------------------------------------------------------

/**
 * One authorized, immutable registry record for one artifact. `internalLocator`
 * is trusted adapter data (a bucket/path/handle/whatever the real adapter
 * needs) and MUST NEVER be echoed into public output, a receipt, an
 * operational event, or a thrown error -- it is typed `unknown` here and this
 * module never serializes it.
 */
export interface AuthorizedArtifactRecord {
  readonly artifactId: string;
  readonly internalLocator: unknown;
  readonly objectVersionRef: string;
  readonly sourceSha256: string;
  readonly byteLength: number;
  readonly chunkSize: AllowedChunkSize;
  readonly chunkCount: number;
  /** Ordered raw chunk hashes: `chunkSha256s[i] === SHA256(chunk i bytes)`. */
  readonly chunkSha256s: readonly string[];
  /** Ordered Merkle leaf hashes: `merkleLeafSha256s[i] === SHA256(0x00 || chunk i bytes)`. */
  readonly merkleLeafSha256s: readonly string[];
  readonly merkleRoot: string;
  readonly mediaType: string;
  readonly createdAt: string;
  readonly expiresAt?: string;
  /** Opaque reference used when `chunkCount` exceeds the S0 inline ceiling. */
  readonly chunkHashesRef?: string;
}

export interface ReadVersionedRangeResult {
  readonly bytes: Uint8Array;
  readonly objectVersionRef: string;
}

export interface ArtifactInspectorOperationalEvent {
  readonly operation: ArtifactInspectionOperation;
  readonly resultClass: 'success' | ArtifactInspectionErrorCode;
  readonly requestCorrelationId?: string;
  readonly elapsedMs: number;
  readonly byteCounts?: {
    readonly requested?: number;
    readonly covering?: number;
    readonly returned?: number;
  };
}

/**
 * The narrow seam between this pure library and the real, trusted
 * principal/client/RLS boundary and byte-custody adapter. The inspector
 * never constructs a Supabase client, performs a fetch, or knows a Storage
 * URL -- every fact about the world arrives through these three
 * dependencies plus the two optional redacted observers.
 */
export interface ArtifactInspectorDependencies {
  /** Stands in for the current principal/client/RLS boundary. Returns
   * `null` for a missing artifact, a wrong principal, a wrong client, or a
   * missing capability -- the inspector treats all of these identically. */
  resolveAuthorizedArtifact(
    context: ArtifactInspectorTrustedContext,
    artifactId: string,
  ): Promise<AuthorizedArtifactRecord | null>;
  /** Reads exactly `length` bytes of the immutable object version starting
   * at `offset`, or throws. Must never leak a signed URL, bucket, path,
   * HTTP method, token, or credential in its return value. */
  readVersionedRange(
    context: ArtifactInspectorTrustedContext,
    internalLocator: unknown,
    objectVersionRef: string,
    offset: number,
    length: number,
  ): Promise<ReadVersionedRangeResult>;
  /** Deterministic clock, injected for reproducible expiry tests. */
  now(): Date;
  /** Redacted operational telemetry. Never receives an artifact ID, an
   * internal locator, content, a token, a path, query text, or source
   * bytes -- see `ArtifactInspectorOperationalEvent`. */
  emitOperationalEvent?(event: ArtifactInspectorOperationalEvent): void;
  /** Evidence-only inspection receipt, emitted only after an artifact has
   * been authorized-resolved. Never emitted for a pre-resolution outcome
   * (invalid request or unavailable artifact). */
  emitInspectionReceipt?(receipt: ArtifactInspectionReceipt): void;
}

// ---------------------------------------------------------------------------
// Manifest reconstruction and validation
//
// The registry record's ordered hash arrays are folded into an S1b
// `ArtifactChunkManifest` so every subsequent proof build/verify call runs
// through the existing, independently calibrated S1b module unchanged.
// ---------------------------------------------------------------------------

function buildManifestFromRecord(record: AuthorizedArtifactRecord): ArtifactChunkManifest {
  if (
    record.chunkSha256s.length !== record.chunkCount ||
    record.merkleLeafSha256s.length !== record.chunkCount
  ) {
    throw new ArtifactChunkManifestError(
      'INCONSISTENT_MANIFEST',
      'Registry record chunk hash arrays do not match the declared chunk count.',
    );
  }
  const chunks: ArtifactChunkManifestEntry[] = [];
  for (let i = 0; i < record.chunkCount; i++) {
    const byteStart = i * record.chunkSize;
    const isFinal = i === record.chunkCount - 1;
    const byteLength = isFinal ? record.byteLength - byteStart : record.chunkSize;
    chunks.push(
      Object.freeze({
        chunkIndex: i,
        byteStart,
        byteLength,
        chunkSha256: definedAt(record.chunkSha256s[i]),
        merkleLeafSha256: definedAt(record.merkleLeafSha256s[i]),
      }),
    );
  }
  return Object.freeze({
    profileVersion: ARTIFACT_CHUNK_MERKLE_PROFILE_VERSION,
    sourceSha256: record.sourceSha256,
    byteLength: record.byteLength,
    chunkSize: record.chunkSize,
    chunkCount: record.chunkCount,
    chunks: Object.freeze(chunks),
    merkleRoot: record.merkleRoot,
  });
}

/**
 * Validates full S1b manifest consistency, including the leaf-hashes-close-
 * to-root check. For a nonempty manifest this is delegated entirely to
 * `buildArtifactChunkProof` (chunk index 0), which runs the exact same
 * `assertManifestConsistent` closure the S1b calibration suite already
 * exercises -- the resulting proof is discarded, only the validation
 * side-effect (throwing on inconsistency) is used. `buildArtifactChunkProof`
 * rejects chunk index 0 as out of range for a zero-chunk manifest even when
 * the manifest itself is perfectly consistent, so the empty case is
 * validated directly here instead.
 */
function validateManifestConsistency(manifest: ArtifactChunkManifest): void {
  if (manifest.chunkCount > 0) {
    buildArtifactChunkProof(manifest, 0);
    return;
  }
  if (manifest.byteLength !== 0 || manifest.chunks.length !== 0) {
    throw new ArtifactChunkManifestError(
      'INCONSISTENT_MANIFEST',
      'A zero-chunk manifest must declare zero bytes and zero chunks.',
    );
  }
  if (manifest.merkleRoot !== EMPTY_ARTIFACT_MERKLE_ROOT) {
    throw new ArtifactChunkManifestError(
      'INCONSISTENT_MANIFEST',
      'A zero-chunk manifest must declare the canonical empty Merkle root.',
    );
  }
  if (!HEX64_PATTERN.test(manifest.sourceSha256)) {
    throw new ArtifactChunkManifestError(
      'MALFORMED_DIGEST',
      'Manifest sourceSha256 must be a lowercase 64-hex-character SHA-256 digest.',
    );
  }
}

type ResolveOutcome =
  | { readonly kind: 'unavailable' }
  | { readonly kind: 'internal_error'; readonly record: AuthorizedArtifactRecord }
  | {
      readonly kind: 'ok';
      readonly record: AuthorizedArtifactRecord;
      readonly manifest: ArtifactChunkManifest;
    };

async function resolveArtifact(
  dependencies: ArtifactInspectorDependencies,
  context: ArtifactInspectorTrustedContext,
  artifactId: string,
): Promise<ResolveOutcome> {
  const record = await dependencies.resolveAuthorizedArtifact(context, artifactId);
  if (record === null) {
    return { kind: 'unavailable' };
  }
  const nowIso = dependencies.now().toISOString();
  if (isArtifactExpired(record.expiresAt, nowIso)) {
    return { kind: 'unavailable' };
  }
  try {
    const manifest = buildManifestFromRecord(record);
    validateManifestConsistency(manifest);
    return { kind: 'ok', record, manifest };
  } catch (error) {
    if (error instanceof ArtifactChunkManifestError) {
      return { kind: 'internal_error', record };
    }
    throw error;
  }
}

// ---------------------------------------------------------------------------
// Covering-chunk proof construction and verification, shared by
// artifact_read_range and artifact_read_lines.
// ---------------------------------------------------------------------------

interface VerifiedChunkEntry {
  readonly chunkIndex: number;
  readonly byteStart: number;
  readonly byteLength: number;
  readonly chunkSha256: string;
  readonly merkleProof: ReadonlyArray<{
    readonly siblingPosition: 'left' | 'right';
    readonly siblingSha256: string;
  }>;
}

function chunkAt(manifest: ArtifactChunkManifest, index: number): ArtifactChunkManifestEntry {
  return definedAt(manifest.chunks[index]);
}

function buildAndVerifyCoveringChunks(
  manifest: ArtifactChunkManifest,
  startChunkIndex: number,
  endChunkIndex: number,
  chunkBytesFor: (chunkIndex: number) => Uint8Array,
): VerifiedChunkEntry[] | null {
  const verified: VerifiedChunkEntry[] = [];
  for (let i = startChunkIndex; i <= endChunkIndex; i++) {
    let proof: ArtifactChunkProof;
    try {
      proof = buildArtifactChunkProof(manifest, i);
    } catch {
      return null;
    }
    const chunkBytes = chunkBytesFor(i);
    if (!verifyArtifactChunkProof(chunkBytes, proof, manifest.merkleRoot)) {
      return null;
    }
    verified.push({
      chunkIndex: proof.chunkIndex,
      byteStart: proof.byteStart,
      byteLength: proof.byteLength,
      chunkSha256: proof.chunkSha256,
      merkleProof: proof.proof.map((node) => ({
        siblingPosition: node.siblingPosition,
        siblingSha256: node.siblingSha256,
      })),
    });
  }
  return verified;
}

// ---------------------------------------------------------------------------
// Receipts and events
// ---------------------------------------------------------------------------

function analyzerProfileIdFor(mediaType: string): 'text/plain' | 'text/markdown' | 'unsupported' {
  return isSupportedLineMediaType(mediaType) ? mediaType : 'unsupported';
}

function receiptResultOrError(
  errorClass: ArtifactInspectionErrorCode | undefined,
): ArtifactInspectionReceipt['resultOrErrorClass'] {
  return errorClass === undefined ? { kind: 'result' } : { kind: 'error', errorClass };
}

interface ReceiptOptions {
  readonly context: ArtifactInspectorTrustedContext;
  readonly record: AuthorizedArtifactRecord;
  readonly artifactId: string;
  readonly recordedAt: string;
  readonly errorClass?: ArtifactInspectionErrorCode;
}

function buildStatReceipt(options: ReceiptOptions): ArtifactInspectionReceipt {
  return buildReceiptBase(options, { operation: 'artifact_stat' });
}

function buildRangeReceipt(
  options: ReceiptOptions,
  requestedRange: { readonly offset: number; readonly length: number },
  returnedRange: { readonly offset: number; readonly length: number },
  returnedByteSha256: string,
): ArtifactInspectionReceipt {
  return buildReceiptBase(options, {
    operation: 'artifact_read_range',
    requestedRange,
    returnedRange,
    returnedByteSha256,
  });
}

function buildLinesReceipt(
  options: ReceiptOptions,
  requestedLineRange: { readonly startLine: number; readonly count: number },
  returnedRange: { readonly offset: number; readonly length: number },
  returnedByteSha256: string,
): ArtifactInspectionReceipt {
  return buildReceiptBase(options, {
    operation: 'artifact_read_lines',
    requestedLineRange,
    returnedRange,
    returnedByteSha256,
  });
}

function buildReceiptBase(
  options: ReceiptOptions,
  operationDetail: ArtifactInspectionReceipt['operationDetail'],
): ArtifactInspectionReceipt {
  const { context, record, artifactId, recordedAt, errorClass } = options;
  return Object.freeze({
    receiptSchemaVersion: ARTIFACT_INSPECTION_RECEIPT_SCHEMA_VERSION,
    verifierAudience: context.verifierAudience,
    principalRef: context.principalRef,
    principalBinding: 'session_derived' as const,
    inspectorClientRef: context.inspectorClientRef,
    inspectorClientBinding: 'approved' as const,
    inspectorCapabilityRef: Object.freeze({
      capability: 'artifact:inspect' as const,
      ref: context.inspectorClientRef,
    }),
    artifactId,
    objectVersionRef: record.objectVersionRef,
    sourceSha256: record.sourceSha256,
    merkleRoot: record.merkleRoot,
    analyzerProfileId: analyzerProfileIdFor(record.mediaType),
    analyzerProfileVersion: ARTIFACT_INSPECTOR_PROFILE_VERSION,
    policyVersion: context.policyVersion,
    inspectorDeploymentGitCoordinate: context.inspectorDeploymentGitCoordinate,
    recordedAt,
    operationDetail,
    resultOrErrorClass: receiptResultOrError(errorClass),
  });
}

function emitReceiptSafely(
  dependencies: ArtifactInspectorDependencies,
  receipt: ArtifactInspectionReceipt,
): void {
  const validated = ArtifactInspectionReceiptSchema.safeParse(receipt);
  if (!validated.success) {
    // A receipt that fails its own schema must never be emitted; the caller
    // still gets the public error output constructed independently below.
    return;
  }
  try {
    dependencies.emitInspectionReceipt?.(deepFreeze(validated.data));
  } catch {
    // Receipt emission must never affect tool execution.
  }
}

function emitEventSafely(
  dependencies: ArtifactInspectorDependencies,
  event: ArtifactInspectorOperationalEvent,
): void {
  try {
    dependencies.emitOperationalEvent?.(deepFreeze(event));
  } catch {
    // Event emission must never affect tool execution.
  }
}

// ---------------------------------------------------------------------------
// artifact_stat
// ---------------------------------------------------------------------------

export async function artifactStat(
  dependencies: ArtifactInspectorDependencies,
  context: ArtifactInspectorTrustedContext,
  rawInput: unknown,
): Promise<ArtifactStatOutput> {
  const startedAtMs = dependencies.now().getTime();
  const emit = (resultClass: 'success' | ArtifactInspectionErrorCode) => {
    emitEventSafely(dependencies, {
      operation: 'artifact_stat',
      resultClass,
      ...(context.requestCorrelationId === undefined
        ? {}
        : { requestCorrelationId: context.requestCorrelationId }),
      elapsedMs: Math.max(0, dependencies.now().getTime() - startedAtMs),
    });
  };

  const input = ArtifactStatInputSchema.safeParse(rawInput);
  if (!input.success) {
    emit('INVALID_REQUEST');
    return createArtifactInspectionError('INVALID_REQUEST');
  }

  const resolved = await resolveArtifact(dependencies, context, input.data.artifactId);
  if (resolved.kind === 'unavailable') {
    emit('RESOURCE_UNAVAILABLE');
    return publicArtifactInspectionUnavailable('missing');
  }

  const recordedAt = dependencies.now().toISOString();
  const receiptOptions: ReceiptOptions = {
    context,
    record: resolved.record,
    artifactId: input.data.artifactId,
    recordedAt,
  };

  if (resolved.kind === 'internal_error') {
    emitReceiptSafely(
      dependencies,
      buildStatReceipt({ ...receiptOptions, errorClass: 'INTERNAL_ERROR' }),
    );
    emit('INTERNAL_ERROR');
    return createArtifactInspectionError('INTERNAL_ERROR');
  }

  const { record, manifest } = resolved;
  const chunkHashes =
    manifest.chunkCount <= MAX_INLINE_CHUNK_HASHES
      ? { kind: 'inline' as const, hashes: [...record.chunkSha256s] }
      : record.chunkHashesRef === undefined
        ? undefined
        : { kind: 'reference' as const, ref: record.chunkHashesRef };

  if (chunkHashes === undefined) {
    emitReceiptSafely(
      dependencies,
      buildStatReceipt({ ...receiptOptions, errorClass: 'INTERNAL_ERROR' }),
    );
    emit('INTERNAL_ERROR');
    return createArtifactInspectionError('INTERNAL_ERROR');
  }

  const candidate = {
    ok: true as const,
    artifact: {
      artifactId: input.data.artifactId,
      objectVersionRef: record.objectVersionRef,
      sourceSha256: record.sourceSha256,
      byteLength: record.byteLength,
      chunkSize: record.chunkSize,
      chunkCount: record.chunkCount,
      chunkHashes,
      merkleRoot: record.merkleRoot,
      mediaType: record.mediaType,
      analyzerProfileSupport: analyzerProfileIdFor(record.mediaType),
      createdAt: record.createdAt,
      ...(record.expiresAt === undefined ? {} : { expiresAt: record.expiresAt }),
    },
  };

  if (artifactInspectionResponseByteLength(null, candidate) > MAX_ARTIFACT_RESPONSE_BYTES) {
    emitReceiptSafely(
      dependencies,
      buildStatReceipt({ ...receiptOptions, errorClass: 'RESPONSE_LIMIT_EXCEEDED' }),
    );
    emit('RESPONSE_LIMIT_EXCEEDED');
    return createArtifactInspectionError('RESPONSE_LIMIT_EXCEEDED');
  }

  const validated = ArtifactStatOutputSchema.safeParse(candidate);
  if (!validated.success) {
    emitReceiptSafely(
      dependencies,
      buildStatReceipt({ ...receiptOptions, errorClass: 'INTERNAL_ERROR' }),
    );
    emit('INTERNAL_ERROR');
    return createArtifactInspectionError('INTERNAL_ERROR');
  }

  emitReceiptSafely(dependencies, buildStatReceipt(receiptOptions));
  emit('success');
  return deepFreeze(validated.data);
}

// ---------------------------------------------------------------------------
// artifact_read_range
// ---------------------------------------------------------------------------

export async function artifactReadRange(
  dependencies: ArtifactInspectorDependencies,
  context: ArtifactInspectorTrustedContext,
  rawInput: unknown,
): Promise<ArtifactReadRangeOutput> {
  const startedAtMs = dependencies.now().getTime();
  const emit = (
    resultClass: 'success' | ArtifactInspectionErrorCode,
    byteCounts?: ArtifactInspectorOperationalEvent['byteCounts'],
  ) => {
    emitEventSafely(dependencies, {
      operation: 'artifact_read_range',
      resultClass,
      ...(context.requestCorrelationId === undefined
        ? {}
        : { requestCorrelationId: context.requestCorrelationId }),
      elapsedMs: Math.max(0, dependencies.now().getTime() - startedAtMs),
      ...(byteCounts === undefined ? {} : { byteCounts }),
    });
  };

  const input = ArtifactReadRangeInputSchema.safeParse(rawInput);
  if (!input.success) {
    emit('INVALID_REQUEST');
    return createArtifactInspectionError('INVALID_REQUEST');
  }
  const { artifactId, offset, length } = input.data;

  const resolved = await resolveArtifact(dependencies, context, artifactId);
  if (resolved.kind === 'unavailable') {
    emit('RESOURCE_UNAVAILABLE', { requested: length });
    return publicArtifactInspectionUnavailable('missing');
  }

  const receiptOptions: ReceiptOptions = {
    context,
    record: resolved.record,
    artifactId,
    recordedAt: dependencies.now().toISOString(),
  };
  const placeholderReturnedRange = { offset: 0, length: 0 };

  const failClosed = (errorClass: ArtifactInspectionErrorCode) => {
    emitReceiptSafely(
      dependencies,
      buildRangeReceipt(
        { ...receiptOptions, errorClass },
        { offset, length },
        placeholderReturnedRange,
        EMPTY_BYTES_SHA256_HEX,
      ),
    );
    emit(errorClass, { requested: length });
    return createArtifactInspectionError(errorClass);
  };

  if (resolved.kind === 'internal_error') {
    return failClosed('INTERNAL_ERROR');
  }

  const { record, manifest } = resolved;

  if (offset >= record.byteLength || offset + length > record.byteLength) {
    return failClosed('INTEGRITY_FAILURE');
  }

  const startChunkIndex = Math.floor(offset / record.chunkSize);
  const endChunkIndex = Math.floor((offset + length - 1) / record.chunkSize);
  const coveringOffset = startChunkIndex * record.chunkSize;
  const coveringEnd = Math.min((endChunkIndex + 1) * record.chunkSize, record.byteLength);
  const coveringLength = coveringEnd - coveringOffset;

  if (coveringLength > MAX_COVERING_FETCH_BYTES) {
    return failClosed('RESPONSE_LIMIT_EXCEEDED');
  }

  let readResult: ReadVersionedRangeResult;
  try {
    readResult = await dependencies.readVersionedRange(
      context,
      record.internalLocator,
      record.objectVersionRef,
      coveringOffset,
      coveringLength,
    );
  } catch {
    return failClosed('INTERNAL_ERROR');
  }

  if (readResult.objectVersionRef !== record.objectVersionRef) {
    return failClosed('INTEGRITY_FAILURE');
  }
  if (readResult.bytes.byteLength !== coveringLength) {
    return failClosed('INTEGRITY_FAILURE');
  }

  const coveringBuffer = readResult.bytes;
  const verifiedChunks = buildAndVerifyCoveringChunks(
    manifest,
    startChunkIndex,
    endChunkIndex,
    (chunkIndex) => {
      const chunk = chunkAt(manifest, chunkIndex);
      const start = chunk.byteStart - coveringOffset;
      return coveringBuffer.subarray(start, start + chunk.byteLength);
    },
  );
  if (verifiedChunks === null) {
    return failClosed('INTEGRITY_FAILURE');
  }
  if (verifiedChunks.length > MAX_VERIFIED_CHUNKS_PER_READ) {
    return failClosed('RESPONSE_LIMIT_EXCEEDED');
  }

  const requestedStart = offset - coveringOffset;
  const requestedBytes = coveringBuffer.subarray(requestedStart, requestedStart + length);

  let data: string;
  try {
    data = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(requestedBytes);
  } catch {
    emitReceiptSafely(
      dependencies,
      buildRangeReceipt(
        { ...receiptOptions, errorClass: 'UNSUPPORTED' },
        { offset, length },
        placeholderReturnedRange,
        EMPTY_BYTES_SHA256_HEX,
      ),
    );
    emit('UNSUPPORTED', { requested: length, covering: coveringLength });
    return createArtifactInspectionError('UNSUPPORTED');
  }

  const returnedByteSha256 = createHash('sha256').update(Buffer.from(requestedBytes)).digest('hex');
  const returnedRange = { offset, length };

  const candidate = {
    ok: true as const,
    data,
    contentTrust: 'untrusted' as const,
    integrity: {
      requestedRange: { kind: 'byte_range' as const, offset, length },
      verifiedCoveringChunkRange: { startChunkIndex, endChunkIndex },
      returnedRange,
      chunkSize: record.chunkSize,
      chunkCount: record.chunkCount,
      verifiedChunks,
      merkleRoot: record.merkleRoot,
      returnedByteSha256,
      sourceSha256: record.sourceSha256,
      contentTrust: 'untrusted' as const,
    },
  };

  if (artifactInspectionResponseByteLength(null, candidate) > MAX_ARTIFACT_RESPONSE_BYTES) {
    emitReceiptSafely(
      dependencies,
      buildRangeReceipt(
        { ...receiptOptions, errorClass: 'RESPONSE_LIMIT_EXCEEDED' },
        { offset, length },
        placeholderReturnedRange,
        EMPTY_BYTES_SHA256_HEX,
      ),
    );
    emit('RESPONSE_LIMIT_EXCEEDED', { requested: length, covering: coveringLength });
    return createArtifactInspectionError('RESPONSE_LIMIT_EXCEEDED');
  }

  const validated = ArtifactReadRangeOutputSchema.safeParse(candidate);
  if (!validated.success) {
    return failClosed('INTERNAL_ERROR');
  }

  emitReceiptSafely(
    dependencies,
    buildRangeReceipt(receiptOptions, { offset, length }, returnedRange, returnedByteSha256),
  );
  emit('success', { requested: length, covering: coveringLength, returned: length });
  return deepFreeze(validated.data);
}

// ---------------------------------------------------------------------------
// artifact_read_lines
// ---------------------------------------------------------------------------

function splitPreservingNewlines(text: string): string[] {
  if (text.length === 0) return [];
  return text.split(/(?<=\n)/);
}

export async function artifactReadLines(
  dependencies: ArtifactInspectorDependencies,
  context: ArtifactInspectorTrustedContext,
  rawInput: unknown,
): Promise<ArtifactReadLinesOutput> {
  const startedAtMs = dependencies.now().getTime();
  const emit = (
    resultClass: 'success' | ArtifactInspectionErrorCode,
    byteCounts?: ArtifactInspectorOperationalEvent['byteCounts'],
  ) => {
    emitEventSafely(dependencies, {
      operation: 'artifact_read_lines',
      resultClass,
      ...(context.requestCorrelationId === undefined
        ? {}
        : { requestCorrelationId: context.requestCorrelationId }),
      elapsedMs: Math.max(0, dependencies.now().getTime() - startedAtMs),
      ...(byteCounts === undefined ? {} : { byteCounts }),
    });
  };

  const input = ArtifactReadLinesInputSchema.safeParse(rawInput);
  if (!input.success) {
    emit('INVALID_REQUEST');
    return createArtifactInspectionError('INVALID_REQUEST');
  }
  const { artifactId, startLine, count } = input.data;

  const resolved = await resolveArtifact(dependencies, context, artifactId);
  if (resolved.kind === 'unavailable') {
    emit('RESOURCE_UNAVAILABLE');
    return publicArtifactInspectionUnavailable('missing');
  }

  const receiptOptions: ReceiptOptions = {
    context,
    record: resolved.record,
    artifactId,
    recordedAt: dependencies.now().toISOString(),
  };
  const placeholderReturnedRange = { offset: 0, length: 0 };

  const failClosed = (errorClass: ArtifactInspectionErrorCode) => {
    emitReceiptSafely(
      dependencies,
      buildLinesReceipt(
        { ...receiptOptions, errorClass },
        { startLine, count },
        placeholderReturnedRange,
        EMPTY_BYTES_SHA256_HEX,
      ),
    );
    emit(errorClass);
    return createArtifactInspectionError(errorClass);
  };

  if (resolved.kind === 'internal_error') {
    return failClosed('INTERNAL_ERROR');
  }

  const { record, manifest } = resolved;

  if (!isSupportedLineMediaType(record.mediaType)) {
    return failClosed('UNSUPPORTED');
  }

  if (record.byteLength > MAX_LINE_SOURCE_SCAN_BYTES) {
    return failClosed('RESPONSE_LIMIT_EXCEEDED');
  }

  let readResult: ReadVersionedRangeResult;
  try {
    readResult = await dependencies.readVersionedRange(
      context,
      record.internalLocator,
      record.objectVersionRef,
      0,
      record.byteLength,
    );
  } catch {
    return failClosed('INTERNAL_ERROR');
  }

  if (readResult.objectVersionRef !== record.objectVersionRef) {
    return failClosed('INTEGRITY_FAILURE');
  }
  if (readResult.bytes.byteLength !== record.byteLength) {
    return failClosed('INTEGRITY_FAILURE');
  }

  if (!verifyArtifactSourceManifest(readResult.bytes, manifest)) {
    return failClosed('INTEGRITY_FAILURE');
  }

  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(readResult.bytes);
  } catch {
    return failClosed('INTEGRITY_FAILURE');
  }

  const lines = splitPreservingNewlines(text);
  const startIndex = startLine - 1;

  if (startIndex >= lines.length) {
    if (manifest.chunkCount === 0) {
      // No content and no chunk exists to anchor a schema-valid successful
      // empty result against -- the fixed non-enumerating/invalid-request
      // class is used instead. See docs/evidence/ISSUE_34_S2_FIXED_INSPECTOR.md.
      return failClosed('INVALID_REQUEST');
    }

    const lastChunkIndex = manifest.chunkCount - 1;
    const verifiedChunks = buildAndVerifyCoveringChunks(
      manifest,
      lastChunkIndex,
      lastChunkIndex,
      (chunkIndex) => {
        const chunk = chunkAt(manifest, chunkIndex);
        return readResult.bytes.subarray(chunk.byteStart, chunk.byteStart + chunk.byteLength);
      },
    );
    if (verifiedChunks === null) {
      return failClosed('INTEGRITY_FAILURE');
    }

    const returnedRange = { offset: record.byteLength, length: 0 };
    const candidate = {
      ok: true as const,
      data: '',
      returnedLineCount: 0,
      contentTrust: 'untrusted' as const,
      integrity: {
        requestedRange: { kind: 'line_range' as const, startLine, count },
        verifiedCoveringChunkRange: {
          startChunkIndex: lastChunkIndex,
          endChunkIndex: lastChunkIndex,
        },
        returnedRange,
        chunkSize: record.chunkSize,
        chunkCount: record.chunkCount,
        verifiedChunks,
        merkleRoot: record.merkleRoot,
        returnedByteSha256: EMPTY_BYTES_SHA256_HEX,
        sourceSha256: record.sourceSha256,
        contentTrust: 'untrusted' as const,
      },
    };

    const validated = ArtifactReadLinesOutputSchema.safeParse(candidate);
    if (!validated.success) {
      return failClosed('INTERNAL_ERROR');
    }
    emitReceiptSafely(
      dependencies,
      buildLinesReceipt(
        receiptOptions,
        { startLine, count },
        returnedRange,
        EMPTY_BYTES_SHA256_HEX,
      ),
    );
    emit('success', { returned: 0 });
    return deepFreeze(validated.data);
  }

  const selected = lines.slice(startIndex, startIndex + count);
  const data = selected.join('');
  const prefix = lines.slice(0, startIndex).join('');
  const byteOffset = new TextEncoder().encode(prefix).byteLength;
  const dataByteLength = new TextEncoder().encode(data).byteLength;

  // Unlike artifact_read_range, the selected line span has no per-request
  // caller-supplied byte-length ceiling (only the whole-source scan ceiling
  // above bounds it) -- a long run of newline-free lines could otherwise
  // produce a `returnedRange.length` over the shared S0 `MAX_RANGE_BYTES`
  // ceiling, which the accepted output schema would then reject wholesale.
  // Detect that case explicitly and report it as a resource-limit denial
  // before ever building proofs or touching the schema.
  if (dataByteLength > MAX_RANGE_BYTES) {
    return failClosed('RESPONSE_LIMIT_EXCEEDED');
  }

  const startChunkIndex = Math.floor(byteOffset / record.chunkSize);
  const endChunkIndex = Math.floor((byteOffset + dataByteLength - 1) / record.chunkSize);

  const verifiedChunks = buildAndVerifyCoveringChunks(
    manifest,
    startChunkIndex,
    endChunkIndex,
    (chunkIndex) => {
      const chunk = chunkAt(manifest, chunkIndex);
      return readResult.bytes.subarray(chunk.byteStart, chunk.byteStart + chunk.byteLength);
    },
  );
  if (verifiedChunks === null) {
    return failClosed('INTEGRITY_FAILURE');
  }
  if (verifiedChunks.length > MAX_VERIFIED_CHUNKS_PER_READ) {
    return failClosed('RESPONSE_LIMIT_EXCEEDED');
  }

  const returnedByteSha256 = createHash('sha256')
    .update(Buffer.from(new TextEncoder().encode(data)))
    .digest('hex');
  const returnedRange = { offset: byteOffset, length: dataByteLength };

  const candidate = {
    ok: true as const,
    data,
    returnedLineCount: selected.length,
    contentTrust: 'untrusted' as const,
    integrity: {
      requestedRange: { kind: 'line_range' as const, startLine, count },
      verifiedCoveringChunkRange: { startChunkIndex, endChunkIndex },
      returnedRange,
      chunkSize: record.chunkSize,
      chunkCount: record.chunkCount,
      verifiedChunks,
      merkleRoot: record.merkleRoot,
      returnedByteSha256,
      sourceSha256: record.sourceSha256,
      contentTrust: 'untrusted' as const,
    },
  };

  if (artifactInspectionResponseByteLength(null, candidate) > MAX_ARTIFACT_RESPONSE_BYTES) {
    emitReceiptSafely(
      dependencies,
      buildLinesReceipt(
        { ...receiptOptions, errorClass: 'RESPONSE_LIMIT_EXCEEDED' },
        { startLine, count },
        placeholderReturnedRange,
        EMPTY_BYTES_SHA256_HEX,
      ),
    );
    emit('RESPONSE_LIMIT_EXCEEDED', { returned: dataByteLength });
    return createArtifactInspectionError('RESPONSE_LIMIT_EXCEEDED');
  }

  const validated = ArtifactReadLinesOutputSchema.safeParse(candidate);
  if (!validated.success) {
    return failClosed('INTERNAL_ERROR');
  }

  emitReceiptSafely(
    dependencies,
    buildLinesReceipt(receiptOptions, { startLine, count }, returnedRange, returnedByteSha256),
  );
  emit('success', { returned: dataByteLength });
  return deepFreeze(validated.data);
}

// ---------------------------------------------------------------------------
// Facade
// ---------------------------------------------------------------------------

/**
 * Binds one immutable `dependencies` bundle to the three S2 operations. The
 * returned functions hold no mutable state of their own -- every call
 * receives its own trusted context and its own raw input, so concurrent,
 * independent calls never share mutable state.
 */
export function createArtifactInspector(dependencies: ArtifactInspectorDependencies) {
  return {
    artifactStat: (context: ArtifactInspectorTrustedContext, rawInput: unknown) =>
      artifactStat(dependencies, context, rawInput),
    artifactReadRange: (context: ArtifactInspectorTrustedContext, rawInput: unknown) =>
      artifactReadRange(dependencies, context, rawInput),
    artifactReadLines: (context: ArtifactInspectorTrustedContext, rawInput: unknown) =>
      artifactReadLines(dependencies, context, rawInput),
  };
}
export type ArtifactInspector = ReturnType<typeof createArtifactInspector>;

export { ALLOWED_CHUNK_SIZES };
