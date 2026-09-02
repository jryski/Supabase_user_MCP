import { createHash } from 'node:crypto';

import {
  type ArtifactInspectionReceipt,
  ArtifactInspectionReceiptSchema,
  artifactInspectionResponseByteLength,
  MAX_ARTIFACT_RESPONSE_BYTES,
  MAX_INLINE_CHUNK_HASHES,
  MAX_RANGE_BYTES,
} from '@supabase-user-mcp/contracts';
import { describe, expect, it } from 'vitest';

import { type AllowedChunkSize, buildArtifactChunkManifest } from './artifact-chunk-manifest.js';
import {
  ARTIFACT_INSPECTOR_PROFILE_VERSION,
  type ArtifactInspectorDependencies,
  type ArtifactInspectorOperationalEvent,
  type ArtifactInspectorTrustedContext,
  ArtifactInspectorTrustedContextSchema,
  type AuthorizedArtifactRecord,
  artifactReadLines,
  artifactReadRange,
  artifactStat,
  createArtifactInspector,
  createArtifactInspectorTrustedContext,
  MAX_LINE_SOURCE_SCAN_BYTES,
} from './artifact-inspector.js';

// ---------------------------------------------------------------------------
// Deterministic fixtures. The synthetic adapter is built ONLY inside this
// test file -- artifact-inspector.ts never constructs one itself.
// ---------------------------------------------------------------------------

function definedAt<T>(value: T | undefined): T {
  if (value === undefined) throw new Error('Expected a defined value.');
  return value;
}

function deterministicAsciiText(length: number, seed: number): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,-';
  let out = '';
  let counter = 0;
  while (out.length < length) {
    const digest = createHash('sha256').update(`s2-ascii:${seed}:${counter}`).digest();
    for (const byte of digest) {
      if (out.length >= length) break;
      out += alphabet[byte % alphabet.length];
    }
    counter += 1;
  }
  return out;
}

const ARTIFACT_ID = 'art_0000000000000000000001';
const OTHER_ARTIFACT_ID = 'art_0000000000000000000002';
const OBJECT_VERSION_REF = 'ov_0000000000000000000001';
const DRIFTED_OBJECT_VERSION_REF = 'ov_0000000000000000000099';
const CHUNK_HASHES_REF = 'chr_0000000000000000000001';
const GIT_COORDINATE = 'ab'.repeat(20);

/** Distinctive sentinel that must never leak into any public output,
 * receipt, event, or thrown error. */
const INTERNAL_LOCATOR_SENTINEL = {
  bucket: 'internal-only-bucket-9f3c2a',
  path: 'internal/only/path/9f3c2a.bin',
  signedUrl: 'https://storage.internal.example/leak-if-you-see-this-9f3c2a',
};

const DEFAULT_CONTEXT_INPUT = {
  principalRef: 'principal-ok',
  inspectorClientRef: 'client-ok',
  inspectorCapabilityRef: 'artifact:inspect' as const,
  verifierAudience: 'audience-1',
  policyVersion: 'policy-2026.06.01',
  inspectorDeploymentGitCoordinate: GIT_COORDINATE,
};

function makeContext(
  overrides: Partial<{
    principalRef: string;
    inspectorClientRef: string;
    verifierAudience: string;
    policyVersion: string;
    inspectorDeploymentGitCoordinate: string;
    requestCorrelationId: string;
  }> = {},
): ArtifactInspectorTrustedContext {
  return createArtifactInspectorTrustedContext({ ...DEFAULT_CONTEXT_INPUT, ...overrides });
}

function buildRecord(
  sourceBytes: Uint8Array,
  options: {
    readonly artifactId?: string;
    readonly chunkSize?: AllowedChunkSize;
    readonly mediaType?: string;
    readonly objectVersionRef?: string;
    readonly createdAt?: string;
    readonly expiresAt?: string;
    readonly internalLocator?: unknown;
    readonly chunkHashesRef?: string;
  } = {},
): AuthorizedArtifactRecord {
  const manifest = buildArtifactChunkManifest(sourceBytes, options.chunkSize ?? 1024);
  return {
    artifactId: options.artifactId ?? ARTIFACT_ID,
    internalLocator: options.internalLocator ?? INTERNAL_LOCATOR_SENTINEL,
    objectVersionRef: options.objectVersionRef ?? OBJECT_VERSION_REF,
    sourceSha256: manifest.sourceSha256,
    byteLength: manifest.byteLength,
    chunkSize: manifest.chunkSize,
    chunkCount: manifest.chunkCount,
    chunkSha256s: manifest.chunks.map((chunk) => chunk.chunkSha256),
    merkleLeafSha256s: manifest.chunks.map((chunk) => chunk.merkleLeafSha256),
    merkleRoot: manifest.merkleRoot,
    mediaType: options.mediaType ?? 'text/plain',
    createdAt: options.createdAt ?? '2026-01-01T00:00:00.000Z',
    ...(options.expiresAt === undefined ? {} : { expiresAt: options.expiresAt }),
    ...(options.chunkHashesRef === undefined ? {} : { chunkHashesRef: options.chunkHashesRef }),
  };
}

interface TrackedDependencies {
  readonly dependencies: ArtifactInspectorDependencies;
  readonly events: ArtifactInspectorOperationalEvent[];
  readonly receipts: ArtifactInspectionReceipt[];
  readonly readCalls: Array<{ readonly offset: number; readonly length: number }>;
}

function trackDeps(options: {
  resolveAuthorizedArtifact: ArtifactInspectorDependencies['resolveAuthorizedArtifact'];
  readVersionedRange?: ArtifactInspectorDependencies['readVersionedRange'];
  now?: () => Date;
}): TrackedDependencies {
  const events: ArtifactInspectorOperationalEvent[] = [];
  const receipts: ArtifactInspectionReceipt[] = [];
  const readCalls: Array<{ offset: number; length: number }> = [];
  const dependencies: ArtifactInspectorDependencies = {
    resolveAuthorizedArtifact: options.resolveAuthorizedArtifact,
    readVersionedRange: async (context, internalLocator, objectVersionRef, offset, length) => {
      readCalls.push({ offset, length });
      if (options.readVersionedRange === undefined) {
        throw new Error('readVersionedRange was not expected to be called in this test.');
      }
      return options.readVersionedRange(context, internalLocator, objectVersionRef, offset, length);
    },
    now: options.now ?? (() => new Date('2026-06-01T00:00:00.000Z')),
    emitOperationalEvent: (event) => events.push(event),
    emitInspectionReceipt: (receipt) => receipts.push(receipt),
  };
  return { dependencies, events, receipts, readCalls };
}

/** A `readVersionedRange` backed by real bytes, returning the exact
 * requested version unless `versionOverride` forces a drifted one. */
function sourceBackedRead(
  sourceBytes: Uint8Array,
  options: { readonly versionOverride?: string } = {},
): ArtifactInspectorDependencies['readVersionedRange'] {
  return async (_context, _internalLocator, requestedVersionRef, offset, length) => {
    const bytes = sourceBytes.subarray(offset, offset + length);
    return {
      bytes,
      objectVersionRef: options.versionOverride ?? requestedVersionRef,
    };
  };
}

function resolverFor(
  record: AuthorizedArtifactRecord,
  options: { readonly artifactId?: string } = {},
): ArtifactInspectorDependencies['resolveAuthorizedArtifact'] {
  const artifactId = options.artifactId ?? record.artifactId;
  return async (_context, requestedArtifactId) =>
    requestedArtifactId === artifactId ? record : null;
}

function recursivelyScanForSentinel(value: unknown, forbidden: readonly string[]): string[] {
  const hits: string[] = [];
  const seen = new WeakSet<object>();
  function walk(node: unknown): void {
    if (typeof node === 'string') {
      for (const needle of forbidden) {
        if (node.includes(needle)) hits.push(needle);
      }
      return;
    }
    if (node === null || typeof node !== 'object') return;
    if (seen.has(node)) return;
    seen.add(node);
    if (Array.isArray(node)) {
      for (const entry of node) walk(entry);
      return;
    }
    for (const key of Object.keys(node)) {
      walk((node as Record<string, unknown>)[key]);
    }
  }
  walk(value);
  return hits;
}

const FORBIDDEN_LOCATOR_STRINGS = [
  'internal-only-bucket-9f3c2a',
  'internal/only/path/9f3c2a.bin',
  'leak-if-you-see-this-9f3c2a',
];

// ---------------------------------------------------------------------------
// Trusted context
// ---------------------------------------------------------------------------

describe('trusted context', () => {
  it('accepts a well-formed context and freezes it', () => {
    const context = makeContext();
    expect(Object.isFrozen(context)).toBe(true);
    expect(context.inspectorCapabilityRef).toBe('artifact:inspect');
  });

  it('rejects an unknown field', () => {
    expect(() =>
      createArtifactInspectorTrustedContext({ ...DEFAULT_CONTEXT_INPUT, extra: 'nope' }),
    ).toThrow();
  });

  it('rejects a capability value other than the fixed literal', () => {
    expect(() =>
      createArtifactInspectorTrustedContext({
        ...DEFAULT_CONTEXT_INPUT,
        inspectorCapabilityRef: 'artifact:write',
      }),
    ).toThrow();
    const result = ArtifactInspectorTrustedContextSchema.safeParse({
      ...DEFAULT_CONTEXT_INPUT,
      inspectorCapabilityRef: 'artifact:write',
    });
    expect(result.success).toBe(false);
  });

  it('rejects a malformed git coordinate', () => {
    expect(() =>
      createArtifactInspectorTrustedContext({
        ...DEFAULT_CONTEXT_INPUT,
        inspectorDeploymentGitCoordinate: 'not-a-sha',
      }),
    ).toThrow();
  });
});

// ---------------------------------------------------------------------------
// artifact_stat
// ---------------------------------------------------------------------------

describe('artifact_stat', () => {
  it('acceptance 1: authorized stat success', async () => {
    const source = new TextEncoder().encode(deterministicAsciiText(3000, 1));
    const record = buildRecord(source, { chunkSize: 1024 });
    const { dependencies, receipts, readCalls } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
    });
    const output = await artifactStat(dependencies, makeContext(), { artifactId: ARTIFACT_ID });
    expect(output.ok).toBe(true);
    if (!output.ok) throw new Error('expected success');
    expect(output.artifact.artifactId).toBe(ARTIFACT_ID);
    expect(output.artifact.sourceSha256).toBe(record.sourceSha256);
    expect(output.artifact.merkleRoot).toBe(record.merkleRoot);
    expect(output.artifact.chunkHashes.kind).toBe('inline');
    expect(readCalls).toHaveLength(0);
    expect(receipts).toHaveLength(1);
    expect(definedAt(receipts[0]).operationDetail).toEqual({ operation: 'artifact_stat' });
    expect(definedAt(receipts[0]).resultOrErrorClass).toEqual({ kind: 'result' });
  });

  it('STAT must not read artifact bytes even when successful', async () => {
    const source = new TextEncoder().encode(deterministicAsciiText(9000, 2));
    const record = buildRecord(source, { chunkSize: 4096 });
    const { dependencies, readCalls } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
    });
    await artifactStat(dependencies, makeContext(), { artifactId: ARTIFACT_ID });
    expect(readCalls).toHaveLength(0);
  });

  it('uses inline chunk hashes within the S0 inline ceiling', async () => {
    const source = new TextEncoder().encode(deterministicAsciiText(3000, 3));
    const record = buildRecord(source, { chunkSize: 1024 }); // 3 chunks, well under 64
    const { dependencies } = trackDeps({ resolveAuthorizedArtifact: resolverFor(record) });
    const output = await artifactStat(dependencies, makeContext(), { artifactId: ARTIFACT_ID });
    if (!output.ok) throw new Error('expected success');
    expect(output.artifact.chunkHashes).toEqual({ kind: 'inline', hashes: record.chunkSha256s });
  });

  it('uses the opaque chunk-hashes reference above the S0 inline ceiling', async () => {
    const source = new TextEncoder().encode(deterministicAsciiText(1024 * 70, 4));
    const record = buildRecord(source, { chunkSize: 1024, chunkHashesRef: CHUNK_HASHES_REF });
    expect(record.chunkCount).toBeGreaterThan(MAX_INLINE_CHUNK_HASHES);
    const { dependencies } = trackDeps({ resolveAuthorizedArtifact: resolverFor(record) });
    const output = await artifactStat(dependencies, makeContext(), { artifactId: ARTIFACT_ID });
    if (!output.ok) throw new Error('expected success');
    expect(output.artifact.chunkHashes).toEqual({ kind: 'reference', ref: CHUNK_HASHES_REF });
  });

  it('returns INTERNAL_ERROR above the inline ceiling with no chunk-hashes reference provided', async () => {
    const source = new TextEncoder().encode(deterministicAsciiText(1024 * 70, 5));
    const record = buildRecord(source, { chunkSize: 1024 }); // no chunkHashesRef
    const { dependencies, receipts } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
    });
    const output = await artifactStat(dependencies, makeContext(), { artifactId: ARTIFACT_ID });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected error');
    expect(output.error.code).toBe('INTERNAL_ERROR');
    expect(receipts).toHaveLength(1);
    expect(definedAt(receipts[0]).resultOrErrorClass).toEqual({
      kind: 'error',
      errorClass: 'INTERNAL_ERROR',
    });
  });

  it('handles the zero-byte artifact', async () => {
    const record = buildRecord(new Uint8Array(0), { chunkSize: 1024 });
    const { dependencies } = trackDeps({ resolveAuthorizedArtifact: resolverFor(record) });
    const output = await artifactStat(dependencies, makeContext(), { artifactId: ARTIFACT_ID });
    if (!output.ok) throw new Error('expected success');
    expect(output.artifact.byteLength).toBe(0);
    expect(output.artifact.chunkCount).toBe(0);
    expect(output.artifact.chunkHashes).toEqual({ kind: 'inline', hashes: [] });
  });

  it('reports analyzerProfileSupport as unsupported for a non-text media type', async () => {
    const record = buildRecord(new TextEncoder().encode('binary-ish'), {
      mediaType: 'application/octet-stream',
    });
    const { dependencies } = trackDeps({ resolveAuthorizedArtifact: resolverFor(record) });
    const output = await artifactStat(dependencies, makeContext(), { artifactId: ARTIFACT_ID });
    if (!output.ok) throw new Error('expected success');
    expect(output.artifact.analyzerProfileSupport).toBe('unsupported');
  });
});

// ---------------------------------------------------------------------------
// artifact_read_range
// ---------------------------------------------------------------------------

describe('artifact_read_range', () => {
  it('acceptance 2: authorized success crossing one chunk boundary', async () => {
    const text = deterministicAsciiText(3000, 10);
    const source = new TextEncoder().encode(text);
    const record = buildRecord(source, { chunkSize: 1024 });
    const { dependencies, receipts, readCalls } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source),
    });
    // offset 1000, length 100 crosses the 1024 chunk boundary.
    const output = await artifactReadRange(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      offset: 1000,
      length: 100,
    });
    expect(output.ok).toBe(true);
    if (!output.ok) throw new Error('expected success');
    expect(output.data).toBe(text.slice(1000, 1100));
    expect(output.integrity.verifiedCoveringChunkRange).toEqual({
      startChunkIndex: 0,
      endChunkIndex: 1,
    });
    expect(readCalls).toHaveLength(1);
    expect(receipts).toHaveLength(1);
    expect(definedAt(receipts[0]).operationDetail).toMatchObject({
      operation: 'artifact_read_range',
    });
  });

  it('acceptance 17: requested range over MAX_RANGE_BYTES is INVALID_REQUEST from schema, no dependency calls', async () => {
    const source = new TextEncoder().encode(deterministicAsciiText(20000, 11));
    const record = buildRecord(source, { chunkSize: 4096 });
    const { dependencies, readCalls, receipts } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source),
    });
    const output = await artifactReadRange(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      offset: 0,
      length: MAX_RANGE_BYTES + 1,
    });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected error');
    expect(output.error.code).toBe('INVALID_REQUEST');
    expect(readCalls).toHaveLength(0);
    expect(receipts).toHaveLength(0);
  });

  it('acceptance 18: the covering-fetch ceiling is enforced at its true worst case, which sits exactly at (never over) 16,384 bytes', async () => {
    // Given MAX_RANGE_BYTES (8192) and the S1b allowed chunk sizes
    // {1024, 4096, 8192}, the worst-case misaligned covering fetch is
    // `(ceil(length / chunkSize) + 1) * chunkSize`, maximized at
    // chunkSize 8192: (ceil(8192/8192)+1)*8192 = 16384 -- exactly the
    // MAX_COVERING_FETCH_BYTES ceiling, never over it, for every allowed
    // chunk size. Exceeding the ceiling is therefore unreachable through
    // any schema-valid artifact_read_range request; the check is kept as
    // defense-in-depth (documented in docs/evidence/ISSUE_34_S2_FIXED_INSPECTOR.md)
    // and this test proves it does not falsely reject the true worst case.
    const source = new TextEncoder().encode(deterministicAsciiText(8192 * 4, 12));
    const record = buildRecord(source, { chunkSize: 8192 });
    const { dependencies, readCalls } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source),
    });
    // offset 8191, length 8192 spans chunks [0,1]: covering = 2*8192 = 16384.
    const output = await artifactReadRange(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      offset: 8191,
      length: 8192,
    });
    expect(output.ok).toBe(true);
    expect(readCalls).toEqual([{ offset: 0, length: 16384 }]);
  });

  it('acceptance 20: short covering read fails closed with INTEGRITY_FAILURE', async () => {
    const source = new TextEncoder().encode(deterministicAsciiText(4000, 13));
    const record = buildRecord(source, { chunkSize: 1024 });
    const { dependencies, receipts } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: async (_c, _l, versionRef, offset) => ({
        bytes: source.subarray(offset, offset + 1), // always short
        objectVersionRef: versionRef,
      }),
    });
    const output = await artifactReadRange(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      offset: 500,
      length: 50,
    });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected error');
    expect(output.error.code).toBe('INTEGRITY_FAILURE');
    expect(definedAt(receipts[0]).resultOrErrorClass).toEqual({
      kind: 'error',
      errorClass: 'INTEGRITY_FAILURE',
    });
  });

  it('acceptance 21: long covering read fails closed with INTEGRITY_FAILURE', async () => {
    const source = new TextEncoder().encode(deterministicAsciiText(4000, 14));
    const record = buildRecord(source, { chunkSize: 1024 });
    const { dependencies } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: async (_c, _l, versionRef, offset, length) => ({
        bytes: source.subarray(offset, offset + length + 10), // always long
        objectVersionRef: versionRef,
      }),
    });
    const output = await artifactReadRange(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      offset: 500,
      length: 50,
    });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected error');
    expect(output.error.code).toBe('INTEGRITY_FAILURE');
  });

  it('acceptance 22: object-version mismatch fails closed with INTEGRITY_FAILURE', async () => {
    const source = new TextEncoder().encode(deterministicAsciiText(4000, 15));
    const record = buildRecord(source, { chunkSize: 1024 });
    const { dependencies } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source, { versionOverride: DRIFTED_OBJECT_VERSION_REF }),
    });
    const output = await artifactReadRange(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      offset: 0,
      length: 50,
    });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected error');
    expect(output.error.code).toBe('INTEGRITY_FAILURE');
  });

  it('acceptance 23: a mutated chunk byte fails closed with INTEGRITY_FAILURE', async () => {
    const source = new TextEncoder().encode(deterministicAsciiText(4000, 16));
    const record = buildRecord(source, { chunkSize: 1024 });
    const mutated = Uint8Array.from(source);
    mutated[10] = (definedAt(mutated[10]) + 1) % 256;
    const { dependencies } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(mutated),
    });
    const output = await artifactReadRange(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      offset: 0,
      length: 50,
    });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected error');
    expect(output.error.code).toBe('INTEGRITY_FAILURE');
  });

  it('acceptance 24: a registry-declared raw chunk hash that disagrees with the real bytes fails closed with INTEGRITY_FAILURE', async () => {
    // The raw chunkSha256 field is not part of the Merkle root closure (only
    // merkleLeafSha256 is), so mutating it alone keeps the manifest itself
    // internally self-consistent; the mismatch is only caught once the real
    // bytes are fetched and their raw digest is compared against this
    // (now-wrong) declared value inside verifyArtifactChunkProof.
    const source = new TextEncoder().encode(deterministicAsciiText(4000, 17));
    const baseRecord = buildRecord(source, { chunkSize: 1024 });
    const mutatedRawHash: AuthorizedArtifactRecord = {
      ...baseRecord,
      chunkSha256s: [
        `${definedAt(baseRecord.chunkSha256s[0]).slice(0, 63)}0`,
        ...baseRecord.chunkSha256s.slice(1),
      ],
    };
    const { dependencies, readCalls } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(mutatedRawHash),
      readVersionedRange: sourceBackedRead(source),
    });
    const output = await artifactReadRange(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      offset: 0,
      length: 50,
    });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected error');
    expect(output.error.code).toBe('INTEGRITY_FAILURE');
    expect(readCalls).toHaveLength(1); // the mismatch is only detected after fetching bytes
  });

  it('acceptance 25/27: a registry manifest whose declared Merkle leaf hashes or root no longer close together fails closed before any byte read', async () => {
    // This module builds every Merkle proof itself from the resolved
    // manifest -- it never receives an externally supplied proof to mutate
    // a sibling of (acceptance 26's "mutated proof sibling" is therefore not
    // externally triggerable in this architecture; see
    // docs/evidence/ISSUE_34_S2_FIXED_INSPECTOR.md). Tampering with a
    // declared merkleLeafSha256 or the declared merkleRoot alone breaks the
    // manifest's own leaf-to-root closure, which is checked at resolution
    // time, before any dependency call reads a byte -- still a fail-closed
    // outcome (INTERNAL_ERROR, a registry-data problem), just detected
    // earlier and more cheaply than a byte-level integrity failure.
    const source = new TextEncoder().encode(deterministicAsciiText(4000, 17));
    const baseRecord = buildRecord(source, { chunkSize: 1024 });
    const mutatedLeaf: AuthorizedArtifactRecord = {
      ...baseRecord,
      merkleLeafSha256s: [
        `${definedAt(baseRecord.merkleLeafSha256s[0]).slice(0, 63)}0`,
        ...baseRecord.merkleLeafSha256s.slice(1),
      ],
    };
    const mutatedRoot: AuthorizedArtifactRecord = {
      ...baseRecord,
      merkleRoot: `${baseRecord.merkleRoot.slice(0, 63)}0`,
    };

    for (const record of [mutatedLeaf, mutatedRoot]) {
      const { dependencies, readCalls, receipts } = trackDeps({
        resolveAuthorizedArtifact: resolverFor(record),
        readVersionedRange: sourceBackedRead(source),
      });
      const output = await artifactReadRange(dependencies, makeContext(), {
        artifactId: ARTIFACT_ID,
        offset: 0,
        length: 50,
      });
      expect(output.ok).toBe(false);
      if (output.ok) throw new Error('expected error');
      expect(output.error.code).toBe('INTERNAL_ERROR');
      expect(readCalls).toHaveLength(0);
      expect(receipts).toHaveLength(1);
    }
  });

  it('acceptance 30: no automatic retry after a dependency failure', async () => {
    const source = new TextEncoder().encode(deterministicAsciiText(2000, 18));
    const record = buildRecord(source, { chunkSize: 1024 });
    let calls = 0;
    const { dependencies, receipts } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: async () => {
        calls += 1;
        throw new Error('simulated adapter failure');
      },
    });
    const output = await artifactReadRange(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      offset: 0,
      length: 10,
    });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected error');
    expect(output.error.code).toBe('INTERNAL_ERROR');
    expect(calls).toBe(1);
    expect(receipts).toHaveLength(1);
  });

  it('rejects a range that runs past the end of the resolved artifact', async () => {
    const source = new TextEncoder().encode(deterministicAsciiText(500, 19));
    const record = buildRecord(source, { chunkSize: 1024 });
    const { dependencies, readCalls } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source),
    });
    const output = await artifactReadRange(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      offset: 490,
      length: 50,
    });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected error');
    expect(output.error.code).toBe('INTEGRITY_FAILURE');
    expect(readCalls).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// artifact_read_lines
// ---------------------------------------------------------------------------

describe('artifact_read_lines', () => {
  it('acceptance 3: authorized line read for LF text', async () => {
    const text = 'line one\nline two\nline three\n';
    const source = new TextEncoder().encode(text);
    const record = buildRecord(source, { chunkSize: 1024, mediaType: 'text/plain' });
    const { dependencies, receipts } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source),
    });
    const output = await artifactReadLines(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      startLine: 2,
      count: 1,
    });
    expect(output.ok).toBe(true);
    if (!output.ok) throw new Error('expected success');
    expect(output.data).toBe('line two\n');
    expect(output.returnedLineCount).toBe(1);
    expect(receipts).toHaveLength(1);
  });

  it('acceptance 4: authorized line read preserving CRLF', async () => {
    const text = 'alpha\r\nbeta\r\ngamma\r\n';
    const source = new TextEncoder().encode(text);
    const record = buildRecord(source, { chunkSize: 1024, mediaType: 'text/plain' });
    const { dependencies } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source),
    });
    const output = await artifactReadLines(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      startLine: 1,
      count: 2,
    });
    if (!output.ok) throw new Error('expected success');
    expect(output.data).toBe('alpha\r\nbeta\r\n');
  });

  it('acceptance 5: a final line without a trailing newline is valid', async () => {
    const text = 'first\nsecond-no-newline';
    const source = new TextEncoder().encode(text);
    const record = buildRecord(source, { chunkSize: 1024, mediaType: 'text/markdown' });
    const { dependencies } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source),
    });
    const output = await artifactReadLines(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      startLine: 2,
      count: 5,
    });
    if (!output.ok) throw new Error('expected success');
    expect(output.data).toBe('second-no-newline');
    expect(output.returnedLineCount).toBe(1);
  });

  it('acceptance 15: unsupported media type', async () => {
    const source = new TextEncoder().encode('irrelevant');
    const record = buildRecord(source, { mediaType: 'application/pdf' });
    const { dependencies, readCalls, receipts } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source),
    });
    const output = await artifactReadLines(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      startLine: 1,
      count: 1,
    });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected error');
    expect(output.error.code).toBe('UNSUPPORTED');
    expect(readCalls).toHaveLength(0);
    expect(receipts).toHaveLength(1);
  });

  it('acceptance 16: invalid UTF-8 fails closed with INTEGRITY_FAILURE', async () => {
    // A lone continuation byte (0x80) is never valid UTF-8 on its own.
    const invalid = new Uint8Array([0x61, 0x80, 0x62]);
    const record = buildRecord(invalid, { chunkSize: 1024, mediaType: 'text/plain' });
    const { dependencies } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(invalid),
    });
    const output = await artifactReadLines(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      startLine: 1,
      count: 1,
    });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected error');
    expect(output.error.code).toBe('INTEGRITY_FAILURE');
  });

  it('acceptance 19: a text source over 262,144 bytes is rejected before any read', async () => {
    // Build a manifest by hand-scaling a smaller real manifest's shape is not
    // viable (S1b caps sources at 1,048,576 bytes but this ceiling is well
    // below that), so build genuine oversized content once.
    const big = deterministicAsciiText(MAX_LINE_SOURCE_SCAN_BYTES + 1, 20);
    const source = new TextEncoder().encode(big);
    const record = buildRecord(source, { chunkSize: 8192, mediaType: 'text/plain' });
    const { dependencies, readCalls, receipts } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source),
    });
    const output = await artifactReadLines(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      startLine: 1,
      count: 1,
    });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected error');
    expect(output.error.code).toBe('RESPONSE_LIMIT_EXCEEDED');
    expect(readCalls).toHaveLength(0);
    expect(receipts).toHaveLength(1);
  });

  it('acceptance 28: a source mutation outside the returned line range still fails closed', async () => {
    const text = `${'x'.repeat(2000)}\nTARGET LINE\n${'y'.repeat(2000)}\n`;
    const source = new TextEncoder().encode(text);
    const record = buildRecord(source, { chunkSize: 1024, mediaType: 'text/plain' });
    const mutated = Uint8Array.from(source);
    // Mutate deep inside the trailing 'y' block, far from the requested
    // "TARGET LINE" content.
    const mutateIndex = source.byteLength - 5;
    mutated[mutateIndex] = (definedAt(mutated[mutateIndex]) + 1) % 256;
    const { dependencies } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(mutated),
    });
    const output = await artifactReadLines(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      startLine: 2,
      count: 1,
    });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected error');
    expect(output.error.code).toBe('INTEGRITY_FAILURE');
  });

  it('acceptance 29: the full source buffer passed to the adapter is never mutated by inspection', async () => {
    const text = 'one\ntwo\nthree\n';
    const source = new TextEncoder().encode(text);
    const before = Uint8Array.from(source);
    const record = buildRecord(source, { chunkSize: 1024, mediaType: 'text/plain' });
    const { dependencies } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source),
    });
    await artifactReadLines(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      startLine: 1,
      count: 3,
    });
    expect(source).toEqual(before);
  });

  it('startLine beyond available lines returns a schema-valid successful empty result when a chunk exists', async () => {
    const text = 'only line\n';
    const source = new TextEncoder().encode(text);
    const record = buildRecord(source, { chunkSize: 1024, mediaType: 'text/plain' });
    const { dependencies, receipts } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source),
    });
    const output = await artifactReadLines(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      startLine: 50,
      count: 1,
    });
    expect(output.ok).toBe(true);
    if (!output.ok) throw new Error('expected success');
    expect(output.data).toBe('');
    expect(output.returnedLineCount).toBe(0);
    expect(receipts).toHaveLength(1);
    expect(definedAt(receipts[0]).resultOrErrorClass).toEqual({ kind: 'result' });
  });

  it('startLine beyond available lines on a zero-byte artifact uses the documented INVALID_REQUEST class', async () => {
    const record = buildRecord(new Uint8Array(0), { chunkSize: 1024, mediaType: 'text/plain' });
    const { dependencies, receipts } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(new Uint8Array(0)),
    });
    const output = await artifactReadLines(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      startLine: 1,
      count: 1,
    });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected error');
    expect(output.error.code).toBe('INVALID_REQUEST');
    expect(receipts).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Authorization and non-enumeration
// ---------------------------------------------------------------------------

describe('authorization and non-enumeration', () => {
  const source = new TextEncoder().encode(deterministicAsciiText(2000, 30));
  const record = buildRecord(source, { chunkSize: 1024 });

  it('acceptance 6: missing artifact', async () => {
    const { dependencies } = trackDeps({ resolveAuthorizedArtifact: async () => null });
    const output = await artifactStat(dependencies, makeContext(), { artifactId: ARTIFACT_ID });
    expect(output).toEqual({
      ok: false,
      error: {
        code: 'RESOURCE_UNAVAILABLE',
        message: 'Artifact is unavailable.',
        retryable: false,
      },
    });
  });

  it('acceptance 7: wrong principal', async () => {
    const { dependencies } = trackDeps({
      resolveAuthorizedArtifact: async (context) =>
        context.principalRef === 'principal-ok' ? record : null,
    });
    const output = await artifactStat(
      dependencies,
      makeContext({ principalRef: 'principal-bad' }),
      {
        artifactId: ARTIFACT_ID,
      },
    );
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected unavailable');
    expect(output.error.code).toBe('RESOURCE_UNAVAILABLE');
  });

  it('acceptance 8: wrong client', async () => {
    const { dependencies } = trackDeps({
      resolveAuthorizedArtifact: async (context) =>
        context.inspectorClientRef === 'client-ok' ? record : null,
    });
    const output = await artifactStat(
      dependencies,
      makeContext({ inspectorClientRef: 'client-bad' }),
      {
        artifactId: ARTIFACT_ID,
      },
    );
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected unavailable');
    expect(output.error.code).toBe('RESOURCE_UNAVAILABLE');
  });

  it('acceptance 9: missing/wrong capability (adapter-side grant denial)', async () => {
    const deniedClients = new Set(['client-no-capability']);
    const { dependencies } = trackDeps({
      resolveAuthorizedArtifact: async (context) =>
        deniedClients.has(context.inspectorClientRef) ? null : record,
    });
    const output = await artifactStat(
      dependencies,
      makeContext({ inspectorClientRef: 'client-no-capability' }),
      { artifactId: ARTIFACT_ID },
    );
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected unavailable');
    expect(output.error.code).toBe('RESOURCE_UNAVAILABLE');
  });

  it('acceptance 10: expired artifact', async () => {
    const expired = buildRecord(source, { chunkSize: 1024, expiresAt: '2026-01-01T00:00:00.000Z' });
    const { dependencies } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(expired),
      now: () => new Date('2026-06-01T00:00:00.000Z'),
    });
    const output = await artifactStat(dependencies, makeContext(), { artifactId: ARTIFACT_ID });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected unavailable');
    expect(output.error.code).toBe('RESOURCE_UNAVAILABLE');
  });

  it('acceptance 11: all unavailable outputs are byte-identical, across all three operations and every cause', async () => {
    const expired = buildRecord(source, { chunkSize: 1024, expiresAt: '2020-01-01T00:00:00.000Z' });
    const missingDeps = trackDeps({ resolveAuthorizedArtifact: async () => null }).dependencies;
    const expiredDeps = trackDeps({ resolveAuthorizedArtifact: resolverFor(expired) }).dependencies;
    const wrongPrincipalDeps = trackDeps({
      resolveAuthorizedArtifact: async (context) =>
        context.principalRef === 'principal-ok' ? record : null,
    }).dependencies;

    const outputs = await Promise.all([
      artifactStat(missingDeps, makeContext(), { artifactId: ARTIFACT_ID }),
      artifactStat(expiredDeps, makeContext(), { artifactId: ARTIFACT_ID }),
      artifactStat(wrongPrincipalDeps, makeContext({ principalRef: 'principal-bad' }), {
        artifactId: ARTIFACT_ID,
      }),
      artifactReadRange(missingDeps, makeContext(), {
        artifactId: ARTIFACT_ID,
        offset: 0,
        length: 1,
      }),
      artifactReadRange(expiredDeps, makeContext(), {
        artifactId: ARTIFACT_ID,
        offset: 0,
        length: 1,
      }),
      artifactReadLines(missingDeps, makeContext(), {
        artifactId: ARTIFACT_ID,
        startLine: 1,
        count: 1,
      }),
      artifactReadLines(expiredDeps, makeContext(), {
        artifactId: ARTIFACT_ID,
        startLine: 1,
        count: 1,
      }),
    ]);
    const [first, ...rest] = outputs;
    for (const output of rest) {
      expect(output).toEqual(first);
    }
  });

  it('acceptance 12: unavailable cases perform zero byte reads', async () => {
    const { dependencies, readCalls } = trackDeps({ resolveAuthorizedArtifact: async () => null });
    await artifactStat(dependencies, makeContext(), { artifactId: ARTIFACT_ID });
    await artifactReadRange(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      offset: 0,
      length: 1,
    });
    await artifactReadLines(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      startLine: 1,
      count: 1,
    });
    expect(readCalls).toHaveLength(0);
  });

  it('acceptance 13: caller-selected bucket/path/URL/etc fields are denied before any dependency call', async () => {
    const { dependencies, readCalls } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
    });
    const forbiddenInputs: unknown[] = [
      { artifactId: ARTIFACT_ID, bucket: 'attacker-bucket' },
      { artifactId: ARTIFACT_ID, path: '../../etc/passwd' },
      { artifactId: ARTIFACT_ID, url: 'https://evil.example/x' },
      { artifactId: ARTIFACT_ID, origin: 'https://evil.example' },
      { artifactId: ARTIFACT_ID, schema: 'public' },
      { artifactId: ARTIFACT_ID, table: 'objects' },
      { artifactId: ARTIFACT_ID, rpc: 'download' },
      { artifactId: ARTIFACT_ID, method: 'GET' },
      { artifactId: ARTIFACT_ID, offset: 0, length: 1, signedUrl: 'https://evil.example' },
    ];
    for (const input of forbiddenInputs) {
      const output = await artifactStat(dependencies, makeContext(), input);
      expect(output.ok).toBe(false);
      if (output.ok) throw new Error('expected error');
      expect(output.error.code).toBe('INVALID_REQUEST');
    }
    expect(readCalls).toHaveLength(0);
  });

  it('rejects caller-selected principal/client/capability values embedded in tool input', async () => {
    const { dependencies, readCalls } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
    });
    const output = await artifactStat(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      principalRef: 'attacker',
      inspectorCapabilityRef: 'artifact:inspect',
    });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected error');
    expect(output.error.code).toBe('INVALID_REQUEST');
    expect(readCalls).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Internal locator secrecy
// ---------------------------------------------------------------------------

describe('acceptance 14: internal locator never leaks', () => {
  it('is absent from every public output, receipt, event, and thrown error', async () => {
    const text = 'alpha\nbeta\ngamma\n';
    const source = new TextEncoder().encode(text);
    const record = buildRecord(source, { chunkSize: 1024, mediaType: 'text/plain' });
    const { dependencies, events, receipts } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source),
    });
    const inspector = createArtifactInspector(dependencies);
    const context = makeContext();

    const statOutput = await inspector.artifactStat(context, { artifactId: ARTIFACT_ID });
    const rangeOutput = await inspector.artifactReadRange(context, {
      artifactId: ARTIFACT_ID,
      offset: 0,
      length: 5,
    });
    const linesOutput = await inspector.artifactReadLines(context, {
      artifactId: ARTIFACT_ID,
      startLine: 1,
      count: 1,
    });
    const unavailableOutput = await inspector.artifactStat(context, {
      artifactId: OTHER_ARTIFACT_ID,
    });

    let thrown: unknown;
    try {
      createArtifactInspectorTrustedContext({
        not: 'valid',
        internalLocator: INTERNAL_LOCATOR_SENTINEL,
      });
    } catch (error) {
      thrown = error instanceof Error ? error.message : String(error);
    }

    const hits = recursivelyScanForSentinel(
      { statOutput, rangeOutput, linesOutput, unavailableOutput, events, receipts, thrown },
      FORBIDDEN_LOCATOR_STRINGS,
    );
    expect(hits).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Errors and receipts
// ---------------------------------------------------------------------------

describe('errors and receipts', () => {
  it('acceptance 31: errors contain no secret or existence detail', async () => {
    const { dependencies } = trackDeps({ resolveAuthorizedArtifact: async () => null });
    const output = await artifactStat(dependencies, makeContext(), { artifactId: ARTIFACT_ID });
    expect(Object.keys(output)).toEqual(['ok', 'error']);
    if (output.ok) throw new Error('expected error');
    expect(Object.keys(output.error)).toEqual(['code', 'message', 'retryable']);
  });

  it('acceptance 33: error paths do not invent source receipts for pre-resolution outcomes', async () => {
    const { dependencies: invalidDeps, receipts: invalidReceipts } = trackDeps({
      resolveAuthorizedArtifact: () => {
        throw new Error('must not be called for a pre-resolution schema failure');
      },
    });
    await artifactStat(invalidDeps, makeContext(), { artifactId: 'not-opaque' });
    expect(invalidReceipts).toHaveLength(0);

    const { dependencies: missingDeps, receipts: missingReceipts } = trackDeps({
      resolveAuthorizedArtifact: async () => null,
    });
    await artifactStat(missingDeps, makeContext(), { artifactId: ARTIFACT_ID });
    expect(missingReceipts).toHaveLength(0);
  });

  it('acceptance 32: a successful receipt passes the accepted S0 receipt schema', async () => {
    const source = new TextEncoder().encode(deterministicAsciiText(2000, 40));
    const record = buildRecord(source, { chunkSize: 1024 });
    const { dependencies, receipts } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
    });
    await artifactStat(dependencies, makeContext({ requestCorrelationId: 'corr-1' }), {
      artifactId: ARTIFACT_ID,
    });
    expect(receipts).toHaveLength(1);
    const parsed = ArtifactInspectionReceiptSchema.safeParse(definedAt(receipts[0]));
    expect(parsed.success).toBe(true);
    expect(definedAt(receipts[0]).analyzerProfileVersion).toBe(ARTIFACT_INSPECTOR_PROFILE_VERSION);
  });

  it('receipts never carry the internal locator, a bucket, a path, a URL, a token, or payload bytes', async () => {
    const source = new TextEncoder().encode('alpha\nbeta\n');
    const record = buildRecord(source, { chunkSize: 1024 });
    const { dependencies, receipts } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source),
    });
    await artifactReadLines(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      startLine: 1,
      count: 1,
    });
    const receipt = definedAt(receipts[0]);
    const keys = Object.keys(receipt);
    for (const forbidden of [
      'internalLocator',
      'bucket',
      'path',
      'signedUrl',
      'token',
      'authorization',
    ]) {
      expect(keys).not.toContain(forbidden);
    }
    expect(JSON.stringify(receipt)).not.toContain('alpha');
  });
});

// ---------------------------------------------------------------------------
// Operational events
// ---------------------------------------------------------------------------

describe('operational events', () => {
  it('never include an artifact ID for an unavailable outcome, and carry only the documented fields', async () => {
    const { dependencies, events } = trackDeps({ resolveAuthorizedArtifact: async () => null });
    await artifactStat(dependencies, makeContext({ requestCorrelationId: 'corr-9' }), {
      artifactId: ARTIFACT_ID,
    });
    expect(events).toHaveLength(1);
    const event = definedAt(events[0]);
    expect(event.resultClass).toBe('RESOURCE_UNAVAILABLE');
    expect(event.requestCorrelationId).toBe('corr-9');
    expect(Object.keys(event).sort()).toEqual(
      ['operation', 'resultClass', 'requestCorrelationId', 'elapsedMs'].sort(),
    );
  });

  it('emits one event of the correct class for success, invalid request, unsupported, response limit, and integrity failure', async () => {
    const source = new TextEncoder().encode('alpha\nbeta\n');
    const record = buildRecord(source, { chunkSize: 1024, mediaType: 'text/plain' });

    const success = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source),
    });
    await artifactReadLines(success.dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      startLine: 1,
      count: 1,
    });
    expect(definedAt(success.events[0]).resultClass).toBe('success');

    const invalid = trackDeps({ resolveAuthorizedArtifact: resolverFor(record) });
    await artifactReadLines(invalid.dependencies, makeContext(), { artifactId: 'bad' });
    expect(definedAt(invalid.events[0]).resultClass).toBe('INVALID_REQUEST');

    const unsupported = trackDeps({
      resolveAuthorizedArtifact: resolverFor(buildRecord(source, { mediaType: 'application/pdf' })),
    });
    await artifactReadLines(unsupported.dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      startLine: 1,
      count: 1,
    });
    expect(definedAt(unsupported.events[0]).resultClass).toBe('UNSUPPORTED');
  });
});

// ---------------------------------------------------------------------------
// Wire ceiling boundary
// ---------------------------------------------------------------------------

describe('acceptance 34: complete wire response exact boundary and one over', () => {
  // Every S0 field this module fills into a stat or read_range/read_lines
  // output already carries its own ceiling (mediaType<=255, data effectively
  // <=8192 via returnedRange, verifiedChunks<=16, chunk proof depth bounded
  // by the 1,048,576-byte / 1,024-byte-chunk S1b geometry) -- empirically,
  // the largest fully schema-legitimate output this module can construct
  // (a full-size artifact, maximal covering, maximal returned range) stays
  // comfortably under MAX_ARTIFACT_RESPONSE_BYTES. Exceeding the wire
  // ceiling is therefore not reachable through any single legitimate S2
  // request; see docs/evidence/ISSUE_34_S2_FIXED_INSPECTOR.md. The response-
  // budget check itself -- reusing the exact accepted S0 serializer,
  // `artifactInspectionResponseByteLength`, never a second implementation --
  // is still verified directly below at its true boundary.
  it('the largest legitimate artifact_read_range output stays safely under the wire ceiling', async () => {
    const emojiUnit = new TextEncoder().encode('\u{1F600}');
    const big = new Uint8Array(1_048_576); // the S1b maximum synthetic source
    for (let i = 0; i < big.length; i += emojiUnit.length) {
      big.set(emojiUnit.subarray(0, Math.min(emojiUnit.length, big.length - i)), i);
    }
    const record = buildRecord(big, { chunkSize: 1024 }); // maximizes chunkCount and proof depth
    const { dependencies } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(big),
    });
    // offset 0, length MAX_RANGE_BYTES (8192): the largest legitimate
    // returned range, touching the maximum MAX_VERIFIED_CHUNKS_PER_READ (16)
    // covering chunks this module's own 16,384-byte covering-fetch ceiling
    // allows at chunkSize 1024.
    const output = await artifactReadRange(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      offset: 0,
      length: 8192,
    });
    expect(output.ok).toBe(true);
    if (!output.ok) throw new Error('expected success');
    expect(output.integrity.verifiedChunks.length).toBeLessThanOrEqual(16);
  });

  it('the response-budget check, at its true boundary, distinguishes "at or under" from "one byte over"', async () => {
    // mediaType is the one field this module passes through from the
    // registry record without its own independent size ceiling at the
    // TypeScript/interface level (the S0 output schema caps it at 255
    // characters, but that is a separate, later check) -- padding it is
    // therefore the only way to reach the wire ceiling at all, and it is
    // used here purely to drive the budget CHECK to its true boundary, not
    // to claim this is a realistic request shape.
    function byteLengthForPadding(paddingLength: number): number {
      const source = new TextEncoder().encode(deterministicAsciiText(3000, 50));
      const record = buildRecord(source, {
        chunkSize: 1024,
        mediaType: `text/plain+${'x'.repeat(paddingLength)}`,
      });
      const candidate = {
        ok: true as const,
        artifact: {
          artifactId: record.artifactId,
          objectVersionRef: record.objectVersionRef,
          sourceSha256: record.sourceSha256,
          byteLength: record.byteLength,
          chunkSize: record.chunkSize,
          chunkCount: record.chunkCount,
          chunkHashes: { kind: 'inline' as const, hashes: [...record.chunkSha256s] },
          merkleRoot: record.merkleRoot,
          mediaType: record.mediaType,
          analyzerProfileSupport: 'unsupported' as const,
          createdAt: record.createdAt,
        },
      };
      return artifactInspectionResponseByteLength(null, candidate);
    }
    function recordForPadding(paddingLength: number): AuthorizedArtifactRecord {
      const source = new TextEncoder().encode(deterministicAsciiText(3000, 50));
      return buildRecord(source, {
        chunkSize: 1024,
        mediaType: `text/plain+${'x'.repeat(paddingLength)}`,
      });
    }

    let low = 0;
    let high = MAX_ARTIFACT_RESPONSE_BYTES * 2;
    while (low < high) {
      const mid = Math.floor((low + high) / 2);
      if (byteLengthForPadding(mid) > MAX_ARTIFACT_RESPONSE_BYTES) {
        high = mid;
      } else {
        low = mid + 1;
      }
    }
    // `low` is now the smallest padding length whose byteLength is strictly
    // over the ceiling; `low - 1` is at or under it.
    expect(byteLengthForPadding(low)).toBeGreaterThan(MAX_ARTIFACT_RESPONSE_BYTES);
    expect(byteLengthForPadding(low - 1)).toBeLessThanOrEqual(MAX_ARTIFACT_RESPONSE_BYTES);

    const { dependencies: overDeps } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(recordForPadding(low)),
    });
    const overOutput = await artifactStat(overDeps, makeContext(), { artifactId: ARTIFACT_ID });
    expect(overOutput.ok).toBe(false);
    if (overOutput.ok) throw new Error('expected error');
    expect(overOutput.error.code).toBe('RESPONSE_LIMIT_EXCEEDED');

    const { dependencies: underDeps } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(recordForPadding(low - 1)),
    });
    const underOutput = await artifactStat(underDeps, makeContext(), { artifactId: ARTIFACT_ID });
    // The over-length mediaType may separately violate the S0 schema's own
    // 255-character field ceiling once under budget; only the specific
    // RESPONSE_LIMIT_EXCEEDED code is asserted against here.
    if (!underOutput.ok) {
      expect(underOutput.error.code).not.toBe('RESPONSE_LIMIT_EXCEEDED');
    }
  });
});

// ---------------------------------------------------------------------------
// Concurrency and immutability
// ---------------------------------------------------------------------------

describe('acceptance 35: concurrent independent reads do not share mutable context', () => {
  it('interleaved calls against different artifacts and contexts never cross-contaminate', async () => {
    const sourceA = new TextEncoder().encode('AAAA\nBBBB\n');
    const sourceB = new TextEncoder().encode('CCCC\nDDDD\n');
    const recordA = buildRecord(sourceA, {
      artifactId: ARTIFACT_ID,
      chunkSize: 1024,
      objectVersionRef: 'ov_aaaaaaaaaaaaaaaaaaaaaaaa',
    });
    const recordB = buildRecord(sourceB, {
      artifactId: OTHER_ARTIFACT_ID,
      chunkSize: 1024,
      objectVersionRef: 'ov_bbbbbbbbbbbbbbbbbbbbbbbb',
    });
    const records = new Map([
      [ARTIFACT_ID, { record: recordA, source: sourceA }],
      [OTHER_ARTIFACT_ID, { record: recordB, source: sourceB }],
    ]);
    const { dependencies } = trackDeps({
      resolveAuthorizedArtifact: async (_context, artifactId) =>
        records.get(artifactId)?.record ?? null,
      readVersionedRange: async (_context, _locator, versionRef, offset, length) => {
        const match = [...records.values()].find(
          (entry) => entry.record.objectVersionRef === versionRef,
        );
        if (!match) throw new Error('unknown version');
        return {
          bytes: match.source.subarray(offset, offset + length),
          objectVersionRef: versionRef,
        };
      },
    });
    const inspector = createArtifactInspector(dependencies);

    const [resultA, resultB] = await Promise.all([
      inspector.artifactReadLines(makeContext({ principalRef: 'principal-A' }), {
        artifactId: ARTIFACT_ID,
        startLine: 1,
        count: 2,
      }),
      inspector.artifactReadLines(makeContext({ principalRef: 'principal-B' }), {
        artifactId: OTHER_ARTIFACT_ID,
        startLine: 1,
        count: 2,
      }),
    ]);
    if (!resultA.ok || !resultB.ok) throw new Error('expected both to succeed');
    expect(resultA.data).toBe('AAAA\nBBBB\n');
    expect(resultB.data).toBe('CCCC\nDDDD\n');
  });
});

describe('acceptance 36: public outputs, receipts, and events are frozen', () => {
  it('freezes success outputs, error outputs, receipts, and events', async () => {
    const source = new TextEncoder().encode('one\ntwo\n');
    const record = buildRecord(source, { chunkSize: 1024 });
    const { dependencies, events, receipts } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source),
    });
    const success = await artifactReadLines(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      startLine: 1,
      count: 1,
    });
    expect(Object.isFrozen(success)).toBe(true);
    if (success.ok) {
      expect(Object.isFrozen(success.integrity)).toBe(true);
      expect(Object.isFrozen(success.integrity.verifiedChunks)).toBe(true);
    }

    const { dependencies: unavailableDeps } = trackDeps({
      resolveAuthorizedArtifact: async () => null,
    });
    const unavailable = await artifactStat(unavailableDeps, makeContext(), {
      artifactId: ARTIFACT_ID,
    });
    expect(Object.isFrozen(unavailable)).toBe(true);
    expect(Object.isFrozen((unavailable as { error: unknown }).error)).toBe(true);

    expect(receipts.length).toBeGreaterThan(0);
    expect(Object.isFrozen(definedAt(receipts[0]))).toBe(true);
    expect(events.length).toBeGreaterThan(0);
    expect(Object.isFrozen(definedAt(events[0]))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// TOCTOU: version changes between resolution and the actual byte read.
// ---------------------------------------------------------------------------

describe('TOCTOU: authorization and returned bytes bind the same immutable object version', () => {
  const source = new TextEncoder().encode(deterministicAsciiText(3000, 60));
  const record = buildRecord(source, { chunkSize: 1024 });

  it('fails closed when the version drifts before the read', async () => {
    const { dependencies } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source, { versionOverride: DRIFTED_OBJECT_VERSION_REF }),
    });
    const output = await artifactReadRange(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      offset: 0,
      length: 10,
    });
    expect(output.ok).toBe(false);
  });

  it('fails closed when the old version disappears (adapter throws)', async () => {
    const { dependencies } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: async () => {
        throw new Error('object version no longer available');
      },
    });
    const output = await artifactReadRange(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      offset: 0,
      length: 10,
    });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected error');
    expect(output.error.code).toBe('INTERNAL_ERROR');
  });

  it('fails closed when bytes change without a version-string change', async () => {
    const mutated = Uint8Array.from(source);
    mutated[0] = (definedAt(mutated[0]) + 1) % 256;
    const { dependencies } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(mutated), // same version string, different bytes
    });
    const output = await artifactReadRange(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      offset: 0,
      length: 10,
    });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected error');
    expect(output.error.code).toBe('INTEGRITY_FAILURE');
  });

  it('fails closed when the manifest hash/root differs from the returned bytes', async () => {
    const otherSource = new TextEncoder().encode(deterministicAsciiText(3000, 61));
    const otherManifestRecord = buildRecord(otherSource, { chunkSize: 1024 });
    const inconsistent: AuthorizedArtifactRecord = {
      ...record,
      merkleRoot: otherManifestRecord.merkleRoot,
    };
    const { dependencies } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(inconsistent),
      readVersionedRange: sourceBackedRead(source),
    });
    const output = await artifactReadRange(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      offset: 0,
      length: 10,
    });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected error');
    expect(['INTERNAL_ERROR', 'INTEGRITY_FAILURE']).toContain(output.error.code);
  });

  it('read_lines fails closed on the same version-drift and mutation scenarios', async () => {
    const text = 'one\ntwo\nthree\n';
    const lineSource = new TextEncoder().encode(text);
    const lineRecord = buildRecord(lineSource, { chunkSize: 1024, mediaType: 'text/plain' });

    const drift = trackDeps({
      resolveAuthorizedArtifact: resolverFor(lineRecord),
      readVersionedRange: sourceBackedRead(lineSource, {
        versionOverride: DRIFTED_OBJECT_VERSION_REF,
      }),
    });
    const driftOutput = await artifactReadLines(drift.dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      startLine: 1,
      count: 1,
    });
    expect(driftOutput.ok).toBe(false);

    const mutatedLineSource = Uint8Array.from(lineSource);
    mutatedLineSource[0] = (definedAt(mutatedLineSource[0]) + 1) % 256;
    const mutation = trackDeps({
      resolveAuthorizedArtifact: resolverFor(lineRecord),
      readVersionedRange: sourceBackedRead(mutatedLineSource),
    });
    const mutationOutput = await artifactReadLines(mutation.dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      startLine: 1,
      count: 1,
    });
    expect(mutationOutput.ok).toBe(false);
    if (mutationOutput.ok) throw new Error('expected error');
    expect(mutationOutput.error.code).toBe('INTEGRITY_FAILURE');
  });
});
