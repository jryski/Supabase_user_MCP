import { createHash } from 'node:crypto';

import {
  type ArtifactInspectionReceipt,
  ArtifactInspectionReceiptSchema,
  ArtifactReadHeadingOutputSchema,
  ArtifactSearchExactOutputSchema,
  artifactInspectionResponseByteLength,
  MAX_ARTIFACT_RESPONSE_BYTES,
  MAX_INLINE_CHUNK_HASHES,
  MAX_RANGE_BYTES,
  MAX_SEARCH_HITS,
  MAX_SEARCH_QUERY_LENGTH,
} from '@supabase-user-mcp/contracts';
import { describe, expect, it, vi } from 'vitest';

import {
  type AllowedChunkSize,
  buildArtifactChunkManifest,
  buildArtifactChunkProof,
  verifyArtifactChunkProof,
} from './artifact-chunk-manifest.js';
import {
  ARTIFACT_INSPECTOR_PROFILE_VERSION,
  type ArtifactInspectorDependencies,
  type ArtifactInspectorOperationalEvent,
  type ArtifactInspectorTrustedContext,
  ArtifactInspectorTrustedContextSchema,
  type AuthorizedArtifactRecord,
  artifactReadHeading,
  artifactReadLines,
  artifactReadRange,
  artifactSearchExact,
  artifactStat,
  createArtifactInspector,
  createArtifactInspectorTrustedContext,
  MAX_EXACT_SEARCH_SOURCE_BYTES,
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
const CAPABILITY_GRANT_REF = 'grant-1';
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
  inspectorCapabilityRef: {
    capability: 'artifact:inspect' as const,
    ref: CAPABILITY_GRANT_REF,
  },
  verifierAudience: 'audience-1',
  policyVersion: 'policy-2026.06.01',
  inspectorDeploymentGitCoordinate: GIT_COORDINATE,
};

function makeContext(
  overrides: Partial<{
    principalRef: string;
    inspectorClientRef: string;
    inspectorCapabilityRef: {
      capability: 'artifact:inspect';
      ref: string;
    };
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
    expect(Object.isFrozen(context.inspectorCapabilityRef)).toBe(true);
    expect(context.inspectorCapabilityRef).toEqual({
      capability: 'artifact:inspect',
      ref: CAPABILITY_GRANT_REF,
    });
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
        inspectorCapabilityRef: {
          capability: 'artifact:write',
          ref: CAPABILITY_GRANT_REF,
        },
      }),
    ).toThrow();
    const result = ArtifactInspectorTrustedContextSchema.safeParse({
      ...DEFAULT_CONTEXT_INPUT,
      inspectorCapabilityRef: {
        capability: 'artifact:write',
        ref: CAPABILITY_GRANT_REF,
      },
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
      // Malformed registry records have no validated source coordinates from
      // which a receipt may be constructed.
      expect(receipts).toHaveLength(0);
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

  it('maps canonical text-index line-count overflow to RESPONSE_LIMIT_EXCEEDED', async () => {
    const source = new TextEncoder().encode(`${'x\n'.repeat(10_000)}x`);
    const record = buildRecord(source, { chunkSize: 8192, mediaType: 'text/plain' });
    const tracked = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source),
    });
    const output = await artifactReadLines(tracked.dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      startLine: 1,
      count: 1,
    });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected line-index limit');
    expect(output.error.code).toBe('RESPONSE_LIMIT_EXCEEDED');
    expect(tracked.readCalls).toEqual([{ offset: 0, length: source.byteLength }]);
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
// artifact_read_heading
// ---------------------------------------------------------------------------

describe('artifact_read_heading', () => {
  it('returns exact original heading bytes with canonical range, hashes, proofs, and receipt', async () => {
    const text = `${'x'.repeat(1018)}\n# Boundary heading\r\nbody\n`;
    const source = new TextEncoder().encode(text);
    const before = Uint8Array.from(source);
    const record = buildRecord(source, { chunkSize: 1024, mediaType: 'text/markdown' });
    const { dependencies, receipts, readCalls, events } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source),
    });
    const output = await artifactReadHeading(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      headingId: 'boundary-heading',
    });

    expect(output.ok).toBe(true);
    if (!output.ok) throw new Error('expected heading success');
    expect(output.headingId).toBe('boundary-heading');
    expect(output.data).toBe('# Boundary heading');
    expect(output.contentTrust).toBe('untrusted');
    expect(output.integrity.returnedRange).toEqual({ offset: 1019, length: 18 });
    expect(output.integrity.returnedByteSha256).toBe(
      createHash('sha256').update('# Boundary heading', 'utf8').digest('hex'),
    );
    expect(output.integrity.verifiedCoveringChunkRange).toEqual({
      startChunkIndex: 0,
      endChunkIndex: 1,
    });
    expect(output.integrity.verifiedChunks).toHaveLength(2);
    const headingManifest = buildArtifactChunkManifest(source, 1024);
    for (const verified of output.integrity.verifiedChunks) {
      const proof = buildArtifactChunkProof(headingManifest, verified.chunkIndex);
      const chunk = definedAt(headingManifest.chunks[verified.chunkIndex]);
      expect(verified).toEqual({
        chunkIndex: proof.chunkIndex,
        byteStart: proof.byteStart,
        byteLength: proof.byteLength,
        chunkSha256: proof.chunkSha256,
        merkleProof: proof.proof,
      });
      expect(
        verifyArtifactChunkProof(
          source.subarray(chunk.byteStart, chunk.byteStart + chunk.byteLength),
          proof,
          record.merkleRoot,
        ),
      ).toBe(true);
    }
    const firstProof = buildArtifactChunkProof(headingManifest, 0);
    const firstSibling = definedAt(firstProof.proof[0]);
    const mutatedSibling = {
      ...firstSibling,
      siblingSha256: `${firstSibling.siblingSha256.slice(0, 63)}${
        firstSibling.siblingSha256.endsWith('0') ? '1' : '0'
      }`,
    };
    const mutatedProof = { ...firstProof, proof: [mutatedSibling, ...firstProof.proof.slice(1)] };
    const firstChunk = definedAt(headingManifest.chunks[0]);
    expect(
      verifyArtifactChunkProof(
        source.subarray(firstChunk.byteStart, firstChunk.byteStart + firstChunk.byteLength),
        mutatedProof,
        record.merkleRoot,
      ),
    ).toBe(false);
    expect(readCalls).toEqual([{ offset: 0, length: source.byteLength }]);
    expect(source).toEqual(before);
    expect(receipts).toHaveLength(1);
    expect(ArtifactInspectionReceiptSchema.safeParse(definedAt(receipts[0])).success).toBe(true);
    expect(definedAt(receipts[0]).operationDetail).toEqual({
      operation: 'artifact_read_heading',
      requestedHeadingId: 'boundary-heading',
      returnedRange: { offset: 1019, length: 18 },
      returnedByteSha256: output.integrity.returnedByteSha256,
    });
    expect(definedAt(events[0]).operation).toBe('artifact_read_heading');
    expect(definedAt(events[0]).resultClass).toBe('success');
    expect(Object.isFrozen(definedAt(events[0]))).toBe(true);
    expect(Object.isFrozen(definedAt(receipts[0]))).toBe(true);
    expect(Object.isFrozen(definedAt(receipts[0]).operationDetail)).toBe(true);
    expect(Object.isFrozen(output)).toBe(true);
    expect(Object.isFrozen(output.integrity)).toBe(true);
  });

  it('uses deterministic duplicate and Unicode IDs and ignores headings inside fenced blocks', async () => {
    const source = new TextEncoder().encode(
      '# Title\n# Title\n```markdown\n# Hidden\n``` not-a-close\n# Still hidden\n````\n# Café\n',
    );
    const record = buildRecord(source, { mediaType: 'text/markdown' });
    const tracked = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source),
    });
    const inspector = createArtifactInspector(tracked.dependencies);
    const context = makeContext();
    const duplicate = await inspector.artifactReadHeading(context, {
      artifactId: ARTIFACT_ID,
      headingId: 'title-2',
    });
    const unicode = await inspector.artifactReadHeading(context, {
      artifactId: ARTIFACT_ID,
      headingId: 'cafu--e9--',
    });
    const fenced = await inspector.artifactReadHeading(context, {
      artifactId: ARTIFACT_ID,
      headingId: 'hidden',
    });
    const stillFenced = await inspector.artifactReadHeading(context, {
      artifactId: ARTIFACT_ID,
      headingId: 'still-hidden',
    });
    if (!duplicate.ok || !unicode.ok) throw new Error('expected indexed headings');
    expect(duplicate.data).toBe('# Title');
    expect(unicode.data).toBe('# Café');
    expect(fenced).toEqual(publicArtifactInspectionUnavailableForTest());
    expect(stillFenced).toEqual(publicArtifactInspectionUnavailableForTest());
  });

  it('rejects invalid input before resolution and non-Markdown media before byte read', async () => {
    let resolverCalls = 0;
    const invalid = trackDeps({
      resolveAuthorizedArtifact: async () => {
        resolverCalls += 1;
        return null;
      },
    });
    for (const rawInput of [
      { artifactId: ARTIFACT_ID, headingId: '' },
      { artifactId: ARTIFACT_ID, headingId: 'bad heading' },
      { artifactId: ARTIFACT_ID, headingId: 'title', path: '/secret' },
    ]) {
      const output = await artifactReadHeading(invalid.dependencies, makeContext(), rawInput);
      expect(output.ok).toBe(false);
      if (output.ok) throw new Error('expected invalid request');
      expect(output.error.code).toBe('INVALID_REQUEST');
    }
    expect(resolverCalls).toBe(0);

    const source = new TextEncoder().encode('# Title\n');
    const record = buildRecord(source, { mediaType: 'text/plain' });
    const unsupported = trackDeps({ resolveAuthorizedArtifact: resolverFor(record) });
    const output = await artifactReadHeading(unsupported.dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      headingId: 'title',
    });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected unsupported media');
    expect(output.error.code).toBe('UNSUPPORTED');
    expect(unsupported.readCalls).toHaveLength(0);
  });

  it('maps source and heading profile ceilings to RESPONSE_LIMIT_EXCEEDED before disclosure', async () => {
    const oversized = new TextEncoder().encode(
      `# Title\n${'x'.repeat(MAX_LINE_SOURCE_SCAN_BYTES)}`,
    );
    const oversizedRecord = buildRecord(oversized, { chunkSize: 8192, mediaType: 'text/markdown' });
    const oversizedTracked = trackDeps({ resolveAuthorizedArtifact: resolverFor(oversizedRecord) });
    const oversizedOutput = await artifactReadHeading(
      oversizedTracked.dependencies,
      makeContext(),
      { artifactId: ARTIFACT_ID, headingId: 'title' },
    );
    expect(oversizedOutput.ok).toBe(false);
    if (oversizedOutput.ok) throw new Error('expected source limit');
    expect(oversizedOutput.error.code).toBe('RESPONSE_LIMIT_EXCEEDED');
    expect(oversizedTracked.readCalls).toHaveLength(0);

    const overlongHeading = new TextEncoder().encode(`# ${'x'.repeat(513)}\n`);
    const overlongRecord = buildRecord(overlongHeading, { mediaType: 'text/markdown' });
    const overlongTracked = trackDeps({
      resolveAuthorizedArtifact: resolverFor(overlongRecord),
      readVersionedRange: sourceBackedRead(overlongHeading),
    });
    const overlongOutput = await artifactReadHeading(overlongTracked.dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      headingId: 'x',
    });
    expect(overlongOutput.ok).toBe(false);
    if (overlongOutput.ok) throw new Error('expected heading limit');
    expect(overlongOutput.error.code).toBe('RESPONSE_LIMIT_EXCEEDED');
  });

  it('makes unknown heading and missing/unauthorized/exact-version-unavailable byte-identical', async () => {
    const source = new TextEncoder().encode('# Known\n');
    const record = buildRecord(source, { mediaType: 'text/markdown' });
    const unknown = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source),
    });
    const missing = trackDeps({ resolveAuthorizedArtifact: async () => null });
    const exactVersionGone = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: async () => null,
    });
    const outputs = await Promise.all([
      artifactReadHeading(unknown.dependencies, makeContext(), {
        artifactId: ARTIFACT_ID,
        headingId: 'unknown',
      }),
      artifactReadHeading(missing.dependencies, makeContext(), {
        artifactId: ARTIFACT_ID,
        headingId: 'known',
      }),
      artifactReadHeading(exactVersionGone.dependencies, makeContext(), {
        artifactId: ARTIFACT_ID,
        headingId: 'known',
      }),
    ]);
    expect(outputs.map((output) => JSON.stringify(output))).toEqual(
      Array(3).fill(JSON.stringify(outputs[0])),
    );
    expect(unknown.receipts).toHaveLength(0);
    expect(missing.receipts).toHaveLength(0);
    expect(exactVersionGone.receipts).toHaveLength(0);
  });

  it.each([
    [
      'version drift',
      'INTEGRITY_FAILURE',
      (source: Uint8Array) =>
        sourceBackedRead(source, { versionOverride: DRIFTED_OBJECT_VERSION_REF }),
    ],
    [
      'short read',
      'INTEGRITY_FAILURE',
      (source: Uint8Array) => async (_c: unknown, _l: unknown, version: string) => ({
        bytes: source.subarray(0, source.byteLength - 1),
        objectVersionRef: version,
      }),
    ],
    [
      'long read',
      'INTEGRITY_FAILURE',
      (source: Uint8Array) => async (_c: unknown, _l: unknown, version: string) => ({
        bytes: Uint8Array.from([...source, 0x20]),
        objectVersionRef: version,
      }),
    ],
    ['malformed read', 'INTERNAL_ERROR', (_source: Uint8Array) => async () => ({}) as never],
    [
      'dependency throw',
      'INTERNAL_ERROR',
      (_source: Uint8Array) => async () => {
        throw new Error('secret-reader-failure');
      },
    ],
  ] as const)('fails closed on %s without retry', async (_label, expectedCode, readerFactory) => {
    const source = new TextEncoder().encode('# Known\nbody\n');
    const record = buildRecord(source, { mediaType: 'text/markdown' });
    let calls = 0;
    const reader = readerFactory(source) as ArtifactInspectorDependencies['readVersionedRange'];
    const tracked = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: async (...args) => {
        calls += 1;
        return reader(...args);
      },
    });
    const output = await artifactReadHeading(tracked.dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      headingId: 'known',
    });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected failure');
    expect(output.error.code).toBe(expectedCode);
    expect(calls).toBe(1);
    expect(
      JSON.stringify({ output, events: tracked.events, receipts: tracked.receipts }),
    ).not.toContain('secret-reader-failure');
  });

  it('fails closed for source, manifest-root, and chunk-hash mutations', async () => {
    const source = new TextEncoder().encode('# Known\nbody\n');
    const record = buildRecord(source, { mediaType: 'text/markdown' });
    const changedDigest = `${record.sourceSha256.slice(0, 63)}${record.sourceSha256.endsWith('0') ? '1' : '0'}`;
    const changedRoot = `${record.merkleRoot.slice(0, 63)}${record.merkleRoot.endsWith('0') ? '1' : '0'}`;
    const firstChunkHash = definedAt(record.chunkSha256s[0]);
    const changedChunkHash = `${firstChunkHash.slice(0, 63)}${firstChunkHash.endsWith('0') ? '1' : '0'}`;
    const scenarios: AuthorizedArtifactRecord[] = [
      { ...record, sourceSha256: changedDigest },
      { ...record, merkleRoot: changedRoot },
      { ...record, chunkSha256s: [changedChunkHash] },
    ];
    for (const mutatedRecord of scenarios) {
      const tracked = trackDeps({
        resolveAuthorizedArtifact: resolverFor(mutatedRecord),
        readVersionedRange: sourceBackedRead(source),
      });
      const output = await artifactReadHeading(tracked.dependencies, makeContext(), {
        artifactId: ARTIFACT_ID,
        headingId: 'known',
      });
      expect(output.ok).toBe(false);
      if (output.ok) throw new Error('expected integrity failure');
      expect(['INTEGRITY_FAILURE', 'INTERNAL_ERROR']).toContain(output.error.code);
    }
  });

  it('output schema catches returned hash/content mutations and the wire stays bounded', async () => {
    const source = new TextEncoder().encode('# Known\n');
    const record = buildRecord(source, { mediaType: 'text/markdown' });
    const tracked = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source),
    });
    const output = await artifactReadHeading(tracked.dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      headingId: 'known',
    });
    if (!output.ok) throw new Error('expected success');
    expect(ArtifactReadHeadingOutputSchema.safeParse(output).success).toBe(true);
    expect(
      ArtifactReadHeadingOutputSchema.safeParse({ ...output, data: `${output.data}!` }).success,
    ).toBe(false);
    expect(
      ArtifactReadHeadingOutputSchema.safeParse({
        ...output,
        integrity: { ...output.integrity, returnedByteSha256: '0'.repeat(64) },
      }).success,
    ).toBe(false);
    expect(artifactInspectionResponseByteLength(null, output)).toBeLessThanOrEqual(
      MAX_ARTIFACT_RESPONSE_BYTES,
    );
  });

  it('keeps concurrent heading reads isolated by artifact and principal', async () => {
    const sourceA = new TextEncoder().encode('# Alpha\n');
    const sourceB = new TextEncoder().encode('# Beta\n');
    const recordA = buildRecord(sourceA, {
      artifactId: ARTIFACT_ID,
      mediaType: 'text/markdown',
      objectVersionRef: 'ov_aaaaaaaaaaaaaaaaaaaaaaaa',
    });
    const recordB = buildRecord(sourceB, {
      artifactId: OTHER_ARTIFACT_ID,
      mediaType: 'text/markdown',
      objectVersionRef: 'ov_bbbbbbbbbbbbbbbbbbbbbbbb',
    });
    const records = new Map([
      [ARTIFACT_ID, { record: recordA, bytes: sourceA }],
      [OTHER_ARTIFACT_ID, { record: recordB, bytes: sourceB }],
    ]);
    const tracked = trackDeps({
      resolveAuthorizedArtifact: async (_context, artifactId) =>
        records.get(artifactId)?.record ?? null,
      readVersionedRange: async (_context, _locator, version, offset, length) => {
        const entry = [...records.values()].find(
          (candidate) => candidate.record.objectVersionRef === version,
        );
        if (entry === undefined) return null;
        return { bytes: entry.bytes.subarray(offset, offset + length), objectVersionRef: version };
      },
    });
    const [alpha, beta] = await Promise.all([
      artifactReadHeading(tracked.dependencies, makeContext({ principalRef: 'principal-A' }), {
        artifactId: ARTIFACT_ID,
        headingId: 'alpha',
      }),
      artifactReadHeading(tracked.dependencies, makeContext({ principalRef: 'principal-B' }), {
        artifactId: OTHER_ARTIFACT_ID,
        headingId: 'beta',
      }),
    ]);
    if (!alpha.ok || !beta.ok) throw new Error('expected both headings');
    expect(alpha.data).toBe('# Alpha');
    expect(beta.data).toBe('# Beta');
  });
});

function publicArtifactInspectionUnavailableForTest() {
  return {
    ok: false,
    error: {
      code: 'RESOURCE_UNAVAILABLE',
      message: 'Artifact is unavailable.',
      retryable: false,
    },
  } as const;
}

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
    const deniedGrantRefs = new Set(['grant-denied']);
    const { dependencies } = trackDeps({
      resolveAuthorizedArtifact: async (context) =>
        deniedGrantRefs.has(context.inspectorCapabilityRef.ref) ? null : record,
    });
    const output = await artifactStat(
      dependencies,
      makeContext({
        inspectorClientRef: 'client-ok',
        inspectorCapabilityRef: { capability: 'artifact:inspect', ref: 'grant-denied' },
      }),
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
    const exactVersionUnavailableDeps = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: async () => null,
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
      artifactReadRange(exactVersionUnavailableDeps, makeContext(), {
        artifactId: ARTIFACT_ID,
        offset: 0,
        length: 1,
      }),
      artifactReadLines(exactVersionUnavailableDeps, makeContext(), {
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
// Injected dependency and runtime-record boundaries
// ---------------------------------------------------------------------------

describe('injected dependency boundaries', () => {
  const source = new TextEncoder().encode('alpha\nbeta\ngamma\n');
  const record = buildRecord(source, { chunkSize: 1024, mediaType: 'text/plain' });

  it('normalizes and redacts a resolver exception without retrying', async () => {
    let calls = 0;
    const { dependencies, events, receipts, readCalls } = trackDeps({
      resolveAuthorizedArtifact: async () => {
        calls += 1;
        throw new Error('resolver-secret-sentinel');
      },
    });
    const output = await artifactStat(dependencies, makeContext(), { artifactId: ARTIFACT_ID });
    expect(output).toEqual({
      ok: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Request could not be completed.',
        retryable: false,
      },
    });
    expect(calls).toBe(1);
    expect(events).toHaveLength(1);
    expect(definedAt(events[0]).resultClass).toBe('INTERNAL_ERROR');
    expect(receipts).toHaveLength(0);
    expect(readCalls).toHaveLength(0);
    expect(JSON.stringify({ output, events, receipts })).not.toContain('resolver-secret-sentinel');
  });

  it.each([
    [
      'a clock exception',
      () => {
        throw new Error('clock-secret-sentinel');
      },
    ],
    ['an invalid clock Date', () => new Date(Number.NaN)],
  ])('normalizes %s before resolution', async (_label, now) => {
    let resolverCalls = 0;
    const { dependencies, events, receipts, readCalls } = trackDeps({
      resolveAuthorizedArtifact: async () => {
        resolverCalls += 1;
        return record;
      },
      now,
    });
    const output = await artifactStat(dependencies, makeContext(), { artifactId: ARTIFACT_ID });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected error');
    expect(output.error.code).toBe('INTERNAL_ERROR');
    expect(resolverCalls).toBe(0);
    expect(readCalls).toHaveLength(0);
    expect(receipts).toHaveLength(0);
    expect(events).toHaveLength(1);
    expect(JSON.stringify({ output, events })).not.toContain('clock-secret-sentinel');
  });

  it('normalizes and redacts a byte-reader exception without retrying', async () => {
    let calls = 0;
    const { dependencies, events, receipts } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: async () => {
        calls += 1;
        throw new Error('read-secret-sentinel');
      },
    });
    const output = await artifactReadRange(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      offset: 0,
      length: 5,
    });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected error');
    expect(output.error.code).toBe('INTERNAL_ERROR');
    expect(calls).toBe(1);
    expect(events).toHaveLength(1);
    expect(receipts).toHaveLength(1);
    expect(JSON.stringify({ output, events, receipts })).not.toContain('read-secret-sentinel');
  });

  it('maps exact immutable-version disappearance to the byte-identical unavailable result for range and lines', async () => {
    const range = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: async () => null,
    });
    const lines = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: async () => null,
    });
    const missing = trackDeps({ resolveAuthorizedArtifact: async () => null });

    const rangeOutput = await artifactReadRange(range.dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      offset: 0,
      length: 5,
    });
    const linesOutput = await artifactReadLines(lines.dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      startLine: 1,
      count: 1,
    });
    const missingOutput = await artifactStat(missing.dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
    });

    expect(rangeOutput).toBe(missingOutput);
    expect(linesOutput).toBe(missingOutput);
    expect(range.receipts).toHaveLength(0);
    expect(lines.receipts).toHaveLength(0);
    expect(range.readCalls).toHaveLength(1);
    expect(lines.readCalls).toHaveLength(1);
    expect(definedAt(range.events[0]).resultClass).toBe('RESOURCE_UNAVAILABLE');
    expect(definedAt(lines.events[0]).resultClass).toBe('RESOURCE_UNAVAILABLE');
  });

  it.each([
    ['a malformed read-result object', {}],
    [
      'non-Uint8Array bytes',
      { bytes: [97, 108, 112, 104, 97], objectVersionRef: OBJECT_VERSION_REF },
    ],
    ['a malformed returned objectVersionRef', { bytes: source, objectVersionRef: 'bad' }],
  ])('fails closed with INTERNAL_ERROR for %s', async (_label, malformedResult) => {
    const { dependencies, events } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: async () => malformedResult as never,
    });
    const output = await artifactReadRange(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      offset: 0,
      length: 5,
    });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected error');
    expect(output.error.code).toBe('INTERNAL_ERROR');
    expect(events).toHaveLength(1);
  });

  it('retains Buffer compatibility as a Uint8Array subtype', async () => {
    const { dependencies } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: async (_context, _locator, versionRef, offset, length) => ({
        bytes: Buffer.from(source.subarray(offset, offset + length)),
        objectVersionRef: versionRef,
      }),
    });
    const output = await artifactReadRange(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      offset: 0,
      length: 5,
    });
    expect(output.ok).toBe(true);
  });

  it('does not leak dependency or locator sentinels through outputs, receipts, events, thrown errors, stdout, or stderr', async () => {
    const stdout = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const observed: unknown[] = [];
    try {
      const resolverFailure = trackDeps({
        resolveAuthorizedArtifact: async () => {
          throw new Error('resolver-secret-sentinel');
        },
      });
      observed.push(
        await artifactStat(resolverFailure.dependencies, makeContext(), {
          artifactId: ARTIFACT_ID,
        }),
        resolverFailure.events,
        resolverFailure.receipts,
      );

      const readFailure = trackDeps({
        resolveAuthorizedArtifact: resolverFor(
          buildRecord(source, { internalLocator: 'locator-secret-sentinel' }),
        ),
        readVersionedRange: async () => {
          throw new Error('read-secret-sentinel locator-secret-sentinel');
        },
      });
      observed.push(
        await artifactReadRange(readFailure.dependencies, makeContext(), {
          artifactId: ARTIFACT_ID,
          offset: 0,
          length: 5,
        }),
        readFailure.events,
        readFailure.receipts,
      );

      const clockFailure = trackDeps({
        resolveAuthorizedArtifact: resolverFor(record),
        now: () => {
          throw new Error('clock-secret-sentinel');
        },
      });
      observed.push(
        await artifactStat(clockFailure.dependencies, makeContext(), { artifactId: ARTIFACT_ID }),
        clockFailure.events,
        clockFailure.receipts,
      );
    } finally {
      const writes = [...stdout.mock.calls, ...stderr.mock.calls];
      stdout.mockRestore();
      stderr.mockRestore();
      observed.push(writes);
    }
    const serialized = JSON.stringify(observed);
    for (const sentinel of [
      'resolver-secret-sentinel',
      'read-secret-sentinel',
      'clock-secret-sentinel',
      'locator-secret-sentinel',
    ]) {
      expect(serialized).not.toContain(sentinel);
    }
  });
});

describe('strict resolved-record validation', () => {
  const source = new TextEncoder().encode('validated source\n');
  const baseRecord = buildRecord(source, { chunkSize: 1024, mediaType: 'text/plain' });

  it('rejects requested artifact A / returned record B before any byte read', async () => {
    const mismatched = { ...baseRecord, artifactId: OTHER_ARTIFACT_ID };
    const { dependencies, events, receipts, readCalls } = trackDeps({
      resolveAuthorizedArtifact: async () => mismatched,
      readVersionedRange: sourceBackedRead(source),
    });
    const output = await artifactReadRange(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      offset: 0,
      length: 5,
    });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected error');
    expect(output.error.code).toBe('INTERNAL_ERROR');
    expect(readCalls).toHaveLength(0);
    expect(receipts).toHaveLength(0);
    expect(events).toHaveLength(1);
    expect(definedAt(events[0]).resultClass).toBe('INTERNAL_ERROR');
  });

  it('rejects a malformed objectVersionRef before any byte read or receipt', async () => {
    const malformed = { ...baseRecord, objectVersionRef: 'bad' };
    const { dependencies, receipts, readCalls } = trackDeps({
      resolveAuthorizedArtifact: async () => malformed,
      readVersionedRange: sourceBackedRead(source),
    });
    const output = await artifactReadRange(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      offset: 0,
      length: 5,
    });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected error');
    expect(output.error.code).toBe('INTERNAL_ERROR');
    expect(readCalls).toHaveLength(0);
    expect(receipts).toHaveLength(0);
  });

  it('rejects malformed identity, digest, media, time, chunk-ref, array, and geometry fields before read or receipt', async () => {
    const badDigest = 'A'.repeat(64);
    const malformedRecords: ReadonlyArray<readonly [string, unknown]> = [
      ['artifactId grammar', { ...baseRecord, artifactId: 'bad' }],
      ['source hash', { ...baseRecord, sourceSha256: badDigest }],
      ['root hash', { ...baseRecord, merkleRoot: badDigest }],
      ['raw chunk hash', { ...baseRecord, chunkSha256s: [badDigest] }],
      ['leaf hash', { ...baseRecord, merkleLeafSha256s: [badDigest] }],
      ['empty media type', { ...baseRecord, mediaType: '' }],
      ['oversized media type', { ...baseRecord, mediaType: 'x'.repeat(256) }],
      ['createdAt without offset', { ...baseRecord, createdAt: '2026-01-01T00:00:00' }],
      ['invalid expiresAt', { ...baseRecord, expiresAt: 'not-a-date' }],
      ['chunkHashesRef grammar', { ...baseRecord, chunkHashesRef: 'bad' }],
      ['unsupported chunk size', { ...baseRecord, chunkSize: 2048 }],
      ['negative chunk count', { ...baseRecord, chunkCount: -1 }],
      ['chunk-count ceiling', { ...baseRecord, chunkCount: 4097 }],
      ['source byte ceiling', { ...baseRecord, byteLength: 1_048_577 }],
      ['array length mismatch', { ...baseRecord, chunkSha256s: [] }],
      [
        'array-length ceiling',
        {
          ...baseRecord,
          chunkSha256s: Array.from({ length: 4097 }, () => baseRecord.sourceSha256),
        },
      ],
      ['geometry mismatch', { ...baseRecord, byteLength: baseRecord.byteLength + 1024 }],
    ];

    for (const [label, malformed] of malformedRecords) {
      const { dependencies, events, receipts, readCalls } = trackDeps({
        resolveAuthorizedArtifact: async () => malformed as AuthorizedArtifactRecord,
        readVersionedRange: sourceBackedRead(source),
      });
      const output = await artifactReadRange(dependencies, makeContext(), {
        artifactId: ARTIFACT_ID,
        offset: 0,
        length: 5,
      });
      expect(output.ok, label).toBe(false);
      if (output.ok) throw new Error(`expected error for ${label}`);
      expect(output.error.code, label).toBe('INTERNAL_ERROR');
      expect(readCalls, label).toHaveLength(0);
      expect(receipts, label).toHaveLength(0);
      expect(events, label).toHaveLength(1);
      expect(definedAt(events[0]).resultClass, label).toBe('INTERNAL_ERROR');
    }
  });

  it('passes the internal locator opaquely by reference without freezing or exposing it', async () => {
    const internalLocator = { secret: 'locator-secret-sentinel', nested: { mutable: true } };
    const record = buildRecord(source, { internalLocator });
    let receivedLocator: unknown;
    const { dependencies, events, receipts } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: async (_context, locator, versionRef, offset, length) => {
        receivedLocator = locator;
        return {
          bytes: source.subarray(offset, offset + length),
          objectVersionRef: versionRef,
        };
      },
    });
    const output = await artifactReadRange(dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      offset: 0,
      length: 5,
    });
    expect(output.ok).toBe(true);
    expect(receivedLocator).toBe(internalLocator);
    expect(Object.isFrozen(internalLocator)).toBe(false);
    expect(Object.isFrozen(internalLocator.nested)).toBe(false);
    expect(JSON.stringify({ output, events, receipts })).not.toContain('locator-secret-sentinel');
  });
});

describe('artifact_search_exact', () => {
  const searchText = 'needle café\nNeedle cafe\u0301\ncafé café\nneedleneedle\n';
  const searchBytes = new TextEncoder().encode(searchText);
  const searchRecord = buildRecord(searchBytes, { chunkSize: 1024, mediaType: 'text/markdown' });

  it('returns deterministic ASCII and multibyte exact matches with hardcoded byte offsets and hashes', async () => {
    const tracked = trackDeps({
      resolveAuthorizedArtifact: resolverFor(searchRecord),
      readVersionedRange: sourceBackedRead(searchBytes),
    });
    const ascii = await artifactSearchExact(tracked.dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      query: 'needle',
      maxHits: 10,
    });
    expect(ascii.ok).toBe(true);
    if (!ascii.ok) throw new Error('expected ASCII search success');
    expect(ascii.hits).toEqual([
      {
        matchRange: { offset: 0, length: 6 },
        snippetRange: { offset: 0, length: 6 },
        snippetSha256: '09881f6ed93360a2f6ad81f435a8ca51ca4575d0f954f197ff8f7d16c6565562',
        lineNumber: 1,
        snippet: 'needle',
        contentTrust: 'untrusted',
      },
      {
        matchRange: { offset: 39, length: 6 },
        snippetRange: { offset: 39, length: 6 },
        snippetSha256: '09881f6ed93360a2f6ad81f435a8ca51ca4575d0f954f197ff8f7d16c6565562',
        lineNumber: 4,
        snippet: 'needle',
        contentTrust: 'untrusted',
      },
      {
        matchRange: { offset: 45, length: 6 },
        snippetRange: { offset: 45, length: 6 },
        snippetSha256: '09881f6ed93360a2f6ad81f435a8ca51ca4575d0f954f197ff8f7d16c6565562',
        lineNumber: 4,
        snippet: 'needle',
        contentTrust: 'untrusted',
      },
    ]);

    const multibyte = await artifactSearchExact(tracked.dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      query: 'café',
      maxHits: 10,
    });
    expect(multibyte.ok).toBe(true);
    if (!multibyte.ok) throw new Error('expected multibyte search success');
    expect(
      multibyte.hits.map((hit) => [hit.matchRange.offset, hit.matchRange.length, hit.lineNumber]),
    ).toEqual([
      [7, 5, 1],
      [27, 5, 3],
      [33, 5, 3],
    ]);
    expect(multibyte.hits.every((hit) => hit.snippet === 'café')).toBe(true);
    expect(
      multibyte.hits.every(
        (hit) =>
          hit.snippetSha256 === '850f7dc43910ff890f8879c0ed26fe697c93a067ad93a7d50f466a7028a9bf4e',
      ),
    ).toBe(true);
    expect(tracked.readCalls).toEqual([
      { offset: 0, length: 52 },
      { offset: 0, length: 52 },
    ]);
  });

  it('is case-sensitive, performs no Unicode normalization, uses non-overlapping matches, and truncates without a total', async () => {
    const tracked = trackDeps({
      resolveAuthorizedArtifact: resolverFor(searchRecord),
      readVersionedRange: sourceBackedRead(searchBytes),
    });
    const upper = await artifactSearchExact(tracked.dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      query: 'Needle',
      maxHits: 10,
    });
    const decomposed = await artifactSearchExact(tracked.dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      query: 'cafe\u0301',
      maxHits: 10,
    });
    const nonoverlapSource = new TextEncoder().encode('aaaaa');
    const nonoverlapRecord = buildRecord(nonoverlapSource, { chunkSize: 1024 });
    const nonoverlapDeps = trackDeps({
      resolveAuthorizedArtifact: resolverFor(nonoverlapRecord),
      readVersionedRange: sourceBackedRead(nonoverlapSource),
    });
    const nonoverlap = await artifactSearchExact(nonoverlapDeps.dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      query: 'aa',
      maxHits: 2,
    });
    const truncated = await artifactSearchExact(tracked.dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      query: 'needle',
      maxHits: 1,
    });
    if (!upper.ok || !decomposed.ok || !nonoverlap.ok || !truncated.ok) {
      throw new Error('expected exact-search success');
    }
    expect(upper.hits.map((hit) => hit.matchRange.offset)).toEqual([13]);
    expect(decomposed.hits.map((hit) => hit.matchRange.offset)).toEqual([20]);
    expect(nonoverlap.hits.map((hit) => hit.matchRange.offset)).toEqual([0, 2]);
    expect(truncated.hits).toHaveLength(1);
    expect(Object.keys(truncated).toSorted()).toEqual(['hits', 'integrity', 'ok']);
    expect(JSON.stringify(truncated)).not.toMatch(/total|more|truncat/i);
  });

  it('uses the canonical starting line for a cross-line match', async () => {
    const tracked = trackDeps({
      resolveAuthorizedArtifact: resolverFor(searchRecord),
      readVersionedRange: sourceBackedRead(searchBytes),
    });
    const output = await artifactSearchExact(tracked.dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      query: 'café\nNeedle',
      maxHits: 10,
    });
    if (!output.ok) throw new Error('expected search success');
    expect(output.hits).toHaveLength(1);
    expect(output.hits[0]).toMatchObject({
      matchRange: { offset: 7, length: 12 },
      snippetRange: { offset: 7, length: 12 },
      lineNumber: 1,
      snippet: 'café\nNeedle',
    });
  });

  it('returns zero hits successfully with complete-source integrity and every chunk verified', async () => {
    const source = new TextEncoder().encode(deterministicAsciiText(2500, 77));
    const record = buildRecord(source, { chunkSize: 1024 });
    const tracked = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source),
    });
    const output = await artifactSearchExact(tracked.dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      query: 'definitely-not-present',
      maxHits: 5,
    });
    if (!output.ok) throw new Error('expected zero-hit success');
    expect(output.hits).toEqual([]);
    expect(output.integrity.verifiedChunks).toHaveLength(record.chunkCount);
    expect(output.integrity.verifiedCoveringChunkRange).toEqual({
      startChunkIndex: 0,
      endChunkIndex: record.chunkCount - 1,
    });
    expect(output.integrity.returnedRange).toEqual({ offset: 0, length: source.byteLength });
    expect(output.integrity.returnedByteSha256).toBe(record.sourceSha256);
  });

  it('returns unavailable for an empty artifact and enforces the exact source byte ceiling before reading', async () => {
    const emptyRecord = buildRecord(new Uint8Array(0), { chunkSize: 1024 });
    const empty = trackDeps({ resolveAuthorizedArtifact: resolverFor(emptyRecord) });
    const emptyOutput = await artifactSearchExact(empty.dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      query: 'x',
      maxHits: 1,
    });
    expect(emptyOutput).toEqual({
      ok: false,
      error: {
        code: 'RESOURCE_UNAVAILABLE',
        message: 'Artifact is unavailable.',
        retryable: false,
      },
    });
    expect(empty.readCalls).toEqual([]);

    const acceptedSource = new TextEncoder().encode(
      `x${'a'.repeat(MAX_EXACT_SEARCH_SOURCE_BYTES - 1)}`,
    );
    const acceptedRecord = buildRecord(acceptedSource, { chunkSize: 1024 });
    const accepted = trackDeps({
      resolveAuthorizedArtifact: resolverFor(acceptedRecord),
      readVersionedRange: sourceBackedRead(acceptedSource),
    });
    expect(
      await artifactSearchExact(accepted.dependencies, makeContext(), {
        artifactId: ARTIFACT_ID,
        query: 'x',
        maxHits: 1,
      }),
    ).toMatchObject({ ok: true });
    expect(accepted.readCalls).toEqual([{ offset: 0, length: MAX_EXACT_SEARCH_SOURCE_BYTES }]);

    const rejectedSource = new TextEncoder().encode('x'.repeat(MAX_EXACT_SEARCH_SOURCE_BYTES + 1));
    const rejectedRecord = buildRecord(rejectedSource, { chunkSize: 1024 });
    const rejected = trackDeps({
      resolveAuthorizedArtifact: resolverFor(rejectedRecord),
      readVersionedRange: sourceBackedRead(rejectedSource),
    });
    expect(
      await artifactSearchExact(rejected.dependencies, makeContext(), {
        artifactId: ARTIFACT_ID,
        query: 'x',
        maxHits: 1,
      }),
    ).toMatchObject({ ok: false, error: { code: 'RESPONSE_LIMIT_EXCEEDED' } });
    expect(rejected.readCalls).toEqual([]);
    expect(acceptedRecord.chunkCount).toBe(8);
    expect(rejectedRecord.chunkCount).toBe(9);
    // With the accepted 1,024-byte minimum chunk size, a 16/17-chunk
    // search source would already exceed the stronger 8,192-byte gate.
    expect(16 * 1024).toBeGreaterThan(MAX_EXACT_SEARCH_SOURCE_BYTES);
  });

  it('accepts a 256-byte query and rejects 257 bytes plus multibyte byte-overflow before dependencies', async () => {
    const ascii256 = 'q'.repeat(MAX_SEARCH_QUERY_LENGTH);
    const source = new TextEncoder().encode(ascii256);
    const record = buildRecord(source, { chunkSize: 1024 });
    const accepted = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source),
    });
    const output = await artifactSearchExact(accepted.dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      query: ascii256,
      maxHits: 1,
    });
    if (!output.ok) throw new Error('expected 256-byte query success');
    expect(output.integrity.requestedRange).toEqual({ kind: 'search_exact', queryLength: 256 });

    for (const query of ['q'.repeat(257), 'é'.repeat(129)]) {
      let resolverCalls = 0;
      const rejected = trackDeps({
        resolveAuthorizedArtifact: async () => {
          resolverCalls += 1;
          return record;
        },
      });
      const result = await artifactSearchExact(rejected.dependencies, makeContext(), {
        artifactId: ARTIFACT_ID,
        query,
        maxHits: 1,
      });
      expect(result).toMatchObject({ ok: false, error: { code: 'INVALID_REQUEST' } });
      expect(resolverCalls).toBe(0);
      expect(rejected.readCalls).toEqual([]);
    }
    const multibyte256 = 'é'.repeat(128);
    const multibyteSource = new TextEncoder().encode(multibyte256);
    const multibyteRecord = buildRecord(multibyteSource, { chunkSize: 1024 });
    const multibyte = trackDeps({
      resolveAuthorizedArtifact: resolverFor(multibyteRecord),
      readVersionedRange: sourceBackedRead(multibyteSource),
    });
    const multibyteOutput = await artifactSearchExact(multibyte.dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      query: multibyte256,
      maxHits: 1,
    });
    if (!multibyteOutput.ok) throw new Error('expected 256-byte multibyte query success');
    expect(multibyteOutput.integrity.requestedRange).toEqual({
      kind: 'search_exact',
      queryLength: 256,
    });
  });

  it('denies unsupported media and unavailable authorization/expiry/version without retries', async () => {
    const unsupportedRecord = buildRecord(searchBytes, { mediaType: 'application/pdf' });
    const unsupported = trackDeps({ resolveAuthorizedArtifact: resolverFor(unsupportedRecord) });
    expect(
      await artifactSearchExact(unsupported.dependencies, makeContext(), {
        artifactId: ARTIFACT_ID,
        query: 'needle',
        maxHits: 1,
      }),
    ).toMatchObject({ ok: false, error: { code: 'UNSUPPORTED' } });
    expect(unsupported.readCalls).toEqual([]);

    const guarded = trackDeps({
      resolveAuthorizedArtifact: async (context) =>
        context.principalRef === 'principal-ok' &&
        context.inspectorClientRef === 'client-ok' &&
        context.inspectorCapabilityRef.ref === CAPABILITY_GRANT_REF
          ? searchRecord
          : null,
      readVersionedRange: sourceBackedRead(searchBytes),
    });
    for (const context of [
      makeContext({ principalRef: 'principal-wrong' }),
      makeContext({ inspectorClientRef: 'client-wrong' }),
      makeContext({
        inspectorCapabilityRef: { capability: 'artifact:inspect', ref: 'grant-wrong' },
      }),
    ]) {
      expect(
        await artifactSearchExact(guarded.dependencies, context, {
          artifactId: ARTIFACT_ID,
          query: 'needle',
          maxHits: 1,
        }),
      ).toMatchObject({ ok: false, error: { code: 'RESOURCE_UNAVAILABLE' } });
    }

    const expiredRecord = buildRecord(searchBytes, { expiresAt: '2026-05-31T23:59:59.000Z' });
    const expired = trackDeps({ resolveAuthorizedArtifact: resolverFor(expiredRecord) });
    expect(
      await artifactSearchExact(expired.dependencies, makeContext(), {
        artifactId: ARTIFACT_ID,
        query: 'needle',
        maxHits: 1,
      }),
    ).toMatchObject({ ok: false, error: { code: 'RESOURCE_UNAVAILABLE' } });

    let readCalls = 0;
    const unavailableVersion = trackDeps({
      resolveAuthorizedArtifact: resolverFor(searchRecord),
      readVersionedRange: async () => {
        readCalls += 1;
        return null;
      },
    });
    expect(
      await artifactSearchExact(unavailableVersion.dependencies, makeContext(), {
        artifactId: ARTIFACT_ID,
        query: 'needle',
        maxHits: 1,
      }),
    ).toMatchObject({ ok: false, error: { code: 'RESOURCE_UNAVAILABLE' } });
    expect(readCalls).toBe(1);
    expect(unavailableVersion.receipts).toEqual([]);
  });

  it('fails closed for malformed, short, long, drifted-version, source, root, and proof mutations without retry', async () => {
    const cases: Array<{
      label: string;
      record: AuthorizedArtifactRecord;
      read: ArtifactInspectorDependencies['readVersionedRange'];
      expected: 'INTERNAL_ERROR' | 'INTEGRITY_FAILURE';
    }> = [
      {
        label: 'malformed result',
        record: searchRecord,
        read: async () => ({ nope: true }) as never,
        expected: 'INTERNAL_ERROR',
      },
      {
        label: 'short result',
        record: searchRecord,
        read: async (_context, _locator, version) => ({
          bytes: searchBytes.subarray(0, searchBytes.byteLength - 1),
          objectVersionRef: version,
        }),
        expected: 'INTEGRITY_FAILURE',
      },
      {
        label: 'long result',
        record: searchRecord,
        read: async (_context, _locator, version) => ({
          bytes: new Uint8Array(searchBytes.byteLength + 1),
          objectVersionRef: version,
        }),
        expected: 'INTEGRITY_FAILURE',
      },
      {
        label: 'version drift',
        record: searchRecord,
        read: sourceBackedRead(searchBytes, { versionOverride: DRIFTED_OBJECT_VERSION_REF }),
        expected: 'INTEGRITY_FAILURE',
      },
      {
        label: 'source mutation',
        record: searchRecord,
        read: async (_context, _locator, version) => ({
          bytes: Uint8Array.from(searchBytes, (byte, index) => (index === 0 ? byte ^ 1 : byte)),
          objectVersionRef: version,
        }),
        expected: 'INTEGRITY_FAILURE',
      },
      {
        label: 'source hash mutation',
        record: { ...searchRecord, sourceSha256: '9'.repeat(64) },
        read: sourceBackedRead(searchBytes),
        expected: 'INTEGRITY_FAILURE',
      },
      {
        label: 'root mutation',
        record: { ...searchRecord, merkleRoot: '9'.repeat(64) },
        read: sourceBackedRead(searchBytes),
        expected: 'INTEGRITY_FAILURE',
      },
      {
        label: 'proof leaf mutation',
        record: { ...searchRecord, merkleLeafSha256s: ['9'.repeat(64)] },
        read: sourceBackedRead(searchBytes),
        expected: 'INTEGRITY_FAILURE',
      },
    ];
    for (const scenario of cases) {
      let reads = 0;
      const tracked = trackDeps({
        resolveAuthorizedArtifact: async () => scenario.record,
        readVersionedRange: async (...args) => {
          reads += 1;
          return scenario.read(...args);
        },
      });
      const output = await artifactSearchExact(tracked.dependencies, makeContext(), {
        artifactId: ARTIFACT_ID,
        query: 'needle',
        maxHits: 2,
      });
      expect(output, scenario.label).toMatchObject({
        ok: false,
        error: { code: scenario.expected },
      });
      expect(reads, scenario.label).toBeLessThanOrEqual(1);
      expect(tracked.receipts, scenario.label).toHaveLength(1);
    }
  });

  it('returns immutable schema- and wire-valid output plus a content-free search receipt', async () => {
    const tracked = trackDeps({
      resolveAuthorizedArtifact: resolverFor(searchRecord),
      readVersionedRange: sourceBackedRead(searchBytes),
    });
    const output = await artifactSearchExact(
      tracked.dependencies,
      makeContext({ requestCorrelationId: 'correlation-safe' }),
      { artifactId: ARTIFACT_ID, query: 'needle', maxHits: MAX_SEARCH_HITS },
    );
    expect(ArtifactSearchExactOutputSchema.safeParse(output).success).toBe(true);
    expect(artifactInspectionResponseByteLength(null, output)).toBeLessThanOrEqual(
      MAX_ARTIFACT_RESPONSE_BYTES,
    );
    expect(Object.isFrozen(output)).toBe(true);
    if (!output.ok) throw new Error('expected search success');
    expect(Object.isFrozen(output.hits)).toBe(true);
    expect(Object.isFrozen(output.integrity.verifiedChunks)).toBe(true);
    expect(tracked.receipts).toHaveLength(1);
    const receipt = definedAt(tracked.receipts[0]);
    expect(ArtifactInspectionReceiptSchema.safeParse(receipt).success).toBe(true);
    expect(receipt.operationDetail).toEqual({
      operation: 'artifact_search_exact',
      queryLength: 6,
      maxHits: MAX_SEARCH_HITS,
      returnedHits: output.hits.map((hit) => ({
        returnedRange: hit.snippetRange,
        returnedByteSha256: hit.snippetSha256,
      })),
    });
    const evidence = JSON.stringify({ output, receipt, events: tracked.events });
    for (const forbidden of [
      INTERNAL_LOCATOR_SENTINEL.bucket,
      INTERNAL_LOCATOR_SENTINEL.path,
      INTERNAL_LOCATOR_SENTINEL.signedUrl,
      'source-token-SENTINEL',
    ]) {
      expect(evidence).not.toContain(forbidden);
    }
    expect(JSON.stringify(receipt)).not.toContain('needle');
  });

  it('keeps concurrent exact searches isolated', async () => {
    const sourceA = new TextEncoder().encode('alpha alpha');
    const sourceB = new TextEncoder().encode('beta beta');
    const recordA = buildRecord(sourceA, {
      artifactId: ARTIFACT_ID,
      objectVersionRef: 'ov_aaaaaaaaaaaaaaaaaaaaaaaa',
    });
    const recordB = buildRecord(sourceB, {
      artifactId: OTHER_ARTIFACT_ID,
      objectVersionRef: 'ov_bbbbbbbbbbbbbbbbbbbbbbbb',
    });
    const records = new Map([
      [ARTIFACT_ID, { record: recordA, source: sourceA }],
      [OTHER_ARTIFACT_ID, { record: recordB, source: sourceB }],
    ]);
    const tracked = trackDeps({
      resolveAuthorizedArtifact: async (_context, artifactId) =>
        records.get(artifactId)?.record ?? null,
      readVersionedRange: async (_context, _locator, version, offset, length) => {
        const entry = [...records.values()].find(
          (candidate) => candidate.record.objectVersionRef === version,
        );
        if (entry === undefined) return null;
        return { bytes: entry.source.subarray(offset, offset + length), objectVersionRef: version };
      },
    });
    const inspector = createArtifactInspector(tracked.dependencies);
    const [alpha, beta] = await Promise.all([
      inspector.artifactSearchExact(makeContext({ principalRef: 'principal-A' }), {
        artifactId: ARTIFACT_ID,
        query: 'alpha',
        maxHits: 10,
      }),
      inspector.artifactSearchExact(makeContext({ principalRef: 'principal-B' }), {
        artifactId: OTHER_ARTIFACT_ID,
        query: 'beta',
        maxHits: 10,
      }),
    ]);
    if (!alpha.ok || !beta.ok) throw new Error('expected concurrent search success');
    expect(alpha.hits.map((hit) => hit.snippet)).toEqual(['alpha', 'alpha']);
    expect(beta.hits.map((hit) => hit.snippet)).toEqual(['beta', 'beta']);
  });
});

describe('capability and receipt custody', () => {
  const source = new TextEncoder().encode('one\ntwo\n');
  const record = buildRecord(source, { chunkSize: 1024, mediaType: 'text/plain' });

  it('keeps the client and capability-grant refs distinct and independently bound', async () => {
    const { dependencies, receipts } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
    });
    const context = makeContext({
      inspectorClientRef: 'client-distinct',
      inspectorCapabilityRef: { capability: 'artifact:inspect', ref: 'grant-distinct' },
    });
    const output = await artifactStat(dependencies, context, { artifactId: ARTIFACT_ID });
    expect(output.ok).toBe(true);
    expect(receipts).toHaveLength(1);
    expect(definedAt(receipts[0]).inspectorClientRef).toBe('client-distinct');
    expect(definedAt(receipts[0]).inspectorCapabilityRef).toEqual({
      capability: 'artifact:inspect',
      ref: 'grant-distinct',
    });
  });

  it('emits exactly one deeply immutable schema-valid receipt for successful stat, range, and lines operations', async () => {
    const tracked = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: sourceBackedRead(source),
    });
    const context = makeContext();
    const outputs = await Promise.all([
      artifactStat(tracked.dependencies, context, { artifactId: ARTIFACT_ID }),
      artifactReadRange(tracked.dependencies, context, {
        artifactId: ARTIFACT_ID,
        offset: 0,
        length: 3,
      }),
      artifactReadLines(tracked.dependencies, context, {
        artifactId: ARTIFACT_ID,
        startLine: 1,
        count: 1,
      }),
    ]);
    expect(outputs.every((output) => output.ok)).toBe(true);
    expect(tracked.receipts).toHaveLength(3);
    expect(tracked.receipts.map((receipt) => receipt.operationDetail.operation).sort()).toEqual(
      ['artifact_read_lines', 'artifact_read_range', 'artifact_stat'].sort(),
    );
    for (const receipt of tracked.receipts) {
      expect(ArtifactInspectionReceiptSchema.safeParse(receipt).success).toBe(true);
      expect(Object.isFrozen(receipt)).toBe(true);
      expect(Object.isFrozen(receipt.inspectorCapabilityRef)).toBe(true);
      expect(Object.isFrozen(receipt.operationDetail)).toBe(true);
      expect(Object.isFrozen(receipt.resultOrErrorClass)).toBe(true);
    }
  });

  it('never returns success when trusted receipt coordinates are malformed at runtime', async () => {
    const malformedContext = {
      ...DEFAULT_CONTEXT_INPUT,
      inspectorCapabilityRef: 'artifact:inspect',
    } as unknown as ArtifactInspectorTrustedContext;
    const { dependencies, events, receipts } = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
    });
    const output = await artifactStat(dependencies, malformedContext, { artifactId: ARTIFACT_ID });
    expect(output.ok).toBe(false);
    if (output.ok) throw new Error('expected error');
    expect(output.error.code).toBe('INTERNAL_ERROR');
    expect(receipts).toHaveLength(0);
    expect(events).toHaveLength(1);
  });
});

describe('proof mutation coverage', () => {
  it('rejects a directly mutated S1b proof sibling using the unchanged builder/verifier primitive', () => {
    const source = new TextEncoder().encode(deterministicAsciiText(3000, 41));
    const manifest = buildArtifactChunkManifest(source, 1024);
    const proof = buildArtifactChunkProof(manifest, 0);
    const firstSibling = definedAt(proof.proof[0]);
    const mutatedSibling = `${firstSibling.siblingSha256.slice(0, 63)}${
      firstSibling.siblingSha256.endsWith('0') ? '1' : '0'
    }`;
    const mutatedProof = {
      ...proof,
      proof: [{ ...firstSibling, siblingSha256: mutatedSibling }, ...proof.proof.slice(1)],
    };
    const firstChunk = definedAt(manifest.chunks[0]);
    const chunkBytes = source.subarray(
      firstChunk.byteStart,
      firstChunk.byteStart + firstChunk.byteLength,
    );
    expect(verifyArtifactChunkProof(chunkBytes, proof, manifest.merkleRoot)).toBe(true);
    expect(verifyArtifactChunkProof(chunkBytes, mutatedProof, manifest.merkleRoot)).toBe(false);
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

  it('the direct response-budget primitive distinguishes "at or under" from "one byte over"', () => {
    // A schema-valid S2 runtime output cannot reach this ceiling because its
    // component bounds are tighter. Exercise the unchanged S0 byte-counting
    // primitive directly rather than misreporting a structurally impossible
    // runtime scenario as executed.
    function byteLengthForPadding(paddingLength: number): number {
      const candidate = {
        ok: true as const,
        padding: 'x'.repeat(paddingLength),
      };
      return artifactInspectionResponseByteLength(null, candidate);
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

  it('normalizes an adapter throw separately from exact-version unavailability', async () => {
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

    const unavailable = trackDeps({
      resolveAuthorizedArtifact: resolverFor(record),
      readVersionedRange: async () => null,
    });
    const unavailableOutput = await artifactReadRange(unavailable.dependencies, makeContext(), {
      artifactId: ARTIFACT_ID,
      offset: 0,
      length: 10,
    });
    expect(unavailableOutput).toEqual({
      ok: false,
      error: {
        code: 'RESOURCE_UNAVAILABLE',
        message: 'Artifact is unavailable.',
        retryable: false,
      },
    });
    expect(unavailable.receipts).toHaveLength(0);
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
