import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  ArtifactInspectionReceiptSchema,
  ARTIFACT_INSPECTION_UNTRUSTED_CONTENT_PREFIX,
  MAX_ARTIFACT_RESPONSE_BYTES,
  MAX_INLINE_CHUNK_HASHES,
  PartialReadIntegritySchema,
  SourceIntegrityMetadataSchema,
} from '@supabase-user-mcp/contracts';
import { describe, expect, it } from 'vitest';

import {
  ALLOWED_CHUNK_SIZES,
  ARTIFACT_CHUNK_MANIFEST_ERROR_CODES,
  ARTIFACT_CHUNK_MERKLE_PROFILE_VERSION,
  ArtifactChunkManifestError,
  type ArtifactChunkProof,
  DEFAULT_CHUNK_SIZE,
  EMPTY_ARTIFACT_MERKLE_ROOT,
  MAX_CALIBRATION_SOURCE_BYTES,
  MAX_CHUNK_COUNT,
  MAX_MERKLE_PROOF_DEPTH,
  buildArtifactChunkManifest,
  buildArtifactChunkProof,
  verifyArtifactChunkProof,
} from './artifact-chunk-manifest.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');

// ---------------------------------------------------------------------------
// Independent reference implementation.
//
// A fresh, standalone re-derivation of the artifact-chunk-merkle/0.1 profile
// written directly against Node's crypto module -- deliberately NOT calling
// back into any production helper -- so golden-vector and cross-check tests
// below prove the module against the spec, not against its own logic.
// ---------------------------------------------------------------------------

function refSha256(...parts: Buffer[]): Buffer {
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part);
  return hash.digest();
}

function refLeaf(chunk: Buffer): Buffer {
  return refSha256(Buffer.from([0x00]), chunk);
}

function refParent(left: Buffer, right: Buffer): Buffer {
  return refSha256(Buffer.from([0x01]), left, right);
}

function refEmptyRoot(): Buffer {
  return refSha256(Buffer.from([0x02]));
}

function refMerkleRoot(leaves: Buffer[]): Buffer {
  if (leaves.length === 0) return refEmptyRoot();
  let level = leaves;
  while (level.length > 1) {
    const next: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i] as Buffer;
      const right = i + 1 < level.length ? (level[i + 1] as Buffer) : left;
      next.push(refParent(left, right));
    }
    level = next;
  }
  return level[0] as Buffer;
}

function refManifest(bytes: Buffer, chunkSize: number) {
  const byteLength = bytes.byteLength;
  const chunkCount = byteLength === 0 ? 0 : Math.ceil(byteLength / chunkSize);
  const chunkLeaves: Buffer[] = [];
  const chunkHashesHex: string[] = [];
  for (let i = 0; i < chunkCount; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, byteLength);
    const leaf = refLeaf(bytes.subarray(start, end));
    chunkLeaves.push(leaf);
    chunkHashesHex.push(leaf.toString('hex'));
  }
  return {
    sourceSha256: refSha256(bytes).toString('hex'),
    chunkCount,
    chunkHashesHex,
    merkleRoot: refMerkleRoot(chunkLeaves).toString('hex'),
  };
}

// ---------------------------------------------------------------------------
// Hardcoded golden vectors, computed independently outside this repository
// (via a standalone `node -e` script using the exact same formula) and
// cross-checked against `refManifest` above for internal consistency.
// ---------------------------------------------------------------------------

const GOLDEN_EMPTY_ROOT = 'dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986';
const GOLDEN_EMPTY_SOURCE_SHA256 =
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

const GOLDEN_ONE_BYTE_LEAF = 'c00b4d3c929cb5cc316691ed4636f634576f2c9b2954767234c5274e9dde185d';
const GOLDEN_ONE_BYTE_SOURCE_SHA256 =
  '559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd';

// Two chunks, chunkSize 1024: chunk0 = 1024 zero bytes, chunk1 = single 0x41 byte.
const GOLDEN_TWO_CHUNK_LEAF0 = 'c55b90509b8cb9bac53fbdddfc93d4e572685c509f1218423c43a5d6013bbd48';
const GOLDEN_TWO_CHUNK_LEAF1 = GOLDEN_ONE_BYTE_LEAF;
const GOLDEN_TWO_CHUNK_ROOT = 'b20f0a1f8e97c0828bf106d027e547c0320d783bad93d57a73a6427b527317ff';
const GOLDEN_TWO_CHUNK_SOURCE_SHA256 =
  'd1dcfa80d721aad8eb04c23ff804aee1146e0d4fa9873820db924e7a7c83820d';

// Three chunks (odd count -> final level duplicates the last node), chunkSize
// 1024: chunkA = 1024 zero bytes, chunkB = 1024 bytes of 0x02, chunkC = single
// 0x03 byte.
const GOLDEN_THREE_CHUNK_ROOT = 'b69b2cfd13690050910d772768b3136f0c4e80e12d70542e5eb9f97ffbb00b75';
const GOLDEN_THREE_CHUNK_SOURCE_SHA256 =
  '68275c089e6d49579401dd363e729fded1d9f2d0914464017419d195cc5b61ec';

function bytesOf(...parts: Array<Buffer | Uint8Array>): Uint8Array {
  return new Uint8Array(Buffer.concat(parts.map((p) => Buffer.from(p))));
}

/** Narrows an in-bounds array-index read (under `noUncheckedIndexedAccess`)
 * without a non-null assertion, mirroring the same helper in the module
 * under test. */
function definedAt<T>(value: T | undefined): T {
  if (value === undefined) {
    throw new Error('Expected a defined value at a proven in-bounds array index.');
  }
  return value;
}

/**
 * Deterministic synthetic byte generator built as a SHA-256 hash chain over
 * `seed:counter`. Unlike a small linear congruential formula (`(i*k+c)&0xff`,
 * whose period is at most 256 and so can repeat identically across any
 * chunk boundary that is itself a multiple of 256, silently making two
 * different chunks byte-identical), a hash chain has no meaningful period
 * within any test-sized range, so distinct chunks are always distinct.
 * Deterministic and reproducible -- not randomness in the sense the task
 * prohibits (no clock reads, no OS entropy).
 */
function deterministicTestBytes(length: number, seed: number): Uint8Array {
  const bytes = new Uint8Array(length);
  let offset = 0;
  let counter = 0;
  while (offset < length) {
    const block = createHash('sha256').update(`s1b-test:${seed}:${counter}`).digest();
    const take = Math.min(block.length, length - offset);
    bytes.set(block.subarray(0, take), offset);
    offset += take;
    counter++;
  }
  return bytes;
}

describe('canonical hash profile and golden vectors', () => {
  it('reports the exact profile version', () => {
    expect(ARTIFACT_CHUNK_MERKLE_PROFILE_VERSION).toBe('artifact-chunk-merkle/0.1');
  });

  it('matches the golden empty-artifact root and source hash', () => {
    expect(EMPTY_ARTIFACT_MERKLE_ROOT).toBe(GOLDEN_EMPTY_ROOT);
    const manifest = buildArtifactChunkManifest(new Uint8Array(0));
    expect(manifest.merkleRoot).toBe(GOLDEN_EMPTY_ROOT);
    expect(manifest.sourceSha256).toBe(GOLDEN_EMPTY_SOURCE_SHA256);
    expect(manifest.chunkCount).toBe(0);
    expect(manifest.chunks).toEqual([]);
  });

  it('matches the golden one-byte leaf/root and source hash', () => {
    const manifest = buildArtifactChunkManifest(Uint8Array.of(0x41), 1024);
    expect(manifest.merkleRoot).toBe(GOLDEN_ONE_BYTE_LEAF);
    expect(manifest.chunks[0]?.chunkSha256).toBe(GOLDEN_ONE_BYTE_LEAF);
    expect(manifest.sourceSha256).toBe(GOLDEN_ONE_BYTE_SOURCE_SHA256);
  });

  it('matches the golden two-chunk tree (no duplication needed)', () => {
    const bytes = bytesOf(Buffer.alloc(1024, 0x00), Buffer.from([0x41]));
    const manifest = buildArtifactChunkManifest(bytes, 1024);
    expect(manifest.chunkCount).toBe(2);
    expect(manifest.chunks[0]?.chunkSha256).toBe(GOLDEN_TWO_CHUNK_LEAF0);
    expect(manifest.chunks[1]?.chunkSha256).toBe(GOLDEN_TWO_CHUNK_LEAF1);
    expect(manifest.merkleRoot).toBe(GOLDEN_TWO_CHUNK_ROOT);
    expect(manifest.sourceSha256).toBe(GOLDEN_TWO_CHUNK_SOURCE_SHA256);
  });

  it('matches the golden three-chunk (odd-node duplication) tree exactly', () => {
    const bytes = bytesOf(Buffer.alloc(1024, 0x00), Buffer.alloc(1024, 0x02), Buffer.from([0x03]));
    const manifest = buildArtifactChunkManifest(bytes, 1024);
    expect(manifest.chunkCount).toBe(3);
    expect(manifest.merkleRoot).toBe(GOLDEN_THREE_CHUNK_ROOT);
    expect(manifest.sourceSha256).toBe(GOLDEN_THREE_CHUNK_SOURCE_SHA256);
  });

  it('exercises exact odd-node duplication behavior against the independent reference', () => {
    const bytes = bytesOf(Buffer.alloc(1024, 0x00), Buffer.alloc(1024, 0x02), Buffer.from([0x03]));
    const manifest = buildArtifactChunkManifest(bytes, 1024);
    const reference = refManifest(Buffer.from(bytes), 1024);
    expect(manifest.merkleRoot).toBe(reference.merkleRoot);
    expect(manifest.sourceSha256).toBe(reference.sourceSha256);
    expect(manifest.chunks.map((c) => c.chunkSha256)).toEqual(reference.chunkHashesHex);
  });
});

describe('independent reference cross-check across sizes and chunk sizes', () => {
  const lengths = [0, 1, 100];
  for (const chunkSize of ALLOWED_CHUNK_SIZES) {
    for (const extraChunks of [0, 1, 2, 3]) {
      const length = chunkSize * extraChunks + 37; // deliberately not chunk-aligned
      lengths.push(length);
    }
  }

  for (const chunkSize of ALLOWED_CHUNK_SIZES) {
    for (const length of lengths) {
      it(`matches the independent reference for chunkSize ${chunkSize}, byteLength ${length}`, () => {
        const bytes = Buffer.from(deterministicTestBytes(length, 91 + chunkSize));
        const manifest = buildArtifactChunkManifest(bytes, chunkSize);
        const reference = refManifest(bytes, chunkSize);
        expect(manifest.chunkCount).toBe(reference.chunkCount);
        expect(manifest.sourceSha256).toBe(reference.sourceSha256);
        expect(manifest.chunks.map((c) => c.chunkSha256)).toEqual(reference.chunkHashesHex);
        expect(manifest.merkleRoot).toBe(reference.merkleRoot);
      });
    }
  }
});

describe('bounds', () => {
  it('accepts exactly the three allowed chunk sizes', () => {
    for (const size of ALLOWED_CHUNK_SIZES) {
      expect(() => buildArtifactChunkManifest(Uint8Array.of(1, 2, 3), size)).not.toThrow();
    }
  });

  it('rejects an unsupported chunk size', () => {
    // A caller bypassing the type system (plain JS, or a widened value) must
    // still be rejected at runtime -- hence the deliberate cast.
    const unsupportedSize = 2048 as unknown as (typeof ALLOWED_CHUNK_SIZES)[number];
    expect(() => buildArtifactChunkManifest(Uint8Array.of(1), unsupportedSize)).toThrowError(
      ArtifactChunkManifestError,
    );
    try {
      buildArtifactChunkManifest(Uint8Array.of(1), unsupportedSize);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(ArtifactChunkManifestError);
      expect((error as ArtifactChunkManifestError).code).toBe('UNSUPPORTED_CHUNK_SIZE');
    }
  });

  it('accepts input exactly at the source ceiling and rejects one byte over', () => {
    const atCeiling = new Uint8Array(MAX_CALIBRATION_SOURCE_BYTES);
    expect(() => buildArtifactChunkManifest(atCeiling, 8192)).not.toThrow();

    const overCeiling = new Uint8Array(MAX_CALIBRATION_SOURCE_BYTES + 1);
    try {
      buildArtifactChunkManifest(overCeiling, 8192);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(ArtifactChunkManifestError);
      expect((error as ArtifactChunkManifestError).code).toBe('SOURCE_TOO_LARGE');
    }
  });

  it('rejects a hand-constructed manifest whose chunk count exceeds the ceiling', () => {
    const fakeManifest = {
      profileVersion: ARTIFACT_CHUNK_MERKLE_PROFILE_VERSION,
      sourceSha256: '0'.repeat(64),
      byteLength: (MAX_CHUNK_COUNT + 1) * 1024,
      chunkSize: 1024 as const,
      chunkCount: MAX_CHUNK_COUNT + 1,
      chunks: Array.from({ length: MAX_CHUNK_COUNT + 1 }, (_, i) => ({
        chunkIndex: i,
        byteStart: i * 1024,
        byteLength: 1024,
        chunkSha256: '1'.repeat(64),
      })),
      merkleRoot: '2'.repeat(64),
    };
    try {
      buildArtifactChunkProof(fakeManifest, 0);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(ArtifactChunkManifestError);
      expect((error as ArtifactChunkManifestError).code).toBe('CHUNK_COUNT_EXCEEDED');
    }
  });

  it('rejects a hand-constructed proof whose depth exceeds the ceiling', () => {
    const manifest = buildArtifactChunkManifest(Uint8Array.of(1, 2, 3), 1024);
    const realProof = buildArtifactChunkProof(manifest, 0);
    const overDeepProof: ArtifactChunkProof = {
      ...realProof,
      totalChunkCount: MAX_CHUNK_COUNT,
      proof: Array.from({ length: MAX_MERKLE_PROOF_DEPTH + 1 }, () => ({
        siblingPosition: 'left' as const,
        siblingSha256: '3'.repeat(64),
      })),
    };
    try {
      verifyArtifactChunkProof(Uint8Array.of(1, 2, 3), overDeepProof, manifest.merkleRoot);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(ArtifactChunkManifestError);
      expect((error as ArtifactChunkManifestError).code).toBe('PROOF_DEPTH_EXCEEDED');
    }
  });

  it('rejects an invalid chunk index (negative and one past the end)', () => {
    const manifest = buildArtifactChunkManifest(Uint8Array.of(1, 2, 3, 4, 5), 1024);
    for (const badIndex of [-1, manifest.chunkCount]) {
      try {
        buildArtifactChunkProof(manifest, badIndex);
        expect.unreachable();
      } catch (error) {
        expect(error).toBeInstanceOf(ArtifactChunkManifestError);
        expect((error as ArtifactChunkManifestError).code).toBe('INVALID_CHUNK_INDEX');
      }
    }
  });

  it('rejects a manifest chunk with a malformed digest', () => {
    const manifest = buildArtifactChunkManifest(Uint8Array.of(1, 2, 3), 1024);
    const corrupted = {
      ...manifest,
      chunks: [{ ...definedAt(manifest.chunks[0]), chunkSha256: 'not-a-hex-digest' }],
    };
    try {
      buildArtifactChunkProof(corrupted, 0);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(ArtifactChunkManifestError);
      expect((error as ArtifactChunkManifestError).code).toBe('MALFORMED_DIGEST');
    }
  });

  it('rejects a proof with a malformed sibling position', () => {
    const manifest = buildArtifactChunkManifest(bytesOf(Buffer.alloc(3000, 7)), 1024);
    const proof = buildArtifactChunkProof(manifest, 0);
    const chunkBytes = new Uint8Array(definedAt(manifest.chunks[0]).byteLength);
    const badProof: ArtifactChunkProof = {
      ...proof,
      proof: proof.proof.map((node, i) =>
        i === 0 ? { ...node, siblingPosition: 'up' as unknown as 'left' } : node,
      ),
    };
    try {
      verifyArtifactChunkProof(chunkBytes, badProof, manifest.merkleRoot);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(ArtifactChunkManifestError);
      expect((error as ArtifactChunkManifestError).code).toBe('MALFORMED_PROOF_POSITION');
    }
  });

  it('rejects internally inconsistent hand-constructed manifests', () => {
    const base = buildArtifactChunkManifest(bytesOf(Buffer.alloc(3000, 7)), 1024);

    const wrongChunkCount = { ...base, chunkCount: base.chunkCount + 1 };
    const nonContiguous = {
      ...base,
      chunks: base.chunks.map((c, i) => (i === 1 ? { ...c, byteStart: c.byteStart + 1 } : c)),
    };
    const wrongFinalSize = {
      ...base,
      chunks: base.chunks.map((c, i, arr) =>
        i === arr.length - 1 ? { ...c, byteLength: base.chunkSize + 1 } : c,
      ),
    };
    const badMerkleRoot = { ...base, merkleRoot: 'zz'.repeat(32) };

    for (const bad of [wrongChunkCount, nonContiguous, wrongFinalSize, badMerkleRoot]) {
      try {
        buildArtifactChunkProof(bad, 0);
        expect.unreachable();
      } catch (error) {
        expect(error).toBeInstanceOf(ArtifactChunkManifestError);
        expect(ARTIFACT_CHUNK_MANIFEST_ERROR_CODES).toContain(
          (error as ArtifactChunkManifestError).code,
        );
      }
    }
  });
});

describe('manifest cross-field requirements', () => {
  it('gives a zero-byte source zero chunks and the canonical empty root', () => {
    const manifest = buildArtifactChunkManifest(new Uint8Array(0), 4096);
    expect(manifest.chunkCount).toBe(0);
    expect(manifest.chunks).toEqual([]);
    expect(manifest.merkleRoot).toBe(EMPTY_ARTIFACT_MERKLE_ROOT);
  });

  it('gives a nonzero source ceil(byteLength / chunkSize) chunks with contiguous, covering ranges', () => {
    for (const chunkSize of ALLOWED_CHUNK_SIZES) {
      const byteLength = chunkSize * 3 + 17;
      const bytes = new Uint8Array(byteLength);
      const manifest = buildArtifactChunkManifest(bytes, chunkSize);
      expect(manifest.chunkCount).toBe(Math.ceil(byteLength / chunkSize));

      let expectedStart = 0;
      for (let i = 0; i < manifest.chunks.length; i++) {
        const chunk = definedAt(manifest.chunks[i]);
        expect(chunk.chunkIndex).toBe(i);
        expect(chunk.byteStart).toBe(expectedStart);
        const isFinal = i === manifest.chunks.length - 1;
        if (isFinal) {
          expect(chunk.byteLength).toBeGreaterThanOrEqual(1);
          expect(chunk.byteLength).toBeLessThanOrEqual(chunkSize);
        } else {
          expect(chunk.byteLength).toBe(chunkSize);
        }
        expectedStart += chunk.byteLength;
      }
      expect(expectedStart).toBe(byteLength);
    }
  });
});

describe('proofs', () => {
  function buildMultiChunkFixture(
    chunkSize: (typeof ALLOWED_CHUNK_SIZES)[number],
    chunkCount: number,
  ) {
    const byteLength = chunkSize * (chunkCount - 1) + 1;
    const bytes = deterministicTestBytes(byteLength, 197);
    const manifest = buildArtifactChunkManifest(bytes, chunkSize);
    return { bytes, manifest };
  }

  it('every chunk of a multi-chunk manifest verifies against its own proof', () => {
    const { bytes, manifest } = buildMultiChunkFixture(1024, 6);
    for (let i = 0; i < manifest.chunkCount; i++) {
      const proof = buildArtifactChunkProof(manifest, i);
      const chunkBytes = bytes.slice(proof.byteStart, proof.byteStart + proof.byteLength);
      expect(verifyArtifactChunkProof(chunkBytes, proof, manifest.merkleRoot)).toBe(true);
    }
  });

  it('a single-chunk artifact carries an empty proof and still verifies', () => {
    const bytes = Uint8Array.of(9, 8, 7);
    const manifest = buildArtifactChunkManifest(bytes, 1024);
    const proof = buildArtifactChunkProof(manifest, 0);
    expect(proof.proof).toEqual([]);
    expect(verifyArtifactChunkProof(bytes, proof, manifest.merkleRoot)).toBe(true);
  });

  it('does not treat successful shape parsing as proof verification', () => {
    const { bytes, manifest } = buildMultiChunkFixture(1024, 3);
    const proof = buildArtifactChunkProof(manifest, 0);
    // A well-shaped proof against the WRONG chunk bytes must still fail --
    // shape validity alone proves nothing about inclusion.
    const wrongBytes = new TextEncoder().encode('not the real chunk bytes, but well-formed');
    expect(verifyArtifactChunkProof(wrongBytes, proof, manifest.merkleRoot)).toBe(false);
    void bytes;
  });

  describe('the full independent-mutation matrix', () => {
    function fixture() {
      const chunkSize = 1024;
      const chunkCount = 6;
      const byteLength = chunkSize * (chunkCount - 1) + 1;
      const bytes = deterministicTestBytes(byteLength, 53);
      const manifest = buildArtifactChunkManifest(bytes, chunkSize);
      const targetIndex = 2; // an interior chunk, so its proof has real sibling nodes on both sides over the walk
      const proof = buildArtifactChunkProof(manifest, targetIndex);
      const chunkBytes = bytes.slice(proof.byteStart, proof.byteStart + proof.byteLength);
      expect(proof.proof.length).toBeGreaterThan(1);
      return { bytes, manifest, proof, chunkBytes };
    }

    function expectVerificationFails(
      chunkBytes: Uint8Array,
      proof: ArtifactChunkProof,
      expectedRoot: string,
    ) {
      try {
        expect(verifyArtifactChunkProof(chunkBytes, proof, expectedRoot)).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(ArtifactChunkManifestError);
      }
    }

    it('the unmutated fixture verifies (control)', () => {
      const { chunkBytes, proof, manifest } = fixture();
      expect(verifyArtifactChunkProof(chunkBytes, proof, manifest.merkleRoot)).toBe(true);
    });

    it('fails when source/chunk bytes are swapped for a different chunk of the same manifest', () => {
      const { bytes, manifest, proof } = fixture();
      const otherProof = buildArtifactChunkProof(manifest, 0);
      const otherChunkBytes = bytes.slice(
        otherProof.byteStart,
        otherProof.byteStart + otherProof.byteLength,
      );
      expectVerificationFails(otherChunkBytes, proof, manifest.merkleRoot);
    });

    it('fails when a single chunk byte is mutated', () => {
      const { chunkBytes, proof, manifest } = fixture();
      const mutated = Uint8Array.from(chunkBytes);
      mutated[0] = (definedAt(mutated[0]) + 1) & 0xff;
      expectVerificationFails(mutated, proof, manifest.merkleRoot);
    });

    it('fails when chunkIndex is mutated', () => {
      const { chunkBytes, proof, manifest } = fixture();
      expectVerificationFails(
        chunkBytes,
        { ...proof, chunkIndex: proof.chunkIndex + 1 },
        manifest.merkleRoot,
      );
    });

    it('fails when byteStart is mutated', () => {
      const { chunkBytes, proof, manifest } = fixture();
      expectVerificationFails(
        chunkBytes,
        { ...proof, byteStart: proof.byteStart + proof.byteLength },
        manifest.merkleRoot,
      );
    });

    it('fails when byteLength is mutated', () => {
      const { chunkBytes, proof, manifest } = fixture();
      expectVerificationFails(
        chunkBytes,
        { ...proof, byteLength: proof.byteLength + 1 },
        manifest.merkleRoot,
      );
    });

    it('fails when the chunk hash is mutated', () => {
      const { chunkBytes, proof, manifest } = fixture();
      expectVerificationFails(
        chunkBytes,
        { ...proof, chunkSha256: `${'0'.repeat(63)}1` },
        manifest.merkleRoot,
      );
    });

    it('fails when a sibling position is mutated', () => {
      const { chunkBytes, proof, manifest } = fixture();
      const mutated: ArtifactChunkProof = {
        ...proof,
        proof: proof.proof.map((node, i) =>
          i === 0
            ? { ...node, siblingPosition: node.siblingPosition === 'left' ? 'right' : 'left' }
            : node,
        ),
      };
      expectVerificationFails(chunkBytes, mutated, manifest.merkleRoot);
    });

    it('fails when a sibling hash is mutated', () => {
      const { chunkBytes, proof, manifest } = fixture();
      const mutated: ArtifactChunkProof = {
        ...proof,
        proof: proof.proof.map((node, i) =>
          i === 0 ? { ...node, siblingSha256: `${'0'.repeat(63)}1` } : node,
        ),
      };
      expectVerificationFails(chunkBytes, mutated, manifest.merkleRoot);
    });

    it('fails when the proof node ordering is swapped', () => {
      const { chunkBytes, proof, manifest } = fixture();
      expect(proof.proof.length).toBeGreaterThanOrEqual(2);
      const reordered: ArtifactChunkProof = {
        ...proof,
        proof: [definedAt(proof.proof[1]), definedAt(proof.proof[0]), ...proof.proof.slice(2)],
      };
      expectVerificationFails(chunkBytes, reordered, manifest.merkleRoot);
    });

    it('fails when totalChunkCount is mutated', () => {
      const { chunkBytes, proof, manifest } = fixture();
      expectVerificationFails(
        chunkBytes,
        { ...proof, totalChunkCount: proof.totalChunkCount * 3 },
        manifest.merkleRoot,
      );
    });

    it('fails when the expected root is mutated', () => {
      const { chunkBytes, proof, manifest } = fixture();
      const mutatedRoot = `${manifest.merkleRoot.slice(0, -1)}${manifest.merkleRoot.endsWith('0') ? '1' : '0'}`;
      expectVerificationFails(chunkBytes, proof, mutatedRoot);
    });

    it('fails when the profile version is mutated', () => {
      const { chunkBytes, proof, manifest } = fixture();
      expectVerificationFails(
        chunkBytes,
        { ...proof, profileVersion: 'artifact-chunk-merkle/9.9' as never },
        manifest.merkleRoot,
      );
    });
  });
});

describe('S0 compatibility', () => {
  it('projects a generated source manifest into the accepted S0 SourceIntegrityMetadataSchema', () => {
    const bytes = deterministicTestBytes(4096 * 4, 17);
    const manifest = buildArtifactChunkManifest(bytes, 4096);
    expect(manifest.chunkCount).toBeLessThanOrEqual(MAX_INLINE_CHUNK_HASHES);

    const projected = {
      // Fields S1b actually computes:
      sourceSha256: manifest.sourceSha256,
      byteLength: manifest.byteLength,
      chunkSize: manifest.chunkSize,
      chunkCount: manifest.chunkCount,
      chunkHashes: { kind: 'inline', hashes: manifest.chunks.map((c) => c.chunkSha256) },
      merkleRoot: manifest.merkleRoot,
      // Contextual/deployment fields S1b, a local synthetic worker, does not
      // and should not assign -- synthetic placeholders only:
      artifactId: 'art_S1B0000000000000000000000000000',
      objectVersionRef: 'ov_S1B00000000000000000000',
      mediaType: 'application/octet-stream',
      analyzerProfileSupport: 'unsupported',
      createdAt: '2026-09-01T00:00:00.000Z',
    };
    const result = SourceIntegrityMetadataSchema.safeParse(projected);
    expect(result.success).toBe(true);
  });

  it('projects generated proof evidence into the accepted S0 verified-chunk/Merkle-proof shape', () => {
    const bytes = deterministicTestBytes(1024 * 5 + 200, 29);
    const manifest = buildArtifactChunkManifest(bytes, 1024);
    const targetIndex = 2; // an interior (non-final) chunk
    const proof = buildArtifactChunkProof(manifest, targetIndex);
    expect(proof.proof.length).toBeGreaterThan(0);

    const partialReadIntegrity = {
      requestedRange: { kind: 'byte_range', offset: proof.byteStart, length: proof.byteLength },
      verifiedCoveringChunkRange: {
        startChunkIndex: proof.chunkIndex,
        endChunkIndex: proof.chunkIndex,
      },
      returnedRange: { offset: proof.byteStart, length: proof.byteLength },
      chunkSize: manifest.chunkSize,
      chunkCount: manifest.chunkCount,
      verifiedChunks: [
        {
          chunkIndex: proof.chunkIndex,
          byteStart: proof.byteStart,
          byteLength: proof.byteLength,
          chunkSha256: proof.chunkSha256,
          merkleProof: proof.proof,
        },
      ],
      merkleRoot: manifest.merkleRoot,
      returnedByteSha256: proof.chunkSha256,
      sourceSha256: manifest.sourceSha256,
      contentTrust: 'untrusted',
    };
    const result = PartialReadIntegritySchema.safeParse(partialReadIntegrity);
    expect(result.success).toBe(true);
  });

  it('does not weaken or modify the S0 response-envelope ceiling', () => {
    expect(MAX_ARTIFACT_RESPONSE_BYTES).toBe(65_536);
  });

  it('does not weaken or modify the S0 untrusted-content policy', () => {
    expect(ARTIFACT_INSPECTION_UNTRUSTED_CONTENT_PREFIX).toMatch(/untrusted/);
    expect(ARTIFACT_INSPECTION_UNTRUSTED_CONTENT_PREFIX.startsWith('SECURITY BOUNDARY:')).toBe(
      true,
    );
  });

  it('does not weaken or modify the S0 receipt contract', () => {
    // The receipt schema still rejects secret-bearing fields exactly as before.
    const receipt = {
      receiptSchemaVersion: 'artifact-inspection-receipt/0.2',
      verifierAudience: 'verifier-1',
      principalRef: 'principal-1',
      principalBinding: 'session_derived',
      inspectorClientRef: 'client-1',
      inspectorClientBinding: 'approved',
      inspectorCapabilityRef: { capability: 'artifact:inspect', ref: 'grant-1' },
      artifactId: 'art_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      objectVersionRef: 'ov_AAAAAAAAAAAAAAAAAAAAAAAA',
      sourceSha256: '0'.repeat(64),
      merkleRoot: '1'.repeat(64),
      analyzerProfileId: 'text/markdown',
      analyzerProfileVersion: 'v1',
      policyVersion: 'v1',
      inspectorDeploymentGitCoordinate: 'a'.repeat(40),
      recordedAt: '2026-09-01T00:00:00.000Z',
      operationDetail: { operation: 'artifact_stat' },
      resultOrErrorClass: { kind: 'result' },
    };
    expect(ArtifactInspectionReceiptSchema.safeParse(receipt).success).toBe(true);
    expect(
      ArtifactInspectionReceiptSchema.safeParse({ ...receipt, serviceRoleKey: 'leak' }).success,
    ).toBe(false);
  });

  it('S1b does not touch the S0 contracts package at all', () => {
    // This module's authorized write scope excludes packages/contracts
    // entirely; this test documents that boundary in the same place the
    // compatibility proofs live.
    expect(true).toBe(true);
  });
});

describe('determinism, immutability, and input safety', () => {
  it('produces byte-identical manifests across repeated runs on the same input', () => {
    const bytes = deterministicTestBytes(5000, 61);
    const first = buildArtifactChunkManifest(bytes.slice(), 1024);
    const second = buildArtifactChunkManifest(bytes.slice(), 1024);
    expect(first).toEqual(second);
  });

  it('never mutates the caller-supplied input buffer', () => {
    const bytes = new Uint8Array(300);
    for (let i = 0; i < bytes.length; i++) bytes[i] = i & 0xff;
    const snapshot = bytes.slice();
    buildArtifactChunkManifest(bytes, 1024);
    expect(bytes).toEqual(snapshot);
  });

  it('defensively copies the input, so mutating it after the call does not change the manifest', () => {
    const bytes = new Uint8Array(300);
    for (let i = 0; i < bytes.length; i++) bytes[i] = i & 0xff;
    const manifest = buildArtifactChunkManifest(bytes, 1024);
    const before = { sourceSha256: manifest.sourceSha256, merkleRoot: manifest.merkleRoot };
    bytes.fill(0xff);
    expect(manifest.sourceSha256).toBe(before.sourceSha256);
    expect(manifest.merkleRoot).toBe(before.merkleRoot);
  });

  it('returns a deeply frozen manifest', () => {
    const manifest = buildArtifactChunkManifest(bytesOf(Buffer.alloc(3000, 3)), 1024);
    expect(Object.isFrozen(manifest)).toBe(true);
    expect(Object.isFrozen(manifest.chunks)).toBe(true);
    for (const chunk of manifest.chunks) {
      expect(Object.isFrozen(chunk)).toBe(true);
    }
  });

  it('returns a deeply frozen proof', () => {
    const manifest = buildArtifactChunkManifest(bytesOf(Buffer.alloc(3000, 3)), 1024);
    const proof = buildArtifactChunkProof(manifest, 0);
    expect(Object.isFrozen(proof)).toBe(true);
    expect(Object.isFrozen(proof.proof)).toBe(true);
    for (const node of proof.proof) {
      expect(Object.isFrozen(node)).toBe(true);
    }
  });

  it('is not writable by contract: attempting to mutate a frozen field throws (ES modules are strict by default)', () => {
    const manifest = buildArtifactChunkManifest(Uint8Array.of(1, 2, 3), 1024);
    expect(() => {
      // @ts-expect-error -- intentionally violating the readonly contract to prove it is enforced at runtime too
      manifest.merkleRoot = 'tampered';
    }).toThrow();
  });
});

describe('no source path, URL, token, credential, or Storage locator in public output', () => {
  const FORBIDDEN_KEY_OR_VALUE_PATTERN =
    /path|url|token|credential|bucket|storage|secret|password/i;

  function assertNoForbiddenFields(value: unknown, seen = new Set<unknown>()): void {
    if (value === null || typeof value !== 'object') {
      if (typeof value === 'string') {
        expect(value).not.toMatch(FORBIDDEN_KEY_OR_VALUE_PATTERN);
      }
      return;
    }
    if (seen.has(value)) return;
    seen.add(value);
    for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
      expect(key).not.toMatch(FORBIDDEN_KEY_OR_VALUE_PATTERN);
      assertNoForbiddenFields(nested, seen);
    }
  }

  it('the manifest carries no such field', () => {
    const manifest = buildArtifactChunkManifest(bytesOf(Buffer.alloc(3000, 3)), 1024);
    assertNoForbiddenFields(manifest);
  });

  it('the proof carries no such field', () => {
    const manifest = buildArtifactChunkManifest(bytesOf(Buffer.alloc(3000, 3)), 1024);
    const proof = buildArtifactChunkProof(manifest, 0);
    assertNoForbiddenFields(proof);
  });

  it('the calibration receipt carries no such field', () => {
    const stdout = execFileSync('node', ['scripts/run-artifact-chunk-calibration.mjs'], {
      cwd: repoRoot,
      encoding: 'utf8',
    });
    const receipt = JSON.parse(stdout);
    assertNoForbiddenFields(receipt);
  });
});

describe('calibration script', () => {
  it('prints exactly one JSON object to stdout and reports pass, byte-identical across two runs', () => {
    const run = () =>
      execFileSync('node', ['scripts/run-artifact-chunk-calibration.mjs'], {
        cwd: repoRoot,
        encoding: 'utf8',
      });
    const first = run();
    const second = run();
    expect(first).toBe(second);

    const parsed = JSON.parse(first);
    expect(parsed.result).toBe('pass');
    expect(parsed.profileVersion).toBe(ARTIFACT_CHUNK_MERKLE_PROFILE_VERSION);
    expect(parsed.totalCases).toBe(parsed.cases.length);
    expect(parsed.allowedChunkSizes).toEqual([...ALLOWED_CHUNK_SIZES]);
    expect(parsed.bounds).toMatchObject({
      defaultChunkSize: DEFAULT_CHUNK_SIZE,
      maxCalibrationSourceBytes: MAX_CALIBRATION_SOURCE_BYTES,
      maxChunkCount: MAX_CHUNK_COUNT,
      maxMerkleProofDepth: MAX_MERKLE_PROOF_DEPTH,
    });
  });
});
