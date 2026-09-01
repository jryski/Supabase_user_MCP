import { createHash } from 'node:crypto';

/**
 * Issue #34 S1b: bounded deterministic synthetic chunk/Merkle worker
 * calibration.
 *
 * This module is a local, deterministic, model-free, network-free utility.
 * It accepts in-memory `Uint8Array` bytes only -- never a file path, URL,
 * Storage object, bucket, object key, or credential. It computes a full
 * source SHA-256, splits bytes into bounded deterministic chunks, computes
 * domain-separated chunk hashes, builds a deterministic binary Merkle tree,
 * and emits/verifies bounded inclusion proofs.
 *
 * This is not the deterministic inspector/Edge execution surface, not
 * Storage byte custody, not MCP runtime registration, and not artifact
 * ingest. It defines the exact hash algorithm those future surfaces would
 * need to agree on, calibrated here against synthetic vectors only. See
 * `docs/evidence/ISSUE_34_S1B_CHUNK_MERKLE_CALIBRATION.md`.
 */

// ---------------------------------------------------------------------------
// Canonical hash profile: artifact-chunk-merkle/0.1
// ---------------------------------------------------------------------------

export const ARTIFACT_CHUNK_MERKLE_PROFILE_VERSION = 'artifact-chunk-merkle/0.1' as const;

/** Domain-separation byte for a leaf hash: `SHA256(0x00 || raw chunk bytes)`. */
const LEAF_DOMAIN_PREFIX = Uint8Array.of(0x00);
/** Domain-separation byte for a parent hash:
 * `SHA256(0x01 || left child digest bytes || right child digest bytes)`. */
const PARENT_DOMAIN_PREFIX = Uint8Array.of(0x01);
/** Domain-separation byte for the canonical empty-artifact Merkle root:
 * `SHA256(0x02)`. */
const EMPTY_ROOT_DOMAIN_PREFIX = Uint8Array.of(0x02);

const HEX64_PATTERN = /^[0-9a-f]{64}$/;

function leafDigest(chunkBytes: Uint8Array): Buffer {
  return createHash('sha256').update(LEAF_DOMAIN_PREFIX).update(chunkBytes).digest();
}

function parentDigest(left: Buffer, right: Buffer): Buffer {
  return createHash('sha256').update(PARENT_DOMAIN_PREFIX).update(left).update(right).digest();
}

const EMPTY_MERKLE_ROOT_DIGEST = createHash('sha256').update(EMPTY_ROOT_DOMAIN_PREFIX).digest();

/** The canonical Merkle root of a zero-byte (zero-chunk) artifact:
 * `SHA256(0x02)`, lowercase hex. */
export const EMPTY_ARTIFACT_MERKLE_ROOT = EMPTY_MERKLE_ROOT_DIGEST.toString('hex');

function hexToBuffer(hex: string): Buffer {
  return Buffer.from(hex, 'hex');
}

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

export const ALLOWED_CHUNK_SIZES = Object.freeze([1_024, 4_096, 8_192] as const);
export type AllowedChunkSize = (typeof ALLOWED_CHUNK_SIZES)[number];

export const DEFAULT_CHUNK_SIZE: AllowedChunkSize = 4_096;
export const MAX_CALIBRATION_SOURCE_BYTES = 1_048_576;
export const MAX_CHUNK_COUNT = 4_096;
export const MAX_MERKLE_PROOF_DEPTH = 32;

function isAllowedChunkSize(value: number): value is AllowedChunkSize {
  return (ALLOWED_CHUNK_SIZES as readonly number[]).includes(value);
}

// ---------------------------------------------------------------------------
// Error vocabulary
// ---------------------------------------------------------------------------

export const ARTIFACT_CHUNK_MANIFEST_ERROR_CODES = Object.freeze([
  'UNSUPPORTED_CHUNK_SIZE',
  'SOURCE_TOO_LARGE',
  'CHUNK_COUNT_EXCEEDED',
  'PROOF_DEPTH_EXCEEDED',
  'INVALID_CHUNK_INDEX',
  'MALFORMED_DIGEST',
  'MALFORMED_PROOF_POSITION',
  'INCONSISTENT_MANIFEST',
] as const);
export type ArtifactChunkManifestErrorCode = (typeof ARTIFACT_CHUNK_MANIFEST_ERROR_CODES)[number];

export class ArtifactChunkManifestError extends Error {
  readonly code: ArtifactChunkManifestErrorCode;

  constructor(code: ArtifactChunkManifestErrorCode, message: string) {
    super(message);
    this.name = 'ArtifactChunkManifestError';
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// Manifest and proof shapes
// ---------------------------------------------------------------------------

export interface ArtifactChunkManifestEntry {
  readonly chunkIndex: number;
  readonly byteStart: number;
  readonly byteLength: number;
  readonly chunkSha256: string;
}

export interface ArtifactChunkManifest {
  readonly profileVersion: typeof ARTIFACT_CHUNK_MERKLE_PROFILE_VERSION;
  readonly sourceSha256: string;
  readonly byteLength: number;
  readonly chunkSize: AllowedChunkSize;
  readonly chunkCount: number;
  readonly chunks: readonly ArtifactChunkManifestEntry[];
  readonly merkleRoot: string;
}

export type MerkleSiblingPosition = 'left' | 'right';

export interface ArtifactChunkMerkleProofNode {
  readonly siblingPosition: MerkleSiblingPosition;
  readonly siblingSha256: string;
}

export interface ArtifactChunkProof {
  readonly profileVersion: typeof ARTIFACT_CHUNK_MERKLE_PROFILE_VERSION;
  readonly chunkIndex: number;
  readonly byteStart: number;
  readonly byteLength: number;
  readonly chunkSha256: string;
  readonly totalChunkCount: number;
  readonly proof: readonly ArtifactChunkMerkleProofNode[];
}

// ---------------------------------------------------------------------------
// Merkle tree construction
//
// Odd-node rule: duplicate the final node at each level before hashing the
// parent. A zero-leaf tree's "root" is the canonical empty root; a one-leaf
// tree's root is that leaf's own digest (no parent hashing is performed).
// ---------------------------------------------------------------------------

function buildMerkleLevels(leaves: readonly Buffer[]): Buffer[][] {
  if (leaves.length === 0) {
    return [[EMPTY_MERKLE_ROOT_DIGEST]];
  }
  const firstLevel: Buffer[] = [...leaves];
  const levels: Buffer[][] = [firstLevel];
  let current = firstLevel;
  while (current.length > 1) {
    const next: Buffer[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const left = current[i];
      const right = i + 1 < current.length ? current[i + 1] : current[i];
      if (left === undefined || right === undefined) {
        throw new ArtifactChunkManifestError(
          'INCONSISTENT_MANIFEST',
          'Merkle level construction produced an undefined node.',
        );
      }
      next.push(parentDigest(left, right));
    }
    levels.push(next);
    current = next;
  }
  return levels;
}

function expectedProofDepthFor(totalChunkCount: number): number {
  return totalChunkCount <= 1 ? 0 : Math.ceil(Math.log2(totalChunkCount));
}

function buildProofNodesFromLevels(
  levels: readonly Buffer[][],
  leafIndex: number,
): ArtifactChunkMerkleProofNode[] {
  const nodes: ArtifactChunkMerkleProofNode[] = [];
  let index = leafIndex;
  for (let level = 0; level < levels.length - 1; level++) {
    const currentLevel = levels[level];
    if (currentLevel === undefined) {
      throw new ArtifactChunkManifestError('INCONSISTENT_MANIFEST', 'Missing Merkle tree level.');
    }
    const isRightChild = index % 2 === 1;
    const siblingIndex = isRightChild ? index - 1 : index + 1;
    const siblingDigest =
      siblingIndex < currentLevel.length ? currentLevel[siblingIndex] : currentLevel[index];
    if (siblingDigest === undefined) {
      throw new ArtifactChunkManifestError(
        'INCONSISTENT_MANIFEST',
        'Merkle proof construction could not resolve a sibling digest.',
      );
    }
    nodes.push(
      Object.freeze({
        siblingPosition: isRightChild ? ('left' as const) : ('right' as const),
        siblingSha256: siblingDigest.toString('hex'),
      }),
    );
    index = Math.floor(index / 2);
  }
  return nodes;
}

// ---------------------------------------------------------------------------
// Manifest / proof internal consistency checks
//
// These validate a manifest or proof object's *shape* -- including one that
// was not produced by this module's own builders -- before any function
// trusts its fields. Successfully parsing a shape is never treated as
// cryptographic verification.
// ---------------------------------------------------------------------------

function assertManifestConsistent(manifest: ArtifactChunkManifest): void {
  if (manifest.profileVersion !== ARTIFACT_CHUNK_MERKLE_PROFILE_VERSION) {
    throw new ArtifactChunkManifestError(
      'INCONSISTENT_MANIFEST',
      'Unknown manifest profile version.',
    );
  }
  if (!isAllowedChunkSize(manifest.chunkSize)) {
    throw new ArtifactChunkManifestError(
      'UNSUPPORTED_CHUNK_SIZE',
      `Unsupported chunk size: ${manifest.chunkSize}.`,
    );
  }
  if (manifest.chunkCount > MAX_CHUNK_COUNT) {
    throw new ArtifactChunkManifestError(
      'CHUNK_COUNT_EXCEEDED',
      `Chunk count ${manifest.chunkCount} exceeds the maximum of ${MAX_CHUNK_COUNT}.`,
    );
  }
  if (manifest.chunks.length !== manifest.chunkCount) {
    throw new ArtifactChunkManifestError(
      'INCONSISTENT_MANIFEST',
      'Chunk array length does not match the declared chunk count.',
    );
  }
  if (manifest.byteLength === 0) {
    if (manifest.chunkCount !== 0) {
      throw new ArtifactChunkManifestError(
        'INCONSISTENT_MANIFEST',
        'A zero-byte source must declare zero chunks.',
      );
    }
  } else {
    const expectedCount = Math.ceil(manifest.byteLength / manifest.chunkSize);
    if (manifest.chunkCount !== expectedCount) {
      throw new ArtifactChunkManifestError(
        'INCONSISTENT_MANIFEST',
        'Chunk count does not match ceil(byteLength / chunkSize).',
      );
    }
  }

  let expectedStart = 0;
  for (let i = 0; i < manifest.chunks.length; i++) {
    const chunk = manifest.chunks[i];
    if (chunk === undefined) {
      throw new ArtifactChunkManifestError('INCONSISTENT_MANIFEST', 'Missing chunk entry.');
    }
    if (chunk.chunkIndex !== i) {
      throw new ArtifactChunkManifestError(
        'INCONSISTENT_MANIFEST',
        'Chunk indexes must begin at zero and be contiguous.',
      );
    }
    if (chunk.byteStart !== expectedStart) {
      throw new ArtifactChunkManifestError(
        'INCONSISTENT_MANIFEST',
        'Chunk byte ranges must begin at zero and be contiguous.',
      );
    }
    const isFinal = i === manifest.chunks.length - 1;
    if (!isFinal && chunk.byteLength !== manifest.chunkSize) {
      throw new ArtifactChunkManifestError(
        'INCONSISTENT_MANIFEST',
        'Every non-final chunk must be exactly chunkSize bytes.',
      );
    }
    if (isFinal && (chunk.byteLength < 1 || chunk.byteLength > manifest.chunkSize)) {
      throw new ArtifactChunkManifestError(
        'INCONSISTENT_MANIFEST',
        'The final chunk must be between 1 and chunkSize bytes.',
      );
    }
    if (!HEX64_PATTERN.test(chunk.chunkSha256)) {
      throw new ArtifactChunkManifestError(
        'MALFORMED_DIGEST',
        'Chunk hash must be a lowercase 64-hex-character SHA-256 digest.',
      );
    }
    expectedStart += chunk.byteLength;
  }
  if (expectedStart !== manifest.byteLength) {
    throw new ArtifactChunkManifestError(
      'INCONSISTENT_MANIFEST',
      'Chunk byte ranges must exactly cover the source.',
    );
  }
  if (!HEX64_PATTERN.test(manifest.merkleRoot)) {
    throw new ArtifactChunkManifestError(
      'MALFORMED_DIGEST',
      'Merkle root must be a lowercase 64-hex-character SHA-256 digest.',
    );
  }
}

function assertProofShapeConsistent(proof: ArtifactChunkProof): void {
  if (proof.profileVersion !== ARTIFACT_CHUNK_MERKLE_PROFILE_VERSION) {
    throw new ArtifactChunkManifestError('INCONSISTENT_MANIFEST', 'Unknown proof profile version.');
  }
  if (!Number.isInteger(proof.totalChunkCount) || proof.totalChunkCount < 1) {
    throw new ArtifactChunkManifestError(
      'INCONSISTENT_MANIFEST',
      'Proof total chunk count must be a positive integer.',
    );
  }
  if (proof.totalChunkCount > MAX_CHUNK_COUNT) {
    throw new ArtifactChunkManifestError(
      'CHUNK_COUNT_EXCEEDED',
      `Proof total chunk count ${proof.totalChunkCount} exceeds the maximum of ${MAX_CHUNK_COUNT}.`,
    );
  }
  if (!Number.isInteger(proof.chunkIndex) || proof.chunkIndex < 0) {
    throw new ArtifactChunkManifestError(
      'INVALID_CHUNK_INDEX',
      'Proof chunk index must be a non-negative integer.',
    );
  }
  if (proof.chunkIndex >= proof.totalChunkCount) {
    throw new ArtifactChunkManifestError(
      'INVALID_CHUNK_INDEX',
      'Proof chunk index must be within the declared total chunk count.',
    );
  }
  if (!Number.isInteger(proof.byteStart) || proof.byteStart < 0) {
    throw new ArtifactChunkManifestError(
      'INCONSISTENT_MANIFEST',
      'Proof byte start must be a non-negative integer.',
    );
  }
  if (!Number.isInteger(proof.byteLength) || proof.byteLength < 1) {
    throw new ArtifactChunkManifestError(
      'INCONSISTENT_MANIFEST',
      'Proof byte length must be a positive integer.',
    );
  }
  // A non-final chunk is always exactly the uniform chunk size (an S1b
  // manifest invariant, checked in assertManifestConsistent), so for a
  // non-final chunk byteLength IS that uniform chunk size, and byteStart
  // must equal chunkIndex * byteLength. This lets byteStart's mutation be
  // caught here even though chunkSize itself is not a proof field. The
  // final chunk's own byteLength may be shorter than the uniform size, so
  // this check does not apply to it.
  const isFinalChunk = proof.chunkIndex === proof.totalChunkCount - 1;
  if (!isFinalChunk && proof.byteStart !== proof.chunkIndex * proof.byteLength) {
    throw new ArtifactChunkManifestError(
      'INCONSISTENT_MANIFEST',
      'Non-final chunk byteStart must equal chunkIndex * byteLength.',
    );
  }
  if (!HEX64_PATTERN.test(proof.chunkSha256)) {
    throw new ArtifactChunkManifestError(
      'MALFORMED_DIGEST',
      'Proof chunk hash must be a lowercase 64-hex-character SHA-256 digest.',
    );
  }
  if (proof.proof.length > MAX_MERKLE_PROOF_DEPTH) {
    throw new ArtifactChunkManifestError(
      'PROOF_DEPTH_EXCEEDED',
      `Proof depth ${proof.proof.length} exceeds the maximum of ${MAX_MERKLE_PROOF_DEPTH}.`,
    );
  }
  if (proof.proof.length !== expectedProofDepthFor(proof.totalChunkCount)) {
    throw new ArtifactChunkManifestError(
      'INCONSISTENT_MANIFEST',
      'Proof depth does not match the depth expected for the declared total chunk count.',
    );
  }
  for (const node of proof.proof) {
    if (node.siblingPosition !== 'left' && node.siblingPosition !== 'right') {
      throw new ArtifactChunkManifestError(
        'MALFORMED_PROOF_POSITION',
        'Sibling position must be "left" or "right".',
      );
    }
    if (!HEX64_PATTERN.test(node.siblingSha256)) {
      throw new ArtifactChunkManifestError(
        'MALFORMED_DIGEST',
        'Sibling hash must be a lowercase 64-hex-character SHA-256 digest.',
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Public deterministic worker functions
// ---------------------------------------------------------------------------

/**
 * Builds a deterministic chunk manifest for in-memory bytes only. Never
 * accepts or resolves a file path, URL, Storage object, bucket, object key,
 * or credential. Always defensively copies `bytes` before use, so the
 * returned manifest can never alias caller-owned memory the caller mutates
 * afterward, and this function never mutates the caller's array.
 */
export function buildArtifactChunkManifest(
  bytes: Uint8Array,
  chunkSize: AllowedChunkSize = DEFAULT_CHUNK_SIZE,
): ArtifactChunkManifest {
  if (!isAllowedChunkSize(chunkSize)) {
    throw new ArtifactChunkManifestError(
      'UNSUPPORTED_CHUNK_SIZE',
      `Unsupported chunk size: ${chunkSize}.`,
    );
  }
  if (bytes.byteLength > MAX_CALIBRATION_SOURCE_BYTES) {
    throw new ArtifactChunkManifestError(
      'SOURCE_TOO_LARGE',
      `Source of ${bytes.byteLength} bytes exceeds the maximum of ${MAX_CALIBRATION_SOURCE_BYTES} bytes.`,
    );
  }

  const source = Buffer.from(bytes); // defensive copy; never aliases the caller's array
  const byteLength = source.byteLength;
  const chunkCount = byteLength === 0 ? 0 : Math.ceil(byteLength / chunkSize);
  if (chunkCount > MAX_CHUNK_COUNT) {
    throw new ArtifactChunkManifestError(
      'CHUNK_COUNT_EXCEEDED',
      `Chunk count ${chunkCount} exceeds the maximum of ${MAX_CHUNK_COUNT}.`,
    );
  }

  const sourceSha256 = createHash('sha256').update(source).digest('hex');

  const chunks: ArtifactChunkManifestEntry[] = [];
  const leafDigests: Buffer[] = [];
  for (let i = 0; i < chunkCount; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, byteLength);
    const chunkBytes = source.subarray(start, end);
    const digest = leafDigest(chunkBytes);
    leafDigests.push(digest);
    chunks.push(
      Object.freeze({
        chunkIndex: i,
        byteStart: start,
        byteLength: end - start,
        chunkSha256: digest.toString('hex'),
      }),
    );
  }

  const levels = buildMerkleLevels(leafDigests);
  const lastLevel = levels[levels.length - 1];
  const rootDigest = lastLevel?.[0];
  if (rootDigest === undefined) {
    throw new ArtifactChunkManifestError('INCONSISTENT_MANIFEST', 'Merkle tree produced no root.');
  }

  return Object.freeze({
    profileVersion: ARTIFACT_CHUNK_MERKLE_PROFILE_VERSION,
    sourceSha256,
    byteLength,
    chunkSize,
    chunkCount,
    chunks: Object.freeze(chunks),
    merkleRoot: rootDigest.toString('hex'),
  });
}

/**
 * Builds a bounded Merkle inclusion proof for one chunk, derived entirely
 * from the manifest's own ordered chunk hashes (no raw source bytes
 * required). Rebuilds the tree from `manifest.chunks[].chunkSha256`, so a
 * hand-constructed, internally inconsistent manifest is rejected before any
 * proof is built.
 */
export function buildArtifactChunkProof(
  manifest: ArtifactChunkManifest,
  chunkIndex: number,
): ArtifactChunkProof {
  assertManifestConsistent(manifest);
  if (!Number.isInteger(chunkIndex) || chunkIndex < 0 || chunkIndex >= manifest.chunkCount) {
    throw new ArtifactChunkManifestError(
      'INVALID_CHUNK_INDEX',
      `Chunk index ${chunkIndex} is out of range for chunk count ${manifest.chunkCount}.`,
    );
  }

  const leafDigests = manifest.chunks.map((chunk) => hexToBuffer(chunk.chunkSha256));
  const levels = buildMerkleLevels(leafDigests);
  const proofNodes = buildProofNodesFromLevels(levels, chunkIndex);
  if (proofNodes.length > MAX_MERKLE_PROOF_DEPTH) {
    throw new ArtifactChunkManifestError(
      'PROOF_DEPTH_EXCEEDED',
      `Proof depth ${proofNodes.length} exceeds the maximum of ${MAX_MERKLE_PROOF_DEPTH}.`,
    );
  }

  const chunk = manifest.chunks[chunkIndex];
  if (chunk === undefined) {
    throw new ArtifactChunkManifestError('INVALID_CHUNK_INDEX', 'Resolved chunk entry is missing.');
  }

  return Object.freeze({
    profileVersion: manifest.profileVersion,
    chunkIndex: chunk.chunkIndex,
    byteStart: chunk.byteStart,
    byteLength: chunk.byteLength,
    chunkSha256: chunk.chunkSha256,
    totalChunkCount: manifest.chunkCount,
    proof: Object.freeze(proofNodes),
  });
}

/**
 * Verifies that `chunkBytes` is included, at the position and under the
 * profile the proof declares, under `expectedRoot`. Always recomputes the
 * leaf hash from the live `chunkBytes` (never trusts `proof.chunkSha256`
 * blindly) and always recomputes the path to the root (never trusts
 * `expectedRoot` without walking the proof). Successfully parsing the
 * proof's shape is a precondition, never a substitute for this walk:
 * shape defects throw a typed `ArtifactChunkManifestError`; a well-shaped
 * but cryptographically failing proof returns `false`.
 */
export function verifyArtifactChunkProof(
  chunkBytes: Uint8Array,
  proof: ArtifactChunkProof,
  expectedRoot: string,
): boolean {
  assertProofShapeConsistent(proof);
  if (!HEX64_PATTERN.test(expectedRoot)) {
    throw new ArtifactChunkManifestError(
      'MALFORMED_DIGEST',
      'Expected root must be a lowercase 64-hex-character SHA-256 digest.',
    );
  }

  if (chunkBytes.byteLength !== proof.byteLength) {
    return false;
  }
  const computedLeafHex = leafDigest(chunkBytes).toString('hex');
  if (computedLeafHex !== proof.chunkSha256) {
    return false;
  }

  let current = hexToBuffer(computedLeafHex);
  let index = proof.chunkIndex;
  for (const node of proof.proof) {
    // The sibling's declared side must match the parity `index` implies at
    // this level; this ties `chunkIndex` itself into the cryptographic walk
    // (not just the shape check above), so mutating chunkIndex alone -- with
    // every hash and position left untouched -- is still caught here.
    const expectedPosition: MerkleSiblingPosition = index % 2 === 1 ? 'left' : 'right';
    if (node.siblingPosition !== expectedPosition) {
      return false;
    }
    const siblingDigest = hexToBuffer(node.siblingSha256);
    current =
      node.siblingPosition === 'left'
        ? parentDigest(siblingDigest, current)
        : parentDigest(current, siblingDigest);
    index = Math.floor(index / 2);
  }

  return current.toString('hex') === expectedRoot;
}
