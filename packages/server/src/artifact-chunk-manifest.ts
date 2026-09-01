import { createHash } from 'node:crypto';

/**
 * Issue #34 S1b: bounded deterministic synthetic chunk/Merkle worker
 * calibration.
 *
 * This module is a local, deterministic, model-free, network-free utility.
 * It accepts in-memory `Uint8Array` bytes only -- never a file path, URL,
 * Storage object, bucket, object key, or credential (enforced at runtime,
 * not just by TypeScript's type system -- see `assertIsUint8Array`). It
 * computes a full source SHA-256, splits bytes into bounded deterministic
 * chunks, computes domain-separated chunk hashes, builds a deterministic
 * binary Merkle tree, and emits/verifies bounded inclusion proofs.
 *
 * This is not the deterministic inspector/Edge execution surface, not
 * Storage byte custody, not MCP runtime registration, and not artifact
 * ingest. It defines the exact hash algorithm those future surfaces would
 * need to agree on, calibrated here against synthetic vectors only. See
 * `docs/evidence/ISSUE_34_S1B_CHUNK_MERKLE_CALIBRATION.md`.
 *
 * Two hash fields on every chunk and every proof are deliberately distinct
 * and never conflated:
 *   - `chunkSha256`      = SHA256(raw chunk bytes) -- the same meaning as
 *                          the accepted S0 `chunkSha256` field.
 *   - `merkleLeafSha256` = SHA256(0x00 || raw chunk bytes) -- this
 *                          module's own domain-separated Merkle leaf.
 *
 * A per-chunk inclusion proof (`ArtifactChunkProof`, verified by
 * `verifyArtifactChunkProof`) proves that one chunk's bytes are included,
 * at a declared position, under a declared Merkle root. It does NOT prove
 * anything about bytes outside that one chunk, and it does NOT prove that
 * `sourceSha256` corresponds to any real bytes (a per-chunk proof never
 * receives the whole source). Full-source integrity -- including bytes
 * outside whichever chunk a caller happened to check -- requires
 * `verifyArtifactSourceManifest`, which does receive the whole source and
 * recomputes everything from it.
 */

// ---------------------------------------------------------------------------
// Canonical hash profile: artifact-chunk-merkle/0.1
// ---------------------------------------------------------------------------

export const ARTIFACT_CHUNK_MERKLE_PROFILE_VERSION = 'artifact-chunk-merkle/0.1' as const;

/** Domain-separation byte for a Merkle leaf hash:
 * `SHA256(0x00 || raw chunk bytes)`. */
const LEAF_DOMAIN_PREFIX = Uint8Array.of(0x00);
/** Domain-separation byte for a parent hash:
 * `SHA256(0x01 || left child digest bytes || right child digest bytes)`. */
const PARENT_DOMAIN_PREFIX = Uint8Array.of(0x01);
/** Domain-separation byte for the canonical empty-artifact Merkle root:
 * `SHA256(0x02)`. */
const EMPTY_ROOT_DOMAIN_PREFIX = Uint8Array.of(0x02);

const HEX64_PATTERN = /^[0-9a-f]{64}$/;

function rawDigest(bytes: Uint8Array): Buffer {
  return createHash('sha256').update(bytes).digest();
}

function merkleLeafDigest(chunkBytes: Uint8Array): Buffer {
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
  'INVALID_INPUT_TYPE',
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

/**
 * Runtime type gate for every public function that accepts byte input.
 * TypeScript callers are already constrained to `Uint8Array`; this exists
 * for callers who bypass the type system (plain JS, deserialized JSON, a
 * widened value) -- an array, a string, a raw `ArrayBuffer` (not a typed
 * array view over one), or a plain object must all be rejected before
 * `byteLength` is read or `Buffer.from` is called on them. `Buffer` is
 * accepted because it is itself a `Uint8Array` subtype.
 */
function assertIsUint8Array(value: unknown, label: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new ArtifactChunkManifestError(
      'INVALID_INPUT_TYPE',
      `${label} must be a Uint8Array (a Buffer is accepted as a Uint8Array subtype); ` +
        'arrays, strings, ArrayBuffer, and plain objects are rejected.',
    );
  }
}

// ---------------------------------------------------------------------------
// Manifest and proof shapes
// ---------------------------------------------------------------------------

export interface ArtifactChunkManifestEntry {
  readonly chunkIndex: number;
  readonly byteStart: number;
  readonly byteLength: number;
  /** SHA256(raw chunk bytes) -- the same meaning as the accepted S0
   * `chunkSha256` field. */
  readonly chunkSha256: string;
  /** SHA256(0x00 || raw chunk bytes) -- this module's domain-separated
   * Merkle leaf. Never the same value as `chunkSha256`. */
  readonly merkleLeafSha256: string;
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

/**
 * A bounded inclusion proof for exactly one chunk. Carries the source
 * geometry it was derived from (`sourceSha256`, `sourceByteLength`,
 * `chunkSize`, `totalChunkCount`) so a verifier can check the proof is
 * internally coherent without needing the manifest it came from -- but
 * `sourceSha256` here can only ever be checked for *shape* (a well-formed
 * hex digest), never for cryptographic correspondence to real bytes, since
 * a per-chunk proof never carries the whole source.
 */
export interface ArtifactChunkProof {
  readonly profileVersion: typeof ARTIFACT_CHUNK_MERKLE_PROFILE_VERSION;
  readonly sourceSha256: string;
  readonly sourceByteLength: number;
  readonly chunkSize: AllowedChunkSize;
  readonly totalChunkCount: number;
  readonly chunkIndex: number;
  readonly byteStart: number;
  readonly byteLength: number;
  readonly chunkSha256: string;
  readonly merkleLeafSha256: string;
  readonly proof: readonly ArtifactChunkMerkleProofNode[];
}

// ---------------------------------------------------------------------------
// Merkle tree construction
//
// Odd-node rule: at any level with an odd node count, the final node is
// duplicated and paired with itself before hashing the parent. A zero-leaf
// tree's "root" is the canonical empty root; a one-leaf tree's root is that
// leaf's own digest (no parent hashing is performed).
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

/**
 * Builds a proof canonically aware of the odd-node duplication rule: the
 * final unpaired node at an odd-width level is recorded as its own sibling
 * (`siblingPosition: 'right'`, `siblingSha256` equal to the node's own
 * digest) rather than as a normal distinct sibling.
 */
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
// Manifest consumer closure -- the structural validator every consumer of a
// (possibly hand-constructed, possibly foreign) manifest runs before
// trusting any of its fields.
//
// Honest limit, stated once here rather than implied: this validator never
// receives source bytes, so it can check `sourceSha256` only for *shape*
// (a well-formed lowercase 64-hex digest) -- never for correspondence to
// real bytes. It DOES cryptographically close every declared chunk's
// `merkleLeafSha256` to `manifest.merkleRoot` by rebuilding the tree from
// the declared leaf hashes and comparing; that part needs no source bytes,
// because the leaf hashes are already given. Closing `sourceSha256` and
// every `chunkSha256`/`merkleLeafSha256` against the ACTUAL bytes they
// claim to hash is what `verifyArtifactSourceManifest` is for.
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
  if (!Number.isInteger(manifest.byteLength) || manifest.byteLength < 0) {
    throw new ArtifactChunkManifestError(
      'INCONSISTENT_MANIFEST',
      'Manifest byte length must be a non-negative integer.',
    );
  }
  // Checked ahead of both the byte-length ceiling and the chunk-count/
  // byte-length consistency requirement below: this is an absolute ceiling
  // on the manifest's own declared chunkCount and does not depend on any
  // other field first being internally consistent.
  if (manifest.chunkCount > MAX_CHUNK_COUNT) {
    throw new ArtifactChunkManifestError(
      'CHUNK_COUNT_EXCEEDED',
      `Chunk count ${manifest.chunkCount} exceeds the maximum of ${MAX_CHUNK_COUNT}.`,
    );
  }
  if (manifest.byteLength > MAX_CALIBRATION_SOURCE_BYTES) {
    throw new ArtifactChunkManifestError(
      'SOURCE_TOO_LARGE',
      `Manifest byte length ${manifest.byteLength} exceeds the maximum of ${MAX_CALIBRATION_SOURCE_BYTES} bytes.`,
    );
  }
  const expectedChunkCount =
    manifest.byteLength === 0 ? 0 : Math.ceil(manifest.byteLength / manifest.chunkSize);
  if (manifest.chunkCount !== expectedChunkCount) {
    throw new ArtifactChunkManifestError(
      'INCONSISTENT_MANIFEST',
      'Chunk count does not match ceil(byteLength / chunkSize).',
    );
  }
  if (!HEX64_PATTERN.test(manifest.sourceSha256)) {
    throw new ArtifactChunkManifestError(
      'MALFORMED_DIGEST',
      'Manifest sourceSha256 must be a lowercase 64-hex-character SHA-256 digest.',
    );
  }
  if (!HEX64_PATTERN.test(manifest.merkleRoot)) {
    throw new ArtifactChunkManifestError(
      'MALFORMED_DIGEST',
      'Manifest merkleRoot must be a lowercase 64-hex-character SHA-256 digest.',
    );
  }
  if (manifest.chunks.length !== manifest.chunkCount) {
    throw new ArtifactChunkManifestError(
      'INCONSISTENT_MANIFEST',
      'Chunk array length does not match the declared chunk count.',
    );
  }

  const leafDigests: Buffer[] = [];
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
    if (chunk.byteStart !== i * manifest.chunkSize) {
      throw new ArtifactChunkManifestError(
        'INCONSISTENT_MANIFEST',
        'Chunk byteStart must equal chunkIndex * chunkSize.',
      );
    }
    if (chunk.byteStart !== expectedStart) {
      throw new ArtifactChunkManifestError(
        'INCONSISTENT_MANIFEST',
        'Chunk byte ranges must be contiguous.',
      );
    }
    const isFinal = i === manifest.chunks.length - 1;
    const expectedByteLength = isFinal ? manifest.byteLength - chunk.byteStart : manifest.chunkSize;
    if (chunk.byteLength !== expectedByteLength) {
      throw new ArtifactChunkManifestError(
        'INCONSISTENT_MANIFEST',
        isFinal
          ? 'The final chunk byteLength must equal byteLength - byteStart.'
          : 'Every non-final chunk must be exactly chunkSize bytes.',
      );
    }
    if (chunk.byteLength < 1 || chunk.byteLength > manifest.chunkSize) {
      throw new ArtifactChunkManifestError(
        'INCONSISTENT_MANIFEST',
        'Chunk byteLength must be positive and at most chunkSize.',
      );
    }
    if (!HEX64_PATTERN.test(chunk.chunkSha256)) {
      throw new ArtifactChunkManifestError(
        'MALFORMED_DIGEST',
        'Chunk chunkSha256 must be a lowercase 64-hex-character SHA-256 digest.',
      );
    }
    if (!HEX64_PATTERN.test(chunk.merkleLeafSha256)) {
      throw new ArtifactChunkManifestError(
        'MALFORMED_DIGEST',
        'Chunk merkleLeafSha256 must be a lowercase 64-hex-character SHA-256 digest.',
      );
    }
    leafDigests.push(hexToBuffer(chunk.merkleLeafSha256));
    expectedStart += chunk.byteLength;
  }
  if (expectedStart !== manifest.byteLength) {
    throw new ArtifactChunkManifestError(
      'INCONSISTENT_MANIFEST',
      'Chunk byte ranges must exactly cover the source.',
    );
  }

  // Cryptographically close the declared leaf hashes to the declared root.
  // This needs no source bytes -- the leaf hashes are already given -- and
  // it is the check that makes an empty manifest's root canonical too
  // (buildMerkleLevels([]) is exactly the SHA256(0x02) empty root).
  const levels = buildMerkleLevels(leafDigests);
  const lastLevel = levels[levels.length - 1];
  const reconstructedRoot = lastLevel?.[0];
  if (
    reconstructedRoot === undefined ||
    reconstructedRoot.toString('hex') !== manifest.merkleRoot
  ) {
    throw new ArtifactChunkManifestError(
      'INCONSISTENT_MANIFEST',
      'Declared merkleRoot does not match the root reconstructed from the declared chunk leaf hashes.',
    );
  }
}

// ---------------------------------------------------------------------------
// Proof shape consistency -- every field of a proof cross-checked against
// every other field, so a hand-constructed or mutated proof is rejected
// before any of it is trusted cryptographically.
// ---------------------------------------------------------------------------

function assertProofShapeConsistent(proof: ArtifactChunkProof): void {
  if (proof.profileVersion !== ARTIFACT_CHUNK_MERKLE_PROFILE_VERSION) {
    throw new ArtifactChunkManifestError('INCONSISTENT_MANIFEST', 'Unknown proof profile version.');
  }
  if (!isAllowedChunkSize(proof.chunkSize)) {
    throw new ArtifactChunkManifestError(
      'UNSUPPORTED_CHUNK_SIZE',
      `Unsupported chunk size: ${proof.chunkSize}.`,
    );
  }
  // Checked ahead of every totalChunkCount/depth consistency requirement
  // below: this is an absolute ceiling on the proof array's own length and
  // does not depend on any other field first being internally consistent.
  if (proof.proof.length > MAX_MERKLE_PROOF_DEPTH) {
    throw new ArtifactChunkManifestError(
      'PROOF_DEPTH_EXCEEDED',
      `Proof depth ${proof.proof.length} exceeds the maximum of ${MAX_MERKLE_PROOF_DEPTH}.`,
    );
  }
  if (
    !Number.isInteger(proof.sourceByteLength) ||
    proof.sourceByteLength < 1 ||
    proof.sourceByteLength > MAX_CALIBRATION_SOURCE_BYTES
  ) {
    throw new ArtifactChunkManifestError(
      'INCONSISTENT_MANIFEST',
      `Proof sourceByteLength must be an integer from 1 through ${MAX_CALIBRATION_SOURCE_BYTES}.`,
    );
  }
  const expectedTotalChunkCount = Math.ceil(proof.sourceByteLength / proof.chunkSize);
  if (!Number.isInteger(proof.totalChunkCount) || proof.totalChunkCount < 1) {
    throw new ArtifactChunkManifestError(
      'INCONSISTENT_MANIFEST',
      'Proof totalChunkCount must be a positive integer.',
    );
  }
  if (proof.totalChunkCount > MAX_CHUNK_COUNT) {
    throw new ArtifactChunkManifestError(
      'CHUNK_COUNT_EXCEEDED',
      `Proof totalChunkCount ${proof.totalChunkCount} exceeds the maximum of ${MAX_CHUNK_COUNT}.`,
    );
  }
  if (proof.totalChunkCount !== expectedTotalChunkCount) {
    throw new ArtifactChunkManifestError(
      'INCONSISTENT_MANIFEST',
      'Proof totalChunkCount must equal ceil(sourceByteLength / chunkSize).',
    );
  }
  if (!Number.isInteger(proof.chunkIndex) || proof.chunkIndex < 0) {
    throw new ArtifactChunkManifestError(
      'INVALID_CHUNK_INDEX',
      'Proof chunkIndex must be a non-negative integer.',
    );
  }
  if (proof.chunkIndex >= proof.totalChunkCount) {
    throw new ArtifactChunkManifestError(
      'INVALID_CHUNK_INDEX',
      'Proof chunkIndex must be within the declared total chunk count.',
    );
  }
  if (proof.byteStart !== proof.chunkIndex * proof.chunkSize) {
    throw new ArtifactChunkManifestError(
      'INCONSISTENT_MANIFEST',
      'Proof byteStart must equal chunkIndex * chunkSize, for every chunk including the final one.',
    );
  }
  const isFinalChunk = proof.chunkIndex === proof.totalChunkCount - 1;
  const expectedByteLength = isFinalChunk
    ? proof.sourceByteLength - proof.byteStart
    : proof.chunkSize;
  if (proof.byteLength !== expectedByteLength) {
    throw new ArtifactChunkManifestError(
      'INCONSISTENT_MANIFEST',
      isFinalChunk
        ? 'The final chunk byteLength must equal sourceByteLength - byteStart.'
        : 'Every non-final chunk byteLength must equal chunkSize.',
    );
  }
  if (
    !Number.isInteger(proof.byteLength) ||
    proof.byteLength < 1 ||
    proof.byteLength > proof.chunkSize
  ) {
    throw new ArtifactChunkManifestError(
      'INCONSISTENT_MANIFEST',
      'Proof byteLength must be positive and at most chunkSize.',
    );
  }
  if (!HEX64_PATTERN.test(proof.sourceSha256)) {
    throw new ArtifactChunkManifestError(
      'MALFORMED_DIGEST',
      'Proof sourceSha256 must be a lowercase 64-hex-character SHA-256 digest (shape only -- a ' +
        'per-chunk proof cannot verify this value against real source bytes).',
    );
  }
  if (!HEX64_PATTERN.test(proof.chunkSha256)) {
    throw new ArtifactChunkManifestError(
      'MALFORMED_DIGEST',
      'Proof chunkSha256 must be a lowercase 64-hex-character SHA-256 digest.',
    );
  }
  if (!HEX64_PATTERN.test(proof.merkleLeafSha256)) {
    throw new ArtifactChunkManifestError(
      'MALFORMED_DIGEST',
      'Proof merkleLeafSha256 must be a lowercase 64-hex-character SHA-256 digest.',
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
  assertIsUint8Array(bytes, 'bytes');
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

  const sourceSha256 = rawDigest(source).toString('hex');

  const chunks: ArtifactChunkManifestEntry[] = [];
  const leafDigests: Buffer[] = [];
  for (let i = 0; i < chunkCount; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, byteLength);
    const chunkBytes = source.subarray(start, end);
    const rawChunkDigest = rawDigest(chunkBytes);
    const leafDig = merkleLeafDigest(chunkBytes);
    leafDigests.push(leafDig);
    chunks.push(
      Object.freeze({
        chunkIndex: i,
        byteStart: start,
        byteLength: end - start,
        chunkSha256: rawChunkDigest.toString('hex'),
        merkleLeafSha256: leafDig.toString('hex'),
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
 * from the manifest's own ordered leaf hashes (no raw source bytes
 * required). Rebuilds the tree from `manifest.chunks[].merkleLeafSha256`,
 * so a hand-constructed, internally inconsistent manifest is rejected
 * before any proof is built.
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

  const leafDigests = manifest.chunks.map((chunk) => hexToBuffer(chunk.merkleLeafSha256));
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
    sourceSha256: manifest.sourceSha256,
    sourceByteLength: manifest.byteLength,
    chunkSize: manifest.chunkSize,
    totalChunkCount: manifest.chunkCount,
    chunkIndex: chunk.chunkIndex,
    byteStart: chunk.byteStart,
    byteLength: chunk.byteLength,
    chunkSha256: chunk.chunkSha256,
    merkleLeafSha256: chunk.merkleLeafSha256,
    proof: Object.freeze(proofNodes),
  });
}

/**
 * Verifies that `chunkBytes` is included, at the position and under the
 * geometry the proof declares, under `expectedRoot`. Always recomputes both
 * `chunkSha256` (raw) and `merkleLeafSha256` (domain-separated) from the
 * live `chunkBytes` and requires both to match the proof's declared values;
 * never trusts either blindly, and never trusts `expectedRoot` without
 * walking the proof.
 *
 * The odd-node duplication rule is verified canonically, tracking both the
 * current index and the current level width: at the one node per level
 * that is the final, unpaired member of an odd-width level, the sibling
 * MUST be recorded as `{ siblingPosition: 'right', siblingSha256: <the
 * current node's own digest> }` -- exactly, not merely a value that closes
 * to some claimed root. A proof that supplies a different "sibling" at
 * that step is rejected before `expectedRoot` is ever consulted, so an
 * attacker cannot route around the duplication rule by also recomputing a
 * matching (but non-canonical) root.
 *
 * Shape defects (malformed digest, malformed position, depth over ceiling,
 * internally inconsistent geometry, non-`Uint8Array` input) throw a typed
 * `ArtifactChunkManifestError`. A well-shaped but cryptographically failing
 * proof returns `false`. Successfully parsing the proof's shape is a
 * precondition, never a substitute for the walk.
 *
 * This function proves inclusion of exactly one chunk. It proves nothing
 * about bytes outside that chunk and nothing about whether `sourceSha256`
 * corresponds to any real bytes -- for that, use
 * `verifyArtifactSourceManifest`.
 */
export function verifyArtifactChunkProof(
  chunkBytes: Uint8Array,
  proof: ArtifactChunkProof,
  expectedRoot: string,
): boolean {
  assertIsUint8Array(chunkBytes, 'chunkBytes');
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
  const rawChunkHex = rawDigest(chunkBytes).toString('hex');
  if (rawChunkHex !== proof.chunkSha256) {
    return false;
  }
  const leafDigestBuf = merkleLeafDigest(chunkBytes);
  if (leafDigestBuf.toString('hex') !== proof.merkleLeafSha256) {
    return false;
  }

  let current = leafDigestBuf;
  let index = proof.chunkIndex;
  let width = proof.totalChunkCount;
  for (const node of proof.proof) {
    const isOddWidthDuplicateStep = width % 2 === 1 && index === width - 1;
    if (isOddWidthDuplicateStep) {
      if (node.siblingPosition !== 'right') {
        return false;
      }
      if (node.siblingSha256 !== current.toString('hex')) {
        return false;
      }
      current = parentDigest(current, current);
    } else {
      const expectedPosition: MerkleSiblingPosition = index % 2 === 1 ? 'left' : 'right';
      if (node.siblingPosition !== expectedPosition) {
        return false;
      }
      const siblingDigest = hexToBuffer(node.siblingSha256);
      current =
        node.siblingPosition === 'left'
          ? parentDigest(siblingDigest, current)
          : parentDigest(current, siblingDigest);
    }
    index = Math.floor(index / 2);
    width = Math.ceil(width / 2);
  }
  if (width !== 1) {
    // Structural safety net: the depth check above should already make this
    // unreachable, but the walk itself must never claim success without
    // having actually reduced to a single root-level node.
    return false;
  }

  return current.toString('hex') === expectedRoot;
}

/**
 * Verifies full-source integrity: that `sourceBytes` is exactly the source
 * `manifest` describes, from the first byte to the last. Unlike a
 * per-chunk proof, this receives the whole source, so it recomputes and
 * checks everything: `sourceSha256`, every chunk's `chunkSha256` and
 * `merkleLeafSha256` against that chunk's actual byte range, and the
 * Merkle root rebuilt from those freshly recomputed leaf hashes. A
 * mutation anywhere in `sourceBytes` -- including outside whichever chunk a
 * caller separately checked with `verifyArtifactChunkProof` -- changes
 * `sourceSha256` and is caught here.
 *
 * Throws a typed `ArtifactChunkManifestError` for malformed shape
 * (non-`Uint8Array` input, or a manifest that fails
 * `assertManifestConsistent`). Returns `false` for a well-shaped
 * cryptographic mismatch between `sourceBytes` and `manifest`.
 */
export function verifyArtifactSourceManifest(
  sourceBytes: Uint8Array,
  manifest: ArtifactChunkManifest,
): boolean {
  assertIsUint8Array(sourceBytes, 'sourceBytes');
  assertManifestConsistent(manifest);

  if (sourceBytes.byteLength !== manifest.byteLength) {
    return false;
  }
  if (rawDigest(sourceBytes).toString('hex') !== manifest.sourceSha256) {
    return false;
  }

  const recomputedLeafDigests: Buffer[] = [];
  for (const chunk of manifest.chunks) {
    const chunkBytes = sourceBytes.subarray(chunk.byteStart, chunk.byteStart + chunk.byteLength);
    if (rawDigest(chunkBytes).toString('hex') !== chunk.chunkSha256) {
      return false;
    }
    const leafDig = merkleLeafDigest(chunkBytes);
    if (leafDig.toString('hex') !== chunk.merkleLeafSha256) {
      return false;
    }
    recomputedLeafDigests.push(leafDig);
  }

  const levels = buildMerkleLevels(recomputedLeafDigests);
  const lastLevel = levels[levels.length - 1];
  const recomputedRoot = lastLevel?.[0];
  if (recomputedRoot === undefined || recomputedRoot.toString('hex') !== manifest.merkleRoot) {
    return false;
  }

  return true;
}
