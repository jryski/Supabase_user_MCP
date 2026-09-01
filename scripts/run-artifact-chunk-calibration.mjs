// Issue #34 S1b calibration receipt.
//
// Synthetic, local, deterministic only: every byte array below is generated
// in-process from a fixed formula or a fixed literal string. This script
// performs no network access and reads no filesystem source bytes (it only
// imports the already-built implementation module). It prints exactly one
// stable JSON object to stdout and prints nothing else there; running it
// twice must produce byte-identical stdout.

import { createHash } from 'node:crypto';

import {
  ALLOWED_CHUNK_SIZES,
  ARTIFACT_CHUNK_MERKLE_PROFILE_VERSION,
  DEFAULT_CHUNK_SIZE,
  EMPTY_ARTIFACT_MERKLE_ROOT,
  MAX_CALIBRATION_SOURCE_BYTES,
  MAX_CHUNK_COUNT,
  MAX_MERKLE_PROOF_DEPTH,
  buildArtifactChunkManifest,
  buildArtifactChunkProof,
  verifyArtifactChunkProof,
} from '../packages/server/dist/artifact-chunk-manifest.js';

const RECEIPT_SCHEMA = 'artifact-chunk-calibration-receipt/0.1';

// Above this chunk count, a case verifies only a deterministic sample of
// chunks (first, middle, final) instead of every chunk, to keep this script
// fast for the maximum-size case. Every case still runs its two mutation
// checks against one of the sampled/verified chunks.
const MAX_FULL_VERIFICATION_CHUNKS = 32;

/**
 * Deterministic, non-degenerate synthetic byte generator: a SHA-256 hash
 * chain over `seed:counter`. Deterministic and reproducible -- not
 * randomness in the sense this script avoids (no clock reads, no OS
 * entropy). Deliberately not a small linear formula: a formula like
 * `(i*k+c)&0xff` repeats with a period of at most 256, which can make two
 * different chunks of the same source byte-identical whenever the chunk
 * size is itself a multiple of that period -- true for every chunk size
 * this module allows. A hash chain has no such period within any size this
 * script generates.
 */
function deterministicBytes(length, seed = 0) {
  const bytes = new Uint8Array(length);
  let offset = 0;
  let counter = 0;
  while (offset < length) {
    const block = createHash('sha256').update(`s1b-calibration:${seed}:${counter}`).digest();
    const take = Math.min(block.length, length - offset);
    bytes.set(block.subarray(0, take), offset);
    offset += take;
    counter++;
  }
  return bytes;
}

const MARKDOWN_SAMPLE =
  '# Titulo—café ☕ naïve résumé 日本語 🎯\n\n' +
  'Body text with an em dash—and ñ, ü diacritics.\n';
const MARKDOWN_BYTES = new TextEncoder().encode(MARKDOWN_SAMPLE.repeat(40));

function caseGeneratorsFor(chunkSize) {
  const evenMultiChunkLength = chunkSize * 4;
  const oddMultiChunkLength = chunkSize * 3 - 100;
  return [
    { name: 'empty', bytes: new Uint8Array(0) },
    { name: 'one-ascii-byte', bytes: Uint8Array.of(0x41) },
    { name: 'exact-one-chunk-boundary', bytes: deterministicBytes(chunkSize, 1) },
    { name: 'one-byte-over-chunk-boundary', bytes: deterministicBytes(chunkSize + 1, 2) },
    { name: 'even-multi-chunk', bytes: deterministicBytes(evenMultiChunkLength, 3) },
    { name: 'odd-multi-chunk', bytes: deterministicBytes(oddMultiChunkLength, 4) },
    { name: 'utf8-multibyte-markdown', bytes: MARKDOWN_BYTES },
    { name: 'max-byte-ceiling', bytes: deterministicBytes(MAX_CALIBRATION_SOURCE_BYTES, 5) },
  ];
}

function sampleChunkIndexes(chunkCount) {
  if (chunkCount <= MAX_FULL_VERIFICATION_CHUNKS) {
    return Array.from({ length: chunkCount }, (_, i) => i);
  }
  const first = 0;
  const middle = Math.floor(chunkCount / 2);
  const last = chunkCount - 1;
  return Array.from(new Set([first, middle, last])).sort((a, b) => a - b);
}

function flipTrailingHexDigit(hex) {
  const lastChar = hex.at(-1);
  const flipped = lastChar === '0' ? '1' : '0';
  return `${hex.slice(0, -1)}${flipped}`;
}

function fail(message) {
  throw new Error(`Calibration FAILED: ${message}`);
}

function runCase(name, bytes, chunkSize) {
  const manifest = buildArtifactChunkManifest(bytes, chunkSize);
  const sampled = manifest.chunkCount > MAX_FULL_VERIFICATION_CHUNKS;
  const indexesToVerify = sampled
    ? sampleChunkIndexes(manifest.chunkCount)
    : Array.from({ length: manifest.chunkCount }, (_, i) => i);

  let proofsChecked = 0;
  for (const index of indexesToVerify) {
    const proof = buildArtifactChunkProof(manifest, index);
    const chunkBytes = bytes.slice(proof.byteStart, proof.byteStart + proof.byteLength);
    if (verifyArtifactChunkProof(chunkBytes, proof, manifest.merkleRoot) !== true) {
      fail(`case "${name}" chunkSize ${chunkSize} chunk ${index} did not verify.`);
    }
    proofsChecked++;
  }

  const mutationChecksTotal = manifest.chunkCount > 0 ? 2 : 0;
  let mutationChecksPassed = 0;

  if (manifest.chunkCount > 0) {
    const sampleIndex = indexesToVerify[0];
    const proof = buildArtifactChunkProof(manifest, sampleIndex);
    const chunkBytes = bytes.slice(proof.byteStart, proof.byteStart + proof.byteLength);

    const mutatedBytes = Uint8Array.from(chunkBytes);
    mutatedBytes[0] = (mutatedBytes[0] + 1) & 0xff;
    if (verifyArtifactChunkProof(mutatedBytes, proof, manifest.merkleRoot) !== false) {
      fail(`case "${name}" chunkSize ${chunkSize} source-byte mutation did not fail verification.`);
    }
    mutationChecksPassed++;

    if (proof.proof.length > 0) {
      const mutatedProof = {
        ...proof,
        proof: proof.proof.map((node, i) =>
          i === 0 ? { ...node, siblingSha256: flipTrailingHexDigit(node.siblingSha256) } : node,
        ),
      };
      if (verifyArtifactChunkProof(chunkBytes, mutatedProof, manifest.merkleRoot) !== false) {
        fail(
          `case "${name}" chunkSize ${chunkSize} sibling-hash mutation did not fail verification.`,
        );
      }
    } else {
      const mutatedRoot = flipTrailingHexDigit(manifest.merkleRoot);
      if (verifyArtifactChunkProof(chunkBytes, proof, mutatedRoot) !== false) {
        fail(`case "${name}" chunkSize ${chunkSize} root mutation did not fail verification.`);
      }
    }
    mutationChecksPassed++;
  }

  return {
    name,
    byteLength: manifest.byteLength,
    chunkSize,
    chunkCount: manifest.chunkCount,
    sourceSha256: manifest.sourceSha256,
    merkleRoot: manifest.merkleRoot,
    proofsChecked,
    sampled,
    mutationChecksPassed,
    mutationChecksTotal,
  };
}

const cases = [];
for (const chunkSize of ALLOWED_CHUNK_SIZES) {
  for (const generator of caseGeneratorsFor(chunkSize)) {
    cases.push(runCase(generator.name, generator.bytes, chunkSize));
  }
}

const caseNames = Array.from(new Set(cases.map((c) => c.name)));

const receipt = {
  schema: RECEIPT_SCHEMA,
  profileVersion: ARTIFACT_CHUNK_MERKLE_PROFILE_VERSION,
  nodeVersion: process.version,
  allowedChunkSizes: [...ALLOWED_CHUNK_SIZES],
  bounds: {
    defaultChunkSize: DEFAULT_CHUNK_SIZE,
    maxCalibrationSourceBytes: MAX_CALIBRATION_SOURCE_BYTES,
    maxChunkCount: MAX_CHUNK_COUNT,
    maxMerkleProofDepth: MAX_MERKLE_PROOF_DEPTH,
  },
  emptyArtifactMerkleRoot: EMPTY_ARTIFACT_MERKLE_ROOT,
  caseNames,
  maxFullVerificationChunks: MAX_FULL_VERIFICATION_CHUNKS,
  samplingNote:
    'A case whose chunkCount exceeds maxFullVerificationChunks verifies a deterministic sample ' +
    '(first, middle, final chunk) instead of every chunk proof; that case reports "sampled": true.',
  cases,
  totalCases: cases.length,
  result: 'pass',
};

process.stdout.write(`${JSON.stringify(receipt)}\n`);
process.exitCode = 0;
