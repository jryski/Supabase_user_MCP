// Issue #34 S1b calibration receipt.
//
// Synthetic, local, deterministic only: every byte array below is generated
// in-process from a SHA-256 hash chain seeded by a fixed integer, or from a
// fixed literal string. This script performs no network access and reads no
// filesystem source bytes (it only imports the already-built implementation
// module). It prints exactly one stable JSON object to stdout and prints
// nothing else there; running it twice must produce byte-identical stdout.
//
// For every non-empty case it executes every APPLICABLE mutation class from
// the full independent-mutation matrix, and explicitly records any class
// that is structurally not applicable to that case (with a reason) rather
// than silently omitting or counting it as passed.

import { createHash } from 'node:crypto';

import {
  ALLOWED_CHUNK_SIZES,
  ARTIFACT_CHUNK_MERKLE_PROFILE_VERSION,
  buildArtifactChunkManifest,
  buildArtifactChunkProof,
  DEFAULT_CHUNK_SIZE,
  EMPTY_ARTIFACT_MERKLE_ROOT,
  MAX_CALIBRATION_SOURCE_BYTES,
  MAX_CHUNK_COUNT,
  MAX_MERKLE_PROOF_DEPTH,
  verifyArtifactChunkProof,
  verifyArtifactSourceManifest,
} from '../packages/server/dist/artifact-chunk-manifest.js';

const RECEIPT_SCHEMA = 'artifact-chunk-calibration-receipt/0.2';

// Above this chunk count, a case verifies only a deterministic sample of
// chunks (first, middle, final) instead of every chunk, to keep this script
// fast for the maximum-size case. The mutation-class matrix always runs
// against the LAST chunk of the manifest (see below), independent of
// sampling.
const MAX_FULL_VERIFICATION_CHUNKS = 32;

/**
 * Deterministic, non-degenerate synthetic byte generator: a SHA-256 hash
 * chain over `seed:counter`. Deterministic and reproducible -- not
 * randomness in the sense this script avoids (no clock reads, no OS
 * entropy). Deliberately not a small linear formula: a formula like
 * `(i*k+c)&0xff` repeats with a period of at most 256, which can make two
 * different chunks of the same source byte-identical whenever the chunk
 * size is itself a multiple of that period -- true for every chunk size
 * this module allows.
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

function expectedDepthFor(totalChunkCount) {
  return totalChunkCount <= 1 ? 0 : Math.ceil(Math.log2(totalChunkCount));
}

/** Another totalChunkCount value sharing the same proof depth, if one
 * exists within the chunk-count ceiling; `undefined` if none does (e.g. a
 * single-chunk artifact, or a count that is the sole occupant of its
 * depth). */
function findSameDepthAlternative(totalChunkCount) {
  const depth = expectedDepthFor(totalChunkCount);
  if (depth === 0) return undefined;
  const low = 2 ** (depth - 1) + 1;
  const high = Math.min(2 ** depth, MAX_CHUNK_COUNT);
  for (let candidate = low; candidate <= high; candidate++) {
    if (candidate !== totalChunkCount) return candidate;
  }
  return undefined;
}

/** For the given (chunkIndex, totalChunkCount), simulate the width/index
 * reduction the verifier performs and classify each proof-node step as
 * 'duplicate' (an odd-width self-duplicate step) or 'ordinary'. */
function classifyProofSteps(chunkIndex, totalChunkCount) {
  const kinds = [];
  let index = chunkIndex;
  let width = totalChunkCount;
  while (width > 1) {
    kinds.push(width % 2 === 1 && index === width - 1 ? 'duplicate' : 'ordinary');
    index = Math.floor(index / 2);
    width = Math.ceil(width / 2);
  }
  return kinds;
}

/** A "trusting" root walker -- mechanically applies whatever
 * siblingPosition/siblingSha256 values a (possibly noncanonical) proof
 * carries, with none of the strict verifier's canonical-duplicate
 * enforcement. Used only to construct the specific noncanonical root the
 * odd-node regression test needs to prove failure isn't merely "root
 * didn't match". */
function walkProofToRootTrusting(leafHex, proofNodes) {
  let current = Buffer.from(leafHex, 'hex');
  for (const node of proofNodes) {
    const sibling = Buffer.from(node.siblingSha256, 'hex');
    const [left, right] = node.siblingPosition === 'left' ? [sibling, current] : [current, sibling];
    current = createHash('sha256')
      .update(Buffer.from([0x01]))
      .update(left)
      .update(right)
      .digest();
  }
  return current.toString('hex');
}

/**
 * Runs every applicable mutation class against the manifest/proof for one
 * selected chunk (always the LAST chunk of the manifest -- its index is
 * "the last" at every level of the width/index reduction, which maximizes
 * how often the odd-node duplicate step is actually exercised). Returns the
 * per-class outcomes; never silently skips a class.
 */
function runMutationChecks({ sourceBytes, manifest, chunkIndex, proof, chunkBytes }) {
  const outcomes = [];

  function applicable(name, fn) {
    let passed;
    try {
      passed = fn() === true;
    } catch (error) {
      // A thrown ArtifactChunkManifestError is itself "verification failed"
      // -- a structural rejection, not a bypass.
      passed = error && typeof error.code === 'string';
    }
    outcomes.push({ name, applicable: true, passed });
  }
  function notApplicable(name, reason) {
    outcomes.push({ name, applicable: false, reason });
  }

  if (manifest.byteLength > proof.byteLength) {
    applicable('source-bytes-outside-selected-chunk', () => {
      const mutated = Uint8Array.from(sourceBytes);
      const outsideIndex = proof.byteStart === 0 ? manifest.byteLength - 1 : 0;
      mutated[outsideIndex] = (mutated[outsideIndex] + 1) & 0xff;
      return verifyArtifactSourceManifest(mutated, manifest) === false;
    });
  } else {
    notApplicable(
      'source-bytes-outside-selected-chunk',
      'single-chunk artifact; no source bytes exist outside the selected chunk',
    );
  }

  applicable('selected-chunk-bytes', () => {
    const mutated = Uint8Array.from(chunkBytes);
    mutated[0] = (mutated[0] + 1) & 0xff;
    return verifyArtifactChunkProof(mutated, proof, manifest.merkleRoot) === false;
  });

  applicable('chunk-index', () => {
    const mutated = { ...proof, chunkIndex: proof.chunkIndex + 1 };
    return verifyArtifactChunkProof(chunkBytes, mutated, manifest.merkleRoot) === false;
  });

  applicable('byte-start', () => {
    const mutated = { ...proof, byteStart: proof.byteStart + proof.chunkSize };
    return verifyArtifactChunkProof(chunkBytes, mutated, manifest.merkleRoot) === false;
  });

  applicable('byte-length', () => {
    const mutatedLength =
      proof.byteLength === proof.chunkSize ? proof.byteLength - 1 : proof.byteLength + 1;
    const mutated = { ...proof, byteLength: mutatedLength };
    return verifyArtifactChunkProof(chunkBytes, mutated, manifest.merkleRoot) === false;
  });

  applicable('raw-chunk-hash', () => {
    const mutated = { ...proof, chunkSha256: flipTrailingHexDigit(proof.chunkSha256) };
    return verifyArtifactChunkProof(chunkBytes, mutated, manifest.merkleRoot) === false;
  });

  applicable('merkle-leaf-hash', () => {
    const mutated = { ...proof, merkleLeafSha256: flipTrailingHexDigit(proof.merkleLeafSha256) };
    return verifyArtifactChunkProof(chunkBytes, mutated, manifest.merkleRoot) === false;
  });

  applicable('source-byte-length', () => {
    // +chunkSize always shifts ceil(sourceByteLength/chunkSize) by exactly
    // 1, guaranteeing the mutation is structurally detectable.
    const mutated = { ...proof, sourceByteLength: proof.sourceByteLength + proof.chunkSize };
    return verifyArtifactChunkProof(chunkBytes, mutated, manifest.merkleRoot) === false;
  });

  if (manifest.chunkCount > 1) {
    applicable('chunk-size', () => {
      const currentIndex = ALLOWED_CHUNK_SIZES.indexOf(proof.chunkSize);
      const otherSize = ALLOWED_CHUNK_SIZES[(currentIndex + 1) % ALLOWED_CHUNK_SIZES.length];
      const mutated = { ...proof, chunkSize: otherSize };
      return verifyArtifactChunkProof(chunkBytes, mutated, manifest.merkleRoot) === false;
    });
  } else {
    // For a single-chunk manifest the sole chunk is index 0, so byteStart
    // (= chunkIndex * chunkSize = 0) and byteLength (= sourceByteLength -
    // byteStart, the final-chunk rule) are BOTH independent of chunkSize's
    // exact value -- chunkSize genuinely has no structural effect on a
    // single-chunk proof's geometry, so no mutation of it is detectable
    // from the proof alone.
    notApplicable(
      'chunk-size',
      "single-chunk manifest; chunkSize has no structural effect on a lone chunk's byteStart (always 0) or byteLength (sourceByteLength - byteStart)",
    );
  }

  const sameDepthAlternative = findSameDepthAlternative(proof.totalChunkCount);
  if (sameDepthAlternative !== undefined) {
    applicable('total-chunk-count-same-depth', () => {
      const mutated = { ...proof, totalChunkCount: sameDepthAlternative };
      return verifyArtifactChunkProof(chunkBytes, mutated, manifest.merkleRoot) === false;
    });
  } else {
    notApplicable(
      'total-chunk-count-same-depth',
      `no other totalChunkCount value shares proof depth ${expectedDepthFor(proof.totalChunkCount)} within the ${MAX_CHUNK_COUNT}-chunk ceiling`,
    );
  }

  applicable('source-hash-shape', () => {
    // A per-chunk proof cannot verify sourceSha256 against real bytes (no
    // source bytes are ever passed to verifyArtifactChunkProof); breaking
    // its SHAPE (not merely its value) is the only mutation this function
    // can ever detect for that field.
    const mutated = { ...proof, sourceSha256: proof.sourceSha256.slice(0, -1) };
    return verifyArtifactChunkProof(chunkBytes, mutated, manifest.merkleRoot) === false;
  });

  const stepKinds = classifyProofSteps(chunkIndex, proof.totalChunkCount);
  const firstOrdinaryStep = stepKinds.indexOf('ordinary');
  if (proof.proof.length === 0) {
    notApplicable('sibling-position', 'single-chunk artifact; the proof carries no nodes');
    notApplicable('sibling-hash', 'single-chunk artifact; the proof carries no nodes');
  } else if (firstOrdinaryStep === -1) {
    notApplicable(
      'sibling-position',
      'every proof node on this selected route is an odd-width self-duplicate step; no ordinary sibling exists to mutate',
    );
    notApplicable(
      'sibling-hash',
      'every proof node on this selected route is an odd-width self-duplicate step; no ordinary sibling exists to mutate',
    );
  } else {
    applicable('sibling-position', () => {
      const mutated = {
        ...proof,
        proof: proof.proof.map((node, i) =>
          i === firstOrdinaryStep
            ? { ...node, siblingPosition: node.siblingPosition === 'left' ? 'right' : 'left' }
            : node,
        ),
      };
      return verifyArtifactChunkProof(chunkBytes, mutated, manifest.merkleRoot) === false;
    });
    applicable('sibling-hash', () => {
      const mutated = {
        ...proof,
        proof: proof.proof.map((node, i) =>
          i === firstOrdinaryStep
            ? { ...node, siblingSha256: flipTrailingHexDigit(node.siblingSha256) }
            : node,
        ),
      };
      return verifyArtifactChunkProof(chunkBytes, mutated, manifest.merkleRoot) === false;
    });
  }

  if (proof.proof.length >= 2) {
    applicable('proof-ordering', () => {
      const reordered = [proof.proof[1], proof.proof[0], ...proof.proof.slice(2)];
      const mutated = { ...proof, proof: reordered };
      return verifyArtifactChunkProof(chunkBytes, mutated, manifest.merkleRoot) === false;
    });
  } else {
    notApplicable(
      'proof-ordering',
      `proof depth is ${proof.proof.length}; at least two nodes are required to test reordering`,
    );
  }

  applicable('expected-root', () => {
    return (
      verifyArtifactChunkProof(chunkBytes, proof, flipTrailingHexDigit(manifest.merkleRoot)) ===
      false
    );
  });

  applicable('profile-version', () => {
    const mutated = { ...proof, profileVersion: 'artifact-chunk-merkle/9.9' };
    return verifyArtifactChunkProof(chunkBytes, mutated, manifest.merkleRoot) === false;
  });

  const duplicateStepIndex = stepKinds.indexOf('duplicate');
  if (duplicateStepIndex !== -1) {
    applicable('noncanonical-odd-node-sibling', () => {
      const original = proof.proof[duplicateStepIndex];
      const mutatedNode = {
        siblingPosition: 'right',
        siblingSha256: flipTrailingHexDigit(original.siblingSha256),
      };
      const mutatedNodes = proof.proof.map((node, i) =>
        i === duplicateStepIndex ? mutatedNode : node,
      );
      // Recompute the root THIS noncanonical route would produce and use it
      // as expectedRoot, so failure proves the structural duplicate rule
      // itself is enforced -- not merely that a root happened to mismatch.
      const noncanonicalRoot = walkProofToRootTrusting(proof.merkleLeafSha256, mutatedNodes);
      const mutatedProof = { ...proof, proof: mutatedNodes };
      return verifyArtifactChunkProof(chunkBytes, mutatedProof, noncanonicalRoot) === false;
    });
  } else {
    notApplicable(
      'noncanonical-odd-node-sibling',
      'the selected chunk route does not pass through any odd-width self-duplicate step',
    );
  }

  return outcomes;
}

function fail(message) {
  throw new Error(`Calibration FAILED: ${message}`);
}

function runCase(name, sourceBytes, chunkSize) {
  const manifest = buildArtifactChunkManifest(sourceBytes, chunkSize);
  const sampled = manifest.chunkCount > MAX_FULL_VERIFICATION_CHUNKS;
  const indexesToVerify = sampled
    ? sampleChunkIndexes(manifest.chunkCount)
    : Array.from({ length: manifest.chunkCount }, (_, i) => i);

  let proofsChecked = 0;
  for (const index of indexesToVerify) {
    const proof = buildArtifactChunkProof(manifest, index);
    const chunkBytes = sourceBytes.slice(proof.byteStart, proof.byteStart + proof.byteLength);
    if (verifyArtifactChunkProof(chunkBytes, proof, manifest.merkleRoot) !== true) {
      fail(`case "${name}" chunkSize ${chunkSize} chunk ${index} did not verify.`);
    }
    proofsChecked++;
  }

  let sourceManifestVerified = null;
  if (manifest.chunkCount > 0) {
    sourceManifestVerified = verifyArtifactSourceManifest(sourceBytes, manifest);
    if (sourceManifestVerified !== true) {
      fail(`case "${name}" chunkSize ${chunkSize} source-manifest verification did not pass.`);
    }
  }

  let mutations = [];
  if (manifest.chunkCount > 0) {
    const selectedChunkIndex = manifest.chunkCount - 1; // "the last" at every reduction level
    const proof = buildArtifactChunkProof(manifest, selectedChunkIndex);
    const chunkBytes = sourceBytes.slice(proof.byteStart, proof.byteStart + proof.byteLength);
    mutations = runMutationChecks({
      sourceBytes,
      manifest,
      chunkIndex: selectedChunkIndex,
      proof,
      chunkBytes,
    });
    for (const outcome of mutations) {
      if (outcome.applicable && !outcome.passed) {
        fail(
          `case "${name}" chunkSize ${chunkSize} mutation "${outcome.name}" did not fail verification.`,
        );
      }
    }
  }

  const mutationChecksApplicable = mutations.filter((m) => m.applicable).map((m) => m.name);
  const mutationChecksPassed = mutations.filter((m) => m.applicable && m.passed).map((m) => m.name);
  const mutationChecksNotApplicable = mutations
    .filter((m) => !m.applicable)
    .map((m) => ({ name: m.name, reason: m.reason }));

  return {
    name,
    byteLength: manifest.byteLength,
    chunkSize,
    chunkCount: manifest.chunkCount,
    sourceSha256: manifest.sourceSha256,
    merkleRoot: manifest.merkleRoot,
    proofsChecked,
    sampled,
    sourceManifestVerified,
    mutationChecksApplicable,
    mutationChecksPassed,
    mutationChecksNotApplicable,
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
    '(first, middle, final chunk) instead of every chunk proof; that case reports "sampled": ' +
    'true. Source-manifest verification (verifyArtifactSourceManifest) always covers the ' +
    'complete source bytes regardless of sampling. The mutation-class matrix always runs ' +
    "against the manifest's LAST chunk.",
  cases,
  totalCases: cases.length,
  result: 'pass',
};

process.stdout.write(`${JSON.stringify(receipt)}\n`);
process.exitCode = 0;
