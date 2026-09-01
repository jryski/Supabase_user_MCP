# Issue #34 S1b: bounded deterministic synthetic chunk/Merkle worker calibration

- **Status:** Unmerged candidate evidence (repair round)
- **Candidate base:** `6bff150d673055028e19e2202875b8f7d27f4782`
- **Candidate branch:** `feat/34-s1b-chunk-merkle-calibration`
- **Scope:** one local, deterministic, model-free, network-free worker utility implementing and
  calibrating the exact chunk/Merkle hash profile a future deterministic inspector/Edge surface
  would need to agree on
- **Production runtime authority change:** none

## Why this document was rewritten

Adversarial verification of the previous candidate head (`2d39b9fc4f1ef6077ab1725777f8cdf5a9e9de9e`)
found genuine proof-format and semantic defects: `ArtifactChunkProof` did not carry enough source
geometry to check a proof's `byteStart` uniformly for every chunk including the final one; the
field documented as a "chunk hash" actually stored the domain-separated Merkle *leaf* hash rather
than a raw content hash, silently changing S0's accepted meaning of that value; odd-node duplication
was implied by root-matching rather than structurally enforced; there was no way to verify bytes
outside a single selected chunk against a whole manifest; and public functions accepted bytes
without a runtime type check, relying on TypeScript alone. This document describes the repaired
state. **The previous version of this document claimed byteStart mutation was fully covered "while
the final chunk remains exempt." That claim is removed: the final chunk is no longer exempt, and
`byteStart` is now checked identically for every chunk.**

## What S1b is, in this repository's roadmap

Issue #34's roadmap runs S0 through S9. S0 (the MCP capability/threat contract) and S1 (the
synthetic artifact registry, chunk table, derivation tables, and Storage RLS lab) already exist on
`main`. This candidate is S1b: it defines and calibrates the exact hash algorithm those layers
assume but do not themselves implement -- S0's `PartialReadIntegritySchema` carries typed
`verifiedChunks`/`merkleProof` evidence and states plainly that it "does not need to recompute
SHA-256 or Merkle roots"; S1's migration stores `sha256_full`, `merkle_root`, and per-chunk
`sha256` columns without computing them. S1b is the first place in this repository those values are
actually computed, against a fixed, versioned, testable profile, using only in-memory synthetic
bytes.

## Canonical hash profile: `artifact-chunk-merkle/0.1`

- **Raw chunk hash (`chunkSha256`):** `SHA256(raw chunk bytes)` -- no domain-separation byte. This
  is the value that matches S0's existing "chunk hash" meaning and is what S1b projects into S0's
  `SourceIntegrityMetadataSchema.chunkHashes.hashes` and `PartialReadIntegritySchema.verifiedChunks`.
- **Merkle leaf hash (`merkleLeafSha256`):** `SHA256(0x00 || raw chunk bytes)` -- domain-separated,
  used only as the Merkle tree's leaf input. This value is never the same as `chunkSha256` and is
  never substituted for it in any S0 projection.
- **Parent hash:** `SHA256(0x01 || left child digest bytes || right child digest bytes)` -- the
  child digests are concatenated as their raw 32 bytes, not as hex text.
- **Empty-artifact Merkle root:** `SHA256(0x02)` -- exported as `EMPTY_ARTIFACT_MERKLE_ROOT`,
  independently verified against a standalone reference computation
  (`dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986`).
- **One-leaf tree:** the root is that leaf's own Merkle leaf digest; no parent hashing is performed.
- **Odd-node rule, enforced canonically:** at every level with an odd node count, the final
  unpaired node is duplicated and paired with itself before hashing the parent. Verification tracks
  both the current node's index and the current level's width; at the exact step where the width is
  odd and the index is the final one, the sibling **must** be declared `siblingPosition: 'right'`
  and its `siblingSha256` **must** equal the current node's own digest exactly. This is checked
  structurally, before `expectedRoot` is ever consulted -- an attacker who mutates the duplicate
  sibling away from self and recomputes a matching (noncanonical) root from that exact mutated path
  still fails verification, because the duplicate-sibling identity is a structural precondition, not
  something a matching root can satisfy after the fact.
- **Wire format:** every hash (source, raw chunk, Merkle leaf, sibling, root) is a lowercase
  64-character hexadecimal string.

## Bounds

| Constant | Value |
| --- | --- |
| Allowed chunk sizes | 1,024 / 4,096 / 8,192 bytes |
| Default chunk size | 4,096 bytes |
| Maximum synthetic calibration source | 1,048,576 bytes (2^20; exactly divisible by all three chunk sizes) |
| Maximum chunks | 4,096 |
| Maximum Merkle-proof depth | 32 |

All bounds are exported constants (`ALLOWED_CHUNK_SIZES`, `DEFAULT_CHUNK_SIZE`,
`MAX_CALIBRATION_SOURCE_BYTES`, `MAX_CHUNK_COUNT`, `MAX_MERKLE_PROOF_DEPTH`) and enforced with a
typed `ArtifactChunkManifestError` (`code` one of `INVALID_INPUT_TYPE`, `UNSUPPORTED_CHUNK_SIZE`,
`SOURCE_TOO_LARGE`, `CHUNK_COUNT_EXCEEDED`, `PROOF_DEPTH_EXCEEDED`, `INVALID_CHUNK_INDEX`,
`MALFORMED_DIGEST`, `MALFORMED_PROOF_POSITION`, `INCONSISTENT_MANIFEST`).

Because the byte ceiling (1,048,576) divided by the smallest allowed chunk size (1,024) yields at
most 1,024 chunks -- well under the 4,096-chunk and 32-proof-depth ceilings for every allowed chunk
size -- `CHUNK_COUNT_EXCEEDED` and `PROOF_DEPTH_EXCEEDED` are unreachable through normal manifest
construction from any input this module accepts. Both ceilings remain enforced as structural
defense-in-depth wherever a manifest or proof object is *consumed* (`buildArtifactChunkProof`,
`verifyArtifactChunkProof`), and both are exercised directly in tests using hand-constructed
objects that bypass the builders. Both checks are ordered ahead of the byte-length ceiling and the
byte-length/chunk-count consistency check in `assertManifestConsistent` (and ahead of the
`sourceByteLength`/`totalChunkCount` consistency chain in the proof shape check), since each is an
absolute ceiling on a single declared field and does not depend on any other field first being
established as internally consistent; a hand-constructed manifest or proof that violates a specific
ceiling therefore always reports that specific code, even when it also happens to violate a broader
ceiling at the same time.

## Runtime input-type enforcement

Every public function that accepts byte input (`buildArtifactChunkManifest`,
`verifyArtifactChunkProof`, `verifyArtifactSourceManifest`) checks `instanceof Uint8Array` at
runtime and throws `ArtifactChunkManifestError` with code `INVALID_INPUT_TYPE` for a plain array, a
string, a raw `ArrayBuffer`, or a plain object -- this is enforced independently of TypeScript's
compile-time types, which a caller using `any`, a cast, or a non-TypeScript consumer of the built
JavaScript could otherwise bypass. `Buffer` (a `Uint8Array` subtype) is accepted everywhere.

## Deterministic worker interface

`packages/server/src/artifact-chunk-manifest.ts` exports:

- `buildArtifactChunkManifest(bytes: Uint8Array, chunkSize?)` -- defensively copies `bytes` (never
  aliases or mutates the caller's array), computes the full source SHA-256, splits into bounded
  chunks, computes both the raw chunk hash and the domain-separated Merkle leaf hash for every
  chunk independently, and returns a deeply frozen manifest: `profileVersion`, `sourceSha256`,
  `byteLength`, `chunkSize`, `chunkCount`, ordered `chunks` (`chunkIndex`, `byteStart`,
  `byteLength`, `chunkSha256`, `merkleLeafSha256`), `merkleRoot`.
- `buildArtifactChunkProof(manifest, chunkIndex)` -- first re-validates the manifest
  (`assertManifestConsistent`, see below), rebuilds the tree from the manifest's own ordered
  `merkleLeafSha256` values (no raw bytes required), and returns a deeply frozen, bounded inclusion
  proof carrying full source geometry: `profileVersion`, `sourceSha256`, `sourceByteLength`,
  `chunkSize`, `totalChunkCount`, `chunkIndex`, `byteStart`, `byteLength`, `chunkSha256`,
  `merkleLeafSha256`, ordered `proof` nodes (`siblingPosition: 'left' | 'right'`, `siblingSha256`).
  Carrying `chunkSize` and `totalChunkCount` on the proof itself is what makes it possible to check
  `byteStart === chunkIndex * chunkSize` uniformly for every chunk, including the final one -- the
  previous candidate's proof shape could not express this for the final chunk and left it
  unchecked; that gap is now closed.
- `verifyArtifactChunkProof(chunkBytes, proof, expectedRoot)` -- always recomputes the raw hash and
  the Merkle leaf hash from the live `chunkBytes` and always recomputes the path to the root; never
  trusts `proof.chunkSha256`, `proof.merkleLeafSha256`, or `expectedRoot` without walking the proof.
  Shape defects (malformed digest, malformed position, depth over ceiling, internally inconsistent
  proof) throw a typed `ArtifactChunkManifestError`; a well-shaped but cryptographically failing
  proof returns `false`. Successfully parsing a proof's shape is never treated as verification.
- `verifyArtifactSourceManifest(sourceBytes, manifest)` -- full-source verification, distinct from
  and not substitutable by a per-chunk proof: recomputes `sourceSha256` from the complete
  `sourceBytes`, recomputes every declared chunk's raw hash and Merkle leaf hash by slicing the
  actual bytes at that chunk's declared range, and rebuilds the Merkle root from those freshly
  recomputed leaves to confirm it matches `manifest.merkleRoot`. Returns `false` for any well-shaped
  cryptographic mismatch (wrong length, wrong source hash, a mutated byte anywhere in the source,
  even outside any single chunk that a caller happens to also hold a proof for); throws the typed
  error only for malformed shape or out-of-contract input (non-`Uint8Array`, an internally
  inconsistent manifest). A per-chunk proof can only vouch for the bytes inside that one chunk --
  it cannot and does not prove anything about bytes elsewhere in the source. Full-source integrity
  requires `verifyArtifactSourceManifest`.

Both `buildArtifactChunkProof` and `verifyArtifactChunkProof` internally re-validate the shape of
whatever they are given (`assertManifestConsistent` / `assertProofShapeConsistent`), including
objects not produced by this module's own builders, so a hand-constructed, internally inconsistent
input is rejected before any of its fields are trusted.

### Manifest consumer closure

`assertManifestConsistent` (used by both `buildArtifactChunkProof` and
`verifyArtifactSourceManifest`) does more than check each field's shape in isolation: after
validating every chunk's declared range and digest shape, it independently rebuilds the Merkle root
from the manifest's own declared `merkleLeafSha256` values and requires the result to equal
`manifest.merkleRoot`. A manifest whose per-chunk leaf hashes do not actually close to its declared
root -- however well-formed each individual field looks -- is rejected before any proof is built
from it. This check validates `sourceSha256` only for *shape* (a lowercase 64-hex-character
string); a manifest consumer cannot verify `sourceSha256`'s *value* without the real source bytes,
which is exactly the gap `verifyArtifactSourceManifest` closes when the caller does have them.

## Calibration matrix

`scripts/run-artifact-chunk-calibration.mjs` imports the *built* implementation from
`packages/server/dist/artifact-chunk-manifest.js`, generates every byte array in-process from a
SHA-256 hash chain seeded by a fixed integer (deterministic and reproducible -- not the randomness
this script avoids: no clock reads, no OS entropy), and performs no network access and no
filesystem source reads.

For each of the three allowed chunk sizes, it runs all eight required cases (24 total):

1. empty byte array
2. one ASCII byte
3. exact one-chunk boundary (`byteLength === chunkSize`)
4. one byte over a chunk boundary (`byteLength === chunkSize + 1`)
5. even multi-chunk source (4 chunks)
6. odd multi-chunk source (3 chunks, short final chunk)
7. UTF-8 multibyte Markdown (fixed literal content, unrelated to chunk size)
8. source exactly at the maximum byte ceiling (1,048,576 bytes)

For every non-empty case it builds the manifest, verifies chunk proofs, calls
`verifyArtifactSourceManifest` once against the complete source, and then runs the **full mutation
matrix** (17 named classes) against the manifest's last chunk. Every mutation class applicable to
that case's geometry is actually executed and must fail verification, or the script throws and
exits nonzero; a mutation class that cannot apply to a given geometry (for example, `chunk-size` on
a single-chunk manifest, where neither `byteStart` (always `0`) nor `byteLength`
(`sourceByteLength - byteStart`) depends on `chunkSize`'s value at all) is explicitly recorded as
**not applicable**, with a name and a human-readable reason, rather than silently skipped or
counted as passed. The 17 classes: `source-bytes-outside-selected-chunk`, `selected-chunk-bytes`,
`chunk-index`, `byte-start`, `byte-length`, `raw-chunk-hash`, `merkle-leaf-hash`,
`source-byte-length`, `chunk-size`, `total-chunk-count-same-depth`, `source-hash-shape`,
`sibling-position`, `sibling-hash`, `proof-ordering`, `expected-root`, `profile-version`,
`noncanonical-odd-node-sibling`. Each case's receipt entry carries `mutationChecksApplicable`,
`mutationChecksPassed` (equal sets for a passing case), and `mutationChecksNotApplicable` (objects
with `name` and `reason`).

**Sampling, stated explicitly:** a case whose `chunkCount` exceeds `maxFullVerificationChunks` (32)
verifies only a deterministic sample -- the first, middle, and final chunk -- rather than every
chunk's proof, and reports `"sampled": true`. `verifyArtifactSourceManifest` always covers the
complete source bytes regardless of sampling. This applies to the `max-byte-ceiling` case only
(1,024 / 256 / 128 chunks depending on chunk size, all above 32); every other case's `chunkCount`
stays at or below 32 for these bounds and is verified in full. The receipt's own `samplingNote`
field states this rule.

### Exact command and result

```shell
npm run artifact:calibrate
```

Which runs `npm run build && node scripts/run-artifact-chunk-calibration.mjs`. At the repaired
candidate head, `node scripts/run-artifact-chunk-calibration.mjs` was additionally run twice
directly and produced byte-for-byte identical single-line stdout, zero stderr both times, exit code
`0` both times:

```json
{"schema":"artifact-chunk-calibration-receipt/0.2","profileVersion":"artifact-chunk-merkle/0.1","nodeVersion":"v22.22.2","allowedChunkSizes":[1024,4096,8192],"bounds":{"defaultChunkSize":4096,"maxCalibrationSourceBytes":1048576,"maxChunkCount":4096,"maxMerkleProofDepth":32},"emptyArtifactMerkleRoot":"dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986","caseNames":["empty","one-ascii-byte","exact-one-chunk-boundary","one-byte-over-chunk-boundary","even-multi-chunk","odd-multi-chunk","utf8-multibyte-markdown","max-byte-ceiling"],"maxFullVerificationChunks":32,"samplingNote":"A case whose chunkCount exceeds maxFullVerificationChunks verifies a deterministic sample (first, middle, final chunk) instead of every chunk proof; that case reports \"sampled\": true. Source-manifest verification (verifyArtifactSourceManifest) always covers the complete source bytes regardless of sampling. The mutation-class matrix always runs against the manifest's LAST chunk.","cases":[ ...24 case objects, each carrying mutationChecksApplicable/mutationChecksPassed/mutationChecksNotApplicable... ],"totalCases":24,"result":"pass"}
```

Summary: `totalCases: 24`, `result: "pass"`, Node `v22.22.2`. Every case's `mutationChecksPassed`
set equals its `mutationChecksApplicable` set (both empty for `empty`); every
`mutationChecksNotApplicable` entry carries a non-empty `name` and `reason`. The single-chunk cases
(`one-ascii-byte`, `exact-one-chunk-boundary` at each chunk size, and `utf8-multibyte-markdown` at
chunk size 8192) each report 10 applicable and 7 not-applicable classes; the `odd-multi-chunk` case
at every chunk size reports all 17 classes applicable and passed, including
`noncanonical-odd-node-sibling`, proving that specific claim is not vacuous. The full 24-case body
is reproduced verbatim by running the command above; it is omitted here for length but is exactly
what ships in the test suite's calibration-script assertions (see next section).

## Verification (test suite)

```shell
npm run check
npm run artifact:calibrate
node scripts/run-artifact-chunk-calibration.mjs
git diff --check
git status --short
```

`packages/server/src/artifact-chunk-manifest.test.ts` (1,324 lines) includes:

- Hardcoded golden vectors for the empty root, a one-byte raw hash and leaf hash (shown to differ),
  a two-chunk tree (no duplication), and a three-chunk tree (odd-node duplication) -- every hex
  value independently computed outside the production module via a from-scratch reference
  implementation, then cross-checked here.
- A from-scratch reference implementation of the profile (`refSha256`/`refRawChunkSha256`/
  `refLeaf`/`refParent`/`refEmptyRoot`/`refMerkleRoot`/`refManifest`), written directly against
  `node:crypto` without calling back into any production helper, tracking both the raw chunk hash
  and the Merkle leaf hash independently and cross-checked against `buildArtifactChunkManifest`'s
  output across all three chunk sizes and a range of chunk-aligned and non-chunk-aligned byte
  lengths.
- A dedicated block proving the raw chunk hash and the Merkle leaf hash are different fields with
  different meanings: the two never compare equal on the same chunk, each is independently
  reproducible from its own formula, and mutating either field alone (while leaving the other
  correct) fails verification.
- Exact allowed-bounds and one-over cases: all three chunk sizes accepted, an unsupported size
  rejected at manifest-build time and rejected again for an existing proof's `chunkSize` field, the
  exact source-byte ceiling accepted and one byte over rejected, a hand-constructed 1,048,577-byte
  manifest rejected, a hand-constructed chunk-count-over-ceiling manifest rejected, a
  hand-constructed proof-depth-over-ceiling proof rejected, invalid chunk indexes (negative and
  one-past-end) rejected, malformed `sourceSha256`/raw `chunkSha256`/`merkleLeafSha256` rejected, a
  well-formed but unrelated Merkle root rejected, and internally inconsistent hand-constructed
  manifests (wrong chunk count, non-contiguous ranges, oversized final chunk) rejected.
- Manifest consumer closure: ordinary manifests are shown to satisfy the leaf-to-root closure by
  construction, and the empty manifest's canonical root is accepted as a special case.
- Manifest cross-field requirements verified structurally across all three chunk sizes: zero-byte
  source, `ceil(byteLength / chunkSize)` chunk count, `byteStart === chunkIndex * chunkSize` for
  every chunk, contiguous covering byte ranges, and the full/short chunk-size split.
- Runtime `Uint8Array` enforcement: a plain array, a string, a raw `ArrayBuffer`, and a plain object
  are each rejected with `INVALID_INPUT_TYPE` by every function that accepts byte input
  (`buildArtifactChunkManifest`, `verifyArtifactChunkProof`, `verifyArtifactSourceManifest`); a
  `Buffer` is accepted everywhere.
- `verifyArtifactSourceManifest`: accepts the exact original bytes; a mutation to a source byte
  **outside** the one chunk covered by a separately verified proof still fails full-source
  verification even though that chunk's own proof still verifies (demonstrating both that a
  per-chunk proof cannot vouch for the rest of the source, and that full-source verification does);
  a source-length mismatch is rejected; a malformed manifest shape throws rather than returning
  `false`.
- The complete independent-mutation matrix (interior chunk, 17 classes) described above, run
  against a real fixture, plus a dedicated "does not treat successful shape parsing as proof
  verification" test (a well-shaped proof checked against the wrong chunk bytes fails), a
  regression proving `totalChunkCount` mutated from 6 to 7 (same proof depth) fails, and a
  regression proving mutating the final chunk's `byteStart` by one byte fails -- closing the
  previous candidate's documented final-chunk exemption.
- A dedicated canonical odd-node duplication regression: a 3-chunk manifest's final chunk's proof
  is confirmed to be the canonical self-duplicate step (`siblingPosition: 'right'`,
  `siblingSha256` equal to the chunk's own Merkle leaf hash); the control proof verifies; the
  sibling is then mutated away from self while `siblingPosition` is kept `'right'`, the noncanonical
  root that exact mutated path would actually produce is independently recomputed via the reference
  `refParent`, and verification is shown to fail against **both** that recomputed noncanonical root
  and the real root -- proving the duplicate-sibling rule is enforced structurally, not merely by
  root comparison.
- S0 compatibility: a generated source manifest projected into the accepted S0
  `SourceIntegrityMetadataSchema.chunkHashes.hashes` using the **raw** `chunkSha256` (imported from
  `@supabase-user-mcp/contracts`, unmodified by this candidate) parses successfully, with a
  companion assertion that projecting the Merkle leaf hash instead would have produced a different
  (wrong) array; generated proof evidence (chunk index/byte range, raw `chunkSha256`, the proof's
  own `siblingPosition`/`siblingSha256` nodes verbatim) projected into the accepted S0
  `PartialReadIntegritySchema` `verifiedChunks`/`merkleProof` shape parses successfully; S0's
  response-envelope ceiling, untrusted-content security prefix, and receipt contract (including its
  rejection of secret-bearing fields) are asserted unchanged.
- Deterministic repeated-run equality (two builds from independent copies of the same bytes deep-
  equal); the caller's input buffer is never mutated; the manifest is a defensive copy (mutating
  the caller's array after the call does not change an already-built manifest); manifests and
  proofs are deeply frozen at every level, and a mutation attempt throws (ES modules are strict by
  default).
- No source path, URL, token, credential, Storage locator, "secret", "password", or similar field
  name or value anywhere in the manifest, the proof, or the calibration script's own JSON receipt
  (checked by a recursive scanner against a forbidden-pattern regex).
- The calibration script itself: spawned as a real child process, its stdout parses as exactly one
  JSON object, is byte-identical across two separate invocations with zero stderr, and reports
  `result: "pass"`; a dedicated regression walks every case in the live receipt and asserts nothing
  is silently skipped-as-passed (`mutationChecksApplicable` and `mutationChecksPassed` are the same
  set for every case, and every `mutationChecksNotApplicable` entry carries a name and a reason),
  that the `empty` case has no applicable mutations, and that every non-empty case's
  `mutationChecksApplicable` and `mutationChecksNotApplicable` entries account for all 17 classes
  between them.

At candidate head:

```text
Checked 64 files in 42ms.       # biome format
Checked 64 files in 97ms.       # biome lint
(tsc -b, tsc -p tsconfig.test.json --noEmit: no output, exit 0)
Test Files  27 passed | 1 skipped (28)
     Tests  534 passed | 4 skipped (538)
```

The 4 skipped tests are pre-existing elsewhere in the suite and unrelated to this change.
`git diff --check` and `git status --short` were run after staging exactly the five authorized
paths (`packages/server/src/artifact-chunk-manifest.ts`,
`packages/server/src/artifact-chunk-manifest.test.ts`,
`scripts/run-artifact-chunk-calibration.mjs`, `package.json`,
`docs/evidence/ISSUE_34_S1B_CHUNK_MERKLE_CALIBRATION.md`), with clean results; `package.json` itself
was not modified again in this repair round (its `artifact:calibrate` script was already correct).

## S0 compatibility

S1b does not touch `packages/contracts/**` at all -- it is outside this candidate's authorized
write paths, so the S0 ceilings, receipt contract, authority boundaries, and untrusted-content
policy are unchanged by construction, not merely by claim. The compatibility tests above go further
and assert specific S0 behaviors still hold at runtime: `MAX_ARTIFACT_RESPONSE_BYTES` is still
65,536; `ARTIFACT_INSPECTION_UNTRUSTED_CONTENT_PREFIX` still starts with `SECURITY BOUNDARY:` and
still names content untrusted; `ArtifactInspectionReceiptSchema` still parses a well-formed receipt
and still rejects one carrying a `serviceRoleKey` field. S1b's own output is demonstrated to be a
valid, honest instance of S0's `SourceIntegrityMetadataSchema` and `PartialReadIntegritySchema`
shapes -- using the raw `chunkSha256`, never the Merkle leaf hash, for the fields S0 defines as
content hashes -- when combined with synthetic placeholder values for the contextual/deployment
fields (`artifactId`, `objectVersionRef`, `mediaType`, `analyzerProfileSupport`, `createdAt`) that a
local, network-free worker cannot and should not assign on its own.

## Claim limits

This candidate is synthetic local calibration only. It is not: a deployment; a change to
production Storage; an Edge Function; MCP runtime registration; artifact ingest; semantic analysis;
proof of hostile-worker containment (this module trusts its own process and makes no claim about
sandboxing, resource limits against an adversarial caller, or side-channel resistance); and it
introduces, uses, or stores no credentials or private data. A per-chunk `verifyArtifactChunkProof`
proves only the bytes of the one chunk it names; it makes no claim about any other byte in the
source, which is exactly why `verifyArtifactSourceManifest` exists as a separate, non-substitutable
operation for whole-source integrity. No authority is promoted by this candidate -- it is a review
candidate defining and calibrating an algorithm, not an accepted architecture, and it does not
itself grant, verify, or bypass any authorization decision. The deterministic inspector/Edge
execution surface (S2), Postgres/RLS authorization, Storage byte custody, and any future
worker-only semantic derivation remain entirely out of scope and untouched.
