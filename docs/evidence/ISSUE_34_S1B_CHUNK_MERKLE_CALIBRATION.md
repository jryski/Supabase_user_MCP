# Issue #34 S1b: bounded deterministic synthetic chunk/Merkle worker calibration

- **Status:** Unmerged candidate evidence
- **Candidate base:** `6bff150d673055028e19e2202875b8f7d27f4782`
- **Candidate branch:** `feat/34-s1b-chunk-merkle-calibration`
- **Scope:** one local, deterministic, model-free, network-free worker utility implementing and
  calibrating the exact chunk/Merkle hash profile a future deterministic inspector/Edge surface
  would need to agree on
- **Production runtime authority change:** none

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

- **Leaf hash:** `SHA256(0x00 || raw chunk bytes)`
- **Parent hash:** `SHA256(0x01 || left child digest bytes || right child digest bytes)` -- the
  child digests are concatenated as their raw 32 bytes, not as hex text.
- **Empty-artifact Merkle root:** `SHA256(0x02)` -- exported as `EMPTY_ARTIFACT_MERKLE_ROOT`,
  independently verified against a standalone `node -e` computation
  (`dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986`).
- **One-leaf tree:** the root is that leaf's own digest; no parent hashing is performed.
- **Odd-node rule:** at every level with an odd node count, the final node is duplicated and paired
  with itself before hashing the parent.
- **Wire format:** every hash (source, chunk, sibling, root) is a lowercase 64-character
  hexadecimal string.

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
typed `ArtifactChunkManifestError` (`code` one of `UNSUPPORTED_CHUNK_SIZE`, `SOURCE_TOO_LARGE`,
`CHUNK_COUNT_EXCEEDED`, `PROOF_DEPTH_EXCEEDED`, `INVALID_CHUNK_INDEX`, `MALFORMED_DIGEST`,
`MALFORMED_PROOF_POSITION`, `INCONSISTENT_MANIFEST`).

Because the byte ceiling (1,048,576) divided by the smallest allowed chunk size (1,024) yields at
most 1,024 chunks -- well under the 4,096-chunk and 32-proof-depth ceilings for every allowed chunk
size -- `CHUNK_COUNT_EXCEEDED` and `PROOF_DEPTH_EXCEEDED` are unreachable through normal manifest
construction from any input this module accepts. Both ceilings remain enforced as structural
defense-in-depth wherever a manifest or proof object is *consumed* (`buildArtifactChunkProof`,
`verifyArtifactChunkProof`), and both are exercised directly in tests using hand-constructed
objects that bypass the builders.

## Deterministic worker interface

`packages/server/src/artifact-chunk-manifest.ts` exports:

- `buildArtifactChunkManifest(bytes: Uint8Array, chunkSize?)` -- defensively copies `bytes` (never
  aliases or mutates the caller's array), computes the full source SHA-256, splits into bounded
  chunks, computes domain-separated leaf hashes, and returns a deeply frozen manifest:
  `profileVersion`, `sourceSha256`, `byteLength`, `chunkSize`, `chunkCount`, ordered `chunks`
  (`chunkIndex`, `byteStart`, `byteLength`, `chunkSha256`), `merkleRoot`.
- `buildArtifactChunkProof(manifest, chunkIndex)` -- rebuilds the tree from the manifest's own
  ordered chunk hashes (no raw bytes required) and returns a deeply frozen, bounded inclusion
  proof: `profileVersion`, `chunkIndex`, `byteStart`, `byteLength`, `chunkSha256`,
  `totalChunkCount`, ordered `proof` nodes (`siblingPosition: 'left' | 'right'`, `siblingSha256`).
- `verifyArtifactChunkProof(chunkBytes, proof, expectedRoot)` -- always recomputes the leaf hash
  from the live `chunkBytes` and always recomputes the path to the root; never trusts
  `proof.chunkSha256` or `expectedRoot` without walking the proof. Shape defects (malformed digest,
  malformed position, depth over ceiling, internally inconsistent manifest/proof) throw a typed
  `ArtifactChunkManifestError`; a well-shaped but cryptographically failing proof returns `false`.
  Successfully parsing a proof's shape is never treated as verification.

Both `buildArtifactChunkProof` and `verifyArtifactChunkProof` internally re-validate the shape of
whatever they are given (`assertManifestConsistent` / `assertProofShapeConsistent`), including
objects not produced by this module's own builders, so a hand-constructed, internally inconsistent
input is rejected before any of its fields are trusted.

### Every listed mutation is independently detectable

`chunkIndex` participates in the cryptographic walk itself (not just a shape check): at each level
the sibling's declared `left`/`right` position must match the parity `chunkIndex` implies, so
mutating `chunkIndex` alone changes the expected parity sequence and fails verification.
`byteStart` is checked against `chunkIndex * byteLength` for every non-final chunk -- always true
by construction, since a non-final chunk's `byteLength` *is* the uniform chunk size (an S1b
manifest invariant) -- catching a `byteStart` mutation on any interior chunk; a proof for the
manifest's own final chunk falls outside this specific check, since its `byteLength` may
legitimately be shorter than the uniform size. Source/chunk bytes, chunk hash, sibling position,
sibling hash, proof ordering, and expected root all participate directly in the hash walk or the
final comparison. `totalChunkCount` is tied to the required proof depth
(`ceil(log2(totalChunkCount))`), so mutating it to a value implying a different depth than the
proof actually carries is rejected. `profileVersion` is checked directly. All eleven are covered by
a dedicated mutation test (`packages/server/src/artifact-chunk-manifest.test.ts`, "the full
independent-mutation matrix").

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

For every non-empty case it builds the manifest, verifies chunk proofs, then runs two independent
mutation checks against one verified chunk: mutating one source/chunk byte, and mutating one proof
sibling hash (or the Merkle root itself, for a single-chunk case with an empty proof) -- both must
fail verification, or the script throws and exits nonzero.

**Sampling, stated explicitly:** a case whose `chunkCount` exceeds `maxFullVerificationChunks` (32)
verifies only a deterministic sample -- the first, middle, and final chunk -- rather than every
chunk, and reports `"sampled": true`. This applies to the `max-byte-ceiling` case only (1,024 / 256
/ 128 chunks depending on chunk size, all above 32); every other case's `chunkCount` stays at or
below 32 for these bounds and is verified in full. The receipt's own `samplingNote` field states
this rule.

### Exact command and result

```shell
npm run artifact:calibrate
```

Which runs `npm run build && node scripts/run-artifact-chunk-calibration.mjs`. At the candidate
head, both invocations below produced byte-for-byte identical stdout, exit code `0`:

```json
{"schema":"artifact-chunk-calibration-receipt/0.1","profileVersion":"artifact-chunk-merkle/0.1","nodeVersion":"v22.22.2","allowedChunkSizes":[1024,4096,8192],"bounds":{"defaultChunkSize":4096,"maxCalibrationSourceBytes":1048576,"maxChunkCount":4096,"maxMerkleProofDepth":32},"emptyArtifactMerkleRoot":"dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986","caseNames":["empty","one-ascii-byte","exact-one-chunk-boundary","one-byte-over-chunk-boundary","even-multi-chunk","odd-multi-chunk","utf8-multibyte-markdown","max-byte-ceiling"],"maxFullVerificationChunks":32,"samplingNote":"A case whose chunkCount exceeds maxFullVerificationChunks verifies a deterministic sample (first, middle, final chunk) instead of every chunk proof; that case reports \"sampled\": true.","cases":[ ...24 case objects... ],"totalCases":24,"result":"pass"}
```

Summary: `totalCases: 24`, `result: "pass"`, Node `v22.22.2`. Every case's `mutationChecksPassed`
equals its `mutationChecksTotal` (2 for every non-empty case, 0 for `empty`). The full 24-case body
is reproduced verbatim by running the command above; it is omitted here for length but is exactly
what ships in the test suite's calibration-script assertions (see next section).

## Verification (test suite)

```shell
npm run check
npm run artifact:calibrate
git diff --check
git status --short
```

`packages/server/src/artifact-chunk-manifest.test.ts` (833 lines) includes:

- Hardcoded golden vectors for the empty root, a one-byte leaf/root, a two-chunk tree (no
  duplication), and a three-chunk tree (odd-node duplication) -- every hex value independently
  computed outside this repository via a standalone `node -e` script using the exact same formula,
  then cross-checked here.
- A from-scratch reference implementation of the profile (`refSha256`/`refLeaf`/`refParent`/
  `refMerkleRoot`/`refManifest`), written directly against `node:crypto` without calling back into
  any production helper, cross-checked against `buildArtifactChunkManifest`'s output across all
  three chunk sizes and a range of chunk-aligned and non-chunk-aligned byte lengths.
- Exact allowed-bounds and one-over cases: all three chunk sizes accepted, an unsupported size
  rejected, the exact source-byte ceiling accepted and one byte over rejected, a hand-constructed
  chunk-count-over-ceiling manifest rejected, a hand-constructed proof-depth-over-ceiling proof
  rejected, invalid chunk indexes (negative and one-past-end) rejected, malformed digests and
  malformed proof positions rejected, and internally inconsistent hand-constructed manifests
  (wrong chunk count, non-contiguous ranges, oversized final chunk, malformed root) rejected.
- Manifest cross-field requirements verified structurally across all three chunk sizes: zero-byte
  source, `ceil(byteLength / chunkSize)` chunk count, contiguous covering byte ranges, and the
  full/short chunk-size split.
- The complete eleven-item independent-mutation matrix described above, plus a dedicated
  "does not treat successful shape parsing as proof verification" test (a well-shaped proof
  checked against the wrong chunk bytes fails).
- S0 compatibility: a generated source manifest projected into the accepted S0
  `SourceIntegrityMetadataSchema` (imported from `@supabase-user-mcp/contracts`, unmodified by
  this candidate) parses successfully; generated proof evidence (chunk index/byte range/hash plus
  the proof's own `siblingPosition`/`siblingSha256` nodes verbatim) projected into the accepted S0
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
  JSON object, reports `result: "pass"`, and is byte-identical across two separate invocations.

At candidate head:

```text
Checked 64 files in 34ms.       # biome format
Checked 64 files in 61ms.       # biome lint
(tsc -b, tsc -p tsconfig.test.json --noEmit: no output, exit 0)
Test Files  27 passed | 1 skipped (28)
     Tests  497 passed | 4 skipped (501)
```

The 4 skipped tests are pre-existing elsewhere in the suite and unrelated to this change.
`git diff --check` and `git status --short` were run after staging exactly the five authorized
paths, with clean results.

## S0 compatibility

S1b does not touch `packages/contracts/**` at all -- it is outside this candidate's authorized
write paths, so the S0 ceilings, receipt contract, authority boundaries, and untrusted-content
policy are unchanged by construction, not merely by claim. The compatibility tests above go further
and assert specific S0 behaviors still hold at runtime: `MAX_ARTIFACT_RESPONSE_BYTES` is still
65,536; `ARTIFACT_INSPECTION_UNTRUSTED_CONTENT_PREFIX` still starts with `SECURITY BOUNDARY:` and
still names content untrusted; `ArtifactInspectionReceiptSchema` still parses a well-formed receipt
and still rejects one carrying a `serviceRoleKey` field. S1b's own output (a manifest and a proof)
is demonstrated to be a valid, honest instance of S0's `SourceIntegrityMetadataSchema` and
`PartialReadIntegritySchema` shapes when combined with synthetic placeholder values for the
contextual/deployment fields (`artifactId`, `objectVersionRef`, `mediaType`,
`analyzerProfileSupport`, `createdAt`) that a local, network-free worker cannot and should not
assign on its own.

## Claim limits

This candidate is synthetic local calibration only. It is not: a deployment; a change to
production Storage; an Edge Function; MCP runtime registration; artifact ingest; semantic analysis;
proof of hostile-worker containment (this module trusts its own process and makes no claim about
sandboxing, resource limits against an adversarial caller, or side-channel resistance); and it
introduces, uses, or stores no credentials or private data. No authority is promoted by this
candidate -- it is a review candidate defining and calibrating an algorithm, not an accepted
architecture, and it does not itself grant, verify, or bypass any authorization decision. The
deterministic inspector/Edge execution surface (S2), Postgres/RLS authorization, Storage byte
custody, and any future worker-only semantic derivation remain entirely out of scope and untouched.
