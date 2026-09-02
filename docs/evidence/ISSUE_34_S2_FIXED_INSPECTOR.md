# Issue #34 S2: one fixed, synthetic/local, read-only artifact inspector

- **Status:** Unmerged draft candidate evidence
- **Candidate base:** `374473bc0700e30649f63d1db164f64c0aab3dee`
- **Candidate branch:** `feat/34-s2-fixed-artifact-inspector`
- **Scope:** one pure TypeScript implementation seam that resolves an authorized, immutable
  artifact registry record and its S1b chunk/Merkle manifest through injected dependencies, then
  implements `artifact_stat`, `artifact_read_range`, and `artifact_read_lines` against the accepted
  S0 contract -- performing no network, filesystem, Storage, database, or Edge access itself
- **Production runtime authority change:** none

## What S2 is, in this repository's roadmap

Issue #34's roadmap runs S0 through S9. S0 (`packages/contracts/src/artifact-inspection.ts`)
defines the MCP capability surface -- input/output shapes, the error vocabulary, source and
partial-read integrity metadata, and the inspection-receipt shape -- without implementing any of
it. S1b (`packages/server/src/artifact-chunk-manifest.ts`) defines and calibrates the exact
chunk/Merkle hash algorithm those S0 shapes assume. S2 is the first place in this repository those
two pieces are wired together into a working (synthetic/local) inspector: given a trusted request
context and a caller's opaque `artifactId`, it resolves an authorized registry record through an
injected dependency, validates that record's S1b manifest, and answers `artifact_stat`,
`artifact_read_range`, and `artifact_read_lines` with S0-shaped, S1b-verified output. It is not the
deterministic inspector/Edge execution surface (S2's own docstring says so explicitly), not MCP
runtime registration, and not a deployment.

## Trusted context vs. tool input

`ArtifactInspectorTrustedContext` (`.strict()`, Zod-validated, frozen on construction) carries
exactly six fields: `principalRef`, `inspectorClientRef`, `inspectorCapabilityRef` (fixed to the
literal `'artifact:inspect'`), `verifierAudience`, `policyVersion`, and
`inspectorDeploymentGitCoordinate` (an exact 40-hex-character Git commit SHA), plus an optional
`requestCorrelationId`. This is supplied by the trusted server layer and is never derived from tool
input. Every operation's tool input is parsed through the unmodified, accepted S0 input schema
(`ArtifactStatInputSchema`, `ArtifactReadRangeInputSchema`, `ArtifactReadLinesInputSchema`), which
is `.strict()`: an unknown field -- a caller-selected `bucket`, `path`, `url`, `origin`, `schema`,
`table`, `rpc`, `method`, `signedUrl`, or even a caller attempting to smuggle its own
`principalRef`/`inspectorCapabilityRef` into the request body -- is rejected as `INVALID_REQUEST`
before any dependency is called, not merely ignored.

## Injected dependencies

`ArtifactInspectorDependencies` declares exactly three required members and two optional redacted
observers:

- `resolveAuthorizedArtifact(context, artifactId)` -- stands in for the current
  principal/client/RLS boundary. Returns `null` for a missing artifact, a wrong principal, a wrong
  client, or a missing capability; the inspector treats all of these identically and never inspects
  *why* a resolution failed.
- `readVersionedRange(context, internalLocator, objectVersionRef, offset, length)` -- reads exactly
  `length` bytes of one immutable object version. `internalLocator` is opaque (`unknown`) trusted
  adapter data and is never read, logged, or serialized by this module.
- `now()` -- a deterministic clock, injected for reproducible expiry tests.
- `emitOperationalEvent?` / `emitInspectionReceipt?` -- optional redacted observers (see below).

This module never constructs a Supabase client, performs a `fetch`, or knows a Storage URL; every
fact about the world arrives through these five members, and the synthetic adapter used to satisfy
them exists ONLY inside `artifact-inspector.test.ts`.

## Authorization and non-enumeration

Authorization is never derived from artifact content or caller input. `resolveAuthorizedArtifact`
is the entire authorization boundary; on top of it, this module itself checks expiry
(`isArtifactExpired`, reused unmodified from S0) using the injected clock. Missing artifact, wrong
principal, wrong client, missing capability, and expired artifact all produce the *exact same*
frozen object: `publicArtifactInspectionUnavailable('missing')`, S0's own frozen singleton --
guaranteed byte-identical (indeed reference-identical) across every cause and across all three
operations, and never accompanied by an S0 inspection receipt. No byte read occurs after an
unavailable resolution: the unavailable branch returns before `readVersionedRange` is ever called,
for all three operations.

"Object version no longer available" is expressed as `readVersionedRange` throwing (there is no
separate null-return variant in its contract); this module catches that and fails closed with
`INTERNAL_ERROR` (see Error-code mapping below) rather than retrying or returning partial content.

## STAT

`artifact_stat` never calls `readVersionedRange`. It resolves the record, validates the S1b
manifest reconstructed from the record's ordered hash arrays (see below), and returns the accepted
`SourceIntegrityMetadataSchema` shape. Chunk hashes are inlined
(`{kind:'inline', hashes: record.chunkSha256s}`, the *raw* hashes, matching S0's existing meaning)
whenever `chunkCount <= MAX_INLINE_CHUNK_HASHES` (64); above that ceiling the trusted opaque
`chunkHashesRef` is returned instead (`{kind:'reference', ref}`). No internal locator ever appears
in the output -- the `SourceIntegrityMetadataSchema` shape has no such field, and this module never
spreads the raw registry record into any public value. The receipt's `operationDetail` for
`artifact_stat` is exactly `{operation:'artifact_stat'}`, with no range fields, matching the
discriminated receipt schema.

## Manifest reconstruction and validation

`buildManifestFromRecord` folds the registry record's ordered `chunkSha256s` / `merkleLeafSha256s`
arrays into an S1b `ArtifactChunkManifest` object. `validateManifestConsistency` then runs the
*exact* S1b consistency closure: for a nonempty manifest this is delegated to
`buildArtifactChunkProof(manifest, 0)` (the resulting proof is discarded; only the
throw-on-inconsistency side effect is used), which is the same `assertManifestConsistent` path the
S1b calibration suite already exercises -- including the leaf-hashes-close-to-declared-root check.
`buildArtifactChunkProof` rejects chunk index 0 as out of range for a zero-chunk manifest even when
that manifest is perfectly consistent, so the empty-artifact case is validated directly (byteLength
0, zero chunks, and the canonical `EMPTY_ARTIFACT_MERKLE_ROOT`). A manifest that fails this
validation resolves to `internal_error` -- a registry-data-corruption class, distinct from a
byte-level integrity failure detected against live bytes (see the mutation-class discussion below).

## Byte-range inspection

`artifact_read_range` follows the exact steps this candidate was scoped to: parse input, resolve
the authorized record (rejecting expiry before any read), reject a request that runs past the
resolved artifact's actual length, expand `[offset, offset+length)` to full covering chunk
boundaries, enforce the fixed internal ceilings (`MAX_RANGE_BYTES` on the requested length, via the
unmodified S0 input schema; `MAX_COVERING_FETCH_BYTES = 16,384` on the covering fetch, enforced
locally), call `readVersionedRange` with the internal locator and the exact resolved
`objectVersionRef`, require the returned `objectVersionRef` to match and the returned byte length to
equal exactly the covering length, build a fresh S1b proof for every covering chunk
(`buildArtifactChunkProof`) and verify each against the manifest's Merkle root
(`verifyArtifactChunkProof`), slice only the requested sub-range *after* every covering chunk has
verified, compute the returned-byte SHA-256, and return the accepted
`ArtifactReadRangeOutputSchema` shape with the operation-specific receipt.

### Why this module builds proofs itself, and what that means for "mutated proof sibling"

This module never receives an externally supplied Merkle proof to mutate a sibling of -- it always
builds a fresh proof itself, on every call, from the already-validated manifest. This is a
deliberate design consequence of S1b's own interface (`buildArtifactChunkProof` takes a manifest and
a chunk index, not a caller-supplied proof object) and means the specific "mutated proof sibling"
attack has no external trigger point in this architecture: a caller cannot hand this module a
tampered proof, because it never accepts one. What a caller (or a compromised registry/byte layer)
*can* do is tamper with the registry record's own declared fields, which this module handles as
follows, verified by dedicated tests:

- **Mutating the raw `chunkSha256` field alone** (`chunkSha256s[i]`) leaves the manifest's own
  leaf-to-root closure untouched (the raw hash is not part of that closure), so resolution succeeds;
  the mismatch is only caught once real bytes are fetched and compared inside
  `verifyArtifactChunkProof`, producing `INTEGRITY_FAILURE` **after** exactly one byte read.
- **Mutating a declared `merkleLeafSha256s[i]` or the declared `merkleRoot` alone** breaks the
  manifest's own self-consistency (the declared root no longer matches the root reconstructed from
  the declared leaves), which is caught at resolution time -- before any byte is read -- producing
  `INTERNAL_ERROR` (a registry-data problem, not a byte-tamper problem). Both are fail-closed; the
  code path and the specific error code differ intentionally by how early the defect is detectable.
- **Mutating the actual bytes returned by the adapter**, leaving the registry record's declared
  fields untouched, always produces `INTEGRITY_FAILURE`, detected inside `verifyArtifactChunkProof`
  after the (now-mismatched) bytes are fetched -- this is the direct analogue of "mutated chunk
  byte," "Merkle leaf mismatch," and "root mismatch" against *live* bytes.

## UTF-8 line inspection

`artifact_read_lines` supports only `text/plain` and `text/markdown` (checked against the resolved
record's `mediaType`; anything else is `UNSUPPORTED`, checked before any read); enforces a fixed
262,144-byte maximum source scan (`MAX_LINE_SOURCE_SCAN_BYTES`, rejecting a larger artifact before
any read, mapped to `RESPONSE_LIMIT_EXCEEDED`); performs exactly one exact-version whole-source read
within that ceiling; calls `verifyArtifactSourceManifest` on the complete source (S1b's dedicated
full-source integrity check, distinct from and not substitutable by a per-chunk proof); decodes with
`TextDecoder('utf-8', {fatal: true, ignoreBOM: true})` (a failed decode is `INTEGRITY_FAILURE` --
bytes that pass Merkle verification but violate their claimed text media type are a content-contract
violation, not merely an unsupported profile, which is why this differs from the pre-read
`UNSUPPORTED` class); computes exact line boundaries over the decoded string via
`text.split(/(?<=\n)/)`, which preserves every LF byte (including a preceding CR, so CRLF sequences
are never split or stripped) and leaves a final non-newline-terminated fragment as a valid last
"line"; and binds the returned text to its exact UTF-8 byte range and SHA-256 by re-encoding the
selected substring and hashing those exact bytes.

`ignoreBOM: true` matters here for a subtle but real reason: `TextDecoder`'s default
(`ignoreBOM: false`) *strips* a leading byte-order mark, which would silently break the byte-exact
round-trip this schema's cryptographic binding (`bindReturnedDataToIntegrity`) requires --
`TextEncoder(TextDecoder(bytes))` must reproduce `bytes` exactly for content that happens to start
with `EF BB BF`.

### `startLine` beyond available lines

Per this candidate's scope, this is handled two ways, chosen so that a receipt-bearing evidence
record can be emitted whenever a real chunk exists to anchor it against:

- If the resolved manifest has at least one chunk (`chunkCount > 0`), a schema-valid **successful
  empty result** is returned: `data: ''`, `returnedLineCount: 0`, and an `integrity` object that
  verifies and cites the artifact's own **final chunk** (`returnedRange: {offset: byteLength,
  length: 0}`, which the accepted `PartialReadIntegritySchema` superRefine permits: a zero-length
  returned range positioned at the end of that chunk's verified coverage). `PartialReadIntegritySchema`
  requires at least one verified chunk (`verifiedChunks.min(1)`), which is exactly what this
  provides -- a real, Merkle-verified chunk, not an invented one.
- If the manifest has zero chunks (a zero-byte artifact, where no chunk exists at all to anchor a
  schema-valid `verifiedChunks` entry against), the fixed non-enumerating/invalid-request class is
  used instead: **`INVALID_REQUEST`**. This is the one place this candidate had to choose a specific
  error code not explicitly named by the originating task text, and it is recorded here exactly as
  required: `INVALID_REQUEST` was chosen (over, say, `RESOURCE_UNAVAILABLE`, which is reserved for
  non-enumeration of the artifact's existence/authorization, not its content) because the artifact
  *is* authorized and *does* exist; the request, applied to *this* artifact's actual (empty)
  content, simply cannot be satisfied -- the same class used for any other structurally unsatisfiable
  request.

## TOCTOU: authorization and returned bytes bind one immutable object version

Every byte read passes the *exact* `objectVersionRef` resolved during authorization to
`readVersionedRange`, and every returned `objectVersionRef` is checked for equality before any byte
is trusted. Verified directly by test, for both `artifact_read_range` and `artifact_read_lines`:
version drift before the read, the byte adapter returning a different version than requested, bytes
changing without a version-string change (still caught, because the Merkle proof / full-source
verification checks the *bytes themselves*, not merely the version label), the old version
"disappearing" (the adapter throws; caught and reported as `INTERNAL_ERROR`, never retried), and a
manifest whose declared root disagrees with a manifest built from unrelated content (caught at
resolution as `INTERNAL_ERROR` before any read is attempted). Every one of these fails closed:
none returns unverified content, and the exact fail-closed code (`INTEGRITY_FAILURE` for a
byte-level mismatch detected after a read, `INTERNAL_ERROR` for a registry-consistency problem
detected before any read) is chosen by the same principle described above for mutated hashes.

## Receipts

Every field the task requires is bound: `receiptSchemaVersion` (S0's own
`ARTIFACT_INSPECTION_RECEIPT_SCHEMA_VERSION`), `verifierAudience`, `principalRef`
(`principalBinding: 'session_derived'`), `inspectorClientRef` (`inspectorClientBinding: 'approved'`),
`inspectorCapabilityRef` (`{capability: 'artifact:inspect', ref: context.inspectorClientRef}`),
`artifactId`, `objectVersionRef`, `sourceSha256`, `merkleRoot`, `analyzerProfileId` /
`analyzerProfileVersion` (this module's own fixed deterministic-profile identity,
`ARTIFACT_INSPECTOR_PROFILE_VERSION = 'artifact-inspector-s2-0.1'` -- S2 performs no semantic
analysis and defines no per-media-type analyzer version of its own), `policyVersion`,
`inspectorDeploymentGitCoordinate`, `recordedAt`, operation-specific `operationDetail`, and
`resultOrErrorClass`.

A receipt is evidence, not authorization, exactly as S0 states. A receipt is emitted **only after**
an artifact has been authorized-resolved -- never for a pre-resolution outcome
(`INVALID_REQUEST` from schema parsing, or `RESOURCE_UNAVAILABLE`). Every post-resolution outcome,
success or error, does emit one, including `INTERNAL_ERROR`/`INTEGRITY_FAILURE`/`UNSUPPORTED`/
`RESPONSE_LIMIT_EXCEEDED` -- because at that point the receipt's coordinates (`objectVersionRef`,
`sourceSha256`, `merkleRoot`) are real, authorized values, not invented ones. Every range/lines
detail schema requires `returnedRange` and `returnedByteSha256` unconditionally (there is no
optional variant for an error outcome), so an error receipt for those two operations uses a fixed,
canonical placeholder: `{offset: 0, length: 0}` and the SHA-256 of zero bytes
(`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`) -- never the hash of any bytes
that were fetched but failed verification, so a receipt never leaks even a hash derived from
unverified content. Receipts never carry the internal locator, a bucket, a path/key, a signed URL, a
token, an authorization header, `service_role`, payload bytes, or an exact-search query -- verified
by a dedicated test that scans a receipt's own keys and JSON-serialized form for forbidden strings.

## Operational events

`ArtifactInspectorOperationalEvent` carries exactly: `operation`, `resultClass` (`'success'` or an
`ArtifactInspectionErrorCode`), an optional `requestCorrelationId` (only if the trusted context
supplied one), `elapsedMs`, and an optional `byteCounts` (`requested`/`covering`/`returned`). This is
an exhaustive allow-list -- **no** event, for **any** outcome including success, ever carries an
artifact ID, the internal locator, content, a token, a path, query text, or source bytes; the type
itself has no field for any of those. One event is emitted per call, for every one of: success,
unavailable, invalid request, unsupported, response limit, integrity failure, and internal failure.

## Output and wire limits

Every constructed success candidate is checked against `MAX_ARTIFACT_RESPONSE_BYTES` using the
*exact* accepted S0 serializer, `artifactInspectionResponseByteLength` -- this module introduces no
second, competing response-budget implementation anywhere. `artifact_read_range` and
`artifact_read_lines` additionally, and explicitly, cap `verifiedChunks.length` at
`MAX_VERIFIED_CHUNKS_PER_READ` (16) before ever reaching schema validation: without that explicit
check, a legitimately-computed-but-oversized `verifiedChunks` array would otherwise be caught only by
the accepted output schema's own `.max(16)`, and this module's generic "schema validation failed"
fallback (`INTERNAL_ERROR`) would then mask what should be reported as
`RESPONSE_LIMIT_EXCEEDED`. `artifact_read_lines` similarly checks the selected line span's UTF-8
byte length against the shared `MAX_RANGE_BYTES` ceiling before proof-building, since (unlike
`artifact_read_range`) its `count` parameter carries no direct byte-length cap of its own -- a long
run of newline-free lines could otherwise produce a `returnedRange.length` over that shared ceiling.

**On "exact boundary and one over" for the wire ceiling specifically:** every individual field this
module fills into any of the three outputs already carries its own S0-locked ceiling (`mediaType` <=
255 chars; `data`'s UTF-8 length effectively <= `MAX_RANGE_BYTES` = 8,192 via the shared
`ReturnedRangeSchema`; `verifiedChunks.length` <= 16; each chunk's Merkle proof depth bounded by
S1b's 1,048,576-byte maximum source combined with the smallest allowed 1,024-byte chunk size, giving
a maximum depth of 10). Empirically, the single largest fully legitimate output this module can
construct -- a full 1,048,576-byte source, 1,024-byte chunks (maximizing both chunk count and proof
depth), the maximum 16 covering chunks this module's own 16,384-byte covering-fetch ceiling allows,
and the maximum 8,192-byte returned range filled with 4-byte-UTF-8 characters -- measures
comfortably under `MAX_ARTIFACT_RESPONSE_BYTES` (65,536) using the accepted serializer. Exceeding
the wire ceiling through any single, schema-legitimate S2 request therefore appears to be
unreachable given this exact combination of S0 and S1b constants -- the same class of finding as
S1b's own documented `CHUNK_COUNT_EXCEEDED`/`PROOF_DEPTH_EXCEEDED` unreachability. The enforcement
code is kept regardless, as defense-in-depth using the exact accepted serializer, and its true
boundary behavior (at-or-under vs. one-byte-over, using the identical `artifactInspectionResponseByteLength`
measurement the schema itself performs) is verified directly in the test suite by driving the one
registry field with no independent length ceiling of its own (`mediaType`) to that exact boundary.

**On the 16,384-byte covering-fetch ceiling specifically:** given `MAX_RANGE_BYTES` (8,192) and the
S1b allowed chunk sizes `{1024, 4096, 8192}`, the worst-case misaligned covering fetch is
`(ceil(length / chunkSize) + 1) * chunkSize`, which is maximized at `chunkSize = 8192`:
`(ceil(8192/8192)+1)*8192 = 16,384` -- exactly the chosen ceiling, and never over it, for every
allowed chunk size. Exceeding this ceiling is therefore also unreachable through any schema-valid
`artifact_read_range` request; the check is kept as defense-in-depth, and the test suite verifies it
correctly accepts (does not falsely reject) the true worst case.

## Synthetic adapter tests

The synthetic adapter (`buildRecord`, `trackDeps`, `sourceBackedRead`, `resolverFor`, and related
helpers) is built **only** inside `artifact-inspector.test.ts`; `artifact-inspector.ts` itself never
constructs one. `packages/server/src/artifact-inspector.test.ts` covers the complete required
acceptance matrix (authorized stat/range/lines success including a chunk-boundary crossing, CRLF
preservation, and a final line without a trailing newline; missing/wrong-principal/wrong-client/
missing-capability/expired non-enumeration with byte-identical outputs and zero byte reads;
caller-selected forbidden input fields rejected pre-dependency; the internal locator absent from
every output/receipt/event/error; unsupported media type; invalid UTF-8; over-limit requested range;
the covering-fetch and text-source-scan ceilings; short/long reads; object-version mismatch; mutated
chunk bytes/raw hash/leaf/root; a source mutation outside the returned line range; the full source
buffer left untouched; no automatic retry; receipts and errors carrying no secret/existence detail;
error paths never inventing a receipt; a successful receipt passing the accepted schema; wire-ceiling
boundary behavior; concurrent independent reads never cross-contaminating; and every public
output/receipt/event being frozen) using mutation-sensitive assertions throughout, not only
happy-path schema parsing.

## Claim limits

This candidate is a synthetic/local implementation seam only. It is not: an Edge Function; a hosted
deployment; a Storage or database mutation of any kind; MCP runtime registration; a signed-URL
issuer; a user of `service_role`; a source of caller-selected Storage coordinates (every byte-custody
fact is resolved by the injected adapter, never accepted from tool input); an artifact-ingest path; a
Markdown heading index (`artifact_read_heading` is not implemented in S2); an exact-search
implementation (`artifact_search_exact` is not implemented in S2); semantic analysis of any kind; a
writer of any state anywhere; and it makes no production-readiness claim. `packages/contracts/**`
and `packages/server/src/artifact-chunk-manifest.ts` are both untouched by this candidate, by
construction (outside its authorized write paths) -- S2 consumes both unmodified.
