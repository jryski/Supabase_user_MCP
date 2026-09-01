# Issue #34: Governed Artifact Inspection -- S0 candidate contract

- **Status:** Unmerged candidate evidence
- **Candidate base:** `d59d6967cb276752878baa5c03f57a179ac8e9c0`
- **Candidate branch:** `feat/34-s0-artifact-contract`
- **Scope:** S0 capability/threat contract only -- Zod v4 schemas, error vocabulary, integrity
  metadata (with verified-chunk and Merkle-inclusion evidence), inspection-receipt shape, and frozen
  tool descriptors, all in `packages/contracts/src/artifact-inspection.ts`
- **Production runtime authority change:** none

## What S0 is, in this repository's roadmap

Issue #34 proposes a roadmap running S0 through S9. This candidate is S0 only: the MCP
capability/threat contract, plus the deterministic analyzer-profile and derivation-lineage
contracts the issue asks S0 to define. S1 (synthetic immutable artifact registry, chunk table,
derivation tables, and `storage.objects` RLS lab) already exists on `main` at
`supabase/migrations/20260826000100_artifact_schema.sql`,
`supabase/migrations/20260826000200_storage_object_policy.sql`, and
`supabase/tests/run-s1-lab.sh` (see [S1 lab evidence](S1-lab.md)). This candidate does not rebuild
or modify that migration surface.

## Four authority surfaces, kept separate

Per the issue's architecture diagram, this repository's authority splits into four surfaces. This
candidate touches exactly one of them:

| Surface | Owns | Touched by this candidate |
| --- | --- | --- |
| MCP capability surface | Tool names, input/output shapes, error vocabulary, frozen descriptors | **Yes** -- this is the entire scope |
| Deterministic inspector/Edge execution surface | Actually reading bytes, parsing Markdown, computing hashes | No |
| Postgres/RLS authorization | Who may see which `artifact_registry` row | No -- already covered by S1's migrations |
| Storage byte custody | `storage.objects` policy, bucket/key resolution | No -- already covered by S1's migrations |

Ingest-time bounded worker hashing and any future worker-only semantic derivation are future-prompt
surfaces; this candidate defines the deterministic/semantic authority-class split
(`SEMANTIC_ANALYSIS_POLICY`, `S0_DETERMINISTIC_DERIVATION_TYPES`) without implementing either side.

## Revision note

This candidate went through one consolidated repair pass after independent review found eight
concrete gaps between the first draft and the claims it made. Every claim below describes the
**repaired** state; nothing in this document describes the pre-repair draft. The eight repairs:

1. the response-envelope ceiling now measures the complete JSON-RPC 2.0 / MCP wire response, not
   bare output JSON, and the request ID carries its own independent byte ceiling;
2. partial-read integrity now carries verified, hash-checked chunks with bounded Merkle-inclusion
   proofs, not just a chunk-index range and a bare Merkle root;
3. the receipt's inspector-client binding is now paired with an explicit capability reference
   (absorbed into repair 6 below, which redesigned the receipt as a whole);
4. the source manifest (`SourceIntegrityMetadataSchema`) now enforces byte-length/chunk-size/
   chunk-count/hash-count cross-field consistency;
5. many-source derivations now reject a repeated source artifact within the same derivation;
6. the receipt's range detail is now operation-discriminated (no globally optional fields a
   mismatched operation could smuggle through), and every receipt requires an explicit
   session-derived principal binding, an approved-client binding, a capability reference bound to
   `artifact:inspect`, and the immutable object/version reference plus source SHA-256 plus Merkle
   root together -- never the Merkle root alone;
7. range/lines/heading/search outputs now cryptographically bind returned content to its declared
   integrity metadata (UTF-8 byte length and real SHA-256, via Node's `crypto`), so mutated content
   or mutated integrity metadata fail validation independently of each other;
8. every tool descriptor now states `readOnly: true` explicitly, documented as a claim independent
   of `idempotency` -- one never stands in for the other in this contract.

## Contract shape

`packages/contracts/src/artifact-inspection.ts` defines, for the five tools the issue proposes
(`artifact_stat`, `artifact_read_range`, `artifact_read_lines`, `artifact_read_heading`,
`artifact_search_exact`):

- **Opaque-ID-only input.** Every input schema is `z.object({...}).strict()` accepting the caller's
  artifact ID plus the minimal bounded operation parameters. `.strict()` rejects, rather than
  ignores, any caller-supplied bucket, object path/key, URL, origin, schema, table, RPC, HTTP
  method, signed URL, service-role material, or arbitrary parser/profile selection -- proven by a
  mutation-sensitive test matrix that tries all fifteen forbidden fields against all five
  operations.
- **Exact ceilings**, each with a boundary and one-over test: artifact-ID length (20-128),
  byte-range length (8,192 B), line count (200), heading-ID length (128), exact-search query length
  (256), exact-search hit count (50), execution time (2,000 ms via
  `isArtifactInspectionDeadlineExceeded`), the complete JSON-RPC/MCP wire response (65,536 B), and
  the request ID's own independent byte budget (1,024 B) -- see "Complete wire envelope" below.
- **Seven non-enumerating error classes** (`INVALID_REQUEST`, `RESOURCE_UNAVAILABLE`,
  `UNSUPPORTED`, `RESPONSE_LIMIT_EXCEEDED`, `INTEGRITY_FAILURE`, `DEADLINE_EXCEEDED`,
  `INTERNAL_ERROR`), each with a fixed literal message. `publicArtifactInspectionUnavailable`
  returns one frozen object regardless of whether the caller passes `'missing'` or `'unauthorized'`,
  so the two reasons are byte-identical on the wire -- this mirrors
  `publicMemoryGetUnavailable` in `read-tools.ts`.

### Complete wire envelope (repair 1)

The ceiling this module measures and enforces is the **complete JSON-RPC 2.0 / MCP wire response**
-- `jsonrpc`, `id`, and an MCP result whose `content[0].text` carries the
`ARTIFACT_INSPECTION_UNTRUSTED_CONTENT_PREFIX` security-boundary prefix, `structuredContent`
(the same output, unwrapped), `isError` (derived from `output.ok`), and a trailing newline -- not
bare output JSON. `artifactInspectionResponseByteLength(requestId, output)` and
`serializeArtifactInspectionResponse(requestId, output)` build and count that complete envelope;
every output schema's `.refine(...)` calls the same measurement at the minimum/null-ID size, so a
caller's request ID can never make an output schema's own ceiling check looser. The request ID
carries its own independent 1,024-byte ceiling (`artifactInspectionRequestIdByteLength`,
`MAX_ARTIFACT_REQUEST_ID_BYTES`), checked before the response-byte check so an oversized ID is
rejected on its own terms.

Tests prove: an output that fits comfortably as plain JSON (well under 65,536 B) still gets
rejected once wrapped in the complete envelope; the complete-envelope ceiling is hit at the exact
byte and rejected one byte over (via a two-phase byte-exact search: the output body closes most of
the gap, the request ID's un-duplicated per-character contribution closes the remainder to the
exact byte); the request-ID ceiling is independently hit at the exact byte and rejected one byte
over, using a small fixed output so the response-byte ceiling is nowhere near triggered; UTF-8
byte counting is multibyte-aware; `structuredContent` and the model-visible text encode the same
output; the untrusted-content prefix is present unconditionally; and `isError` follows `output.ok`.

### Verified chunk and Merkle-inclusion evidence (repair 2)

`PartialReadIntegritySchema` (shared by all four read/search operations) now carries `chunkSize`,
the artifact's total `chunkCount`, and an ordered `verifiedChunks` array (1 to 16 entries), each
with `chunkIndex`, `byteStart`, `byteLength`, `chunkSha256`, and a bounded (depth ≤ 32) ordered
`merkleProof` of `{ siblingPosition: 'left' | 'right', siblingSha256 }` nodes. The schema does not
recompute SHA-256 or Merkle roots itself -- it carries enough bounded typed evidence for a
deterministic inspector/verifier to do so. A `superRefine` rejects: duplicate or out-of-order
indexes; index gaps; overlapping or non-contiguous byte ranges; indexes outside the declared total
chunk count; a first/last verified chunk that doesn't match `verifiedCoveringChunkRange`; a
non-final chunk whose `byteLength` isn't exactly `chunkSize`; a requested or returned range outside
the verified byte coverage; and, for any artifact with more than one chunk, an empty
`merkleProof` on any verified chunk. An empty proof is valid only when the artifact's total chunk
count is exactly 1. `requestedRange` remains a discriminated union so a search request never has to
smuggle a byte offset, and `PARTIAL_READ_INTEGRITY_STATEMENT` states in words that a whole-object
hash cannot stand in for this.

### Source-manifest cross-field consistency (repair 4)

`SourceIntegrityMetadataSchema` (the `artifact_stat` payload) now enforces, via `superRefine`: a
zero-byte artifact must declare zero chunks and an empty inline chunk-hash list; a nonzero-byte
artifact must declare at least one chunk; an inline hash list's length must equal the declared
chunk count; and `byteLength` must fit exactly within `chunkSize * chunkCount`, with only the final
chunk possibly short (`ceil(byteLength / chunkSize) === chunkCount`). Reference-mode chunk hashes
remain valid at any chunk count, including counts exceeding the 64-entry inline ceiling. Tests cover
a valid zero-byte artifact, an exact-multiple byte length, a short final chunk, a mismatched inline
hash count (both under- and one-over), and an impossible byte length in both directions.

## Contract shape, continued

- **Inspection receipt** (`ArtifactInspectionReceiptSchema`, redesigned -- repairs 3 and 6): schema
  version `artifact-inspection-receipt/0.2`, explicit verifier audience, a session-derived
  `principalRef` paired with `principalBinding: 'session_derived'`, an approved `inspectorClientRef`
  paired with `inspectorClientBinding: 'approved'`, an `inspectorCapabilityRef` bound to the literal
  `artifact:inspect` capability (never a bare opaque string that could drift to mean something
  else), the artifact ID, the immutable `objectVersionRef` **plus** `sourceSha256` **plus**
  `merkleRoot` together (a Merkle root alone can no longer stand in for immutable source identity),
  `analyzerProfileId`, `analyzerProfileVersion`, `policyVersion`, an exact 40-hex-character
  inspector deployment Git coordinate, recorded time, an **operation-discriminated**
  `operationDetail` union, and a result-or-error-class union. `artifact_stat`'s detail carries no
  range at all; each of the other four operations requires exactly its own request/return shape
  (`.strict()` per variant), so a receipt cannot be reshaped into another operation's detail by
  adding or omitting fields -- tested by cross-pairing every detail shape against every other
  operation. The search detail records only `queryLength` and `maxHits`, never query text, and its
  `returnedHits` array rejects a zero-length shared range or duplicate ranges standing in for
  disjoint hits. `.strict()` at the top level rejects JWTs, authorization headers, service-role
  values, raw Storage paths, payload bytes, query text, and other secret-bearing metadata --
  tested field-by-field. `ARTIFACT_INSPECTION_RECEIPT_IS_NOT_AUTHORIZATION` states plainly that a
  receipt is evidence, not bearer authorization.
- **Deterministic analyzer-profile and derivation contracts**: `ANALYZER_PROFILE_IDS` names exactly
  the two S0-supported profiles (`text/plain`, `text/markdown`); `PROPOSED_NEXT_DETERMINISTIC_PROFILE_ID`
  documents CSV as proposed-not-implemented; `SEMANTIC_ANALYSIS_POLICY` is frozen with
  `enabled: false` and `executionClass: 'local_worker_only'`; `S0_DETERMINISTIC_DERIVATION_TYPES`
  excludes `semantic_summary` by construction (tested); `ArtifactDerivationWithInputsSchema` mirrors
  S1's `artifact_derivations` + `derivation_inputs` many-source shape, requires every input to bind
  its own exact source SHA, and now rejects a repeated `sourceArtifactId` within the same
  derivation (repair 5).
- **Bound returned content (repair 7)**: `ArtifactReadRangeOutputSchema`,
  `ArtifactReadLinesOutputSchema`, and `ArtifactReadHeadingOutputSchema` each `superRefine` their
  `data` field against `integrity.returnedRange.length` (real UTF-8 byte length) and
  `integrity.returnedByteSha256` (real SHA-256, via Node's `crypto`) -- mutated data with unchanged
  integrity fails, and a mutated `returnedRange` with unchanged data fails. `ArtifactSearchHitSchema`
  binds each hit's own `snippet` to its own `snippetRange` (byte length) and `snippetSha256` (real
  hash), and requires its `matchRange` to lie inside that same `snippetRange`.
  `ArtifactSearchExactSuccessSchema` further requires hits to be ordered and non-overlapping by
  offset, rejects two hits sharing an identical fabricated range, and requires every hit's
  `snippetRange` to lie inside the shared `integrity.verifiedChunks` byte coverage. Nothing here
  claims cryptographic binding without a mutation test proving the specific mutation fails.
- **Frozen tool descriptors** (`ARTIFACT_STAT_TOOL` and its four siblings, plus
  `ARTIFACT_INSPECTION_TOOLS`): capability name, fixed operation, the strict input/output schemas,
  `readOnly: true` (repair 8, stated independently of `idempotency` -- neither is treated as proof
  of the other anywhere in this contract), `retry: { maxAttempts: 1, policy: 'none' }`,
  `idempotency: 'idempotent'`, `authorizationRequired: true`, `contentTrust: 'untrusted'`, and exact
  resource ceilings including the request-ID budget. Every descriptor and every nested
  `limits`/`retry`/`errorMapping` object is `Object.freeze`d and tested as frozen.
  `ARTIFACT_INSPECTION_DESCRIPTOR_IS_NOT_PERMISSION` states, and a test confirms by structural
  absence of any `grant`/`bypassAuthorization`/`authority` property, that a descriptor is
  scheduling/interface metadata, not permission.
- **Source expiry vs. historical manifest durability**: `isArtifactExpired` is a pure predicate over
  a timestamp with no side effect on manifest data. A test parses a full
  `SourceIntegrityMetadataSchema` object and a full `ArtifactInspectionReceiptSchema` object that
  both reference an already-expired artifact and confirms both still parse -- expiry denies future
  access without erasing the fields needed to verify a receipt issued before expiry.

## Explicit exclusions

This candidate adds no migration, Edge Function, MCP runtime registration, Storage deployment,
semantic analysis implementation, or hosted configuration. It does not implement the deterministic
inspector/Edge execution surface (S2), Postgres/RLS authorization beyond what S1 already has, or
Storage byte custody. It contains no production bucket, credential, or private data. It is a review
candidate, not accepted architecture.

## Verification

Run from a clean checkout of `feat/34-s0-artifact-contract` at head `<see PR head SHA>`:

```shell
npm ci
npm run check
```

`npm run check` runs `format:check`, `lint`, `typecheck`, and `test` (which itself runs `tsc -b`
before `vitest run`). Exact result at the repaired candidate head:

```text
Checked 61 files in 34ms.       # biome format
Checked 61 files in 59ms.       # biome lint
(tsc -b, tsc -p tsconfig.test.json --noEmit: no output, exit 0)
Test Files  26 passed | 1 skipped (27)
     Tests  403 passed | 4 skipped (407)
```

`packages/contracts/src/artifact-inspection.test.ts` (1,510 lines) alone contributes over 260 of the
passing tests added by the repair pass on top of the original 137, covering: every accepted
operation with hash-bound fixtures; unknown-operation denial; all fifteen forbidden extra-field
cases across all five operations; every enumerated exact ceiling with its one-over rejection,
including the complete wire envelope and the independent request-ID budget; missing-vs-unauthorized
byte-identical output; unsupported media type; verified-chunk and Merkle-proof required-field,
duplicate, out-of-order, gapped, overlapping, out-of-bounds, absent-proof, and over-ceiling
rejection; source-manifest zero-byte, exact-multiple, short-final-chunk, mismatched-hash-count, and
impossible-byte-length cases; content/integrity binding for range, lines, heading, and per-hit
search output, each with a mutation that must fail; receipt audience, forbidden-field, and
operation-detail cross-pairing rejection; session-derived/approved-client/capability binding
rejection; source-expiry vs. manifest durability; semantic-analysis prohibition; duplicate
derivation-input rejection; explicit read-only descriptors; capability descriptors not granting
authority; and every exported descriptor/policy object being frozen. The 4 skipped tests are
pre-existing elsewhere in the suite and unrelated to this change.

## Claim limits

This candidate does not add remote HTTP/OAuth, writes, production credentials or data, an Edge
Function implementation, MCP runtime registration, Storage deployment, a semantic-analysis
implementation, deployment, or production readiness. It is S0 only: a capability/threat contract
for review. Postgres/RLS and Storage byte custody remain governed entirely by the S1 migrations
already on `main`; nothing here changes them. The schemas here validate typed evidence and bind it
cryptographically to returned content within a single request/response; they do not themselves
fetch bytes, compute a live Merkle tree against Storage, or verify a chunk's hash against the actual
persisted object -- that remains the deterministic inspector/Edge execution surface's job (S2+).
