# Issue #34: Governed Artifact Inspection -- S0 candidate contract

- **Status:** Unmerged candidate evidence
- **Candidate base:** `d59d6967cb276752878baa5c03f57a179ac8e9c0`
- **Candidate branch:** `feat/34-s0-artifact-contract`
- **Scope:** S0 capability/threat contract only -- Zod v4 schemas, error vocabulary, integrity
  metadata, inspection-receipt shape, and frozen tool descriptors, all in
  `packages/contracts/src/artifact-inspection.ts`
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
  `isArtifactInspectionDeadlineExceeded`), and the complete UTF-8 response envelope (65,536 B via
  `artifactInspectionResponseByteLength` / `serializeArtifactInspectionResponse`, enforced on every
  output schema through `.refine(...)`).
- **Seven non-enumerating error classes** (`INVALID_REQUEST`, `RESOURCE_UNAVAILABLE`,
  `UNSUPPORTED`, `RESPONSE_LIMIT_EXCEEDED`, `INTEGRITY_FAILURE`, `DEADLINE_EXCEEDED`,
  `INTERNAL_ERROR`), each with a fixed literal message. `publicArtifactInspectionUnavailable`
  returns one frozen object regardless of whether the caller passes `'missing'` or `'unauthorized'`,
  so the two reasons are byte-identical on the wire -- this mirrors
  `publicMemoryGetUnavailable` in `read-tools.ts`.
- **Source-integrity metadata** (`SourceIntegrityMetadataSchema`, the `artifact_stat` payload):
  artifact ID, an opaque immutable object/version reference, full source SHA-256, byte length,
  chunk size/count, ordered chunk hashes (inline, bounded, or an opaque typed reference), Merkle
  root, media type, an explicit `analyzerProfileSupport` field distinguishing the two S0-supported
  profiles from `'unsupported'`, created time, and optional expiry.
- **Partial-read integrity metadata** (`PartialReadIntegritySchema`, shared by all four read/search
  operations): requested range (a discriminated union so a search request never has to smuggle a
  byte offset), verified covering chunk range, returned range, Merkle root, returned-byte SHA-256,
  exact source SHA-256, and an untrusted-content classification. Every field is required, so a
  whole-object source hash alone cannot satisfy the schema -- tested directly, plus the exported
  `PARTIAL_READ_INTEGRITY_STATEMENT` says so in words.
- **Inspection receipt** (`ArtifactInspectionReceiptSchema`): schema version, explicit verifier
  audience, session-derived opaque principal reference, approved inspector client reference,
  artifact ID, an immutable-object-or-Merkle-root source identity, operation, requested/returned
  range where applicable, returned-byte hash, policy version, analyzer profile version, an exact
  40-hex-character inspector deployment Git coordinate, recorded time, and a result-or-error-class
  union. `.strict()` rejects JWTs, authorization headers, service-role values, raw Storage paths,
  payload bytes, exact-search query text (the schema records only `queryLength`, never the query
  itself), and other secret-bearing metadata -- tested field-by-field. The exported
  `ARTIFACT_INSPECTION_RECEIPT_IS_NOT_AUTHORIZATION` states plainly that a receipt is evidence, not
  bearer authorization.
- **Deterministic analyzer-profile and derivation contracts**: `ANALYZER_PROFILE_IDS` names exactly
  the two S0-supported profiles (`text/plain`, `text/markdown`); `PROPOSED_NEXT_DETERMINISTIC_PROFILE_ID`
  documents CSV as proposed-not-implemented; `SEMANTIC_ANALYSIS_POLICY` is frozen with
  `enabled: false` and `executionClass: 'local_worker_only'`; `S0_DETERMINISTIC_DERIVATION_TYPES`
  excludes `semantic_summary` by construction (tested); `ArtifactDerivationWithInputsSchema` mirrors
  S1's `artifact_derivations` + `derivation_inputs` many-source shape and requires every input to
  bind its own exact source SHA.
- **Frozen tool descriptors** (`ARTIFACT_STAT_TOOL` and its four siblings, plus
  `ARTIFACT_INSPECTION_TOOLS`): capability name, fixed operation, the strict input/output schemas,
  `retry: { maxAttempts: 1, policy: 'none' }`, `idempotency: 'idempotent'`,
  `authorizationRequired: true`, `contentTrust: 'untrusted'`, and exact resource ceilings. Every
  descriptor and every nested `limits`/`retry`/`errorMapping` object is `Object.freeze`d and tested
  as frozen. `ARTIFACT_INSPECTION_DESCRIPTOR_IS_NOT_PERMISSION` states, and a test confirms by
  structural absence of any `grant`/`bypassAuthorization`/`authority` property, that a descriptor is
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
before `vitest run`). Exact result at candidate head:

```text
Checked 61 files in 23ms.       # biome format
Checked 61 files in 55ms.       # biome lint
(tsc -b, tsc -p tsconfig.test.json --noEmit: no output, exit 0)
Test Files  26 passed | 1 skipped (27)
     Tests  344 passed | 4 skipped (348)
```

The `artifact-inspection.test.ts` file alone contributes 137 of the passing tests, covering every
accepted operation, unknown-operation denial, all fifteen forbidden extra-field cases across all
five operations, every enumerated exact ceiling with its one-over rejection, missing-vs-unauthorized
byte-identical output, unsupported media type, incomplete receipt audience denial, ten forbidden
receipt fields, partial-read integrity field-by-field requirement, source-expiry vs. manifest
durability, semantic-analysis prohibition, the many-source derivation contract, capability
descriptors not granting authority, and every exported descriptor/policy object being frozen. The 4
skipped tests are pre-existing elsewhere in the suite and unrelated to this change.

## Claim limits

This candidate does not add remote HTTP/OAuth, writes, production credentials or data, an Edge
Function implementation, MCP runtime registration, Storage deployment, a semantic-analysis
implementation, deployment, or production readiness. It is S0 only: a capability/threat contract
for review. Postgres/RLS and Storage byte custody remain governed entirely by the S1 migrations
already on `main`; nothing here changes them.
