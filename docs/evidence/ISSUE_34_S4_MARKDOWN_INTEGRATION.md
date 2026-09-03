# Issue #34 S4: bounded Markdown integration and synthetic SDK demo

- **Status:** S4 complete only for synthetic/local deterministic in-memory line/heading integration
  and one fixed synthetic Markdown SDK demo
- **Exact base:** `2d7405f7c4a1d94d2cb07d94dfcf1be5596f5d9d`
- **Exact base tree:** `cad4e56997e1aba68f48bdd11c86bb1034371c6c`
- **Branch:** `feat/34-s4-markdown-integration-demo`
- **Production runtime authority change:** none

## Integrated behavior

The merged `artifact-text-index/0.1` primitive is exported from the server package and consumed only
after an exact-version complete-source read passes the accepted S1b manifest check.
`artifactReadLines` now uses `buildArtifactTextIndex` and `readIndexedLines` for canonical line
geometry and source-byte selection. Existing LF, CRLF, final-line, success-empty beyond-range, empty
source, invalid UTF-8, complete-source integrity, proof, receipt, and complete-wire behavior remains
fixed.

`artifactReadHeading` implements the unchanged S0 `ArtifactReadHeadingInputSchema` and
`ArtifactReadHeadingOutputSchema`. It:

1. validates strict input and trusted context/clock;
2. resolves one opaque artifact under the current principal, approved client, and capability grant;
3. accepts only `text/markdown` and rejects a source above 262,144 bytes before byte access;
4. performs one exact-version complete-source read with no retry;
5. verifies length, version, complete S1b manifest, UTF-8, and the canonical text index;
6. reads one canonical ATX heading line, excluding its newline;
7. builds and verifies every covering S1b proof and hashes the exact returned UTF-8 bytes; and
8. emits one immutable, schema-valid heading receipt binding the requested heading ID, returned
   range/hash, principal/client/grant, source/version/root/profile/policy, and Git coordinate.

Missing, unauthorized, expired, exact-version-unavailable, fenced, and unknown headings return the
same frozen `RESOURCE_UNAVAILABLE` result. Typed text-index errors are mapped by code; messages and
source content are never exposed. Unsupported media maps to `UNSUPPORTED`; source/response profile
limits map to `RESPONSE_LIMIT_EXCEEDED`; source mismatch, inconsistent index, and invalid UTF-8 map to
`INTEGRITY_FAILURE`; invalid line ranges map to `INVALID_REQUEST`; unexpected failures map to
`INTERNAL_ERROR`.

This is deterministic in-memory extraction during a verified read. The index is not persisted,
published, cached as a derived artifact, or generated at ingest.

## Optional MCP registration and Storage closure

The optional S3 registration seam now exposes exactly four artifact tools:

- `artifact_stat` — zero byte reads;
- `artifact_read_range` — one bounded covering read;
- `artifact_read_lines` — one bounded complete-source read; and
- `artifact_read_heading` — one bounded complete-source read.

Together with the three memory tools, valid injected artifact configuration lists exactly seven tools.
Without artifact configuration, the server remains exactly three memory tools. The heading tool uses
the accepted strict schemas, read-only annotations, verified-principal context, fixed configuration,
redacted request correlation, timeout/abort observer gate, shared complete-wire limits, and the same
untrusted renderer. `artifact_search_exact`, ingest, semantic analysis, listing, generic access, and
write operations remain absent.

`ARTIFACT_STORAGE_CLOSURE_MANIFEST` includes the heading read class and removes heading from its
unregistered list. Exact manifest validation and mutation tests reject heading omission and added
search/write operations.

## Fixed synthetic Markdown artifact

The sole S4 demo fixture lives in `packages/server/src/artifact-mcp-registration.test.ts`:

- artifact ID: `art_s4_synthetic_markdown_0001`;
- immutable version: `ov_s4_synthetic_markdown_0001`;
- media type: `text/markdown`;
- source byte length: 167;
- hardcoded source SHA-256:
  `262e40ee94b26db00178579e911bbd532776b532e68043026560e3dce4066cf3`;
- newline profile: mixed CRLF (first line) and LF (remaining lines);
- accepted headings: `approved-synthetic` and `verified-section`;
- fenced heading: `fenced-secret`, which remains unavailable;
- hostile instruction/link text: inert, explicitly untrusted returned source data; and
- internal locator/token sentinels: adapter-only and asserted absent from outputs and evidence.

Through the real MCP SDK `Client` plus `StreamTransport`, the test lists exactly seven tools, calls
stat and lines, reads `verified-section`, denies the fenced and unknown headings, and proves wrong
client/capability/artifact outcomes are byte-identical. It checks the exact heading bytes/range/hash,
all covering proofs, unchanged source bytes, schema-valid content-free receipts, a single unforgeable
model-visible untrusted prefix, exact `structuredContent`, and absence of write, listing, search,
network, filesystem, Storage, database, Edge, or model operations.

## Regression evidence

The focused suites cover line integration and heading success, duplicate and Unicode IDs, fence-close
semantics, source and heading profile ceilings, strict input, media denial, unknown headings, source
and version mutation, short/long/malformed/null/throwing reads, manifest/hash/root mutation, proof and
returned-hash checks, complete-wire bounds, receipt validity/secrecy, immutability, concurrency, and
heading-specific timeout/abort late-evidence suppression. Repository-wide verification is the
canonical `npm@11.19.0 run check`, followed by the two focused suites, `git diff --check`, and clean
scope/status review.

## Claim limits and next stage

S4 is complete only at this synthetic/local boundary. Default CLI/stdio remains memory-only, and
optional artifact registration still requires injected dependencies. This change adds no live
adapter, ingest persistence, derived-artifact publication, Edge or hosted deployment,
Storage/database mutation, `service_role`, signed URL, caller-selected coordinate, listing, exact
search, semantic analysis, write, private data, or production-readiness claim.

S5 exact search and durable operational adoption are next and require their own authority, evidence,
and review. This stage does not merge, deploy, or start S5.
