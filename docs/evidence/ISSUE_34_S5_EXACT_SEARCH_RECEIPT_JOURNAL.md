# Issue #34 S5a: deterministic exact search and acknowledged receipt journal

- **Status:** S5a complete only for the synthetic/local exact-search and receipt-journal seam
- **Exact base:** `0d61ebe419d62e64e5f5e4efa9b1a09f4fdbb586`
- **Exact base tree:** `5f170cd6da6ca29e8d667616fe3674cc82c2b91b`
- **Branch:** `feat/34-s5-exact-search-receipts`
- **Production runtime authority change:** none

## Deterministic exact search

`artifactSearchExact` implements the unchanged accepted S0 `artifact_search_exact` input, output,
and receipt schemas. It:

1. accepts only `text/plain` and `text/markdown` after current principal/client/grant resolution;
2. rejects an empty source as the exact fixed `RESOURCE_UNAVAILABLE` result because the S0
   successful-search integrity shape requires at least one verified chunk;
3. rejects sources over 8,192 bytes or over 16 chunks before byte access;
4. performs exactly one complete-source exact-version read with no retry;
5. treats a null exact-version read as `RESOURCE_UNAVAILABLE`, malformed dependency data as a fixed
   redacted failure, and version/length/source/manifest mismatch as `INTEGRITY_FAILURE`;
6. verifies the complete S1b manifest and every source chunk, then builds
   `artifact-text-index/0.1` only in memory for canonical line numbers;
7. requires the parsed and trimmed query to contain only Unicode scalar values before authorization,
   dependency calls, journal operations, or source reads; an unpaired high or low UTF-16 surrogate
   returns the fixed `INVALID_REQUEST`, performs zero resolver/read/journal calls, emits no source
   receipt, and emits only the existing redacted invalid-request operational event;
8. encodes an accepted scalar-value query as UTF-8, decodes those bytes with fatal, BOM-preserving
   UTF-8 semantics, requires exact string equality, and applies an additional 256-byte query ceiling,
   so `TextEncoder` replacement can never become an exact match; valid U+FFFD and valid
   supplementary-plane code points remain distinct and searchable; and
9. matches raw UTF-8 bytes exactly, case-sensitively, left-to-right, without normalization, stemming,
   case folding, regular expressions, semantic behavior, or locale dependence;
10. advances by the query byte length, so matches are ordered and non-overlapping, and returns only the
    first `maxHits` without a total count or hidden-match indicator; and
11. returns each exact match as the entire snippet, with equal match/snippet ranges, an independent
    snippet SHA-256, starting canonical line number, and `contentTrust: "untrusted"`.

Successful zero-hit searches still return complete-source integrity. The returned range is always
`{ offset: 0, length: sourceByteLength }`, the returned-byte digest is the full source SHA-256, and all
source chunks and proofs appear in `PartialReadIntegrity`. At the accepted minimum 1,024-byte chunk
size, a 16- or 17-chunk source would already exceed the stronger 8,192-byte source gate; tests therefore
exercise exact 8,192/8,193-byte behavior and document that geometry rather than fabricating an
unreachable accepted 16-chunk case.

Search receipts contain only the operation, UTF-8 query length, `maxHits`, and each returned snippet
range/hash. They contain no query, snippet, total count, source bytes, locator, path, token, or journal
acknowledgement.

## Acknowledged append-only receipt-journal seam

The pure `artifact-receipt-journal/0.1` module defines:

- `ArtifactReceiptJournal`, whose single append receives an already S0-valid immutable receipt and its
  expected lowercase SHA-256;
- the strict `artifact-receipt-journal-ack/0.1` acknowledgement with matching digest and an
  authorization-identifier-compatible opaque `journalRef`;
- deterministic recursive-key-sorted JSON UTF-8 serialization and SHA-256 helpers; and
- an append/ack validation helper that validates the receipt, deep-freezes a parsed safe copy, appends
  exactly once, validates the strict acknowledgement, requires digest equality, and returns a frozen
  acknowledgement.

Canonical serialization preserves array order and adds no time or randomness. It rejects undefined,
symbols, functions, bigint, cycles, non-finite numbers, accessors, custom `toJSON`, non-plain records,
and nonordinary arrays without executing accessors. Journal throws, malformed acknowledgements, and
digest mismatches collapse to one fixed local `JOURNAL_APPEND_FAILED` error without sink-message
leakage or retry.

Optional artifact MCP registration now requires an injected receipt journal. Operation-scoped observer
gates buffer the inspector receipt and redacted event while the original operation and journal append
share the same 2,000 ms deadline. A source-bound receipt must be acknowledged before the original
success or source-bound error can return. After acknowledgement, the validated receipt and buffered
events are forwarded once. Pre-resolution and exact-version-null unavailable outcomes produce no
source receipt and no journal append.

A missing, malformed, throwing, or digest-mismatched acknowledgement discards buffered evidence,
returns the fixed `INTERNAL_ERROR`, and emits exactly one redacted registration-level internal-error
event. Timeout or abort closes and discards the buffer and emits only the existing registration-level
`DEADLINE_EXCEEDED` event. Late journal success or rejection forwards no evidence and creates no
unhandled rejection. A journal acknowledgement is internal operational evidence; it is never exposed
through MCP output or an inspection receipt, and a receipt remains evidence rather than authorization.
Current policy evaluation remains required.

## Registration and executable closure

The optional configured server now lists exactly eight tools: three memory tools plus five artifact
tools. `artifact_search_exact` uses the accepted strict schemas, read-only annotations, trusted context,
shared renderer, deadline, observer/journal gate, and complete-wire budget. The default no-config
server remains exactly the three memory tools.

`artifact-storage-closure/0.2` records:

- five exact registered artifact operations, with exact search classified as one bounded
  complete-source read;
- no artifact-data writes;
- acknowledged append-only inspection receipts as the only operational-evidence write;
- mandatory acknowledgement before every source-bound MCP return;
- no append for unavailable outcomes without a source receipt;
- zero retries, listing, signed URLs, or privileged credentials; and
- receipts as evidence, not authorization, with current policy evaluation required.

Generic search, regex, semantic/vector search, ingest, listing, arbitrary Storage/network access, and
write/publication tools remain absent.

## Fixed synthetic SDK adoption demo

The fixed Markdown fixture in `packages/server/src/artifact-mcp-registration.test.ts` has:

- artifact ID `art_s4_synthetic_markdown_0001`;
- immutable version `ov_s4_synthetic_markdown_0001`;
- source byte length 210;
- hardcoded SHA-256 `219f6d8e995539a99ffd48221e8f4357c8946f3395e03fb36f75f6d9c12c2501`;
- repeated ASCII `needle` at offsets 183 and 196;
- repeated multibyte `café` at offsets 190 and 203;
- a fixed zero-hit query; and
- hostile instruction/link content that remains inert and explicitly untrusted.

The real MCP `Client` plus `StreamTransport` test checks exact offsets, byte lengths, line numbers,
snippet hashes, complete source/chunk/proof integrity, zero-hit success, unavailable behavior, unchanged
source bytes, and complete-frame estimator parity. Its deterministic synthetic journal receives only
schema-valid content-free receipts, returns strict digest-matching acknowledgements, and records no
query, snippet, source, locator, or token. The test performs no external I/O and uses no private data.

## Verification

Canonical repository and focused gates:

```shell
npx --yes npm@11.19.0 run check
npx vitest run packages/server/src/artifact-receipt-journal.test.ts packages/server/src/artifact-inspector.test.ts packages/server/src/artifact-mcp-registration.test.ts
git diff --check
git status --short
```

The focused suites cover canonical golden bytes/digest, mutation sensitivity, unsupported canonical
values, strict append acknowledgements, exact ASCII/multibyte matching, no normalization, non-overlap,
truncation, line mapping, zero-hit and empty-source behavior, exact byte ceilings, authorization and
version denial, integrity mutations, immutability, concurrency, SDK registration, journal ordering and
failure normalization, timeout/abort late-evidence suppression, closure mutation sensitivity, and the
fixed synthetic adoption demo.

## Claim limits and next gate

S5a closes deterministic exact search and the acknowledged append-only receipt-journal interface only.
This repository still supplies no persistent journal backend and no live Storage/network adapter.
Default CLI/stdio startup remains memory-only.

Live S5 operational adoption remains gated on selecting and approving a real caller-context Storage
adapter and durable operational-evidence backend. S6 semantic summaries do not start here. This stage
adds no semantic/vector search, ingest, publication, hosted or Edge deployment, Storage/database
mutation, `service_role`, signed URL, listing, caller-selected coordinate, canonical write, private
data, or production-readiness claim. It does not merge or deploy anything.
