# Issue #34 S4 deterministic text-index spike

Base commit: `374473bc0700e30649f63d1db164f64c0aab3dee`
Base tree: `af37d139509a1ffea193c2baecf589c90a92f02c`
Candidate profile: `artifact-text-index/0.1`

This is a blocked S4 spike. S2 and S3 remain prerequisites; this candidate has no merge authority until both are accepted.

## Exact semantics and bounds

The worker accepts only in-memory `Uint8Array` input, copies it defensively, validates the complete source with fatal UTF-8 decoding, and computes SHA-256 over the complete original byte sequence. Supported media types are exactly `text/plain` and `text/markdown`; every other media type is `UNSUPPORTED_MEDIA_TYPE`.

Line offsets refer to original source bytes. LF and CRLF are line endings, are included in the preceding line record, and mixed endings are preserved. An isolated CR is content. Empty input has zero lines; a final newline does not fabricate an extra line. A final non-newline segment is a line. A UTF-8 BOM is valid source content and is not stripped; consequently it is not indentation or an ATX marker.

Markdown recognizes only ATX headings with one through six `#` markers, a required following ASCII space, and at most three leading ASCII spaces. Optional closing hashes are stripped only when separated from heading text by whitespace. Setext headings are ordinary text. Backtick and tilde fences of three or more matching markers suppress headings until a matching marker fence at least as long closes them. No links, HTML, directives, macros, includes, code, or embedded text is executed or interpreted; all returned source text is labeled `untrusted`.

Bounds are: 262144 source bytes, 10000 lines, 1000 headings, heading level 6, 512 heading-text characters, 200 lines per read, and 8192 returned source bytes. Heading IDs are deterministic lowercase-ASCII slugs, encode non-ASCII code points as `u` plus hex, collapse separator runs, use `heading` for empty slugs, make duplicates `-2`, `-3`, and cap output to 128 characters.

## Verification and claim limits

Clean baseline passed before changes: `npx --yes npm@11.19.0 ci` and `npx --yes npm@11.19.0 run check` (27 passed / 1 skipped test files; 534 passed / 4 skipped tests). Final verification passed: `npm run check`; `npx vitest run packages/server/src/artifact-text-index.test.ts` (1 file, 10 tests); `git diff --check`; and `git status --short` (only the three paths below).

Excluded: S2 inspector changes, MCP registration, Edge or hosted deployment, Storage/database access, artifact ingest, semantic analysis, search, vector indexing, writes, private data, production-readiness claims, and merge authority before S2/S3 acceptance.
