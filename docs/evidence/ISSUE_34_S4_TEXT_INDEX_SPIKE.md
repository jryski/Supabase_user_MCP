# Issue #34 S4 deterministic text-index spike

Base commit: `374473bc0700e30649f63d1db164f64c0aab3dee`
Base tree: `af37d139509a1ffea193c2baecf589c90a92f02c`
Candidate profile: `artifact-text-index/0.1`

This is a blocked S4 spike. S2 and S3 remain prerequisites; this candidate has no merge authority until both are accepted.

## Exact semantics and bounds

The worker accepts only in-memory `Uint8Array` input, copies it defensively, validates the complete source with fatal UTF-8 decoding, and computes SHA-256 over the complete original byte sequence. Supported media types are exactly `text/plain` and `text/markdown`; every other media type is `UNSUPPORTED_MEDIA_TYPE`.

Line offsets refer to original source bytes. LF and CRLF are line endings, are included in the preceding line record, and mixed endings are preserved. An isolated CR is content. Empty input has zero lines; a final newline does not fabricate an extra line. A final non-newline segment is a line. A UTF-8 BOM is valid source content and is not stripped; consequently it is not indentation or an ATX marker.

Markdown recognizes only ATX headings with one through six `#` markers, a required following ASCII space, and at most three leading ASCII spaces. Optional closing hashes are stripped only when separated from heading text by whitespace. Setext headings are ordinary text. Opening backtick and tilde fences of three or more markers retain bounded deterministic info-text behavior. A closing fence must have zero through three leading ASCII spaces, the same marker, a run at least as long as its opener, and only ASCII spaces or tabs afterward; trailing non-whitespace is fenced content. No links, HTML, directives, macros, includes, code, or embedded text is executed or interpreted; all returned source text is labeled `untrusted`.

Bounds are: 262144 source bytes, 10000 lines, 1000 headings, heading level 6, 512 heading-text Unicode code points, 200 lines per read, and 8192 returned source bytes. A 513-code-point heading is `RESPONSE_LIMIT_EXCEEDED`. Heading IDs are deterministic lowercase-ASCII slugs: each non-ASCII code point is encoded as collision-resistant `u--<lowercase-hex>--`, while ordinary ASCII separator collapsing emits no double hyphen. This keeps literal `u43f` distinct from U+043F. Empty slugs use `heading`, genuine duplicates receive `-2`, `-3`, and IDs cap at 128 characters.

Read helpers reject malformed indexes before rebuilding them: the index, its arrays, and every line/heading record must have the exact expected own keys, ordinary object/array prototypes, enumerable data properties only, no symbols, no hidden fields, no accessors, and no custom `toJSON`. Primitive field types and bounds are validated before a canonical rebuild comparison against the supplied source bytes.

## Verification and claim limits

Clean baseline passed before changes: `npx --yes npm@11.19.0 ci` and `npx --yes npm@11.19.0 run check` (27 passed / 1 skipped test files; 534 passed / 4 skipped tests). Final verification passed: `npx --yes npm@11.19.0 run check` (552 passed, 4 skipped, 556 total); `npx vitest run packages/server/src/artifact-text-index.test.ts` (1 file, 18 passed); `git diff --check`; and `git status --short` (only the three paths below). This spike remains BLOCKED ON S2/S3.

Excluded: S2 inspector changes, MCP registration, Edge or hosted deployment, Storage/database access, artifact ingest, semantic analysis, search, vector indexing, writes, private data, production-readiness claims, and merge authority before S2/S3 acceptance.
