# Issue #34 S4 deterministic text-index spike

Rebased base commit: `f8a3a77963e5e8abf9b1b13b84c8df01adb2d412`
Rebased base tree: `e1c810e40525b0b59e15df8ada68b814def2d74c`
Candidate profile: `artifact-text-index/0.1`

S2 and S3 are merged. This artifact remains only the deterministic S4 text-index primitive: it adds
no inspector/MCP integration, automatic extraction, ingest lifecycle, or approved-artifact demo.

## Exact semantics and bounds

The worker accepts only in-memory `Uint8Array` input, copies it defensively, validates the complete source with fatal UTF-8 decoding, and computes SHA-256 over the complete original byte sequence. Supported media types are exactly `text/plain` and `text/markdown`; every other media type is `UNSUPPORTED_MEDIA_TYPE`.

Line offsets refer to original source bytes. LF and CRLF are line endings, are included in the preceding line record, and mixed endings are preserved. An isolated CR is content. Empty input has zero lines; a final newline does not fabricate an extra line. A final non-newline segment is a line. A UTF-8 BOM is valid source content and is not stripped; consequently it is not indentation or an ATX marker.

Markdown recognizes only ATX headings with one through six `#` markers, a required following ASCII space, and at most three leading ASCII spaces. Optional closing hashes are stripped only when separated from heading text by whitespace. Setext headings are ordinary text. Opening backtick and tilde fences of three or more markers retain bounded deterministic info-text behavior. A closing fence must have zero through three leading ASCII spaces, the same marker, a run at least as long as its opener, and only ASCII spaces or tabs afterward; trailing non-whitespace is fenced content. No links, HTML, directives, macros, includes, code, or embedded text is executed or interpreted; all returned source text is labeled `untrusted`.

Bounds are: 262144 source bytes, 10000 lines, 1000 headings, heading level 6, 512 heading-text Unicode code points, 200 lines per read, and 8192 returned source bytes. A 513-code-point heading is `RESPONSE_LIMIT_EXCEEDED`. Heading IDs are deterministic lowercase-ASCII slugs: each non-ASCII code point is encoded as collision-resistant `u--<lowercase-hex>--`, while ordinary ASCII separator collapsing emits no double hyphen. This keeps literal `u43f` distinct from U+043F. Empty slugs use `heading`, genuine duplicates receive `-2`, `-3`, and IDs cap at 128 characters.

Read helpers reject malformed indexes before rebuilding them: the index, its arrays, and every line/heading record must have the exact expected own keys, ordinary object/array prototypes, enumerable data properties only, no symbols, no hidden fields, no accessors, and no custom `toJSON`. Primitive field types and bounds are validated before a canonical rebuild comparison against the supplied source bytes.

## Verification and claim limits

The original isolated baseline passed before S4 changes. After rebasing onto merged S2/S3 and adding
same-stage documentation closure, exact npm 11.19.0 `npm run check` passes 645 tests with four
pre-existing skips (649 total), and `npx vitest run packages/server/src/artifact-text-index.test.ts`
passes all 18 focused tests. `git diff --check` and authorized-path status also pass.

Excluded: S2 inspector changes, S3 registration changes, server-barrel export, MCP activation, Edge or
hosted deployment, Storage/database access, artifact ingest, automatic extraction, approved-artifact
demo, semantic analysis, exact search, vector indexing, writes, private data, and production-readiness
claims. These bytes do not complete the full S4 integration stage.
