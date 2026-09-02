# Issue #34 S3: optional MCP registration and Storage closure

- **Status:** S3 complete for the optional synthetic/local registration seam and executable
  external-data-plane containment accounting only
- **Exact base:** `a0b648d4da0e66de71c628317cb5b80f6a767cce`
- **Branch:** `feat/34-s3-mcp-artifact-registration`
- **Production runtime authority change:** none

## What S3 adds

`ReadOnlyServerOptions.artifactRegistration` is an optional, fixed trusted configuration. When it is
absent, `createReadOnlyServer` retains the exact three memory tools. When it is present and valid, the
real MCP SDK `tools/list` seam adds exactly:

- `artifact_stat`;
- `artifact_read_range`; and
- `artifact_read_lines`.

The option carries only the injected S2 `ArtifactInspectorDependencies`, an approved inspector client
reference, a distinct `{ capability: 'artifact:inspect', ref }` grant reference, verifier audience,
policy version, and exact inspector deployment Git coordinate. Runtime validation rejects unknown
configuration keys and invalid fixed values before an artifact tool is registered. There is no
configured principal: every artifact call derives `principalRef` only from the already verified
`verifyUserIdentity().principalId` result.

No artifact option or tool input accepts a token, JWT, bucket, object key/path, URL, origin, method,
schema, table, RPC, signed URL, `service_role`, parser, query, arbitrary tool name, or caller-selected
principal/client/capability coordinate. The accepted S0 strict input/output schemas remain unchanged.
Heading, exact search, compatibility, generic request/SQL/PostgREST/Storage, listing, ingest,
semantic, write, and admin tools are not registered.

## Per-request execution

For each call, the registration seam copies the validated fixed client, capability grant, audience,
policy version, and deployment coordinate into `createArtifactInspectorTrustedContext`. It derives a
deterministic bounded correlation reference as `mcp_req:<sha256(JSON(request-id))>`; the raw MCP
request ID is not embedded. Each handler calls exactly one matching S2 operation and renders its
output with `createArtifactInspectionMcpResult`, preserving the complete dual representation and the
single untrusted-content prefix.

The registration enforces the accepted fixed 2,000 ms ceiling by racing each operation against one
deadline and the MCP request `AbortSignal`. Timeout and abort normalize to the accepted
`DEADLINE_EXCEEDED` artifact output. There is no retry, and the losing operation promise always has a
rejection handler so a late adapter rejection cannot become unhandled. The adapter dependency
interface has no cancellation seam, so remote work may continue after the MCP result closes.

Each call creates an operation-scoped wrapper around the fixed S2 dependencies and a per-call S2
inspector. The wrapper closes as soon as MCP execution returns and suppresses every late S2 receipt or
operational event. After closure, registration emits exactly one redacted `DEADLINE_EXCEEDED` event
with the matching operation, bounded elapsed time, and `mcp_req:<sha256>` correlation. It issues no
source-bound receipt for a registration timeout or abort because source/version integrity may not
have been established. This remains read-only and does not prove remote cancellation.

## Complete-wire containment

Artifact responses continue through the existing `BoundedReadOnlyTransport`; S3 adds no second frame
estimator. Static and construction-time assertions require the artifact contract's 65,536-byte
complete-response limit and 1,024-byte serialized-request-ID limit to equal the shared transport
constants. The focused test captures an actual SDK JSON-RPC tool response and proves that its UTF-8
size, including the newline delimiter, equals `artifactInspectionResponseByteLength` exactly.
Existing exact/one-over transport tests remain unchanged.

## Executable Supabase Storage closure

`ARTIFACT_STORAGE_CLOSURE_MANIFEST` is a deeply frozen, exact-keyed, versioned
`artifact-storage-closure/0.1` value consumed directly by registration. It closes the external byte
plane as follows:

- plane: Supabase Storage byte custody;
- authorization: injected `resolveAuthorizedArtifact` under the verified principal, approved
  inspector client, and approved `artifact:inspect` capability grant;
- current policy evaluation is required on every call; historical receipts are evidence, not
  authorization;
- resolution input: opaque artifact ID only;
- internal locator: adapter-only and never tool input, output, receipt, or event;
- byte access: injected exact-version `readVersionedRange` only;
- version binding: returned immutable `objectVersionRef` must equal the authorized version;
- integrity: accepted S1b source hash, raw chunk hash, domain-separated Merkle leaf, and Merkle
  verification;
- `artifact_stat`: zero byte reads;
- `artifact_read_range`: one bounded covering read;
- `artifact_read_lines`: one bounded complete-source read;
- retries: zero; writes, listing/enumeration, and signed URLs: none;
- privileged credentials, including `service_role`: prohibited; and
- heading, exact search, ingest, semantic analysis, and write operations: unregistered.

Registration iterates the manifest's operation list and checks the resulting names against that same
list. The manifest validator rejects added or changed keys/values. Mutation tests prove failure when
heading/search is added, writes/retries/signed URLs/`service_role`/listing are permitted, immutable
version equality changes, approved client/capability policy is removed, or an operation's byte-read
class changes.

## Test evidence

`packages/server/src/artifact-mcp-registration.test.ts` exercises `tools/list` and `tools/call`
through the real SDK `Client` and `StreamTransport`. It covers default three-tool behavior, exact
six-tool opt-in behavior, strict schemas and annotations, absent names, verified-principal context,
distinct fixed references, redacted correlation, exact S2 routing/read classes, pre-dependency
rejection of caller authority/Storage fields, non-enumerating unavailable results, hostile content,
generic dependency errors, timeout/abort/no-retry/late-rejection behavior, estimator parity, closure
mutations, invalid configuration, and absence of locators/tokens/source bytes/raw request IDs from
listings and evidence. The repository-wide check retains all existing memory and S2 tests.

## Claim limits and next gate

S3 completes only optional synthetic/local MCP registration and executable Storage closure
accounting. Default CLI/stdio startup remains memory-only because this change does not wire the
option into startup and does not add a real Storage/network adapter.

This is not an Edge or hosted deployment; network or Storage adapter; Storage/database mutation;
privileged credential or `service_role` path; signed-URL issuer; caller-selected coordinate; listing;
ingest; heading or exact-search implementation; semantic analysis; write; private-data access; or
production-readiness claim. No deployment or merge is performed by this artifact.

S4 deterministic Markdown text indexing is now the next dependency-ready stage. The existing S4 draft
PR #51 predates this exact S3 head and must be rebased onto the merged S3 coordinate and freshly
reviewed; S3 does not rebase, integrate, merge, deploy, or otherwise start S4.
