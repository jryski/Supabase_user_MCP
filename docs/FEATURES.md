# Feature Catalog

- **Status:** Mixed — merged local contracts and factories; later capabilities proposed
- **Last reviewed:** 2026-09-01

This catalog defines both merged foundations and the intended product surface. Each section's
status governs its named scope. `Implemented` or `Partially implemented` does not mean that a
larger milestone, deployment profile, or production security gate is complete.

## Status legend

| Status | Meaning |
| --- | --- |
| Research | Architecture or external behavior is unresolved |
| Specified | Contract and acceptance criteria are reviewable |
| Planned | Approved for a named milestone |
| In progress | Implementation work has begun |
| Partially implemented | Some named layers are merged; remaining layers or acceptance are explicit |
| Implemented | Code and tests on `main` demonstrate only the named scope |
| Experimental | Usable only in controlled development environments |
| Stable | Covered by the stable compatibility and security policy |

## Tool contract

Every public tool must define:

- a stable name and versioned input/output schema;
- the principal and capability it requires;
- the exact allowed view or function;
- bounded rows, bytes, filters, execution time, and retries;
- idempotency and concurrency behavior;
- approval and audit classification;
- errors that do not reveal forbidden resource existence; and
- positive, denied, cross-identity, and malformed-input tests.

### Read-tool contract v1

The executable schemas in `@supabase-user-mcp/contracts` freeze the initial read-only
surface. Every object is closed: unknown keys are invalid, including caller-selected
origins, schemas, relations, RPCs, URLs, raw SQL, and PostgREST operators. Memory IDs use
an opaque `mem_` token and pagination cursors use an opaque `cur_` token; callers must not
construct or decode either token.

All three tools enforce a project-defined 65,536-byte wire-response ceiling and a 2,000 ms
execution ceiling on merged `main`. The byte unit is the UTF-8 encoding of the complete
serialized outbound JSON-RPC frame, including the request ID, result/content envelope, JSON
escaping, the stdio newline delimiter, protocol overhead, and every selected compatibility representation. The contract
package and registered server now share one dual-representation renderer and estimator. Contract
boundary tests and an actual captured SDK `JSONRPCMessage` prove estimator parity; an oversized
eight-row response returns a bounded `RESPONSE_LIMIT_EXCEEDED` result instead of an oversized
success frame. A registered transport guard closes any oversized inbound or outbound JSON-RPC
frame before dispatch/send, so extreme request IDs cannot amplify a denial beyond the same ceiling.
Serialized request IDs have a separate inclusive 1,024-byte ceiling.
This frame-budget behavior is merged and covered by exact-head M2 acceptance.
`memory_search` accepts at most 512 query characters, five allowlisted filters (tag and
creation-time filters combined), and 20 rows. When both creation bounds are present,
`createdAfter` must be earlier than or equal to `createdBefore`. `memory_list_recent` accepts
at most five allowlisted tag filters and 25 rows. `memory_get` accepts exactly one opaque ID
and returns at most one row. Limits are inclusive; values one above a ceiling are invalid.
Search and recent-list results omit total counts. Recent-list ordering is fixed to creation
time descending with opaque ID descending as the tie-breaker; callers cannot select sort
fields or direction.

Each descriptor declares one attempt with no automatic retry, idempotent and parallel-safe
read behavior, no approval requirement, and `read_access` audit classification. Validation,
unavailable records, response overflow, timeout, and unexpected failures map respectively
to `INVALID_REQUEST`, `RESOURCE_UNAVAILABLE`, `RESPONSE_LIMIT_EXCEEDED`,
`DEADLINE_EXCEEDED`, and `INTERNAL_ERROR`; reaching 2,000 ms is the timeout condition. These
describe merged contracts, strict MCP registration, and the synthetic Data API/RLS path on `main`.
The executable environment-only stdio/operator package is merged and remains experimental,
local-stdio, read-only, and synthetic-only.

The only serialized record fields are `id`, `title`, `content`, `contentTrust`, `createdAt`,
and `provenanceSummary`; search results additionally include `rank`. Stored `content` is
always labeled `contentTrust: "untrusted"`. Each output is either `{ ok: true, ... }` or a
closed `{ ok: false, error: { code, message, retryable } }` result. Exact-record misses and
authorization denials both pass their distinct internal reasons through
`publicMemoryGetUnavailable`, which returns the byte-identical `RESOURCE_UNAVAILABLE` /
`Record is unavailable.` public error without the requested ID or diagnostic details.

## Reference memory tools

### `memory_search`

- **Milestone:** M2
- **Status:** Implemented
- **Capability:** `memory:search`
- **Risk:** Read

The contract reserves bounded text and semantic modes over records visible to the caller.
The current database candidate is lexical; semantic ANN quality, recall, latency, and
multitenant behavior are not implemented or accepted.

Initial contract:

- accepts a query, search mode, optional allowlisted filters, limit, and opaque cursor;
- rejects raw SQL, arbitrary PostgREST operators, caller-selected embeddings, and
  caller-selected relation names;
- applies authorization before ranking and aggregation;
- returns an allowlisted projection, rank, provenance summary, and next cursor;
- caps query length, filter count, rows, response bytes, and execution time; and
- does not return total counts where they could reveal unauthorized data.

Acceptance highlights:

- Equivalent searches by two principals return only their authorized intersections.
- Unauthorized rows cannot affect visible ranking or counts.
- A stored injection string is returned as data and cannot expand the tool surface.
- Over-limit input fails before a database request.

### `memory_get`

- **Milestone:** M2
- **Status:** Implemented
- **Capability:** `memory:read`
- **Risk:** Read

Retrieves one record by opaque identifier using an allowlisted projection.

Acceptance highlights:

- Missing and unauthorized identifiers use a non-enumerating result shape.
- Restricted fields are never serialized.
- The response declares stored text as untrusted content.

### `memory_list_recent`

- **Milestone:** M2
- **Status:** Implemented
- **Capability:** `memory:read`
- **Risk:** Read

Lists recent authorized records with stable ordering and cursor pagination.

Acceptance highlights:

- Page size has a server-side maximum.
- Cursors cannot change tenant, principal, filters, or sort direction.
- Insertions between pages do not create unbounded duplication or omission.

### `memory_append_observation`

- **Milestone:** M3
- **Status:** Specified
- **Capability:** `memory:append`
- **Risk:** Low write

Appends a non-canonical, attributable observation.

Initial contract:

- requires an idempotency key;
- derives actor, client, workspace, and creation time from trusted context;
- accepts only allowlisted content and provenance fields;
- never overwrites or deletes an existing record; and
- records a correlation identifier and trusted data event.

Acceptance highlights:

- Replaying the same key and payload returns the original result.
- Reusing the key with a different payload is rejected.
- Caller-supplied owner or workspace values are rejected or ignored by schema.

### `memory_propose_change`

- **Milestone:** M3
- **Status:** Specified
- **Capability:** `memory:propose`
- **Risk:** Staged write

Stages an exact canonical mutation without applying it.

Acceptance highlights:

- The proposal stores a canonical payload digest, reason, proposer, client, and expiry.
- The proposer cannot mark the proposal approved or applied.
- Editing the proposed payload creates a new revision and invalidates approval.

### `memory_get_proposal`

- **Milestone:** M3
- **Status:** Specified
- **Capability:** `memory:propose` or `memory:review`
- **Risk:** Sensitive read

Returns the current state and caller-visible evidence for one proposal.

Acceptance highlights:

- Proposers and reviewers see only proposals in their authorized workspace and class.
- Audit-only fields and reviewer-private notes follow separate projections.

### Review and application surface

- **Milestone:** M3
- **Status:** Research

Canonical approval may be delivered through a dedicated human UI, an MCP App, or a
separate reviewer tool set. Regardless of interface:

- approval requires `memory:review` and may require `aal2`;
- the proposal author cannot self-approve by default;
- approval is bound to one payload digest and expiry; and
- only a trusted transaction can change `approved` to `applied`.

The exact user experience is deliberately open; the database state machine is not.

## Identity and transport features

### Stdio user-token profile

- **Milestone:** M2
- **Status:** Experimental

- Protected local credential source.
- Fixed Supabase origin.
- No credentials in command arguments or output.
- Read-only default.
- Clear expiry and re-authentication behavior.

### Remote HTTP OAuth profile

- **Milestone:** M4
- **Status:** Research / blocked

- Current MCP HTTP protocol and protected-resource metadata.
- Supabase Auth OAuth 2.1 integration.
- PKCE, exact issuer and audience validation, and secure client registration strategy.
- A standards-compliant downstream credential chain.
- Stateless authorization and horizontally scalable request handling.

Blocked by [ADR-0002](decisions/0002-remote-identity-chain.md).

## Governed Artifact Inspection

- **Roadmap:** [Issue #34](https://github.com/jryski/Supabase_user_MCP/issues/34)
- **Status:** Partially implemented
- **Risk:** Read and external byte-custody boundary

Merged foundations:

- S0 strict contracts for opaque IDs, bounded operations, complete-wire outputs, non-enumerating
  errors, source/partial-read integrity, receipts, deterministic profiles, and derivation lineage;
- synthetic S1 artifact registry, chunk and derivation tables, approved inspector-client policy,
  and Storage RLS laboratory; and
- S1b deterministic source manifests, distinct raw and domain-separated chunk hashes, canonical
  Merkle proofs, full-source verification, and mutation-sensitive calibration.

The next gate is S2 fixed read-only inspection: `artifact_stat` plus bounded range and UTF-8 text
reads behind injected caller-context authorization and immutable artifact identity. S2 is not yet
an MCP-registered tool or deployed Edge Function. No caller may select a bucket, object path, URL,
origin, method, schema, table, RPC, parser, or privileged credential.

Later heading/search indexing, durable operational adoption, semantic analysis, and any write or
derived-artifact publication remain separate stages.

### Principal lifecycle

- **Milestone:** M4–M5
- **Status:** Research

- Named owner and purpose.
- Human, delegated-agent, and service-agent classifications.
- Environment and workspace binding.
- Issue, rotate, expire, suspend, revoke, and decommission lifecycle.
- Tested revocation bound.
- No shared agent credentials.

## Policy tooling

### Access-matrix test harness

- **Milestone:** M1
- **Status:** Implemented

Loads representative principals, clients, workspaces, capabilities, records, and states,
then tests every intended allow and deny cell through the same API boundary used by the
server.

### Policy catalog checks

- **Milestone:** M1
- **Status:** Implemented

Checks for exposed tables without RLS, incomplete update policies, unsafe views, public
definer functions, missing grants, and unindexed policy predicates. Supabase security and
performance advisors remain required after schema changes.

### Reference policy pack

- **Milestone:** M1–M3
- **Status:** Partially implemented

Provides migrations and tests for the reference sovereign-memory schema. It is an example
integration, not a universal policy generator.

## Safety and operations

### Result and cost governor

- **Milestone:** M2
- **Status:** Partially implemented

Central enforcement for input length, filters, rows, bytes, duration, rate, concurrency,
and retry budget. Tools may lower but not exceed global ceilings.

### Dual-layer audit

- **Milestone:** M3
- **Status:** Partially implemented

Correlates redacted MCP operational events with trusted database mutation events. Supports
authorized incident review without storing tokens or default record bodies.

### Revocation and incident controls

- **Milestone:** M5
- **Status:** Planned

- Revoke one principal, client, session, or capability.
- Identify affected requests and mutations.
- Preserve evidence.
- Rotate deployment secrets without fleet-wide identity sharing.
- Exercise a documented incident drill.

### Adversarial corpus

- **Milestone:** M2–M5
- **Status:** Partially implemented

Versioned synthetic records and requests covering stored prompt injection, cross-tenant
references, filter manipulation, oversized context, credential confusion, approval
replay, audit tampering, and inference channels.

## Deferred features

The following require separate design and are not part of v1 unless promoted through an
ADR:

- Generic Supabase Storage tools. The fixed governed inspector in issue #34 is a separately bounded
  capability and does not authorize generic Storage access.
- Realtime subscriptions.
- Cross-project federation.
- Customer-defined arbitrary tools.
- Generic CRUD over caller-selected tables.
- Administrative or schema-management tools.
- Automated policy generation from natural language.
- Automatic execution of irreversible actions.
