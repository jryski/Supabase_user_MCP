# Feature Catalog

- **Status:** Proposed
- **Last reviewed:** 2026-08-17

This catalog defines the intended product surface. A feature is not available until its
roadmap milestone is complete and its acceptance criteria are backed by tests.

## Status legend

| Status | Meaning |
| --- | --- |
| Research | Architecture or external behavior is unresolved |
| Specified | Contract and acceptance criteria are reviewable |
| Planned | Approved for a named milestone |
| In progress | Implementation work has begun |
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

## Reference memory tools

### `memory_search`

- **Milestone:** M2
- **Status:** Specified
- **Capability:** `memory:search`
- **Risk:** Read

Runs bounded full-text or semantic search over records visible to the caller.

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
- **Status:** Specified
- **Capability:** `memory:read`
- **Risk:** Read

Retrieves one record by opaque identifier using an allowlisted projection.

Acceptance highlights:

- Missing and unauthorized identifiers use a non-enumerating result shape.
- Restricted fields are never serialized.
- The response declares stored text as untrusted content.

### `memory_list_recent`

- **Milestone:** M2
- **Status:** Specified
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
- **Status:** Planned

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
- **Status:** Planned

Loads representative principals, clients, workspaces, capabilities, records, and states,
then tests every intended allow and deny cell through the same API boundary used by the
server.

### Policy catalog checks

- **Milestone:** M1
- **Status:** Planned

Checks for exposed tables without RLS, incomplete update policies, unsafe views, public
definer functions, missing grants, and unindexed policy predicates. Supabase security and
performance advisors remain required after schema changes.

### Reference policy pack

- **Milestone:** M1–M3
- **Status:** Planned

Provides migrations and tests for the reference sovereign-memory schema. It is an example
integration, not a universal policy generator.

## Safety and operations

### Result and cost governor

- **Milestone:** M2
- **Status:** Planned

Central enforcement for input length, filters, rows, bytes, duration, rate, concurrency,
and retry budget. Tools may lower but not exceed global ceilings.

### Dual-layer audit

- **Milestone:** M3
- **Status:** Planned

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
- **Status:** Planned

Versioned synthetic records and requests covering stored prompt injection, cross-tenant
references, filter manipulation, oversized context, credential confusion, approval
replay, audit tampering, and inference channels.

## Deferred features

The following require separate design and are not part of v1 unless promoted through an
ADR:

- Supabase Storage tools.
- Realtime subscriptions.
- Cross-project federation.
- Customer-defined arbitrary tools.
- Generic CRUD over caller-selected tables.
- Administrative or schema-management tools.
- Automated policy generation from natural language.
- Automatic execution of irreversible actions.
