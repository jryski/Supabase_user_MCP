# Product Definition

- **Status:** Proposed
- **Last reviewed:** 2026-08-17

## Product statement

Supabase User MCP is a reference MCP data plane that lets an AI client perform a small
set of application operations under a verifiable human or agent identity while Supabase
Postgres RLS remains the authoritative row-access boundary.

It is built for teams that already use Supabase Auth and Postgres and need agent access
to real application data without putting a project-wide administrative credential in the
agent's execution path.

## Users

### Application operator

Owns the Supabase project, policies, deployment, and incident response. Needs auditable
least privilege and a way to revoke one client or agent without interrupting the fleet.

### Policy author

Translates product roles into database-enforced access rules. Needs a repeatable access
matrix, realistic fixtures, and proof that denied paths remain denied.

### Human user

Authorizes an MCP client to act on their behalf. Needs clear consent, predictable tools,
and assurance that the client cannot access another user's data.

### Delegated agent

Acts for a human through an identifiable OAuth client. Its effective authority must be
the intersection of the human, client, tenant, tool, and row policies.

### Service agent

Runs an approved autonomous workflow without an interactive human session. It needs an
independently owned, expiring, and revocable identity. Its exact authentication lifecycle
is an M0 architecture gate.

### Security reviewer

Needs a compact threat model, traceable decisions, negative tests, dependency provenance,
and release evidence that can be audited without trusting marketing claims.

## Jobs to be done

1. Connect an MCP client to authorized Supabase application data without a project-admin
   credential in the request path.
2. Search and retrieve memory records without exposing unauthorized rows or unbounded
   result sets.
3. Append low-risk observations with attribution and replay safety.
4. Stage consequential mutations for a human decision enforced by database state.
5. Determine which principal, OAuth client, and tool attempted an operation and whether
   it succeeded.
6. Revoke a compromised principal or client within a documented time bound.
7. Demonstrate containment when stored content attempts to instruct an AI model.

## Product boundaries

### In scope

- Supabase Auth-backed human identities.
- Delegated and non-human principal models after their architecture gates pass.
- Domain-specific tools over an allowlisted Supabase API surface.
- RLS policy templates and an executable access matrix.
- Full-text and embedding-backed retrieval with hard bounds.
- Append-only low-risk writes and proposal-based canonical writes.
- Correlated application and database audit evidence.
- Local stdio and, after M4, standards-compliant remote HTTP deployment profiles.

### Out of scope

- DDL, migrations, project creation, branch management, or organization administration.
- Arbitrary SQL, generic database browsing, or unrestricted PostgREST proxying.
- Secret-key or `service_role` execution of end-user tool calls.
- A general identity provider or authorization server.
- Model behavior guarantees or prompt-injection prevention.
- Automatic approval of canonical or irreversible changes.
- Supporting every Supabase product in the initial releases.

## Differentiators

- **Database-enforced containment:** authorization survives a buggy or compromised MCP
  process because exposed data still requires RLS permission.
- **Capability-shaped tools:** the model receives business operations, not a generic data
  console.
- **Evidence-driven releases:** denied cases and adversarial fixtures are milestone gates.
- **Human authority for canonical state:** approval is represented as data and enforced
  below the model.
- **Reference-quality transparency:** unresolved protocol and identity questions remain
  visible as ADRs and blockers.

## Success measures

The first stable release should demonstrate:

- zero successful cross-tenant, cross-user, or cross-agent cases in the maintained access
  matrix;
- 100% of public tools mapped to a named capability and bounded schema;
- 100% of canonical mutations linked to an immutable approval record;
- no bearer tokens or sensitive row bodies in default logs, traces, or errors;
- deterministic pagination and configured maximum response size for every read tool;
- a tested revocation bound for every supported principal type; and
- successful adversarial containment tests for stored prompt injection, identifier
  guessing, replay, filter manipulation, and audit tampering.

Performance and availability targets will be set after the M2 reference workload exists.
They must not weaken authorization or response bounds.

## Product principles

1. Deny by default.
2. Make authority visible.
3. Prefer narrow tools to flexible primitives.
4. Derive ownership; never trust it from model input.
5. Make risky operations two-step and replay-safe.
6. Bound cost, rows, fields, and time.
7. Preserve evidence without recording secrets.
8. Document uncertainty before turning it into code.
