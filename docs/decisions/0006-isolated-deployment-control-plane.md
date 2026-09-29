# ADR-0006: Isolate privileged deployment control-plane tools

- **Status:** Proposed, implementation trial in issue #70
- **Date:** 2026-09-13
- **Owners:** Maintainers and deployment owner
- **Milestone:** Adjacent deployment profile, outside accepted M2 user path

## Context

VAULT gained bounded `planning.create_work_item` and `public.post_model_message` functions after a
ChatGPT connector blocked routine planning and coordination mutations. Requiring every agent to
construct raw SQL also duplicated defaults, leaked schema details, and made behavior depend on the
client's SQL classifier.

The accepted Supabase User MCP architecture is a user-context application data plane. Its current
server verifies an authenticated user and preserves that identity into RLS. VAULT's new functions
are privileged deployment operations restricted to service-role and database-owner paths. Adding
them to the existing user server would collapse two distinct authorities.

## Constraints

- The existing read-only user server cannot load a service-role or secret key.
- Privileged tools cannot be co-registered with user-context tools.
- Tool calls cannot choose a database object, RPC, URL, role, credential, or actor identity.
- HOUSE and VAULT remain separate trust domains.
- Agent labels are provenance only.
- The current implementation cannot claim Ariadne runtime integration.

## Options considered

### Add the tools to the existing read-only server

Rejected. One process and credential path would combine authenticated user reads with privileged
deployment mutation authority.

### Expose a generic PostgREST or SQL tool

Rejected. A caller-selected method, path, schema, relation, RPC, or SQL statement restores the
same interpretation and authority problem that dogfooding exposed.

### Create a new repository before proving the interface

Deferred. A second repository would add ownership and release machinery before the first two
capabilities and their boundaries are validated.

### Add a separate privileged profile in this repository

Proposed. Reuse the pinned MCP transport, strict contracts, byte limits, and test conventions while
keeping construction, credentials, registration, and exports separate from the user server.

## Decision

Issue #70 implements a library-level `createControlPlaneServer` with exactly two fixed tools and a
separate `createControlPlaneClient`. The accepted read-only CLI remains unchanged. No privileged
credential loader or production startup path is added in this slice.

Reconsider repository ownership after the ten-primitive interface is validated across more than
one deployment or when the control-plane release lifecycle diverges from the user data plane.

## Consequences

### Positive

- ChatGPT, Claude, local agents, and Ariadne can target one stable tool contract.
- Direct SQL and client-specific mutation behavior leave the model request path.
- The accepted user-context server retains its current authority boundary.
- Database locks, constraints, and idempotency remain authoritative.

### Negative

- The repository now contains two security profiles that maintainers must not confuse.
- The deployment still needs a reviewed secret-loading and process-isolation mechanism.
- Live function signature and ACL drift can break the fixed adapter.

## Validation required before acceptance

- Exact live function definitions and receipts match the fixed adapter.
- `service_role` can execute both functions; `anon`, `authenticated`, and `PUBLIC` cannot.
- Function owners, `SECURITY DEFINER` status, fixed `search_path`, and PostgREST schema exposure are
  reviewed.
- Synthetic registration and fixed-route tests pass.
- A deployment test proves Ariadne can invoke both tools without raw SQL.
- An independent reviewer accepts the exact implementation head.
