# ADR-0005: Finite, reviewed database capability registration

- **Status:** Proposed (design and contract only; not implemented or wired)
- **Date:** 2026-10-21
- **Owners:** Maintainers; author grok-mcp, independent review grok-verifier, architecture review ATLAS
- **Milestone:** Post-M2 extension, gated on acceptance of this ADR
- **Issue:** #122 (reviewed main `bd8e9a3c67a2f2533a7a8340eb10a84e2a7421eb`)

## Context

The connector exposes fixed memory RPCs. Application-specific data and approval rules belong
in an adopter's database, but an adopter cannot expose a small reviewed capability without
editing connector business logic. Issue #122 proposes an optional server-owned registry that
maps a finite set of tool descriptors to exact, configured Data API RPCs.

Related work is reused, not claimed: #77 (configurable fixed-memory schema and IDs) and #73
(declared capability visibility). Neither implements this registry.

This ADR proposes the trust boundary and the descriptor and registration contract only. The
contract lives in `packages/contracts/src/capability-registration.ts`. It is not exported from
the package index, not imported by the server, and registers nothing.

## Security constraints

- **Authority stays in the database.** RLS, grants and RPC bodies remain authoritative. A
  registered descriptor confers no permission; it only names one RPC the server may call on the
  caller's behalf.
- **Caller credential custody.** Every call uses the verified caller credential that the fixed
  tools already use (ADR-0002, ADR-0003), including after refresh or rotation. No service-role,
  owner or shared key is ever used, and there is no fallback to one.
- **Model inputs are arguments only.** The model cannot choose schema, function, URL, HTTP method,
  relation, SQL, headers, credentials, identity or approval state. These are fixed by the
  descriptor or supplied by the server.
- **Untrusted output.** Returned descriptions and results are untrusted evidence, never
  permission grants, and use the same untrusted-content framing and byte bounds as the fixed tools.
- **The default server is unchanged.** With no registry or an empty one, the tool list and
  behaviour stay byte- and behaviour-compatible with `main`.

## Decision drivers

- Keep domain logic and authorization in the adopter's database.
- Keep the connector's authority surface finite, reviewable and diffable.
- Avoid per-adopter forks without opening arbitrary SQL or RPC reach.

## Options considered

### A. Per-adopter code forks (rejected)

Every adopter edits connector logic. Review cost scales with adopters, security fixes fork,
and there is no shared invariant on what a capability may do.

### B. Runtime discovery or enumeration of database functions or SQL (rejected)

For example, exposing every RPC listed by PostgREST OpenAPI, or a generic `call_rpc` or `sql`
tool. This turns the connector into a general database client: the model could pick targets, and
the authority surface would grow every time someone adds a database function. It is incompatible
with ADR-0004's narrow-reuse decision.

### C. Project the whole application into the memory schema (rejected)

This overloads memory semantics and still needs connector changes for every new shape.

### D. Finite, reviewed, server-owned descriptor registry (proposed)

A static list, loaded at startup, of at most 16 descriptors. Each one is pinned by digest to a
review record and validated atomically. Lookups are deny-by-default.

## Decision

Adopt option D as the contract for a future implementation, subject to the invariants below.

### Security invariants

1. **Finite allowlist.** At most `MAX_REGISTERED_CAPABILITIES` (16) descriptors, provided as
   static configuration at process start. There is no runtime discovery, hot reload, or adding
   tools from tool output or database content.
2. **Deny-by-default.** `resolve(name)` returns a descriptor only for a listed name. Everything
   else, including prototype keys, is `undefined`, and the call is refused.
3. **Atomic validation.** One invalid descriptor rejects the whole registry, and the server
   then starts with only its fixed tools (fail closed, no partial registration).
4. **Separate namespace.** Names must match `^app_[a-z][a-z0-9_]{2,47}$`, cannot be any fixed
   tool name (`RESERVED_TOOL_NAMES`), and must be unique. Each target `schema.function` may be
   registered only once.
5. **Bounded kinds.** Only `read` and `proposal` exist. The read-only composition (today's
   server) rejects anything that isn't `read`. `proposal` is accepted only in a separately explicit
   `application` composition. There is no `approval`, `admin` or `write` kind by construction.
   Adding one requires a new ADR.
6. **Fixed routing.** `rpc.schema` and `rpc.function` are lowercase identifiers. Platform and
   system schemas are forbidden (`auth`, `storage`, `vault`, `realtime`, `graphql*`,
   `extensions`, `net`, `cron`, `pgsodium`, `pgbouncer`, `information_schema`, `pg_*`,
   `supabase_*`). The HTTP method and Data API path are fixed by the server, never by the descriptor.
7. **Closed input envelope.** A flat JSON object with `additionalProperties: false` and at most
   16 scalar arguments (bounded string, bounded integer, boolean). Argument names that could
   forge routing, identity or approval (`FORBIDDEN_ARGUMENT_NAMES`, for example `schema`, `url`,
   `user_id`, `role`, `token`, `approved`) cannot be declared. At call time, extra keys are
   rejected, never stripped (`validateCapabilityArguments`).
8. **Bounds.** `limits.maxResponseBytes` ≤ `MAX_RESPONSE_BYTES` (65,536) and `limits.timeoutMs` ≤
   `MAX_TOOL_EXECUTION_MS` (2,000). An oversized, malformed or late response is a failure, not a
   truncated success.
9. **Review pinning.** Each descriptor carries `review.adr` and `review.approvedBodySha256`, the
   sha256 of the canonical body (sorted keys, no whitespace). Any edit to the body without a new
   review fails as `descriptor_not_reviewed`.

### Descriptor fields (v1)

`descriptorVersion`, `name`, `title`, `description`, `kind`, `rpc.schema`, `rpc.function`,
`inputSchema`, and `limits.maxResponseBytes` and `limits.timeoutMs`, wrapped as `{ body, review }`. The
registry wrapper is `{ registryVersion, composition, descriptors }`. All objects are strict:
unknown fields are rejected.

### Versioning

The descriptor and registry carry literal version strings
(`supabase-user-mcp.capability-descriptor.v1`, `supabase-user-mcp.capability-registry.v1`). An
unknown version is rejected. Any change that widens authority (new kind, argument type, schema
or bound) is a new major version and needs a new ADR. Narrowing changes may be minor.

### Failure, revocation, cancellation and rollback (for the future implementation)

- **Failure:** each failed call maps to the existing fixed error envelope. Raw database errors,
  schema names and function names are never echoed to the model.
- **Revocation:** database-side revocation (grant removal, RLS, function drop) takes effect on the
  next call because the database stays authoritative. Removing a descriptor takes effect on restart.
- **Cancellation and timeouts:** the request is aborted at `limits.timeoutMs` or on client
  cancellation, and no result is returned after an abort.
- **Credential rotation:** each call reads the current verified caller credential. Concurrent
  users never share a credential or a cached result.
- **Rollback:** remove the registry configuration, or set it to `[]`, and restart. The server reverts
  to the fixed tool set with no data migration.

### How a future surface gets approved

1. The adopter writes the RPC and its RLS and grants in their own database, plus a descriptor.
2. A reviewer (author ≠ reviewer) checks the descriptor against these invariants and the RPC's
   authorization, then records the body digest under an accepted ADR.
3. The descriptor ships as static configuration. The validator enforces digest, bounds and
   composition at startup.
4. Any wider kind or argument type requires a new ADR, not a configuration change.

## Consequences

### Positive

- One reviewable, finite authority surface per deployment, diffable by digest.
- Domain logic stays in the database. The connector carries no application rules.

### Negative

- Adopters still need a review step for every capability.
- The scalar-only envelope rules out nested inputs until a later ADR.
- Descriptor `pattern` regexes are reviewer-trusted input. The validator only checks that they compile.

### Follow-up

- Accept or revise this ADR (grok-verifier review, ATLAS architecture review, Primary Users decision).
- Only then, in a separate PR: an exported registration adapter, an optional composition hook,
  and the synthetic test matrix listed in #122 (SDK round trip, rotation, isolation, cancellation,
  oversize, read-only denial).

## Validation

`packages/contracts/src/capability-registration.test.ts` (offline, synthetic) covers: empty
registry, valid read registration, deny-by-default lookup, the finite bound, reserved and
non-prefixed names, name and RPC collisions, read-only composition denial, absence of
approval/admin/write kinds, digest tampering, forbidden schemas, forbidden routing and
identity arguments, unknown fields, open envelopes, over-limit bounds, closed call-time
arguments, and that nothing is exported from the package index or imported by the server.

## Revisit when

- #77 or #73 lands and changes how capabilities are declared or shown.
- An adopter needs a kind, argument type or bound outside v1.
- ADR-0002 changes how the remote credential chain works.

## References

- Issue #122 and its assignment comment.
- ADR-0002, ADR-0003, ADR-0004.
