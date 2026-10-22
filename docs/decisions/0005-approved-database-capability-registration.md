# ADR-0005: Finite, reviewed database capability registration

- **Status:** Proposed (design and contract only; not implemented or wired)
- **Date:** 2026-10-21 (revision 3 after independent re-check)
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
the package index or exports map, not imported by the server, and registers nothing.

## Security constraints

- **Authority stays in the database.** RLS, grants and RPC bodies remain authoritative. A
  registered descriptor confers no permission; it only names one RPC the server may call on the
  caller's behalf.
- **Configuration cannot authorize itself.** Permissions are enforced outside the documents
  they govern. The adopter's descriptor file can propose capabilities, but it cannot select its
  composition, approve its own descriptors, or add a schema. Those three inputs come from the
  server (see "Authority split").
- **Caller credential custody.** Every call uses the verified caller credential that the fixed
  tools already use (ADR-0002, ADR-0003), including after refresh or rotation. No service-role,
  owner or shared key is ever used, and there is no fallback to one.
- **Model inputs are arguments only.** The model cannot choose schema, function, URL, HTTP method,
  relation, SQL, headers, credentials, identity or approval state.
- **Untrusted output.** Returned descriptions and results are untrusted evidence, never
  permission grants, and use the same untrusted-content framing and byte bounds as the fixed tools.
- **The default server is unchanged.** With no registry or an empty one, the tool list and
  behaviour stay byte- and behaviour-compatible with `main`.

## Decision drivers

- Keep domain logic and authorization in the adopter's database.
- Keep the connector's authority surface finite, reviewable and diffable.
- Never let the input being validated widen its own authority.
- Avoid per-adopter forks without opening arbitrary SQL or RPC reach.

## Options considered

### A. Per-adopter code forks (rejected)

Every adopter edits connector logic. Review cost scales with adopters, security fixes fork,
and there is no shared invariant on what a capability may do.

### B. Runtime discovery or enumeration of database functions or SQL (rejected)

For example, exposing every RPC listed by PostgREST OpenAPI, or a generic `call_rpc` or `sql`
tool. This turns the connector into a general database client and grows the authority surface
whenever someone adds a function. It is incompatible with ADR-0004.

### C. Project the whole application into the memory schema (rejected)

This overloads memory semantics and still needs connector changes for every new shape.

### D. Finite, server-approved descriptor registry (proposed)

A static descriptor file of at most 16 entries. It is validated atomically against a
server-owned policy: the composition, an adopter schema allowlist, and a release-shipped approval
allowlist. Lookups are deny-by-default.

### Where approval lives (sub-decision)

| Option | Offline-testable | New key or DB surface | Chosen |
| --- | --- | --- | --- |
| Release-shipped digest allowlist in a file the agent cannot write | Yes | None | **Yes** |
| Detached signature over the descriptor | Yes, with fixtures | A reviewer key pair, rotation and key custody | No |
| Server-only approval table in the database | No (needs a database) | A new table, grants and RLS | No |

The allowlist is the simplest option. It needs no key management and no new database object,
it is pure data that a unit test can exercise, and adding an approval is an ordinary reviewed
release change. A signature or table can supersede it in a later ADR if adopters need approvals
without a release.

## Decision

Adopt option D with a release-shipped approval allowlist, subject to the invariants below.

### Authority split

| Input | Owner | Source |
| --- | --- | --- |
| Descriptor file (`registryVersion`, `descriptors`) | Adopter (untrusted) | Configuration |
| `composition` (`read-only` or `application`) | Server code | `CapabilityServerPolicy`, chosen by the composition root |
| `adopterSchemas` (at most 8) | Server operator | `CapabilityServerPolicy` |
| `approvals` (release allowlist) | Release reviewers | **Not implemented in this commit.** No loader exists; the validator receives a parsed object from its caller. See "Required loader design" and Follow-up |

`validateCapabilityRegistry(input, policy)` takes the policy as a separate parameter. A
descriptor file that contains `composition` or any other extra field is rejected.

### Security invariants

1. **Finite allowlist.** At most `MAX_REGISTERED_CAPABILITIES` (16) descriptors, loaded at
   process start. There is no runtime discovery, hot reload, or adding tools from tool output
   or database content. "Loaded at process start, no hot reload" is a property the future
   composition root must provide. It is not enforced by the pure validator, which can be called
   at any time.
2. **Deny-by-default.** `resolve(name)` returns a descriptor only for a listed name. Everything
   else, including prototype keys, is `undefined`.
3. **Atomic validation.** An invalid policy, or any invalid descriptor, rejects the whole
   registry. The server then starts with only its fixed tools.
4. **Separate namespace.** Names match `^app_[a-z][a-z0-9_]{2,47}$`, are never a fixed tool name,
   and are unique. Each `schema.function` target appears at most once.
5. **Bounded kinds, chosen by the server.** Only `read` and `proposal` exist. When the server
   passes `composition: 'read-only'` (today's server), anything that isn't `read` is rejected.
   `proposal` is accepted only when server code passes `'application'`. There is no approval,
   admin or write kind. Adding one requires a new ADR.
6. **Adopter schema allowlist.** `rpc.schema` must be in the server's `adopterSchemas`.
   Defence in depth: a descriptor or policy naming `public`, `auth`, `storage`, `vault`,
   `realtime`, `extensions`, `net`, `cron`, `pgbouncer`, `information_schema`, `supabase`,
   `tiger`, `tiger_data` or `topology`, any schema starting with `graphql`, `pg` (including
   `pgsodium*`, `pgmq*`, `pgtle`), `supabase`, `auth`, `storage`, `vault`, `realtime`, `net` or
   `cron`, or any schema with a leading `_`, is rejected. `public` is refused with no opt-in in v1: Supabase default grants
   and stray helper functions accumulate there, so a reviewed `public.*` surface would depend on
   everything later added to `public`. Adopters use a dedicated schema.
7. **Closed input envelope.** A flat JSON object with `additionalProperties: false` and at most 16
   arguments: bounded strings (length, optional enum), bounded integers or booleans. v1 has no
   regex `pattern`, so no model-supplied string is ever matched against a descriptor regex.
   An argument name is rejected if it contains a forbidden substring
   (`FORBIDDEN_ARGUMENT_SUBSTRINGS`, for example `token`, `auth`, `role`, `owner`, `tenant`,
   `session`, `passw`, `user`, `approv`), or if any `_`-separated token is a forbidden token or
   synonym (`FORBIDDEN_ARGUMENT_TOKENS`, `FORBIDDEN_ARGUMENT_SYNONYMS`, for example `uid`, `key`,
   `pwd`, `email`, `scope`, `host`, `path`). String
   argument bounds must be consistent (`minLength` ≤ `maxLength`, enum values unique, within the
   bounds and free of control characters). At call time, extra keys are rejected, never stripped.
8. **Bounds.** `limits.maxResponseBytes` ≤ 65,536 and `limits.timeoutMs` ≤ 2,000. This is
   static validation only. Runtime enforcement (abort, oversize as failure) is future work.
9. **Approval is external; the in-file link is integrity only.** Each descriptor carries
   `approval: { adr, bodySha256 }`. The validator checks that `bodySha256` equals the canonical
   sha256 of the body (`descriptor_digest_mismatch` otherwise), and that the pair
   `(adr, bodySha256)` is present in the `approvals` allowlist passed in the caller's policy
   (`descriptor_not_approved` otherwise). This commit has no allowlist loader: where that
   allowlist comes from, and whether it is really release-shipped and non-writable, is future
   work governed by "Required loader design". The policy is snapshotted once, so mutating it or
   its getters during or after validation cannot change the decision.
10. **Reviewable text and strict input.** Title, description and enum values reject Unicode
    `Cc`, `Cf`, `Zl` and `Zp` characters (controls, bidi overrides, zero-width, line separators).
    Input is snapshotted once with `structuredClone`, so getters run once and functions are refused,
    and any own `__proto__` key at any depth is rejected rather than silently dropped. Length is
    checked before the character scan, and an oversized `descriptors` array is rejected before it
    is copied.

### What is and is not enforced

Enforced by the contract (offline, at startup), **assuming the caller supplies a trustworthy
policy**. The validator checks the policy's shape, not its provenance:

- Editing a descriptor body and recomputing its digest in the file fails as
  `descriptor_not_approved` unless that exact digest and ADR are in the release allowlist.
- A descriptor file cannot select `application`, add a schema, or reference an unapproved ADR.

Not enforced by the contract:

- That the allowlist was really reviewed. It is as trustworthy as the release process and the
  file permissions of the installed release. If an attacker can write the release files, the
  boundary is gone.
- That the referenced ADR is Accepted. The ADR id is a label recorded by release reviewers.
- That the RPC actually behaves as reviewed. The database stays authoritative, and the digest
  covers the descriptor, not the RPC body.
- Runtime limits, credential handling, routing and error mapping, which are future work.
- Where the approval allowlist comes from. No loader exists in this commit, so location,
  permissions and fail-closed loading are not enforced yet (see "Required loader design").
- That the author is not the reviewer. This is a process rule (CODEOWNERS and branch protection),
  not something code enforces.
- No hot reload. A pure function can be called at any time; this is a future composition-root
  property.

### Required loader design (future PR)

The approval allowlist is the sole approval authority, so whoever controls where it is loaded
from controls approval. An approval file that the service or agent can write is just another
configuration document. The future loader MUST use one of these two designs:

1. **Embed the allowlist in the build (preferred).** Compile it into a generated TypeScript module
   whose digest is recorded in the release or tag. There is no runtime path, no environment
   override and no working-directory lookup.
2. **A fixed absolute path only**, with no environment or flag override, preferably on a read-only
   mount. The loader refuses to load, failing closed to the fixed tools, if any of these holds:
   - the file, or any parent directory, is writable by the effective uid or gid, or is group- or
     world-writable;
   - the owner is not root or a dedicated release user;
   - the path is a symlink (open with `O_NOFOLLOW`, then `fstat`).

In both designs:

- The server logs the allowlist's sha256 at startup, so an out-of-band change is visible.
- The allowlist is never loaded from the repository working tree at runtime.
- Any change to the allowlist needs at least one reviewer other than the author, enforced by
  CODEOWNERS on the allowlist plus branch protection. That is the human approval, enforced
  outside the agent.

### Descriptor fields (v1)

Body: `descriptorVersion`, `name`, `title`, `description`, `kind`, `rpc.schema`, `rpc.function`,
`inputSchema`, `limits.maxResponseBytes`, `limits.timeoutMs`. Wrapped as `{ body, approval }`.
The descriptor file is `{ registryVersion, descriptors }`. The allowlist is
`{ allowlistVersion, approvals: [{ adr, bodySha256 }] }`. All objects are strict.

### Versioning

Descriptor, registry and allowlist carry literal version strings
(`supabase-user-mcp.capability-descriptor.v1`, `supabase-user-mcp.capability-registry.v1`,
`supabase-user-mcp.capability-approvals.v1`). An unknown version is rejected. Any change that
widens authority (new kind, argument type, `pattern`, schema family or bound) is a new major
version and needs a new ADR. Narrowing changes may be minor.

### Failure, revocation, cancellation and rollback (for the future implementation)

- **Fixed routing:** a `read` capability will be called as a PostgREST GET (read-only
  transaction), and a `proposal` as a POST, so the `read` label is enforced by the database
  transaction mode, not just declared. The method and path are fixed by the server.
- **Failure:** each failed call maps to the existing fixed error envelope. Raw database errors,
  schema names and function names are never echoed to the model.
- **Revocation:** database-side revocation (grant removal, RLS, function drop) takes effect on the
  next call. Removing a descriptor or allowlist entry takes effect on restart.
- **Cancellation and timeouts:** the request is aborted at `limits.timeoutMs` or on client
  cancellation, and no result is returned after an abort.
- **Credential rotation:** each call reads the current verified caller credential. Concurrent
  users never share a credential or a cached result.
- **Rollback:** remove the descriptor file (or set `descriptors` to `[]`) and restart. The server
  reverts to the fixed tool set with no data migration.

### How a future surface gets approved

1. The adopter writes the RPC, with its RLS and grants, in a dedicated adopter schema, plus a
   descriptor.
2. A reviewer (author ≠ reviewer, a process rule enforced by CODEOWNERS and branch protection,
   not by code) checks the descriptor against these invariants and the RPC's authorization.
3. The approved `(adr, bodySha256)` pair is added to the release allowlist in a reviewed release
   change, and the operator lists the adopter schema in the server policy.
4. At startup the validator enforces digest, approval, schema, bounds and composition.
5. Any wider kind, argument type or schema family requires a new ADR, not a configuration change.

## Consequences

### Positive

- One finite authority surface per deployment, pinned by digests that only a release can approve.
- Domain logic stays in the database. The connector carries no application rules.

### Negative

- Every new or changed capability needs a release to update the allowlist.
- Scalar-only inputs without `pattern` rule out nested or regex-shaped inputs until a later ADR.
- Substring and token argument-name rejection can refuse harmless names (for example `sort_key`,
  `author_note` or `factor`).

### Follow-up

- Accept or revise this ADR (independent review, architecture review, Primary Users decision).
- Only then, in a separate PR: an exported registration adapter, an optional composition hook,
  the allowlist loader built to "Required loader design" (with a startup sha256 log line and
  CODEOWNERS on the allowlist), and the synthetic test matrix listed
  in #122 (SDK round trip, rotation, isolation, cancellation, oversize, read-only denial).

## Validation

`packages/contracts/src/capability-registration.test.ts` (offline, synthetic) covers: empty
registry, approved read registration, deny-by-default lookup, the finite bound, reserved and
non-prefixed names, collisions, absent approval/admin/write kinds, self-attested edits rejected
by the release allowlist, unlisted ADR references, digest mismatch, strict allowlist parsing,
server-selected composition (a file declaring `application` is rejected), invalid policy,
the schema allowlist with `public` and platform-schema refusal, absence of `pattern`,
substring, token and synonym argument names, further platform schemas, string-bound
consistency, own `__proto__` keys, unreviewable Unicode, length checked before the character
scan (asserted by spying on the scan), single-read input snapshotting, policy snapshotting
against getters and later mutation, oversized arrays rejected before copying, closed call-time
arguments, and that nothing is exported from the package index or imported by any server file.

## Revisit when

- #77 or #73 lands and changes how capabilities are declared or shown.
- Adopters need approvals without a release (consider a signature or a server-only table).
- An adopter needs a kind, argument type, `pattern` (with a linear-time engine) or bound outside v1.
- ADR-0002 changes how the remote credential chain works.

## References

- Issue #122 and its assignment comment.
- ADR-0002, ADR-0003, ADR-0004.
