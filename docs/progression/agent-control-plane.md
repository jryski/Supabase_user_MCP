# Agent control-plane progression

This is the repository mirror of the durable VAULT progression page. Entries are append-oriented
and dated in America/Detroit. Repository evidence and live database evidence retain their own
authority; this narrative does not make an implementation complete.

## 2026-09-13: Dogfood failure exposed the missing layer

While preparing the WireSpeed website migration, ChatGPT could read VAULT planning state but could
not create board items or post to `model_channel`. PostgreSQL permission errors did not occur. The
connector blocked side-effecting SQL before it reached the database.

Decision: stop treating raw SQL as a portable cross-agent interface. Add bounded database functions
and expose them as explicit MCP capabilities.

Database milestone reported and partly reverified:

- Migration `20260913152459_add_bounded_planning_and_model_channel_write_rpcs` is present.
- Generated public-schema types expose `post_model_message(p_body, p_from_agent, p_re_seq,
  p_subject, p_to_agent)` returning JSON.
- The custom `planning.create_work_item` signature is not included in generated public-schema
  types and still requires catalog verification.

Failure: the ChatGPT SQL connector also blocked invoking a mutating function through SQL. This
confirmed that the durable fix belongs at the explicit MCP capability layer.

## 2026-09-13: Preliminary implementation rejected as architecture

The first untracked contract file was reviewed before reuse. It had no client or MCP registration,
used status and item-kind values that do not match live constraints, exposed caller-controlled
authority and sender fields, assumed an incompatible opaque ID shape, allowed unbounded metadata,
and had no stable error or response boundary.

Decision: replace the file rather than extend it.

## 2026-09-13: Affected systems bounded before further edits

The implementation owner is `Supabase_user_MCP`. VAULT owns the deployment functions, planning
state, model channel, and durable progression copy. HOUSE is inventory-only and receives no writes.
`Household_os_private` may receive a later private cross-reference, and `sovereign-memory-core`
still has raw-SQL operational guidance that may need a later correction. No dependency was found in
`sovereign-memory-protocol` or Hermes.

Decision: do not broaden this work into Household OS redesign or cross-store unification.

## 2026-09-13: Privileged profile isolated

The accepted user-context read server explicitly forbids a master key in its request path. The new
VAULT functions are service-role operations. Co-registering them would violate the current security
thesis.

Decision: create a separate privileged control-plane server and client. Keep the production
read-only CLI unchanged. Do not add a privileged credential loader in this slice.

Implementation milestone:

- Added strict contracts for `create_work_item` and `post_model_message`.
- Required board-scoped idempotency for work creation.
- Removed sender, source-agent, principal, role, SQL, schema, table, URL, and method selection from
  tool inputs.
- Added fixed PostgREST RPC paths and schema profiles.
- Added bounded execution, normalized errors, operational events, and separate tool registration.
- Added deterministic tests for idempotency-key preservation, concurrent calls, invalid board and
  reply handling, direct-DML avoidance, and public MCP registration.
- Focused result after final hardening: 15 tests passed after a successful TypeScript build.
- Final review removed an inferred `created: true` result when the database omits that field and
  restricted public identifiers to a bounded ASCII grammar.

Repository verification milestone:

- Formatting and lint passed.
- TypeScript build and test typecheck passed.
- GitHub `origin/main` refreshed to `9b08821a3860d0455538c9febb40ff4e4bb15948`.
- The candidate rebased onto that head after preserving upstream evidence-index and export additions.
- 35 test files passed and 1 existing environment-gated file remained skipped.
- 706 tests passed and 4 existing environment-gated tests remained skipped.

Database metadata milestone:

- A VAULT security-advisor run did not list either new function among mutable-search-path findings
  or anonymously executable `SECURITY DEFINER` findings.
- Direct catalog checks verified both functions are owned by `postgres`, use `SECURITY DEFINER`,
  have fixed search paths, and grant EXECUTE only to `postgres` and `service_role`.
- `PUBLIC`, `anon`, and `authenticated` do not have EXECUTE on either function.
- The work-item adapter was corrected to accept the live `item_id` receipt and to set configured
  agent attribution as both source and creator.
- The service role still has direct DML on the underlying deployment tables. The fixed MCP route is
  therefore the application containment boundary.

Durable documentation milestone:

- Published the capability catalog at
  `projects/sovereign-ai-os/control-plane/capability-catalog`.
- Published the decision at
  `projects/sovereign-ai-os/decisions/2026-09-13-agent-control-plane`.
- Published the running progression at `projects/sovereign-ai-os/control-plane/progression`.
- Superseded the existing `projects/sovereign-ai-os/chronicle` page with a new active version that
  appends the fifth field note and links to its predecessor.

Gateway verification milestone:

- Anonymous REST probes with both current public key forms received HTTP 401 before schema routing;
  VAULT requires a service-role or secret key at the gateway.
- The probes made no RPC call. They do not verify custom `planning` schema exposure for the
  privileged deployment profile.

Open verification gates:

- Verify PostgREST exposure of the custom `planning` schema.
- Exercise both RPCs through the isolated deployment profile with synthetic rollback-safe data.
- Prove an Ariadne runtime invocation before claiming coordinator readiness.

## 2026-09-13: Tooling failures recorded

Two read/refresh actions were rejected by the approval layer because an internal request ID did not
match the expected format. The failures occurred before `session_boot()` reached VAULT and before
`git fetch` reached GitHub. These are access-path failures, not evidence about database or remote
repository state.

The Supabase changelog markdown endpoint also returned an unsupported-content response through the
web reader. The searchable changelog was used instead. The relevant 2026 Data API change requires
explicit grants for exposed functions and reinforces the need to verify ACLs rather than infer them
from RLS alone.
