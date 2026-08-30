# Issue #17: principal-bound read-path acceptance

## Scope

This branch advances the M2 read-only path from registered MCP tools to a real synthetic authorization chain:

`MCP client -> read-only server -> fixed Supabase client -> Data API -> memory RPC -> PostgreSQL RLS`

It does not deploy to a hosted project, use production data, add write authority, or merge itself.

## Identity and authority boundary

The exposed Data API schema is `memory`. It contains only three versioned RPCs:

- `authorized_memory_search_v1`
- `authorized_memory_get_v1`
- `authorized_memory_list_recent_v1`

All three are `SECURITY INVOKER`. Their signatures contain no principal, client, token, origin, schema, relation, path, or method parameter. The calling principal comes from `auth.uid()` and the approved client context comes from the verified JWT `app_metadata.client_id` claim. PostgreSQL RLS remains the final record-visibility boundary.

The underlying synthetic records remain in `policy_lab.memories`; the `memory` schema does not expose a general table, generic PostgREST request, arbitrary RPC selector, or write operation.

## Synthetic acceptance matrix

`supabase/tests/database/memory_rpc_test.sql` pins:

- exact invoker mode and execute grants;
- absence of identity or transport authority in RPC arguments;
- permitted-principal positive reads;
- cross-principal non-enumeration;
- active capability intersection;
- revoked-client denial;
- missing-client denial;
- bounded recent ordering;
- bounded search and cursor resumption;
- invalid-cursor denial; and
- anonymous execute denial.

The existing policy-lab suite continues to cover expired/revoked memberships and grants plus deliberate rollback-only policy weakening.

## Real local Auth path

`supabase/tests/run-m2-memory-lab.sh` starts only the pinned loopback Supabase lifecycle, resets synthetic migrations/fixtures, runs the database matrices, mints real local GoTrue sessions, and runs `packages/server/src/m2-local-e2e.test.ts`.

The TypeScript suite loads bearer material from mode-0600 temporary credential files, creates the fixed client, and uses `StreamTransport` with a real MCP `Client`. A trusted test-only fetch adapter rewrites the fixed virtual HTTPS origin to the loopback local Supabase API; no tool argument can choose or alter that destination.

The end-to-end cases prove:

- Alice can read/search/list only Alice workspace records;
- Bob can read only Bob workspace records;
- an attempted `principalId` tool argument is rejected by the closed schema;
- a revoked client and a missing-client session fail closed;
- hostile stored text is rendered only behind the unconditional untrusted-data boundary; and
- a malformed bearer is rejected before governed data is returned.

## Receipt

A successful M2 harness emits one secret-free JSON receipt binding:

- repository SHA;
- pinned Node, npm, and Supabase CLI versions;
- named acceptance case IDs; and
- overall pass status.

The receipt deliberately excludes JWTs, publishable keys, credential-file paths, stored content, host identifiers, and private payloads. It proves only the synthetic test execution at that SHA.

## Claim limits

This is authorization-path evidence, not a production deployment claim. The local policy lab is synthetic. The `semantic` search mode uses the same deterministic lexical fixture behavior as `text` so the authorization path can be exercised without introducing an embedding provider; this branch does not claim semantic-search quality.

Real deployment still requires deployment-specific schema mapping, issuer/resource configuration, operator credential provisioning, independent exact-head review, and a separate promotion decision. No service-role or `BYPASSRLS` identity is accepted as read-path evidence.
