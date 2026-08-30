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

Cross-principal denial is checked against the complete response for a well-formed nonexistent record. Both return the same `{"record": null}` JSON object so authorization cannot reveal whether a record exists outside the caller's workspace.

## Searchable-field contract

The `query` argument performs deterministic case-insensitive substring matching over memory `title` and `content` only. Tags are not free-text query material; callers constrain tags through the closed `filters.tags` field. The synthetic `semantic` mode deliberately uses this same title/content lexical behavior so the authorization path can be exercised without claiming semantic-search quality.

The existing policy-lab suite continues to cover expired/revoked memberships and grants plus deliberate rollback-only policy weakening.

## Repair rationale at Ariadne takeover

PR #40's first exact-head M2 run reached PostgreSQL and failed four pgTAP expectations rather than implementation behavior:

1. Tests 8, 19, and 20 expected SQL `NULL`, but `jsonb_build_object('record', <empty scalar subquery>)` intentionally serializes a present JSON key with the JSONB value `null`. The corrected expected literal is `'null'::jsonb`; the RPC remains unchanged.
2. The cross-principal assertion now also compares the complete denied response with the complete response for a well-formed nonexistent record. This proves non-enumeration instead of checking only the `record` member.
3. Test 11 expected two lexical `network` matches. Only `mem_01JTESTALPHA000000000001` contains `network` in title/content; `mem_01JTESTALPHA000000000003` carries it only as a tag. Under the documented title/content query contract the correct count is one, and the TypeScript end-to-end expectation is corrected to the same single ID.
4. Because PR #40 is stacked on unmerged PR #38, exact-head CI now passes and records the pull-request base SHA as well as the head SHA. This binds acceptance to the reviewed stack coordinate.
5. The first repaired CI run advanced past 91 database tests and exposed a fresh-checkout harness gap: the focused M2 Vitest command could not resolve workspace package exports before compiled output existed. The M2 harness now runs the existing workspace build before focused Vitest; package exports and application behavior remain unchanged.
6. Warden review seq. 783 identified that recording a 40-hex base value did not prove it belonged to the accepted head. Exact-head CI now fetches full history, requires the base commit to exist, and requires `git merge-base --is-ancestor` before the base is emitted in a passing receipt.
7. The same review identified that `export TOKEN="$(mint_token ...)"` masks command-substitution failure behind the successful `export` builtin. Each token is now assigned before export so `set -e` observes mint failure, and the harness positively requires all four tokens to be non-empty before focused E2E Vitest. The local test suite may still skip without harness variables; the M2 acceptance harness cannot silently do so.

No migration, seed, RLS policy, ACL, RPC, MCP server, credential, or production source behavior is changed by this repair.

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
- stacked pull-request base SHA when supplied by exact-head CI;
- pinned Node, npm, and Supabase CLI versions;
- named acceptance case IDs; and
- overall pass status.

The receipt deliberately excludes JWTs, publishable keys, credential-file paths, stored content, host identifiers, and private payloads. It proves only the synthetic test execution at that SHA.

## Producer provenance

The original PR #40 commits are authored under Jesse's GitHub identity, but the implementation agent/model attribution was not durably captured before Ariadne took over SAOS-0013; that prior producer model remains unknown. Ariadne's expectation/evidence repair was coordinated with GPT-5.6 Sol. A bounded Locutus Qwen3.8 read-only diagnosis completed at the runtime level but returned no final analysis and contributed no accepted code or conclusion.

## Claim limits

This is authorization-path evidence, not a production deployment claim. The local policy lab is synthetic. The `semantic` search mode uses the same deterministic lexical fixture behavior as `text` so the authorization path can be exercised without introducing an embedding provider; this branch does not claim semantic-search quality.

Real deployment still requires deployment-specific schema mapping, issuer/resource configuration, operator credential provisioning, independent exact-head review, and a separate promotion decision. No service-role or `BYPASSRLS` identity is accepted as read-path evidence.
