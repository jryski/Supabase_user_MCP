# Issue #70: Isolated deployment control-plane tools

- **Status:** Unmerged candidate; live catalog verified and deployment acceptance incomplete
- **Date:** 2026-09-13
- **Base reviewed locally:** `9b08821a3860d0455538c9febb40ff4e4bb15948`
- **Data:** Synthetic fixtures only

## Implemented candidate

- Strict `create_work_item` and `post_model_message` contracts.
- Required board-scoped idempotency key for work creation.
- Fixed PostgREST RPC paths and fixed `planning` or `public` profile headers.
- Server-configured agent attribution, absent from tool inputs.
- Separate privileged MCP server with exactly two tools.
- No privileged tools added to the accepted user-context read-only server or CLI.
- Bounded metadata, bodies, execution time, responses, and request IDs.
- Bounded ASCII identifiers in public inputs and model-visible receipts.
- Normalized model-visible errors and payload-free operational events.

## Direct-DML containment

The client contains only these mutation paths:

```text
/rest/v1/rpc/create_work_item
/rest/v1/rpc/post_model_message
```

The public schemas reject `sql`, `schema`, `table`, `url`, `method`, credentials, roles, principals,
senders, and source-agent fields. Tests inspect both exact request URLs and request bodies. No retry
is performed by the client or governor.

## Deterministic test evidence

Focused command:

```shell
npm run test -- packages/contracts/src/control-plane-tools.test.ts \
  packages/server/src/control-plane-client.test.ts \
  packages/server/src/control-plane-server.test.ts
```

Result after final hardening: 3 files passed, 15 tests passed.

Full command:

```shell
npm run check
```

Result after rebasing onto the refreshed GitHub `origin/main`:

- formatting passed;
- lint passed;
- TypeScript build and test typecheck passed;
- 35 test files passed and 1 skipped;
- 706 tests passed and 4 skipped.

The skipped tests are existing environment-gated tests. This slice did not convert a failure into a
skip.

## Covered behaviors

- Planning defaults match the live table constraint vocabulary reported by Supabase metadata.
- Duplicate concurrent work requests preserve the same board and idempotency key and accept the
  database's original receipt.
- An omitted database creation flag stays omitted; the adapter does not invent a creation outcome.
- Distinct concurrent work and message calls remain independent and accept unique database-assigned
  numbers.
- Invalid board and reply references map to stable non-leaking errors.
- MCP registration exposes exactly two tools and rejects generic database controls before invoking
  the privileged client.
- The accepted read-only server's existing exact-three-tool registration test still passes.

## Live verification findings and remaining gaps

- Both live functions are owned by `postgres`, use `SECURITY DEFINER`, set a fixed `search_path`, and
  return `jsonb`.
- Their explicit ACLs contain only `postgres` and `service_role`. Direct privilege checks confirmed
  EXECUTE for those roles and denial for `PUBLIC`, `anon`, and `authenticated`.
- `planning.create_work_item` returns `item_id`, `item_number`, `item_key`, `created`, `status`, and
  `title`. The fixed adapter was aligned to `item_id` and sends configured agent attribution as both
  source and creator.
- `public.post_model_message` returns `id`, `seq`, `from_agent`, and `to_agent`; the adapter emits the
  bounded `id` and `seq` receipt.
- The 2026-09-13 VAULT security-advisor run did not flag either new function for mutable
  `search_path` or anonymous `SECURITY DEFINER` execution. That is useful negative evidence, but it
  does not replace direct catalog and role-execution checks.
- Database settings did not expose the PostgREST schema list to the catalog session. Custom
  `planning` schema exposure therefore remains unverified.
- `service_role` retains direct table DML on planning and model-channel relations. Direct-DML
  avoidance is enforced by this MCP's fixed routes, not by removing the credential's database
  authority.
- No live mutation, production data, private fixture, deployment, or Ariadne runtime was used.
- Concurrency and idempotency tests prove adapter behavior against deterministic synthetic
  PostgREST responses. They do not independently prove the live PostgreSQL lock implementation.

## Required acceptance follow-up

1. Verify that PostgREST exposes the custom `planning` schema to the isolated deployment profile.
2. Run service-role success and `anon`/`authenticated` denial tests with synthetic rows in a safe
   test board or local database.
3. Run concurrent database calls and verify one work-item identity per idempotency key plus unique
   item/message numbering.
4. Disposition relevant security-advisor findings and retain the result with the acceptance
   evidence.
5. Prove Ariadne can invoke the two MCP tools without raw SQL.
6. Freeze an exact commit and obtain independent review.
