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
  packages/server/src/control-plane-server.test.ts \
  packages/server/src/post-model-message-migration.test.ts
```

Result after the identity-allocation repair: 4 files passed, 18 tests passed.

Full command:

```shell
npm run check
```

Result after rebasing onto the refreshed GitHub `origin/main`:

- formatting passed;
- lint passed;
- TypeScript build and test typecheck passed;
- 36 test files passed and 1 skipped;
- 709 tests passed and 4 skipped.

The skipped tests are existing environment-gated tests. This slice did not convert a failure into a
skip.

## Covered behaviors

- Planning defaults match the live table constraint vocabulary reported by Supabase metadata.
- Duplicate concurrent work requests preserve the same board and idempotency key and accept the
  database's original receipt.
- An omitted database creation flag stays omitted; the adapter does not invent a creation outcome.
- Distinct concurrent work and message calls remain independent and accept unique database-assigned
  numbers and message IDs.
- Invalid board and reply references map to stable non-leaking errors.
- The reviewed database migration omits the generated identity column from the insert and returns
  the generated `id` and `seq` from the stored row.
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
- Pre-change evidence showed `model_channel.seq` as a `bigint GENERATED ALWAYS` identity backed by
  `public.model_channel_seq_seq`. The function nevertheless took an advisory lock, computed
  `max(seq) + 1`, and explicitly inserted `seq`. A live review-request call therefore failed with
  PostgreSQL `428C9`. The table maximum and identity-sequence last value were both 1106 at that
  failure, and no message was inserted.
- Migration `20260913175421_repair_post_model_message_identity_allocation` replaced that body. The
  insert now omits `seq`, and `returning id, seq` captures PostgreSQL's generated values. Required
  field checks and optional `re_seq` validation remain in place.
- A service-role exercise returned UUID `e65c0fd2-f583-4aed-83d7-4c7a94b3cbe2` and sequence 1108.
  An exact-subject check found one row, both receipt fields matched the stored row, and the identity
  sequence advanced from 1107 to 1108. The invalid-`re_seq` probe created zero rows.
- The repaired live function remains owned by `postgres`, uses `SECURITY DEFINER`, has
  `search_path=pg_catalog, public`, and grants EXECUTE only to `postgres` and `service_role`.
- The 2026-09-13 VAULT security-advisor run did not flag either new function for mutable
  `search_path` or anonymous `SECURITY DEFINER` execution. That is useful negative evidence, but it
  does not replace direct catalog and role-execution checks.
- Database settings did not expose the PostgREST schema list to the catalog session. Custom
  `planning` schema exposure therefore remains unverified.
- Read-only REST probes with the current legacy anonymous and publishable keys both stopped at the
  VAULT gateway with HTTP 401 responses requiring a service-role or secret key. They made no RPC
  call and do not establish whether the `planning` schema is exposed to the privileged profile.
- `service_role` retains direct table DML on planning and model-channel relations. Direct-DML
  avoidance is enforced by this MCP's fixed routes, not by removing the credential's database
  authority.
- No live mutation, production data, private fixture, deployment, or Ariadne runtime was used.
- Concurrency and idempotency tests prove adapter behavior against deterministic synthetic
  PostgREST responses. They do not independently prove the live PostgreSQL lock implementation.

## Durable VAULT documentation receipts

| Path | UUID | Content SHA-256 |
| --- | --- | --- |
| `projects/sovereign-ai-os/control-plane/capability-catalog` | `7c9dcad4-eee7-48da-a09d-66a707330c3e` | `f05bb4be3dc4370974d57b01a2dbbd74570766d8e062233cd3a45402865dab57` |
| `projects/sovereign-ai-os/decisions/2026-09-13-agent-control-plane` | `e7700964-abf1-45b5-a149-ac4a9959c7f2` | `f17dcae97258965c391ff53a28c6393e32fa660d98d0b7dff0c4c424b6a975f4` |
| `projects/sovereign-ai-os/control-plane/progression` | `72d7069f-c1b8-4b26-bdf0-482e82a90f85` | `bfe79983a826edd09eaa134ec6bac64b9bd0ef7bafdbe995fd98e9663b3ad9b1` |
| `projects/sovereign-ai-os/chronicle` | `fae5bea8-02d9-42af-b634-22a5703bd955` | `6445746a86b0607d0627f7669d73c77acb3d46664ef701e8b92c77282d7ec815` |

The catalog, progression, and Chronicle receipts supersede the versions that recorded the 428C9
blocker. Those predecessors remain stored with `superseded` status and archived paths. The active
versions append the correction and retain the original failure narrative.

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
