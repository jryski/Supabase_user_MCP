# Issue #123 S4: Storage RLS (option A)

- **Status:** Draft. Assumes option A; pending RLS layout decision.
- **Base:** `04efff32` (S2 user-scoped storage client)
- **Production runtime authority change:** none. The migration is for the local lab.

## What S4 adds

- `supabase/migrations/20261027000100_storage_option_a.sql`:
  - extends the grant CHECK with `storage:read` and `storage:write`;
  - adds the SELECT policy `storage_grant_is_active_context` so a caller sees its own active storage
    grants under the same predicate as `grant_is_active_context`;
  - adds `policy_lab.storage_delegations` (agent, human, client, capabilities, state, expiry) with
    CHECK constraints, a kind guard trigger, forced RLS, and SELECT-only access for the agent itself;
  - adds SECURITY INVOKER functions `storage_has_capability`, `storage_principal`,
    `storage_session_capabilities`, `storage_relative_key_ok`, `storage_object_prefix`, and
    `storage_object_allowed`, each with
    `search_path = ''`, revoked from `PUBLIC` and `anon`;
  - creates the private bucket `mcp-user-storage` with the S1 size and MIME limits;
  - adds SELECT, INSERT, and DELETE policies on `storage.objects` for `authenticated` only.
- `supabase/migrations/20261027000200_storage_delegation_human_grant.sql` (additive follow-up):
  - adds the SELECT policy `storage_delegator_grant_is_active_context`, so a delegated agent sees
    its human's active storage grants, only through the delegation's client and only for the
    capabilities the delegation lists;
  - replaces `storage_has_capability` with the same body plus one check: for a delegated agent,
    the human must also hold an active grant for the same capability through the same client.
- `supabase/tests/database/storage_option_a_test.sql`: 78 pgTAP assertions, no psql meta-commands.
  Deletes go through the hosted Storage delete guard (see below).
- `test/support/pglite-supabase-stub.ts`: the synthetic Supabase stub used for local SQL runs,
  including a copy of the hosted Storage `protect_delete` trigger.
- `test/storage-protect-delete-stub.test.ts`: the stub refuses a bare delete and allows a flagged
  one, scoped by RLS.
- `test/policy-lab/storage-option-a-contract.test.ts`: static checks, including byte pins for the
  grant-check invariant migrations.
- `test/storage-option-a-e2e.test.ts`: end-to-end run in PGlite. The real storage tools and the
  real user-scoped client talk to a small in-process stand-in for the Storage API and the Data
  API, which runs each request as `authenticated` with the caller's claims, so RLS decides. It
  covers 2 humans on 2 clients and 1 delegated agent: allow, cross-principal and overwrite
  denials, the agent capped by its human's grant, revocation, expiry, signed URLs that stay
  valid after revocation until they expire, and cleanup through the delete guard.

## Hosted delete guard

Hosted Storage refuses a direct SQL `DELETE` on `storage.objects` or `storage.buckets` with
error `42501` unless the transaction sets `storage.allow_delete_query` to `true`. The Storage API
sets it for its own deletes. The pgTAP file now:

1. asserts that a bare delete is refused (skipped when the trigger is not installed);
2. sets the flag, then asserts that deleting another user's object removes 0 rows and deleting
   the caller's own object removes exactly 1 row;
3. clears the flag and asserts that the guard applies again.

Before this change the file aborted at its first delete when the trigger was present.

## Revocation and signed URLs

Revoking a grant, a delegation, or a client takes effect on the next statement. It does **not**
cancel signed URLs that were already issued. A signed URL stays valid until it expires (60 seconds
under the S1 bounds), even after revocation. Deleting the object is the only way to stop an
issued URL from returning content before it expires.

## Open: agent sub-prefix

Agents write under the human's prefix. A `<human>/agents/<agent>/` sub-prefix is still open. The
choice is kept in one function, `policy_lab.storage_object_prefix()`.

## Threat and invariant mapping

| Threat                            | Control                               | Test                                            |
| --------------------------------- | ------------------------------------- | ----------------------------------------------- |
| Another user's prefix             | prefix equals `storage_principal()`   | user_a and agent_a put/list against user_b      |
| Look-alike prefix                 | exact `<uuid>/` match                 | `look-alike prefix denied`                      |
| Path escape or active type        | key-shape and extension check         | key cases, `path escape denied`                 |
| Cross-client token                | client claim in grant and delegation  | cross-client rows                               |
| Agent overreach                   | own grant and delegation capabilities | agent_b write denied                            |
| Agent outlives human's grant      | human's active grant, same client     | `expired human grants` rows                     |
| Revocation                        | state and expiry read per statement   | revoked delegation, read grant, expired grants  |
| Denied or non-human principal     | kind and eligibility check            | denied principal, service agent                 |
| Missing or top-level client claim | only `app_metadata.client_id`         | missing and top-level claim rows                |
| Anonymous caller                  | no anon policy or EXECUTE             | anon rows                                       |
| Overwrite or move                 | no UPDATE policy                      | rename has no effect                            |
| Grant-check drift                 | invariant files unchanged             | `has_active_capability is unchanged`, byte pins |

## Validation run here

- `npm run check` (format, lint, typecheck, vitest).
- The pgTAP file was run in PGlite with the repository stub, after all repository migrations:
  78 of 78 passed with the delete guard installed. Without the guard, 76 passed and the 2 guard
  assertions were skipped. Without the follow-up migration, the 5 human-grant assertions failed.
- `npx vitest run test/storage-option-a-e2e.test.ts`: 7 of 7 passed. Without the follow-up
  migration, the human-grant scenario failed.
- The stand-in is not the hosted Storage API. It models only the routes the client calls.
- `supabase test db` was not run: it needs Docker and a local Supabase stack.

## Review items

1. **`policy_lab` is not exposed in `supabase/config.toml`.** Still open. The client calls the
   two RPCs in `policy_lab`, so storage tools stay unreachable over HTTP until this is decided.
   Exposing the schema would also expose its tables over the Data API (under RLS). The narrower
   choice is two wrapper functions in an already exposed schema, with a matching client change.
   This needs a decision, so it is not changed here.
2. **The capability CHECK is widened** by `storage:read` and `storage:write` only. Kept. A contract
   test pins the exact list.
3. **The additive `storage_grant_is_active_context` policy** is kept as is. It has the same
   predicate as `grant_is_active_context`, limited to the two storage capabilities. The memory
   policy and `has_active_capability` are unchanged; a pgTAP assertion pins the latter by digest.
4. **Agent access did not check the human's own grants.** Addressed by the follow-up migration.
   An agent now needs its own grant, an active delegation that lists the capability, and the
   human's active grant for that capability through the same client. The human's membership and
   identity eligibility are still not re-checked on the agent path; that remains open.

## Rollback

Drop `storage_delegator_grant_is_active_context`, then the three `storage.objects` policies, the
bucket, the functions, the delegation table, and `storage_grant_is_active_context`, and restore the
two-value capability CHECK. No other migration depends on S4.

## Scope limits

No live Supabase project, no Storage API calls against a real project, no UPDATE path, and no
change to memory tools. Synthetic identifiers only. The storage tools (`storage_put`,
`storage_delete` and the read tools) register only when the session reports the matching
capability, and they reach the database only through the RPCs described in item 1.

## Follow-up outside S4

`packages/server/src/downstream-oauth-grant.ts` treats any host starting with `127.` as loopback.
It is intentionally left unchanged in this branch and is tracked as a separate follow-up.
