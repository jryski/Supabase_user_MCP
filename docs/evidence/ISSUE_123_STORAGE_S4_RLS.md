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
    the human must also be a verified human principal with an active, unexpired membership on the
    delegation's client, and hold an active grant for the same capability through that client
    and the membership's workspace;
  - adds the SELECT policies `storage_delegator_principal_is_verified` and
    `storage_delegator_membership_is_active_context`, so the agent sees only that human's
    principal row and active membership rows, only through an active delegation on the same
    client.
- `supabase/migrations/20261027000300_storage_session_rpc_seam.sql` (additive): two wrappers in
  the exposed `public` schema, `mcp_storage_principal_v1()` and
  `mcp_storage_session_capabilities_v1()`. Each is SECURITY INVOKER with `search_path = ''`, calls
  the matching `policy_lab` function and nothing else, and is executable by `authenticated` only.
  `policy_lab` stays unexposed in `supabase/config.toml`. The storage client calls the wrappers
  with the `public` profile.
- `supabase/seed-storage-m2.sql`: synthetic storage grants for the M2 lab user, loaded by the
  local stack only.
- `supabase/tests/database/storage_option_a_test.sql`: 99 pgTAP assertions, no psql meta-commands.
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
  valid after revocation until they expire, and cleanup through the delete guard. The stand-in
  refuses any profile that `supabase/config.toml` does not expose and any RPC other than the two
  wrappers.
- `test/policy-lab/storage-session-rpc-seam.test.ts`: PGlite contract test for the wrappers:
  exposed schemas, catalog shape, privileges, results equal to the `policy_lab` functions for
  the same caller, and `anon` refused.
- `test/review-139-human-suspension.test.ts`: the delegating human's revoked membership, denied
  eligibility, or expired membership removes the agent's storage access.
- `packages/server/src/m2-storage-e2e.test.ts`: real-stack probe, run by
  `supabase/tests/run-m2-memory-lab.sh` in the CI M2 job against local PostgREST and Storage
  with real Auth sessions. It checks that the `policy_lab` profile is refused, that `anon`
  cannot call the wrappers, an upload, list, download and delete round trip, and that a second
  user is denied. Skipped without the M2 environment.
- `packages/server/src/native-user-mcp-read-handler.ts`: an opt-in `storageBucket` builds the
  storage client from the downstream grant B and the publishable key, the same credential as the
  Data API client. The ingress Token A is never used. A test calls `storage_list` through the
  handler and checks every outbound storage request.

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
| Human suspended or not verified   | human membership and eligibility      | delegator rows, human-suspension test           |
| Unexposed schema over HTTP        | public INVOKER wrappers only          | seam test, M2 probe                             |
| Token A reaches Storage           | storage client built from B only      | read handler storage test                       |
| Revocation                        | state and expiry read per statement   | revoked delegation, read grant, expired grants  |
| Denied or non-human principal     | kind and eligibility check            | denied principal, service agent                 |
| Missing or top-level client claim | only `app_metadata.client_id`         | missing and top-level claim rows                |
| Anonymous caller                  | no anon policy or EXECUTE             | anon rows                                       |
| Overwrite or move                 | no UPDATE policy                      | rename has no effect                            |
| Grant-check drift                 | invariant files unchanged             | `has_active_capability is unchanged`, byte pins |

## Validation run here

- `npm run check` (format, lint, typecheck, vitest).
- The pgTAP file was run in PGlite with the repository stub, after all repository migrations:
  99 of 99 passed, with and without the delete guard installed.
- `npx vitest run test/storage-option-a-e2e.test.ts`: passed. Without the follow-up migration,
  the human-grant scenario failed. With the client pointed at the `policy_lab` profile, the
  stand-in refuses it and the run fails.
- The stand-in is not the hosted Storage API. It models only the routes the client calls.
- `supabase test db` and the M2 storage probe were not run here: they need Docker and a local
  Supabase stack. The probe runs in the CI M2 job.

## Review items

1. **`policy_lab` is not exposed in `supabase/config.toml`.** Addressed without exposing it. The
   client now calls two SECURITY INVOKER wrappers in `public`, which run with the caller's role
   and claims, so RLS on `policy_lab` still decides. No `policy_lab` table is reachable over the
   Data API.
2. **The capability CHECK is widened** by `storage:read` and `storage:write` only. Kept. A contract
   test pins the exact list.
3. **The additive `storage_grant_is_active_context` policy** is kept as is. It has the same
   predicate as `grant_is_active_context`, limited to the two storage capabilities. The memory
   policy and `has_active_capability` are unchanged; a pgTAP assertion pins the latter by digest.
4. **Agent access did not check the human's own grants.** Addressed by the follow-up migration.
   An agent now needs its own grant, an active delegation that lists the capability, and the
   human's active grant for that capability through the same client. The human must also be a
   verified human principal with an active, unexpired membership on that client.

## Rollback

Drop the two `public.mcp_storage_*_v1` wrappers, the delegator policies, then the three `storage.objects` policies, the
bucket, the functions, the delegation table, and `storage_grant_is_active_context`, and restore the
two-value capability CHECK. No other migration depends on S4.

## Scope limits

No live Supabase project, no Storage API calls against a real project, no UPDATE path, and no
change to memory tools. Synthetic identifiers only. The storage tools (`storage_put`,
`storage_delete` and the read tools) register only when the session reports the matching
capability, and they reach the database only through the two wrappers described in item 1.

## Downstream redirect loopback check

`packages/server/src/downstream-oauth-grant.ts` treated any host starting with `127.` as loopback.
It now uses the shared exact check in `loopback-host.ts` (`localhost` or a canonical
`127.0.0.0/8` address, no user info), plus an exact `[::1]` match. Look-alike hosts such as
`127.0.0.1.evil.example` are refused. Accepting `[::1]` is new: the old `::1` comparison never
matched because the URL host is bracketed.
