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
- `supabase/tests/database/storage_option_a_test.sql`: 69 pgTAP assertions, no psql meta-commands.
- `test/policy-lab/storage-option-a-contract.test.ts`: static checks, including byte pins for the
  grant-check invariant migrations.

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
| Revocation                        | state and expiry read per statement   | revoked delegation, read grant, expired grants  |
| Denied or non-human principal     | kind and eligibility check            | denied principal, service agent                 |
| Missing or top-level client claim | only `app_metadata.client_id`         | missing and top-level claim rows                |
| Anonymous caller                  | no anon policy or EXECUTE             | anon rows                                       |
| Overwrite or move                 | no UPDATE policy                      | rename has no effect                            |
| Grant-check drift                 | invariant files unchanged             | `has_active_capability is unchanged`, byte pins |

## Validation run here

- `npm run check` (format, lint, typecheck, vitest).
- The pgTAP file was run in PGlite with Supabase-shaped stubs for `auth.uid()`, `auth.jwt()`,
  `storage.buckets`, and `storage.objects`, after all repository migrations: 69 of 69 passed. The
  harness is local evidence and is not added to the repository.
- `supabase test db` was not run: it needs Docker and a local Supabase stack.

## Review questions

- Is extending the capability CHECK and adding `storage_grant_is_active_context` acceptable, given
  that `has_active_capability` and `grant_is_active_context` are unchanged?
- Should `policy_lab` be exposed through the Data API, or should the two RPCs move to a narrow
  exposed schema with a matching change to the S2 client?
- Is a delegation row enough human-side authorization for an agent, given that RLS hides the
  human's own grants from the agent?

## Rollback

Drop the three `storage.objects` policies, the bucket, the five functions, the delegation table,
and `storage_grant_is_active_context`, and restore the two-value capability CHECK. No other
migration depends on S4.

## Scope limits

No live Supabase project, no Storage API calls, no tool registration, no UPDATE path, and no change
to memory tools. Synthetic identifiers only.
