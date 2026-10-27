# ADR-0009: Storage RLS layout for issue #123 (option A, path prefix)

- **Status:** Proposed. This ADR assumes option A; pending RLS layout decision.
- **Date:** 2026-10-27
- **Owners:** Maintainers
- **Milestone:** Issue #123 S4

> Draft: assumes option A; pending RLS layout decision. If the Primary Users choose a different
> layout, this ADR and the S4 migration are replaced, not amended.

## Context

Issue #123 adds user-scoped Storage tools. S1 fixed the key, size, and MIME bounds. S2 added a
user-scoped client that asks the database for the session's storage principal and capabilities
through two RPCs, `storage_principal` and `storage_session_capabilities`, and composes every key as
`<principal>/<relative key>` in one server-configured bucket. Authorization must live in database
RLS on `storage.objects`, evaluated with the caller's own token.

## Security constraints

- No `service_role` and no SECURITY DEFINER in the request path.
- Authority comes from `auth.uid()` and `auth.jwt() -> 'app_metadata' ->> 'client_id'`, never from a
  caller-supplied principal, bucket, or prefix.
- The grant check `policy_lab.has_active_capability` and the memory grant policy stay unchanged.
- An agent never reaches more than its own grant and the human's delegation both allow.
- Every unknown, expired, revoked, denied, or malformed input resolves to no access.

## Decision drivers

- Smallest RLS surface that the S2 client already assumes.
- Revocation that takes effect on the next statement.
- Testable with pgTAP and without a running Storage API.

## Options considered

### Option A: path prefix in one fixed bucket

Object name is `<storage principal uuid>/<relative key>` in the private bucket
`mcp-user-storage`. One SELECT, one INSERT, and one DELETE policy on `storage.objects` call
`policy_lab.storage_object_allowed(name, capability)`. The storage principal is the verified human
caller, or the human named by an active `policy_lab.storage_delegations` row keyed on the agent's
`auth.uid()` and the `app_metadata.client_id` claim.

Two details differ in form from the short definition
`(storage.foldername(name))[1] = storage_principal()::text and has_active_capability(...)`, with the
same intent:

- The prefix is an exact `starts_with(name, policy_lab.storage_object_prefix())` match plus the S1
  key-shape check on the rest. `storage_object_prefix()` is the single seam for the layout.
- `has_active_capability` takes a workspace. `storage_has_capability` calls it, unchanged, for each
  of the caller's visible memberships, and for an agent also requires the capability in the
  delegation row.

### Open: agent sub-prefix

Agents currently write under the human's prefix. Whether they should use a
`<human>/agents/<agent>/` sub-prefix is open. The choice lives only in
`policy_lab.storage_object_prefix()`; changing it does not touch the policies.

### Option C

The alternative layout remains open and is not implemented here.

## Decision

Pending. S4 implements option A so the layout can be reviewed as running code. Nothing here is
accepted until the Primary Users record the RLS layout decision.

## Consequences

### Positive

- Every check is SECURITY INVOKER under the caller's RLS; no elevated function exists.
- Grants, clients, memberships, and delegations are re-read on every statement, so revocation
  applies to the next request.
- The bucket size and MIME limits and the key-shape check mirror the S1 bounds.

### Negative

- The grant CHECK gains `storage:read` and `storage:write`, and one additive SELECT policy lets a
  caller see its own active storage grants. Both need review against the grant-check invariant.
- There is no UPDATE policy, so overwrite, upsert, and move are denied.
- Delete needs `storage:write` and `storage:read`, because Storage reads the row it deletes.
- Revocation does **not** cancel signed URLs that were already issued. They stay valid until
  they expire (60 s in S1).
- A delegated agent also needs the human's own active grant for the same capability through the
  same client (`20261027000200_storage_delegation_human_grant.sql`). One additive SELECT policy
  lets the agent see only those grant rows. The human's membership and identity eligibility are
  not re-checked on the agent path.
- Hosted Storage refuses direct SQL deletes on its tables unless `storage.allow_delete_query` is
  set. The Storage API sets it; SQL tests must set it too.
- Workspaces are not a storage partition under option A.
- The S2 client calls the RPCs in schema `policy_lab`, which `supabase/config.toml` does not expose
  through the Data API. Exposing `policy_lab`, or moving the two RPCs to a narrow exposed schema, is a
  separate decision. Until then the RPCs are unreachable over HTTP and storage tools stay off.

### Follow-up

- Record the layout decision (A versus C, agent sub-prefix).
- Decide the RPC schema exposure.
- Run the pgTAP suite with `supabase test db` against a local stack.

## Validation

`supabase/tests/database/storage_option_a_test.sql` (78 assertions) and
`test/policy-lab/storage-option-a-contract.test.ts`. See
[ISSUE_123_STORAGE_S4_RLS](../evidence/ISSUE_123_STORAGE_S4_RLS.md).

## Revisit when

- The Primary Users choose a layout other than option A.
- Storage changes how it evaluates RLS for upload, upsert, move, or delete.

## References

- `supabase/migrations/20261027000100_storage_option_a.sql`
- `supabase/migrations/20261027000200_storage_delegation_human_grant.sql`
- `packages/contracts/src/storage-bounds.ts`
- `packages/server/src/user-scoped-storage-client.ts`
