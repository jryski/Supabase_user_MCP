# Retained memory-read lab

Local synthetic packet for a later Ariadne-hosted read of `memory_get`,
`memory_list_recent`, and `memory_search`. Not filing, not acceptance, and
not an OAuth repair. This writer does not apply SQL to Ari TEST and does
not contact `odbcejsuuqdzhabjmozi`.

Owned version: `ari-memory-read-lab-v1`.

| | |
| --- | --- |
| Install | `sql/08-memory-read-lab.sql` |
| Schema recovery | `sql/08-memory-read-lab-rollback.sql` |
| Local runner | `node scripts/ari-memory-read-lab.mjs plan` then `run` |
| Pinned hosted ref, not contacted | `odbcejsuuqdzhabjmozi` |
| Forbidden | `lygftpbjgqgvuunkwnxf`, HOUSE, VAULT, production |

`acceptance` stays false. A green local receipt is not a hosted PASS.

## Install

The file is not a `supabase/migration`. It creates `policy_lab` and `memory`
only when both are absent. A second run must already carry the owned version
and the exact object allowlist. A partial schema, a different version, an
extra relation, or `public.policy_lab_memory_read` fails closed. There is no
`CREATE IF NOT EXISTS`.

Cherry-picked shape: principals, clients, memberships, capability grants, and
memories with `content`, `created_at`, `provenance_summary`, and `tags` in
the original `CREATE TABLE`. `verified_client_id()` reads top-level
`client_id`, then `app_metadata`, and does not read `user_metadata`. The four
context policies and `has_active_capability` use that helper. The three read
RPCs are `SECURITY INVOKER` with `search_path = pg_catalog`. RLS is enabled
and forced. Capabilities stay `memory:read` and `memory:search`.

Excluded: the access-token hook, `supabase_auth_admin` grants, the public
memory view, revocation audit, artifact and storage objects, a raw memories
endpoint, and any write capability. `sql/03` through `sql/07` stay untouched.
The installer does not create or alter `anon`, `authenticated`, or
`mcp_ingress`. It refuses to continue when `mcp_ingress` inherits
`authenticated`.

`authenticated` receives schema `USAGE`, table `SELECT`, and `EXECUTE` on the
two helpers and the three RPCs. `PUBLIC`, `anon`, and `mcp_ingress` receive
none of those. There is no `INSERT`, `UPDATE`, or `DELETE` for data callers.
`policy_lab` is not an API schema.

Client ids stored in this lab are UUID text, so a retained native B client
UUID fits. Seed-m2 subject strings and client strings are not a binding.

## Exposed schemas

The fixed client already sends `Accept-Profile: memory` and
`Content-Profile: memory` on the three read RPCs. It does not send
`policy_lab`.

This writer did not read the hosted exposed-schema list. The snapshot is an
Ariadne readback, recorded before any change. The only allowed delta is to
add `memory` when that snapshot does not already contain it. If `memory` is
already present, the delta is empty. Do not add `policy_lab`. Do not remove
or reorder other schemas. Restore writes the exact prior snapshot back.
The runner does not call the management API and does not widen permissions
while it reads.

## MC1681 provenance

Principal provenance for this packet is Jesse via Warden.

- D1, memory-only exposure on ari-test, is not executed here.
- D2, one additional persistent synthetic user alongside
  `1928e465-6ab9-439c-9ab8-d7d0c8bba16d` with a `.invalid` identity, is not
  executed here.

The local manifest keeps that baseline user id and one declared second
identity, `ari-memory-lab-second@loopback.invalid`. The local B client UUID
is a synthetic stand-in, not a claim that a hosted client was registered.
No new client registration is performed. Baseline passwords and consents are
not reset.

## Local runner

`ARI_MEMORY_LAB_MODE=local` is required. A URL that names the hosted ref is
refused before any database opens. The runner does not start
`supabase/tests/run-m2-memory-lab.sh` and does not listen on a port. One
controller lock is held for the process. The receipt pins the git head, the
tree, the installer hash, and the run id.

Admin seeding on the hosted project is a separate Ariadne step. Admin
credentials never enter the read path. Local reads use the embedded database
as `authenticated` with each user's subject and the same retained B client.
Both users' grants coexist in that database. The read path calls the real
RPCs.

Each run seeds three memories in each of two disjoint workspaces, in a fixed
timestamp order, with one shared search token, one foreign-only token on
each side, a run-scoped tag, and the inert sentinel
`inert-hostile-content-sentinel`. Expiry is `2099-01-01`, which the runner
rejects if it is inside 24 hours. One-variable denials cover a denied
identity, revoked and expired membership, revoked and expired client, a
revoked read grant, and an expired search grant that leaves get working.
`user_metadata` does not select a client. `app_metadata` does, when the
top-level claim is absent.

Cleanup deletes only the memory, grant, membership, transient client, and
denied-principal ids for that run. The two declared principals and the
retained B client row stay. A nonzero remainder is `cleanupStatus:
unresolved` and a nonzero exit. Issuance is `not_required` because this
local packet does not mint a session. `acceptance` is false.

`same_user_different_b_client` is `not_executed`. Hook bypass and a direct
Token A read are excluded from the first hosted batch. The local runner does
not toggle a hook and does not sign a hosted JWT.

## Hosted first round, later

Ariadne executes this. The writer does not.

- Own get, list, and search return the exact seeded ids.
- Limit-1 pagination walks every own id and stops.
- Foreign get returns `record: null`, the same shape as a missing id.
- A foreign-only search token returns no rows.
- List returns own rows only.
- The other user's cursor fails with the existing invalid-cursor contract:
  SQLSTATE `22023` and message `invalid cursor`. The fixed client already
  maps that PostgREST `400` to `FIXED_CLIENT_INVALID_CURSOR`.
- Bounded concurrent retry returns the same id.
- Same user with a different B client stays a named `not_executed` gap.

Stop when any of those proofs is incomplete. Unresolved issuance or cleanup
exits nonzero with `acceptance` false.

## Schema recovery

`sql/08-memory-read-lab-rollback.sql` is a separate reviewed recovery for
version `ari-memory-read-lab-v1`. It checks the ref and the version, then
looks for views, external constraints, and functions that depend on the lab.
Any of those stops the transaction before a drop. Drops then follow the
reverse object order, without `CASCADE`. A missing expected object fails the
script rather than being ignored. Fixture cleanup is not this rollback.
