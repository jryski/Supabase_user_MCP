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
and the source-pinned manifest of policy expressions, helper and RPC bodies,
columns, constraints, indexes, and triggers. Drift stops the transaction.
Reentry does not bless the drifted objects and does not overwrite them. A
partial schema, a different version, an extra relation, or
`public.policy_lab_memory_read` fails closed. There is no
`CREATE IF NOT EXISTS`.

The constraint fingerprint hashes check, foreign-key, primary-key,
unique, and exclusion constraints. It omits `pg_constraint` rows whose
`contype` is `n`. PostgreSQL 18 records table `NOT NULL` there, and
PostgreSQL 17 keeps that fact only on `pg_attribute.attnotnull`. The
column fingerprint still includes `attnotnull`, so dropping `NOT NULL`
stops on the column manifest. Changing a check, foreign key, or primary
key still stops on the constraint manifest. The pinned digest is the
value both catalogs produce for this reviewed schema.

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
controller lock is held for the process. The lock directory is in the process
temporary directory. A spawned runner must receive the same `TMPDIR` as the
process that holds the lock. The suite does not require the working checkout
to be bind-mounted on `/tmp`. The receipt pins the git head, the
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

## Hosted controller

`node scripts/ari-memory-read-lab.mjs hosted-synthetic` is the local
loopback controller. It keeps the PGlite runner and the local-only guard.
`run` still requires `ARI_MEMORY_LAB_MODE=local` and refuses a URL that
names `odbcejsuuqdzhabjmozi`.

Ariadne's retained command is:

```bash
ARI_MEMORY_LAB_EXECUTOR=ariadne node scripts/ari-memory-read-lab.mjs hosted \
  --manifest <reviewed-run-manifest.json> \
  --credentials <protected-credential-file.json>
```

Missing `--manifest` is `manifest_required`. Missing `--credentials` is
`credentials_required`. Both are checked before the clean-worktree gate.
Without `ARI_MEMORY_LAB_EXECUTOR=ariadne`, `hosted` is
`hosted_execution_refused`. This writer does not run that command against
the hosted ref and does not put passwords or the publishable key in the
receipt.

The reviewed manifest is a file. It has no synthetic defaults. Required
fields are `version` `ari-memory-read-lab-v1`, `projectRef`
`odbcejsuuqdzhabjmozi`, `supabaseUrl`, `reviewedHead`, `reviewedTree`,
`resource`, `aClientId`, `bClientId`, `agentId`, `aRedirectUri`,
`bRedirectUri`, two `users` (`baseline` and `second`, each with `id` and
`email`), and `fixtures` (`runId`, `deniedPrincipalId`,
`transientClients`, and `rows`). `reviewedHead` and `reviewedTree` must
match `git rev-parse HEAD` and `HEAD^{tree}`. The manifest carries
nonsecret ids only. The credential file is separate and is not printed. It
holds the publishable key, the public JWKS, and each user's password.
A private JWK parameter is refused.

`node scripts/ari-memory-read-lab.mjs prepare --manifest <reviewed-run-manifest.json>`
reads that file and prints the seed and cleanup plan. It does not dial the
network, does not require the executor, and does not check the worktree.
The plan is available before any read. It asserts the baseline principals
and the retained B client already match, and it does not insert them again.
Membership and grant tuples are deduplicated per principal, client, and
workspace. An existing row that does not match is a transactional
`23505` collision. A missing or different baseline row is `baseline_mismatch`.
Identical rows are preserved on a repeat run.

Phases, in order: parse the manifest and credentials; build that plan; take
the shared controller lock; reconcile the reviewed head and tree; bind one
loopback MCP listener at the manifest resource; for each user, password
grant with the publishable `apikey`, Token A on scope `email` through the
hosted consent helper (first `approval_post`, later `already_consented_get`),
then the handler-driven Token B consent; reconcile the password, source, and
B session ledger; call `memory_get`, `memory_list_recent`, and
`memory_search` through that listener for both users, including pagination,
foreign get, owner search, empty foreign search, and cross-user cursors;
release the lock. Password, token, consent, and MCP calls, including the
response body, use the same abort deadline as the N-gate marker read.
The retained path does not open PGlite, does not start a synthetic issuer,
does not sign tokens, and does not clear sessions. Admin seed and ownership
projection stay outside the data calls. `cleanupStatements` delete only the
proved memory ids and the proved authorization keys. They do not delete by
workspace string, and they do not delete the baseline principals or the
retained B client. Token A's fresh `session_id` is a decoy observation.
It is not a cleanup session. The read path does not execute the plan.
`cleanupStatus` stays `unresolved` until a separate ownership-before, exact
deletion, and after-zero receipt. A live attempt that times out, stalls, or
receives SIGINT or SIGTERM still returns the issued ids and any unresolved
issuance attempt ids. It does not replace that receipt with
`hostedContact: false`. Exit 0 requires confirmed cleanup. `acceptance`
stays false.

An injected fetch may dial only `https://127.0.0.1` or `https://localhost`.
Any `supabase.co` host, including the hosted ref, is `wrong_target` before
a request. The live dial, with no injected fetch, accepts only
`https://odbcejsuuqdzhabjmozi.supabase.co`. A mismatched reviewed head is
`manifest_head_mismatch`.

The synthetic controller remains the local stand-in. It binds each manifest
user through native Token A and Token B. The second user id comes from the
manifest, not a hardcoded local UUID. Data reads are the same three tools
on `createNativeUserMcpReadHandler`. The controller does not call the SQL
RPCs and does not manufacture `request.jwt.claims`. A loopback PostgREST
stand-in verifies Token B, then applies that verified bearer to the RPCs.
Both users' grants stay live together. Own foreign-only tokens must be found
by their owner, and the other user's search of that token must be empty.
A stalled header or body is `orchestration_timeout` or `signal_received`,
then cleanup. The receipt lists the run-owned memories, memberships, grants,
transient clients, denied principal, and session ids. Baseline principals,
the retained B client, and both schemas stay. `acceptance` stays false.

## Hosted first round, later

Ariadne executes the retained command above. The writer does not.

- Own get, list, and search return the exact seeded ids.
- Limit-1 pagination walks every own id and stops.
- Foreign get is unavailable, the same public shape as a missing id.
- The owner of a foreign-only token finds that row. The other user's search
  of that token returns no rows.
- List returns own rows only.
- The other user's cursor fails with the existing invalid-cursor contract:
  SQLSTATE `22023` and message `invalid cursor`. The fixed client already
  maps that PostgREST `400` to `FIXED_CLIENT_INVALID_CURSOR`.
- Concurrent reads under both credentials return each user's own id.
- Same user with a different B client stays a named `not_executed` gap.

Stop when any of those proofs is incomplete. Unresolved issuance or cleanup
exits nonzero with `acceptance` false.

## Schema recovery

`sql/08-memory-read-lab-rollback.sql` is a separate reviewed recovery for
version `ari-memory-read-lab-v1`. Before any drop it revalidates the same
owned manifest, including the version-neutral constraint digest, and the
same authenticated-select ownership check. Policy
fingerprints include the target, command, permissive mode, roles, and a
literal-aware expression. Function fingerprints include volatility.
Whitespace inside a quoted literal is not removed. An unknown policy,
trigger, constraint, column, index, function body, volatility change, or
role change stops the transaction without rewriting or deleting the drifted
object. It then looks for views, external constraints, and functions that
depend on the lab. Any of those stops the transaction before a drop. Drops
then follow the reverse object order, without `CASCADE`. A missing expected
object fails the script rather than being ignored. Fixture cleanup is the
retained receipt's `cleanupStatements`, not this rollback.
