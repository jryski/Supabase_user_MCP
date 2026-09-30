# Remaining N-gates controller packet

Controller runbook for N3, N7, N8, N2, and N6. Not executed against hosted
TEST from this branch. Not acceptance. Not a merge, Pages, DNS, hook install,
or client registration. The Lane B H1 runner still labels these five gates
`not_executed`. This packet does not rewrite that receipt.

`node scripts/run-ari-test-n-gates.mjs plan` prints the order and opens no
socket. `run` stays closed until the reviewed head equals the actual clean
head, `npm run build` has just completed, and `ARI_N_GATES_EXECUTE=1`.

## Order

Default order is N3, N7, N8, N2, N6. N6 is last and uses its own runtime.
A failure before N6 does not disable the hook. Set `ARI_N_GATES` to run a
subset. The packet reorders a subset into that same sequence.

## Profiles

| Profile | Callback | Resource |
| --- | --- | --- |
| Baseline A, where the consent harness still uses it | `/callback` | mapped resource |
| External A | `/oauth/callback` | exact mapped resource on authorize and token exchange |
| B | `/oauth/downstream/callback` | omitted on authorize and on token exchange |

The callback must be the full loopback URI: scheme, host, port, and path.
No userinfo, query, or fragment. B must not inherit a default resource.

## What the controller answers

Every controller line is one JSON object. It carries `runId` and `action`
copied from the request. A bare `continue`, a stale run id, or the wrong
action cannot satisfy cleanup or restore. Neither line carries a password,
bearer, code, or admin key.

1. `prepare_second_synthetic_user` for N2. Create one run-owned second
   synthetic user first. Reply with `type: readback` and that user's UUID
   as `secondUserId`. The packet does not create the user. Keep the
   reusable baseline user.
2. `cleanup_sessions`. Delete only the listed session ids and their refresh
   rows. Reply with `sessionsRows: 0`, `refreshRows: 0`, and the same
   `sessionIds`. Do this before deleting the second synthetic user.
3. `delete_second_synthetic_user` carries `secondUserId` only. Reply with
   `type: continue` and the same id after that user's sessions are gone.
4. `capture_hook_manifest`. Reply with the full enabled hook configuration,
   including URI and settings, the F1 policy name
   `ari_probe_marker_reject_a_client`, `mappingReady: true`, and
   `grantsUnchanged: true`. A manifest with only enabled and function is
   rejected. Project, client, and resource must match this TEST setup.
5. `disable_current_hook`. The packet arms restoration and writes a local
   recovery file before this line. Disable only the current hook. Reply
   that it is disabled, repeat the saved hook hash and function, and repeat
   the unchanged F1 policy fields. A malformed, missing, or stale reply
   still requires restore.
6. `restore_hook_configuration` carries the saved manifest, not only the
   hash. Restore that configuration exactly. Reply with the enabled
   manifest itself. The packet recomputes the hash from that readback.
   Do this on failure, timeout, EOF, and SIGINT or SIGTERM as well.
   Until that readback matches, restoration is `pending` or `failed`,
   never `not_required`.

N6 passes only when a cryptographically verified hook-off A for the same
synthetic owner returns HTTP 200 with an empty marker, the owner marker
was read, the session is live, cleanup and the restored hook both hold,
and the signed A canary holds. HTTP 401, HTTP 403, HTTP 500, an expired
token, and a permission denial are inconclusive. Rows showing the marker
are not a denial. Hook-off A is not sent through User MCP.

N8 unbound, wrong state, and replay use a legitimate native B code.
PKCE `invalid_grant` is labeled on its own and is not binding proof.
An issuer or service failure is not binding proof. Callback HTTP 500 is
not a redirect-mismatch pass. After a successful bind, replay must leave
that binding and session in place. N7 records the consent flow it actually
sees. Policy proof remains exchange HTTP 403 `openid_scope_refused` with
no token. A retained client that is already consented does not need a new
registration.

## Local proof

The synthetic process test drives the same CLI against loopback. It does not
contact hosted TEST. A green synthetic receipt still has `acceptance: false`.
It is not a hosted run and not a G5 re-PASS.
