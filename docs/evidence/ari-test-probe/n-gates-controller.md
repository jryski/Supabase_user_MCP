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

Stdin is either the line `continue` or one JSON readback line. Neither line
carries a password, bearer, code, or admin key.

1. `prepare_second_synthetic_user` for N2. Create one run-owned second
   synthetic user first, then type `continue`. The packet does not create
   the user.
2. `delete_second_synthetic_user` carries `secondUserId` only. Delete that
   run-owned user after the listed sessions are gone, then type `continue`.
3. `capture_hook_manifest`. Reply with the enabled hook manifest, the F1
   policy name `ari_probe_marker_reject_a_client`, and `mappingReady: true`.
4. `disable_current_hook`. Disable only the current hook. Reply that it is
   disabled and repeat the saved hook hash.
5. `cleanup_sessions`. Delete only the listed session ids and their refresh
   rows, then type `continue`.
6. `restore_hook_configuration`. Restore the saved manifest exactly. Reply
   that the hook is enabled and repeat the same hash. Do this on failure,
   timeout, and abort as well.

N6 passes only when the marker denial, the cleanup, the restored hook, and
the signed A canary all hold. An empty marker read with HTTP 200 is a
restrictive denial. HTTP 403 is also a denial. Rows showing the marker are
not a denial.

## Local proof

The synthetic process test drives the same CLI against loopback. It does not
contact hosted TEST. A green synthetic receipt still has `acceptance: false`.
It is not a hosted run and not a G5 re-PASS.
