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

Every controller line is one JSON object. It carries `runId`, `action`, and
the request `requestId` copied from that action instance. A bare `continue`,
a stale run id, the wrong action, or a previous cleanup's request id cannot
satisfy a later cleanup or restore. Neither line carries a password, bearer,
code, or admin key.

1. `prepare_second_synthetic_user` for N2. Create one run-owned second
   synthetic user first. Reply with `type: readback`, `createdForRun: true`,
   that user's email, and that user's UUID as `secondUserId`. The email
   must be the configured second-user email and must not be the reusable
   baseline email. The packet does not create the user. It learns the
   baseline UUID from verified native A and will not authorize deletion
   when the prepared id, email, or token subject is the baseline or is
   otherwise unproven. A failure before the first grant does not delete
   the prepared id.
2. `cleanup_sessions`. Delete only the listed session ids and their refresh
   rows. Reply with `sessionsRows: 0`, `refreshRows: 0`, and the same
   `sessionIds`, each id once. A duplicate, a missing id, an extra id, or
   a nonzero row count is not confirmation and does not clear an omitted
   id. Do this before deleting the second synthetic user.
3. `delete_second_synthetic_user` carries `secondUserId` only after the
   packet has marked that id deletion-eligible. Reply with `type: continue`
   and the same id. Do not delete the baseline user.
4. `capture_hook_manifest`. Reply with the full enabled hook configuration,
   including URI and settings, and the effective F1 readback: restrictive
   policy `ari_probe_marker_reject_a_client` on `public.ari_probe_marker`
   for `select` to `authenticated`, forced RLS, the owner-read policy, the
   current grants, and the current client mappings. F1 and the owner policy
   must each include `qual`, the current `pg_policies.qual` text from
   `pg_get_expr`. F1's expression must be the two `IS DISTINCT FROM`
   comparisons of `coalesce(auth.jwt()->>'client_id','')` against the
   baseline client and then the external client, joined by `AND`, matching
   sql/06. A claimed client-id list is not that expression. `USING true`
   and `USING false` are different expressions and neither is F1. The owner
   expression is the deparsed form of `((select auth.uid()) = owner_id)`.
   That qual text is part of the snapshot compared after disable and after
   restore. A name plus `mappingReady` or `grantsUnchanged` is not enough.
   A manifest with only enabled and function is rejected. Project, client,
   and resource must match this TEST setup.
5. `disable_current_hook`. The packet arms restoration and writes a local
   recovery file before this line. Disable only the current hook. Reply
   that it is disabled, repeat the saved hook hash and function, and repeat
   the unchanged effective F1 readback. A malformed, missing, or stale reply
   still requires restore. A name-only or boolean policy reply does not.
6. `restore_hook_configuration` carries the saved manifest, not only the
   hash. Restore that configuration exactly. Reply with the enabled
   manifest itself. The packet recomputes the hash from that readback.
   Do this on failure, timeout, EOF, and SIGINT or SIGTERM as well.
   Until that readback matches, restoration is `pending` or `failed`,
   never `not_required`.

N6 passes only when a cryptographically verified hook-off A for the same
synthetic owner returns HTTP 200 with an empty marker, the owner marker
text is exactly `ari-probe-marker-` plus this TEST project ref and its
`owner_id` is that verified owner, the session is live, the effective F1
readback is unchanged, cleanup and the restored hook both hold, and the
signed A canary holds. Verified tokens must carry `exp`, `iat`, `sub`,
and the role, client, and session claims for that token. HTTP 401, HTTP
403, HTTP 500, an expired token, a same-format wrong marker, and a
permission denial are inconclusive. Rows showing the marker are not a
denial. Hook-off A is not sent through User MCP.

The hook-off liveness check is `GET /auth/v1/user` for that verified
owner. The request and its response body use the run timeout and the
same SIGINT or SIGTERM interruption as the rest of the packet. The N6
marker read uses that same bound for its body. A stall after disable
still requests restore. The saved configuration is either read back
exactly, or the receipt stays `pending` or `failed` and keeps the
recovery locator. Neither stall is an F1 pass.

An issuance attempt is resolved only after the token response body is
fully read and either a real session UUID from that body is on the ledger,
or the body is a complete pre-issuance denial. A denial is HTTP 400, 401,
or 403 with a JSON `error` of `invalid_request`, `invalid_client`,
`invalid_grant`, `unauthorized_client`, `unsupported_grant_type`,
`invalid_scope`, or `access_denied`, and no access token. Headers alone,
a truncated or stalled body, an aborted read, malformed JSON, HTTP 2xx
without a usable session UUID, and HTTP 5xx stay `unresolved`. The packet
asks for `reconcile_unresolved_issuance` for those attempt ids only. That
readback does not resolve the attempt and is not permission to list or
delete baseline sessions, including any ids the controller sends back.
`cleanupStatus` stays `unresolved`. A late token whose body does arrive
in full, with a real session UUID, is ledgered and cleaned before the
receipt.

`cleanupStatus` is `confirmed` when every recorded session id for the
run already has a confirmed cleanup readback. It is `not_required` only
when the run recorded no session id that required cleanup. `failed` and
`unresolved` take priority over both. Per-action cleanup readbacks stay
mandatory. A final `confirmed` does not replace those readbacks.

Every receipt is written after that finalization. It carries
`issuanceStatus`, `cleanupStatus`, and `restoreStatus`, and
`unresolvedAttemptIds` for any attempt that is still unresolved. A failed
gate row is finalized the same way. `acceptance` stays false.

N8 callback transport cases stay in the row. They do not pass N8 by
themselves. The gate also needs a legitimate signed native B that is
either left unbound or refused at binding, with the real PKCE exchange.
On a non-loopback issuer those signed-B cases stay `not_executed` and N8
stays incomplete. PKCE `invalid_grant` is labeled on its own and is not
binding proof.
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
