# Lane B controller runbook

Not executed by the writer. Not acceptance. Not a merge, Pages, DNS, or
publish step. The hook is not installed. Hosted TEST was not contacted to
produce this packet.

Lane A closed at `6e142ed510bab5c6b15312e0d25530f5840d0424` (Warden MC1552).
Do not rewrite `sql/03-mcp-ingress-role.sql`. `sql/04` stays the accepted
baseline hook packet. `sql/07` is the additive B and external-A mapping.

| | |
| --- | --- |
| Target | `odbcejsuuqdzhabjmozi` only |
| Forbidden | `lygftpbjgqgvuunkwnxf`, HOUSE, VAULT, production |
| B profile | `TEST_ONLY_PUBLIC_PKCE` — public client, S256, no secret, scope `email`, no `openid`, no refresh retention |
| F1 | `sql/06` covers `public.ari_probe_marker` only. Production F1 is every protected surface. |
| N4 | A source-session revocation on its own fresh A/B pair. B stays live. Not the B grant. |
| N5 | B-session revocation on a different fresh A/B pair. The A source stays live. A first-party B auth session, not a refresh token. |

## G5 before any hosted write

Warden reviews the exact commit you are about to apply. Stop if that review
is not recorded for the commit you will execute. Do not enable
Authentication → Hooks, do not run the SQL, and do not start the external
client until then.

G5 PASS for the Lane B packet is
`8f2de7ecadaad023ac9d292a5577ad69bdd8d8e8` (tree
`f3e06397770fdc4a60a036529896ffe030e8b6f4`). Lane A is closed at
`6e142ed510bab5c6b15312e0d25530f5840d0424`, which is the parent of the first
Lane B commit, not the parent of later orchestration commits. A later tip is
not a G5 re-PASS and is not acceptance.

Startup compares `ARI_LANE_B_G5_HEAD` to the actual `git rev-parse HEAD`.
A different 40-character sha is refused (`g5_head_mismatch`). A dirty tracked
worktree or index is refused (`g5_worktree_dirty`). Untracked files are not
that check. The receipt records `actualHead` and `reviewedHead`, and they
are equal. Neither value is a token.

```bash
git fetch origin cursor/supabase-native-user-mcp-g2
git rev-parse HEAD
git rev-parse origin/cursor/supabase-native-user-mcp-g2
git rev-parse origin/cursor/supabase-native-user-mcp-g2^{tree}
git status --porcelain=v1 --untracked-files=no
```

Stop unless `git rev-parse HEAD` is exactly the reviewed sha you will put in
`ARI_LANE_B_G5_HEAD`, and the porcelain command prints nothing. Run
`npm run build` only after those two checks, and immediately before the
live launch below. Do not build first and then edit the tree.

## Stop and report (N25)

`sql/05` refuses to continue when `current_user` cannot `SELECT` from
`auth.sessions`, when `auth.sessions.oauth_client_id` is absent, or when the
owner cannot read the mapping tables. The file does not grant privileges on
schema `auth`. If it raises `STOP AND REPORT`, stop. Do not add a grant on
`auth.sessions` or `auth` to make the function compile.

## Register clients later (not done in this packet)

Two additional public clients, no client secret, no DCR, no `openid`:

1. External A. Redirect is the loopback MCP callback the external client
   uses. `sql/07` inserts that row's `mcp_resource` as the fixed constant
   `http://127.0.0.1:8788/mcp`. It is not taken from `ari.mcp_resource`.
2. B, labeled TEST-only public PKCE. Redirect is
   `http://127.0.0.1:8788/oauth/downstream/callback`. Do not send a `resource`
   parameter. Scope is `email`.

Keep the existing baseline A client in `ari_probe.mcp_client` with
`probe_label = ari-test-synthetic`. Do not replace that row.

## Apply order, one batch each, TEST ref only

```sql
select set_config('ari.project_ref', 'odbcejsuuqdzhabjmozi', false);
```

1. `sql/00`, `sql/01`, `sql/03`, and `sql/04` if they are not already applied.
   Do not apply `sql/02`.
2. `sql/07-downstream-and-external-a.sql` with `ari.oauth_client_id`,
   `ari.external_a_client_id`, `ari.downstream_client_id`, `ari.mcp_resource`,
   and `ari.agent_id` set in the same batch. `ari.mcp_resource` stays the
   hosted TEST `/mcp` URL and is the baseline A resource only. `ari.agent_id`
   is the same trusted agent for A and B.
3. `sql/05-source-session-liveness.sql`.
4. `sql/06-ingress-client-rls.sql` with the baseline and external A client ids.

Leave Authentication → Hooks disabled until G5 names this function:
`ari_probe.custom_access_token_hook`.

## Safe controller input

`run` reads the parent environment and prints line-delimited JSON on stdout.
Stderr is an error code. The child environment is an allowlist: loopback MCP
URL, external A client id, external A redirect, timeout, and process basics
such as `PATH`. It is forced to `ARI_LANE_B_LIVE=controller-g5` and
`ARI_LANE_B_EXECUTE=1`.

Do not put these in the child, and do not pass them on the command line:

- access tokens, refresh tokens, passwords, or service-role keys
- `ARI_TEST_SYNTHETIC_PASSWORD` (parent only)
- `ARI_FIRST_PARTY_ACCESS_TOKEN`
- `ARI_TEST_PUBLISHABLE_KEY` (parent only)
- `ARI_TEST_JWKS_JSON` (parent only)
- `ARI_TEST_SUPABASE_URL` (parent only; the child discovers the issuer)

The parent performs consent for `external_a` and `downstream_b`. It GETs each
authorization URL with `redirect: manual`, reads `authorization_id` from
`Location`, password-logs in the synthetic user with
`ARI_TEST_SYNTHETIC_PASSWORD`, then GETs
`/auth/v1/oauth/authorizations/{id}`. Supabase `/oauth/authorize` does not
return a code. It redirects to the Site URL consent page, and that page is
not deployed. When the authorization GET already returns a loopback
`redirect_url` with a code, that user and client are already consented and
the parent does not POST. Otherwise the parent POSTs `/consent` and uses a
code only from that successful POST. A failed POST does not replace an
already-consented GET redirect. The parent then GETs `redirect_url` so the
code lands on the loopback callback. Callback HTTP 4xx/5xx is
`callback_rejected` with `deliveryStatus`. A thrown callback fetch is
`redirect_transport_failed`.

`ARI_TEST_SYNTHETIC_PASSWORD` stays in the parent environment. It is not
copied to the child, not written to stdout or stderr, and not read from
stdin. Each fresh pair password-logs in once and reuses that password
session for the A consent and the B consent. A successful run therefore
creates three password sessions. When a pair reaches P5, the parent
appends one `sessionLedger` entry: `pair` (`positive`, `n4`, or `n5`),
`passwordSessionId`, `sourceSessionId`, and `bSessionId`. Those values
are UUIDs. They are not bearers, tokens, codes, or verifiers. The
top-level `passwordSessionId` is only the positive pair's password
session. A failed run still prints a receipt when any safe session id is
known. That receipt lists every pair ledger accumulated before the abort
and the known safe ids for the pair that aborted. Cleanup walks the
ledger, not the single top-level id.

The CLI never reads a bearer from stdin. After P5 it prints a
`controller_action` and waits for one stdin line whose text is exactly
`continue`:

```json
{"type":"controller_action","action":"revoke_a_source_session","pair":"n4","source_session_id":"<a-uuid>","b_session_id":"<b-uuid>"}
```

```json
{"type":"controller_action","action":"revoke_b_session","pair":"n5","source_session_id":"<a-uuid>","b_session_id":"<b-uuid>"}
```

N4 and N5 are different processes and different A/B pairs. The parent never
sends N5 for a `source_session_id` it already revoked. Each executed receipt
row carries that row's `sourceSessionId` and `bSessionId`.

Do not paste a token, password, or code on the continue line. The last
stdout line is a receipt with `acceptance: false`. It has no token, code,
or refresh token. Rows use the Atlas MC1545 J ids. `actualHead` and
`reviewedHead` are the same 40-character sha.

Without `ARI_LANE_B_EXECUTE=1`, `run` exits 2 and prints
`live_runtime_not_started`. It does not listen and does not spawn the child.

## Local proof, not a hosted run

This proves the CLI entrypoints call the SDK and the loopback handler. It
does not contact `odbcejsuuqdzhabjmozi`. It is not G5 re-PASS and not
acceptance. The hook is not installed.

```bash
npm run build
node --test scripts/ari-test-external-ipc.test.mjs
```

## Live loopback, after a review of the exact commit

Confirm the exact head and a clean tracked tree first. Build only after
that, immediately before launch.

```bash
git rev-parse HEAD
git status --porcelain=v1 --untracked-files=no
npm run build
unset SUPABASE_SERVICE_ROLE_KEY SUPABASE_SECRET_KEY SERVICE_ROLE_KEY SUPABASE_SERVICE_KEY
unset ARI_FIRST_PARTY_ACCESS_TOKEN
export ARI_LANE_B_LIVE=controller-g5
export ARI_LANE_B_EXECUTE=1
export ARI_LANE_B_G5_HEAD=<reviewed commit sha>
export ARI_LANE_B_TIMEOUT_MS=120000
export ARI_TEST_PROJECT_REF=odbcejsuuqdzhabjmozi
export ARI_TEST_SUPABASE_URL=https://odbcejsuuqdzhabjmozi.supabase.co
export ARI_TEST_PUBLISHABLE_KEY=<publishable key>
export ARI_TEST_JWKS_JSON='<public jwks json>'
export ARI_EXTERNAL_MCP_URL=http://127.0.0.1:8788/mcp
export ARI_EXTERNAL_A_CLIENT_ID=<external A client id>
export ARI_EXTERNAL_A_REDIRECT_URI=http://127.0.0.1:8788/oauth/callback
export ARI_DOWNSTREAM_CLIENT_ID=<B client id>
export ARI_DOWNSTREAM_REDIRECT_URI=http://127.0.0.1:8788/oauth/downstream/callback
export ARI_TEST_SYNTHETIC_PASSWORD=<synthetic user password>
export ARI_AGENT_ID=<trusted agent id>
node scripts/run-ari-test-external-e2e.mjs plan
node scripts/run-ari-test-external-e2e.mjs run
```

The parent consents. Do not open the authorization URL by hand and do not
follow `/authorize` as if it returned a code. External A still redirects to
`/oauth/callback` only after consent. B redirects to
`/oauth/downstream/callback` only after the second consent. The parent binds
B only when that callback `state` matches the handshake for the verified A.
A green receipt still has `acceptance: false`. Hosted contact is not
acceptance, not a hook install, and not a G5 re-PASS.

`run` proves P1–P5 and N1 on one A/B pair and does not revoke that pair.
It then starts a new child and a new A/B pair for N4 only, and another new
child and pair for N5 only. Do not answer N5 on the N4 source session.

When `revoke_a_source_session` appears, delete only that
`source_session_id`. When `revoke_b_session` appears, delete only that
`b_session_id`. The other id on the same line is the opposite session.
Read it back and leave it in place. Type a line that is exactly `continue`
only after the readback below. Do not put a bearer on stdin. The child
then makes one more tool call. The row passes only when that call fails
closed at liveness and the marker is not requested. N4 also requires B
still live. N5 also requires the A source still live. Revoking the opposite
session fails that row.

## Revocation readback before continue

Target is `odbcejsuuqdzhabjmozi` only. User is
`ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid`. Replace
`<target_session_id>` with `source_session_id` for N4 or `b_session_id` for
N5. Replace `<opposite_session_id>` with the other uuid on that
`controller_action`. Do not delete the opposite id. Do not delete the decoy
`session_id` claim. Do not paste a token into the batch.

Before, confirm the target is one synthetic-user row:

```sql
select session.id, session.user_id, session.not_after, usr.email
from auth.sessions as session
join auth.users as usr on usr.id = session.user_id
where session.id = '<target_session_id>'::uuid
  and usr.email = 'ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid';
```

Stop unless that returns exactly one row. Confirm the opposite session
is already one live synthetic-user row. If it is missing, stop. Do not
delete the target and do not type `continue`.

```sql
select session.id, session.not_after
from auth.sessions as session
join auth.users as usr on usr.id = session.user_id
where session.id = '<opposite_session_id>'::uuid
  and usr.email = 'ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid'
  and (session.not_after is null or session.not_after > now());
```

Record the refresh count:

```sql
select count(*) as refresh_rows
from auth.refresh_tokens
where session_id = '<target_session_id>'::uuid;
```

Delete only that session, still under the synthetic-user guard:

```sql
delete from auth.refresh_tokens
where session_id = '<target_session_id>'::uuid
  and session_id in (
    select session.id
    from auth.sessions as session
    join auth.users as usr on usr.id = session.user_id
    where session.id = '<target_session_id>'::uuid
      and usr.email = 'ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid'
  );

delete from auth.sessions
where id = '<target_session_id>'::uuid
  and user_id = (
    select id
    from auth.users
    where email = 'ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid'
  );
```

Read back independently. Continue only when both target counts are 0 and
the opposite session is still one live row (`not_after` null or future):

```sql
select count(*) as target_session_rows
from auth.sessions
where id = '<target_session_id>'::uuid;

select count(*) as target_refresh_rows
from auth.refresh_tokens
where session_id = '<target_session_id>'::uuid;

select session.id, session.not_after
from auth.sessions as session
join auth.users as usr on usr.id = session.user_id
where session.id = '<opposite_session_id>'::uuid
  and usr.email = 'ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid'
  and (session.not_after is null or session.not_after > now());
```

`target_session_rows` and `target_refresh_rows` must be 0. The opposite
query must return exactly one row. For N4 that opposite row is the B
session. For N5 it is the A source session. If the opposite row is missing,
do not type `continue`.

Keep a count receipt. It has uuids and counts only:

```json
{"action":"revoke_a_source_session","targetSessionId":"<target_session_id>","targetSessionRows":0,"targetRefreshRows":0,"oppositeSessionId":"<opposite_session_id>","oppositeSessionRows":1}
```

Then write `continue`.

Acceptance ids match Atlas MC1545 J. Receipt rows use these same ids.

- P1. Canary shape. The marker text is `ari-probe-marker-` plus the
  20-character TEST project ref.
- P2. B via the second consent.
- P3. Discovery and initialize.
- P4. `listTools`.
- P5. Marker read.
- N1. Token A offered to the B store is rejected and is not stored. This
  run does that in-process.
- N2. Wrong user. Not executed by this run. A second synthetic user is a
  later controller run. This packet does not create one.
- N3. Wrong agent, client, or resource. Not executed by this run.
- N4. A source-session revocation on a fresh pair after the positive proof.
  The parent prints `revoke_a_source_session` with that pair's
  `source_session_id` and `b_session_id`. Delete only the A source. B must
  still be live. The next tool call must fail closed at liveness with zero
  marker requests. Do not use a service-role shortcut. This is not the B
  grant. Do not run N5 on this source session.
- N5. B-session revocation on a second fresh pair. The A source for this
  pair stays live. Delete only the B auth session after the same readback.
  The next tool call must fail closed at liveness with zero marker
  requests. N5 is not a refresh-token exercise and is not an A-liveness
  denial left over from N4. This packet does not keep refresh tokens.
- N6. Hook-bypass F1. Not executed by this run. `sql/06` covers
  `public.ari_probe_marker` only.
- N7. `openid` on A or B. Not executed by this run. A structured 403 from
  the hook is the later check. This id is not Atlas N6.
- N8. An unbound B token, or a B token whose handshake fields do not all
  match, is not stored. Not executed by this run. This id is not Atlas N5.

N2, N3, N6, N7, and N8 are labelled `not_executed` on the receipt. They are
not passed.

## Honest gaps

`run` executes P1–P5 and N1 on one pair, then N4 and N5 on two later fresh
pairs, against the configured issuer. On the synthetic loopback that issuer
is not hosted TEST. N2, N3, N6, N7, and N8 are not executed. Restarting the
process drops B; this CLI does not prove that restart. The subprocess test
is synthetic loopback. It is not hosted client delivery, not acceptance,
and not a new G5 PASS. `sql/05` in this commit checks the caller B session
as well as the A source and must be re-reviewed at this exact head before
any apply. The hook is not installed. SQL is not applied. No client is
registered. No durable B custody and no refresh retention.

## Rollback

On `odbcejsuuqdzhabjmozi` only, after the hook is disabled:

```sql
select set_config('ari.project_ref', 'odbcejsuuqdzhabjmozi', false);
drop function if exists public.ari_probe_source_session_live_v1(uuid, text);
drop policy if exists ari_probe_marker_reject_a_client on public.ari_probe_marker;
delete from ari_probe.mcp_client where probe_label = 'ari-test-external-a';
drop table if exists ari_probe.downstream_client;
```

Re-apply the function body from `sql/04-hook-v2-for-ariadne.sql` if the hook
must return to the baseline A mapping. Do not delete
`probe_label = ari-test-synthetic`. Do not drop the synthetic user, the
marker row, or `mcp_ingress`.

N4 and N5 deletion during `run` is the readback above: one target session,
a zero-row session and refresh readback, and the opposite session still
live. After `run`, finish cleanup from `oauth-session-cleanup.md`. Delete
and read back every receipt-linked password session, A source session, and
B session, including each one's refresh rows. If you already typed
`continue` for N4, `n4.sourceSessionId` is already gone and reads zero. If
you already typed `continue` for N5, `n5.bSessionId` is already gone and
reads zero. Those zeros are expected. Keep cleaning the other ledger ids.
Leave the synthetic user, the marker fixture, `mcp_ingress`, and any
baseline `auth.sessions` row the receipt does not name. Do not delete the
decoy `session_id` claim. That value is not an `auth.sessions` row. Ledger
ids are not Token A and not bearers.
