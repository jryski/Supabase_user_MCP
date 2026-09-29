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
| N4 | A source-session revocation. Not the B grant. |
| N5 | B-session revocation. A first-party B auth session, not a refresh token. |

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

```bash
git fetch origin cursor/supabase-native-user-mcp-g2
git rev-parse origin/cursor/supabase-native-user-mcp-g2
git rev-parse origin/cursor/supabase-native-user-mcp-g2^{tree}
```

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
`ARI_TEST_SYNTHETIC_PASSWORD`, then GETs and POSTs
`/auth/v1/oauth/authorizations/{id}`. Supabase `/oauth/authorize` does not
return a code. It redirects to the Site URL consent page, and that page is
not deployed. The code is issued only after the consent POST. The parent
then GETs `redirect_url` so the code lands on the loopback callback.

`ARI_TEST_SYNTHETIC_PASSWORD` stays in the parent environment. It is not
copied to the child, not written to stdout or stderr, and not read from
stdin. The receipt carries `passwordSessionId` for cleanup. That id is not
a bearer.

The CLI never reads a bearer from stdin. After P5 it prints a
`controller_action` and waits for one stdin line whose text is exactly
`continue`:

```json
{"type":"controller_action","action":"revoke_a_source_session","source_session_id":"<uuid>"}
```

```json
{"type":"controller_action","action":"revoke_b_session","b_session_id":"<uuid>"}
```

Do not paste a token, password, or code on that line. The last stdout line
is a receipt with `acceptance: false`. It has no token, code, or refresh
token. Rows use the Atlas MC1545 J ids.

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

```bash
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

When `revoke_a_source_session` appears, revoke that `source_session_id` out
of band, then write a line that is exactly `continue`. When
`revoke_b_session` appears, revoke that B auth session out of band, then
write `continue` again. The child then makes one more tool call. The row
passes only when that call fails closed at liveness and the marker is not
requested.

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
- N4. A source-session revocation. After P5, the parent prints
  `revoke_a_source_session` with `source_session_id`, waits for `continue`,
  and the next tool call must fail closed at liveness with zero marker
  requests. Do not use a service-role shortcut. This is not the B grant.
- N5. B-session revocation. Same continue pattern for the B auth session.
  The next tool call must fail closed at liveness with zero marker
  requests. N5 is not a refresh-token exercise. This packet does not keep
  refresh tokens.
- N6. Hook-bypass F1. Not executed by this run. `sql/06` covers
  `public.ari_probe_marker` only.
- N7. `openid` on A or B. Not executed by this run. A structured 403 from
  the hook is the later check. This id is not Atlas N6.
- N8. An unbound B token, or a B token whose handshake fields do not all
  match, is not stored. Not executed by this run. This id is not Atlas N5.

N2, N3, N6, N7, and N8 are labelled `not_executed` on the receipt. They are
not passed.

## Honest gaps

`run` executes P1–P5, N1, N4, and N5 against the configured issuer. On the
synthetic loopback that issuer is not hosted TEST. N2, N3, N6, N7, and N8
are not executed. Restarting the process drops B; this CLI does not prove
that restart. The subprocess test is synthetic loopback. It is not hosted
client delivery, not acceptance, and not a new G5 PASS. The hook is not
installed. SQL is not applied. No client is registered. No durable B custody
and no refresh retention.

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

Session cleanup for the real A `source_session_id` stays in
`oauth-session-cleanup.md`. Do not delete the decoy `session_id` claim. That
value is not an `auth.sessions` row. `passwordSessionId` on the receipt is
the synthetic password-grant session created for consent. Clean that session
up on TEST only. It is not Token A and not a bearer.
