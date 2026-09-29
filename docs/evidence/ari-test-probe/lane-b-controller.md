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
| N4 | A-session revocation only. Revoke or delete the Token A source session. Not the B grant. |

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
- `ARI_FIRST_PARTY_ACCESS_TOKEN`
- `ARI_TEST_PUBLISHABLE_KEY` (parent only)
- `ARI_TEST_JWKS_JSON` (parent only)
- `ARI_TEST_SUPABASE_URL` (parent only; the child discovers the issuer)

First-party consent stays in the browser. The CLI never reads a bearer from
stdin. Stdout `controller_action` lines are the only consent prompt:

```json
{"type":"controller_action","action":"open_authorization","flow":"external_a","authorizationUrl":"https://…","state":"…"}
```

`flow` is `external_a` or `downstream_b`. Open `authorizationUrl` in the
browser. The redirect returns to loopback with `code` and `state` only. Do
not copy the code into the shell. The last stdout line is a receipt with
`acceptance: false`. It has no token, code, or refresh token.

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
export ARI_AGENT_ID=<trusted agent id>
node scripts/run-ari-test-external-e2e.mjs plan
node scripts/run-ari-test-external-e2e.mjs run
```

When a `controller_action` line appears, open that URL in the browser where
the TEST user already has a session. External A redirects to
`/oauth/callback`. B redirects to `/oauth/downstream/callback`. The parent
binds B only when that callback `state` matches the handshake for the
verified A. A green receipt still has `acceptance: false`. Hosted contact is
not acceptance, not a hook install, and not a G5 re-PASS.

Positive checks the controller records later, without pasting tokens:

- P1. External A reaches the loopback MCP resource and the receipt shows one
  downstream handshake.
- P2. After the B callback, the marker tool is called with B.
- P3. The Data API bearer is B, not A.
- P4. Liveness is called with A's `source_session_id` and A's client id.
- P5. Restarting the process loses B. The next call asks for a new handshake.
  This CLI does not prove P5. B is in memory only.

Negative checks. Not executed by `run`. Atlas J keeps A-session revocation
and B-session revocation as separate cases. This runbook used to fold both
into N4. That was drift.

- N1. Token A used as B is rejected and is not stored.
- N2. A second synthetic user is a controller step. This packet does not create one.
- N3. A dead or mismatched A session fails closed before tool dispatch.
- N4. A-session revocation. Revoke or delete the Token A `source_session_id`.
  The next MCP call must fail closed at liveness, before tool dispatch. Do
  not use a service-role shortcut. This is not the B grant delete.
- N5. An unbound B token, or a B token whose handshake fields do not all
  match, is not stored.
- N6. `openid` on A or B is a structured 403 from the hook.
- N7. B-session revocation. From a first-party session for the same user,
  delete the B grant, or admin-delete that B `auth.sessions` row. The next
  MCP call must fail closed. N7 is not a refresh-token exercise. This packet
  does not keep refresh tokens.

N7 grant delete, parent shell only. The CLI does not accept this bearer:

```bash
curl -sS -X DELETE \
  "$ARI_TEST_SUPABASE_URL/auth/v1/user/oauth/grants?client_id=$ARI_DOWNSTREAM_CLIENT_ID" \
  -H "Authorization: Bearer $ARI_FIRST_PARTY_ACCESS_TOKEN" \
  -H "apikey: $ARI_TEST_PUBLISHABLE_KEY"
```

`$ARI_FIRST_PARTY_ACCESS_TOKEN` is the user's own session, not Token A and
not a service-role key. Unset it before `run`.

## Honest gaps

`run` does not execute N1–N7 or P5. The subprocess test is synthetic
loopback. It is not hosted client delivery, not acceptance, and not a new
G5 PASS. The hook is not installed. SQL is not applied. No client is
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

Session cleanup for the real A `source_session_id` stays in
`oauth-session-cleanup.md`. Do not delete the decoy `session_id` claim. That
value is not an `auth.sessions` row.
