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
| Cases | Atlas MC1545 J ids, verbatim: P1 canary shape, P2 B via second consent, P3 discovery and initialize, P4 listTools, P5 marker read, N1 A-as-B, N2 wrong user, N3 wrong agent/client/resource, N4 A source-session revocation, N5 B-session revocation, N6 hook-bypass F1. Extras are N7 openid and N8 unbound or mismatched B. |

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
- `ARI_TEST_SYNTHETIC_PASSWORD` (parent only; never logged)
- `ARI_FIRST_PARTY_ACCESS_TOKEN`
- `ARI_TEST_PUBLISHABLE_KEY` (parent only)
- `ARI_TEST_JWKS_JSON` (parent only)
- `ARI_TEST_SUPABASE_URL` (parent only; the child discovers the issuer)

Supabase `/auth/v1/oauth/authorize` answers 302 with the Site URL plus
`/oauth/consent?authorization_id=...`. It does not answer with a code. The
consent frontend is not deployed, and the Site URL is not this loopback, so
opening `authorizationUrl` in a browser cannot finish external A or
downstream B.

The parent performs consent for both flows with the synthetic user's password
session:

1. GET `authorizationUrl` with `redirect: manual`.
2. Take `authorization_id` from `Location`.
3. Password-login the synthetic user with `ARI_TEST_SYNTHETIC_PASSWORD`.
4. GET and POST `/auth/v1/oauth/authorizations/{authorization_id}` consent with that first-party bearer.
5. GET the returned `redirect_url` so `code` and `state` land on the loopback callback.
6. Put the password session id on the receipt for cleanup. The receipt has no password, bearer, or code.

The CLI never reads a bearer from stdin. After P5, stdout asks for revocation
and then waits for a line that is exactly `continue`:

```json
{"type":"controller_action","action":"revoke_a_source_session","source_session_id":"…"}
```

```json
{"type":"controller_action","action":"revoke_b_session","b_session_id":"…"}
```

`source_session_id` and `b_session_id` are session ids, not secrets. Revoke
that session out of band, then type `continue`. Do not type a password, a
bearer, or any other credential. The child then makes one more tool call.
The receipt row passes only when that call fails closed at liveness and the
marker is not requested again.

The last stdout line is a receipt with `acceptance: false`. Case ids match
Atlas MC1545 J. It has no token, code, or refresh token.

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
export ARI_TEST_SYNTHETIC_PASSWORD='<synthetic user password>'
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

The parent consents for external A and downstream B. External A lands on
`/oauth/callback`. B lands on `/oauth/downstream/callback`. The parent binds
B only when that callback `state` matches the handshake for the verified A.
A green receipt still has `acceptance: false`. Hosted contact is not
acceptance, not a hook install, and not a G5 re-PASS.

Receipt rows use these ids. Do not renumber them.

- P1. Canary shape. External A completes through parent consent.
- P2. B via second consent.
- P3. Discovery and initialize.
- P4. listTools.
- P5. Marker read. This id is the marker call, not a process restart.

This `run` also executes:

- N1. Offer Token A to the B store in-process. Pass only when the store rejects it and does not retain it.
- N4. A source-session revocation. The CLI prints `source_session_id`. Revoke that session, then type `continue`. The next tool call must fail closed at liveness with zero marker requests.
- N5. B-session revocation. The CLI prints `b_session_id`. Revoke that session, then type `continue`. Same fail-closed rule. N5 is not a refresh-token exercise. This packet does not keep refresh tokens.

Not executed by this run, and not silently passed:

- N2. Wrong user. A second synthetic user is a later controller run.
- N3. Wrong agent, client, or resource. A later controller run.
- N6. Hook-bypass F1. The hook is not installed.
- N7. `openid` on A or B.
- N8. Unbound or mismatched B.

Restarting the process drops B. That behavior has no Atlas id here. This CLI does not prove it.

## Honest gaps

N2, N3, N6, N7, and N8 are labelled `not_executed_by_this_run` with `passed: false`. The subprocess test is synthetic loopback. It is not hosted client delivery, not acceptance, and not a new G5 PASS. The hook is not installed. SQL is not applied. No client is registered. No durable B custody and no refresh retention.

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
