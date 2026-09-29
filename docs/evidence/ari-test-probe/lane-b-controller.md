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
| N4 | The real user revokes the OAuth grant from a first-party session, or an admin deletes that session. Do not substitute a service-role shortcut as the N4 proof. |

## G5 before any hosted write

Warden reviews the exact commit you are about to apply. Stop if the reviewed
tree is not the pushed Lane B head. Do not enable Authentication → Hooks,
do not run the SQL, and do not start the external client until that review
is recorded.

```bash
git fetch origin cursor/supabase-native-user-mcp-g2
git rev-parse origin/cursor/supabase-native-user-mcp-g2
git rev-parse origin/cursor/supabase-native-user-mcp-g2^{tree}
```

Parent of the Lane B commit must be
`6e142ed510bab5c6b15312e0d25530f5840d0424`.

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

## Live loopback, after G5

```bash
unset SUPABASE_SERVICE_ROLE_KEY SUPABASE_SECRET_KEY SERVICE_ROLE_KEY SUPABASE_SERVICE_KEY
export ARI_LANE_B_LIVE=controller-g5
export ARI_LANE_B_G5_HEAD=<reviewed commit sha>
export ARI_TEST_PROJECT_REF=odbcejsuuqdzhabjmozi
export ARI_TEST_SUPABASE_URL=https://odbcejsuuqdzhabjmozi.supabase.co
export ARI_EXTERNAL_MCP_URL=http://127.0.0.1:8788/mcp
export ARI_DOWNSTREAM_REDIRECT_URI=http://127.0.0.1:8788/oauth/downstream/callback
node scripts/run-ari-test-external-e2e.mjs plan
node scripts/run-ari-test-external-e2e.mjs run
```

The child process may print authorization URLs, authorization codes, and
OAuth `state` only. It must not print Token A, Token B, or a refresh token.
The parent completes consent in the browser. B is bound only when the
callback `state` matches the handshake minted for that verified A.

Positive checks the controller records later, without pasting tokens:

- P1. External A calls the loopback MCP resource and receives
  `downstream_authorization_required` plus one handshake.
- P2. After the B callback, a marker read returns the TEST marker using B.
- P3. The Data API request's bearer is B, not A.
- P4. Liveness is called on that request with A's `source_session_id` and
  A's client id.
- P5. Restarting the process loses B and the next call asks for a new handshake.

Negative checks:

- N1. Token A used as B is rejected and not stored.
- N2. A second synthetic user is a controller step. This packet does not create one.
- N3. A dead or mismatched A session fails closed before tool dispatch.
- N4. From a first-party session for the same user, revoke the B grant:

```bash
curl -sS -X DELETE \
  "$ARI_TEST_SUPABASE_URL/auth/v1/user/oauth/grants?client_id=$ARI_DOWNSTREAM_CLIENT_ID" \
  -H "Authorization: Bearer $ARI_FIRST_PARTY_ACCESS_TOKEN" \
  -H "apikey: $ARI_TEST_PUBLISHABLE_KEY"
```

  `$ARI_FIRST_PARTY_ACCESS_TOKEN` is the user's own session, not Token A and
  not a service-role key. An admin delete of that `auth.sessions` row is the
  other N4 path. The next MCP call must fail closed. N4 is not a refresh-token
  exercise. This packet does not keep refresh tokens.
- N5. An unbound B token, or a B token whose handshake fields do not all
  match, is not stored.
- N6. `openid` on A or B is a structured 403 from the hook.

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
