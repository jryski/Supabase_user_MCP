# Issue 62: experimental local remote HTTP + OAuth 2.1

- **Issue:** [#62](https://github.com/jryski/Supabase_user_MCP/issues/62) (parent [#60](https://github.com/jryski/Supabase_user_MCP/issues/60))
- **Profile:** experimental local loopback only; Data API dispatch fail-closed
- **Hosted live OAuth:** unmet
- **Downstream credential:** unresolved
- **Issue #62 completion:** no
- **Privileged remote-CLI credentials:** rejected (HMAC/JWT signing secrets and `service_role` are forbidden in startup env). Synthetic HMAC remains confined to the in-process authorization-server fixture.

## What this evidence covers

- Dual-bound MCP tokens: JWT `aud` must include `authenticated` and the canonical MCP
  resource `https://mcp.loopback.invalid/mcp`. Dual audience does **not** authorize forwarding
  that bearer to the Data API.
- After a valid MCP bearer, the remote handler returns `downstream_credential_unresolved`
  and makes zero `/rest/v1` calls with that Authorization header.
- Wrong-client bearers fail at MCP verification before dispatch, with zero Data API calls.
- Synthetic in-process PKCE authorization server covering consent approve/deny, exact
  redirect, S256, refresh rotation that does not kill prior access tokens, and
  access-token fingerprint revocation distinct from grant revoke.
- RFC 9728 protected-resource metadata and `WWW-Authenticate` `resource_metadata` on 401.
- Process-global principal-scoped rate-limit counters surviving executor rebuilds (stdio path).
- SQL `policy_lab.verified_client_id()` using top-level `client_id` else
  `app_metadata.client_id`, never `user_metadata`.
- Local CLI `[auth.oauth_server]` with DCR disabled. Live GoTrue tokens are ES256 and verified
  via JWKS, not HMAC `JWT_SECRET`.
- HTTP ingress rejects oversized chunked bodies (including 4MiB without Content-Length),
  exact-ceiling overflow, deadline expiry, disconnect, forbidden methods such as TRACE, and
  malformed Host values before handler execution. Request-construction failures settle through
  the same reader cleanup path and return a bounded 4xx instead of an uncaught callback exception.
- Real local GoTrue PKCE/consent (GET authorization details then POST consent `redirect_url`).
  This fixture obtains a token and posts it to the in-process handler. It does **not** prove a
  supported MCP client performing discovery/PKCE/consent UI itself.

## What this evidence does not cover

- A supported separate short-lived Data API credential that is not the inbound MCP bearer.
- Remote `memory_*` tool execution over HTTP.
- Hosted Supabase projects, real human login, tunnels, or public listeners.
- External MCP clients (Claude Desktop, Cursor, etc.) against a public origin.
- Asymmetric JWKS verification against a hosted GoTrue.
- Production readiness or a stable remote deployment.
- Completion of issue #62.

## Executable seams

| Layer | Seam |
| --- | --- |
| Contracts | `packages/contracts/src/remote-oauth-http-policy.ts` |
| Verifier / synthetic AS | `packages/server/src/remote-token-verifier.test.ts`, `synthetic-oauth-lab.test.ts` |
| HTTP profile | `packages/server/src/remote-http-profile.test.ts` |
| Ingress | `packages/server/src/remote-http-startup.test.ts` |
| SQL | `supabase/tests/database/oauth_client_claim_test.sql` |
| Local Auth PKCE | `packages/server/src/local-oauth-pkce.e2e.test.ts` via `npm run test:remote-oauth` |

## Reproduction

```shell
npm ci
npm run check
npm run test:remote-oauth
```

`npm run check` skips the live PKCE e2e unless `M4_*` env is present.
`test:remote-oauth` requires a clean worktree, Docker loopback-only networking, and the
pinned local Supabase CLI. It registers temporary OAuth clients and synthetic users inside
the disposable lab only.

## Token trace (local lab)

1. Pre-register a public client (`token_endpoint_auth_method=none`, exact redirect).
2. Authorization code + PKCE S256 + `resource=https://mcp.loopback.invalid/mcp`.
3. Official consent sequence (same as `@supabase/auth-js` `oauth.getAuthorizationDetails` then
   `approveAuthorization`): `GET /auth/v1/oauth/authorizations/{id}` binds the fixture user,
   then `POST .../consent` with `{action:"approve"}` returns `redirect_url` (no browser UI,
   no listener on Site URL).
4. Token exchange. Custom Access Token Hook sets `aud=["authenticated", MCP resource]` and
   `resource`.
5. MCP `requireBearerAuth` verifies the ES256 signature via GoTrue JWKS, dual binding, the
   configured client id, and live `GET /auth/v1/user`. HMAC signing secrets are not used.
6. Valid MCP bearer receives `403 downstream_credential_unresolved`. The inbound Authorization
   value is not sent to `/rest/v1`.
7. Logout of that access token yields 401 on the next MCP request while `exp` is still in
   the future.

No access token, refresh token, JWT secret, or service-role key is written to this document
or to operational events.

## 2026-09-22 downstream-credential recheck

[ADR-0006](../decisions/0006-downstream-credential-recheck.md) re-read current Supabase OAuth
docs, `supabase/auth` master `ce9a8eee0cc042be8c7a42981a7ddae631e41d91`, and MCP `2026-07-28`.
No supported grant mints a second user-bound Data API credential. Remote dispatch stays
fail-closed. This note does not complete issue #62.

Executable hooks added with that ADR:

- `DOWNSTREAM_CREDENTIAL_RECHECK_2026_09_22` in `packages/contracts/src/remote-oauth-http-policy.ts`
- HTTP profile denial of missing resource binding and a conflicting `resource` before
  `downstream_credential_unresolved`, with zero outbound `Authorization` headers

## Suggested comment for issue #62

The block below is paste-ready text. This change does not post it.

````markdown
## Downstream credential recheck — 2026-09-22

Base under review: `fcbaca121d0717ee8ff98df90b2f12475b05bb78` (PR #75).
This follow-up is a design and regression scaffold only. Remote Data API dispatch stays
fail-closed with `downstream_credential_unresolved`. No merge to main. Not #62 completion.

### Finding

No supported non-passthrough mechanism currently yields a second short-lived user-bound Data
API credential (same subject and server-controlled client, not the inbound MCP bearer, no
`service_role`). A dual-grant broker is still an unapproved architecture. I did not implement one.

Pinned on 2026-09-22 (detail and proof bars are in ADR-0006):

- Supabase docs `ef0f7f2b3d8cd2075c48b7d94b2badd59c4721b9`, `oauth-flows.mdx`: OAuth 2.1 server
  grant types are only `authorization_code` and `refresh_token`. The page's "token exchange"
  section is authorization-code redemption, not RFC 8693.
- `supabase/auth` master `ce9a8eee0cc042be8c7a42981a7ddae631e41d91`: `POST /token` accepts
  `password`, `refresh_token`, `id_token`, `pkce`, and `web3` only. The OAuth server token
  handler accepts `authorization_code` and `refresh_token` only.
- supabase/auth#2609 is still open. Its RFC 8693 grant is provider access-token sign-in
  (Facebook), not an MCP resource token exchanged for a Data API token, and it is not on master.
- The MCP authentication guide still says the MCP server sends the Supabase-issued access token
  to Supabase APIs. That is inbound-bearer use. MCP 2026-07-28 forbids passing that token through
  to an upstream API.
- Enterprise ID-JAG remains Supabase's operated management MCP. Custom Auth-backed MCP servers
  are pointed at the MCP authentication guide.
- A Custom Access Token Hook edits the same issued JWT. Refresh of the MCP grant is the same
  authorization, and this server does not custody the client refresh token.

### What did not change

Stdio still loads one protected user access token and calls the fixed Data API as that user.
After a valid MCP bearer, remote HTTP still returns `403 downstream_credential_unresolved` and
makes no `/rest/v1` call. Missing resource binding and a conflicting `resource` still fail with
`401` before that response. The inbound bearer is not forwarded.

### Decision needed

1. Wait for a documented Supabase grant that mints a distinct Data API token for the same
   subject and client, with the proof list in ADR-0006 (Option 1).
2. Separately approve a dual-grant broker (MCP-facing token plus a distinct Supabase
   authorization-code grant and refresh custody). That is a new authorization boundary
   (ADR-0006 Option 2), not an #62 patch.
3. Keep fail-closed and leave #62 open (ADR-0006 Option 3, current disposition).

I recommend (3) until you explicitly choose (1) or (2). Option (2) should not start without
the custody decision ADR-0006 lists.
````
