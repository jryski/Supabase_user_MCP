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
  exact-ceiling overflow, deadline expiry, and disconnect before handler execution.
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
