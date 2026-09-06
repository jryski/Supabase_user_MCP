# Issue 62: experimental local remote HTTP + OAuth 2.1

- **Issue:** [#62](https://github.com/jryski/Supabase_user_MCP/issues/62) (parent [#60](https://github.com/jryski/Supabase_user_MCP/issues/60))
- **Profile:** experimental local loopback only
- **Hosted live OAuth:** unmet
- **Privileged user-path credentials:** none

## What this evidence covers

- Dual-bound access tokens: JWT `aud` must include `authenticated` and the canonical MCP
  resource `https://mcp.loopback.invalid/mcp`. `aud=authenticated` or `client_id` alone is
  rejected at MCP before any Data API call.
- Synthetic in-process PKCE authorization server covering consent approve/deny, exact
  redirect, S256, refresh rotation that does not kill prior access tokens, and
  access-token fingerprint revocation distinct from grant revoke.
- RFC 9728 protected-resource metadata and `WWW-Authenticate` `resource_metadata` on 401.
- Request-scoped MCP servers over `WebStandardStreamableHTTPServerTransport` with
  `enableJsonResponse: true`. The MCP layer receives a redacted `AuthInfo.token`.
- Process-global principal-scoped rate-limit counters surviving request-scoped rebuilds.
- SQL `policy_lab.verified_client_id()` using top-level `client_id` else
  `app_metadata.client_id`, never `user_metadata`, including same-user/different-client,
  different-user, spoofed `user_metadata.read_only`, dual `aud`, and permissive-policy
  detection.
- Local CLI `[auth.oauth_server]` with DCR disabled and an in-lab Custom Access Token Hook
  that adds the MCP resource only when a top-level OAuth `client_id` is present. Password-grant
  M2 tokens are unchanged.
- MCP TypeScript SDK `Client` + `StreamableHTTPClientTransport` against the local resource after
  a real GoTrue PKCE/consent round trip. External MCP clients remain unmet.

## What this evidence does not cover

- Hosted Supabase projects, real human login, tunnels, or public listeners.
- External MCP clients (Claude Desktop, Cursor, etc.) against a public origin. The local lab
  uses the official MCP TypeScript client only.
- Asymmetric JWKS verification against a hosted GoTrue.
- Production readiness or a stable remote deployment.

## Executable seams

| Layer | Seam |
| --- | --- |
| Contracts | `packages/contracts/src/remote-oauth-http-policy.ts` |
| Verifier / synthetic AS | `packages/server/src/remote-token-verifier.test.ts`, `synthetic-oauth-lab.test.ts` |
| HTTP profile | `packages/server/src/remote-http-profile.test.ts` |
| SQL | `supabase/tests/database/oauth_client_claim_test.sql` |
| Local Auth PKCE | `packages/server/src/local-oauth-pkce.e2e.test.ts` via `npm run test:remote-oauth` |

## Reproduction

```shell
npm ci
npm run check
npm run test:remote-oauth
```

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
5. MCP `requireBearerAuth` verifies the ES256 signature via GoTrue JWKS, dual binding, client
   id, and live `GET /auth/v1/user`. HMAC `JWT_SECRET` is not used for live Auth tokens.
6. Request-scoped Data API calls use the same JWT against the fixed origin.
7. Logout of that access token yields 401 on the next MCP request while `exp` is still in
   the future.

No access token, refresh token, JWT secret, or service-role key is written to this document
or to operational events.
