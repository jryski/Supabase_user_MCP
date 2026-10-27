# Native-first consent block

## What upstream ships

`@supabase/server` 1.9.2 has no consent screen or consent helper. Its MCP guide
(`docs/mcp.md`, "Supabase Auth prerequisites") lists "a consent screen hosted in
the app's frontend" as a project prerequisite. The package covers discovery
(`withOAuthProtectedResource`) and token verification (`withSupabase`) only.

The official consent building blocks are in supabase-js (2.117.2 here, bundled
auth-js 2.117.2), under `supabase.auth.oauth`:

- `getAuthorizationDetails(id)`: `GET /auth/v1/oauth/authorizations/{id}`
  with the user's session.
- `approveAuthorization(id, options)`:
  `POST /auth/v1/oauth/authorizations/{id}/consent` with `{"action":"approve"}`.
- `denyAuthorization(id, options)`:
  `POST /auth/v1/oauth/authorizations/{id}/consent` with `{"action":"deny"}`.

Supabase Auth redirects the browser to Site URL + authorization path with an
`authorization_id`. This repo's local lab already sets
`[auth.oauth_server] authorization_url_path = "/oauth/consent"` with dynamic
registration off. Nothing here changes either value.

## What this change stages

`packages/server/src/oauth-consent.ts` (`createOAuthConsentBlock`) wraps exactly
those three methods and puts the existing client binding in front of them:

- the client id must equal the one server-controlled client id the MCP
  resource already binds (`expectedClientId`);
- the redirect URI must exactly equal a pre-registered URI (ADR-0005: exact
  redirect URIs, explicit consent);
- every requested scope must be in the configured allowlist, itself a subset of
  `openid email profile phone`;
- the authorization must belong to the signed-in user.

A request that fails the binding is never approved. On a decision it is denied
upstream and returned as `refused` without a redirect URL. Approval re-reads the
authorization before approving. A redirect URL from upstream (existing consent,
approve, or deny) is returned only when its origin and path match a bound URI.
Browser redirects are always skipped.

## What it does not do

- No new sign-in method. The block takes the `auth.oauth` namespace of a
  supabase-js client that already holds the user's session. Without a session it
  returns `sign_in_required` and makes no call.
- No Site URL or authorization path change; no config change.
- No hosted page, route, or deploy. Mounting it in a frontend is a later step.
- No change to token verification, the issuer, resource or client binding, the
  separate Data API token (ADR-0005), or the grant checks.

## Tests

`packages/server/src/oauth-consent.test.ts` drives a real supabase-js 2.117.2
client against a synthetic Auth server with a seeded in-memory session. It checks
the bound approve and deny paths, refusal plus upstream deny for a wrong client,
redirect URI or scope, user mismatch, missing session, redirect-out-of-binding,
upstream error mapping, input validation, and loose-binding configuration.
Mutation: removing the client or the user check fails the suite.
