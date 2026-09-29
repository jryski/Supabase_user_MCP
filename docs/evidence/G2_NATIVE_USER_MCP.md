# G2 native-user MCP adapter

- **Status:** Draft scaffold. Not merged. Not issue #62 completion.
- **Base:** `ariadne/remote-oauth-rebased-20260919` @ `fcbaca121d0717ee8ff98df90b2f12475b05bb78`
- **Package pin:** `@supabase/server@1.7.2` (MIT) and peer `@supabase/supabase-js@2.117.2` (MIT)

## What this is

The smallest Node fetch adapter that verifies MCP-facing auth with upstream Supabase Auth
through the stable nested middleware form documented in `@supabase/server` 1.7.2
`docs/mcp.md`:

```ts
withOAuthProtectedResource(
  { resourceServer, authorizationServer: fromSupabaseUrl(supabaseUrl) },
  withSupabase({ auth: 'user' }, handler),
)
```

The config-only `pipeline([...])` entry form is alpha in that package and is not used.
This branch does not add an MCP issuer, JWKS authorization server, authorize/token/revoke
routes, or a lab dual-grant broker.

## Token A and Token B

| Credential | Role on this branch |
| --- | --- |
| Token A | Inbound `Authorization: Bearer` JWT. `withSupabase({ auth: 'user' })` verifies signature, `kid`, expiry, configured issuer (`{supabaseUrl}/auth/v1`), and MCP resource audience against the supplied asymmetric JWKS or JWKS URL. The handler then requires configured `role=mcp_ingress` and rejects `role=authenticated`, plus server-controlled `client_id`, a UUID `sub`, and a `session_id` that is a non-nil UUID (empty and nil are rejected), and a resource-only `aud`: exactly one value, as a string or a true singleton array, that canonicalizes to the MCP resource. Any other `aud` length or value, or any other role, is `401` `{ "error": "invalid_token" }`. The handler rejects `user_metadata` authority fields. Configuring an ingress role other than `mcp_ingress` is a config error. |
| Token B | Unresolved. No second Data API client is created. A resource-only Token A returns `403` `{ "error": "downstream_credential_unresolved" }`. |

## Fixed in this slice: MCP-side intended-recipient check

`aud` must be resource-only: exactly one value, either a string or a true
singleton array, and that value must canonicalize to the configured MCP resource.
`withSupabase({ audience: resource })` uses jose, which treats any matching array
entry as success, so the library alone accepts `[resource, other]`,
`[resource, "authenticated"]`, duplicate `[resource, resource]`, and a
case-variant co-audience that is not a true singleton. The local predicate
rejects those with `401` `{ "error": "invalid_token" }`. A resource-only string
or singleton `[resource]` passes auth and then hits the existing fail-closed
`403` `downstream_credential_unresolved`. Role, client, session, issuer,
signature, and expiry checks stay in place. The handler rejects `user_metadata`
authority fields. This is not acceptance and not direct-API separation.

## Ingress role check (L2)

Token A `role` must be the configured ingress role `mcp_ingress`.
`role=authenticated` is `401` `{ "error": "invalid_token" }`. Any other role
is the same denial. This is the MCP-edge check only. It does not create the
Postgres role, install the Auth hook, or prove upstream Data API denial.

## Not shipped

`docs/evidence/ari-test-probe/sql/03-mcp-ingress-role.sql` is controller SQL
for project `odbcejsuuqdzhabjmozi` only. This branch does not apply it.
`sql/04-hook-v2-for-ariadne.sql` is the uninstalled hook v2 packet: absent
`client_id` stays unchanged, `openid` raises for every OAuth client, an
unmapped `client_id` raises, and the mapped client rewrites `aud`, `role`,
and `session_id` while checking the original session on each call. That
liveness check is not a revocation receipt. `sql/02` must not be applied.
The live probe was not run. Token B is not wired into the MCP tool path.
This is not acceptance.

## Still open

- Upstream authority denial. This check does not make PostgREST, Storage, GraphQL,
  or Realtime reject a bearer. Data API capability of a presented credential is
  not closed.
- Token B. No distinct Data API credential exists. Dispatch stays fail-closed.
- Live OAuth issuance and a real MCP client are not in this slice.

This is not acceptance and not direct-API separation.

G5 / MC1418: a stock single-grant BYO-MCP path that forwards the inbound JWT to the Data API
is not MCP `2026-07-28` conformant. `withSupabase` still constructs that same-bearer user
client, and an admin client, before the handler runs. G2 does not call either client. Their
`fetch` implementation throws `downstream_credential_unresolved` if invoked. The admin client
is built with the fixed non-credential placeholder `g2-unused-admin-client-not-a-credential`,
not with `SUPABASE_SECRET_KEY` or a service-role JWT. Explicit `env` is passed so process
environment secrets are not read.

Same-bearer passthrough is not the finished design. The MCP-side audience check
above does not close upstream Data API denial or Token B.

## Preserved

Stdio startup, the fixed read-only tools, governors, verified-principal propagation on the
existing stdio client, bounds (`65,536` byte ingress, `2,000` ms body deadline), and
secret-free fail-closed receipts stay in place. This HTTP adapter does not replace them and
does not attach tool execution.

## Residual gaps (G3)

- Token B still does not exist. Do not point Data API calls at the library user client.
- Live access-token revocation is not performed. An unexpired revoked JWT reaches the
  fail-closed `403` instead of a revocation denial.
- The existing read-only `McpServer` is not mounted on this fetch handler. Tool dispatch
  waits on a distinct downstream credential.
- Hosted OAuth, consent, dynamic client registration, Pages, and DNS are out of scope.
  Issue #62 remains incomplete.
