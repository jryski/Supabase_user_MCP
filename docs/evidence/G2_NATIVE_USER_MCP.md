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
| Token A | Inbound `Authorization: Bearer` JWT. `withSupabase({ auth: 'user' })` verifies signature, `kid`, expiry, configured issuer (`{supabaseUrl}/auth/v1`), and MCP resource audience against the supplied asymmetric JWKS or JWKS URL. The handler then requires `role=authenticated`, `aud` containing `authenticated`, server-controlled `client_id`, a UUID `sub` and `session_id`, and rejects `user_metadata` authority fields. |
| Token B | Unresolved. No second Data API client is created. A verified Token A returns `403` `{ "error": "downstream_credential_unresolved" }`. |

G5 / MC1418: a stock single-grant BYO-MCP path that forwards the inbound JWT to the Data API
is not MCP `2026-07-28` conformant. `withSupabase` still constructs that same-bearer user
client, and an admin client, before the handler runs. G2 does not call either client. Their
`fetch` implementation throws `downstream_credential_unresolved` if invoked. The admin client
is built with the fixed non-credential placeholder `g2-unused-admin-client-not-a-credential`,
not with `SUPABASE_SECRET_KEY` or a service-role JWT. Explicit `env` is passed so process
environment secrets are not read.

Same-bearer passthrough is not the finished design.

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
