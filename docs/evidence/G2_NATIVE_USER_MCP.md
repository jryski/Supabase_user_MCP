# G2 native-user MCP adapter

- **Status:** Draft. Not merged. Not issue #62 completion.
- **Base:** `main`
- **Package pin:** `@supabase/server@1.9.2` (MIT) and peer `@supabase/supabase-js@2.117.2` (MIT)

## What this is

The smallest Node fetch adapter that verifies MCP-facing auth with upstream Supabase Auth
through the stable nested middleware form documented in `@supabase/server` 1.9.2
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
| Token B | Not held by the bare adapter: without `onVerified`, a resource-only Token A returns `403` `{ "error": "downstream_credential_unresolved" }`. The opt-in read composition (`createNativeUserMcpReadHandler`) binds a distinct grant B through a one-time PKCE handshake for the same verified principal, checks source-session liveness with B before every dispatch, and runs the fixed read tools with B only. See [ADR-0005](../decisions/0005-dual-resource-data-api-binding.md) Option D. |

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

This repository does not contain or apply the `mcp_ingress` Postgres role or
the Auth hook that mints Token A with a resource-only `aud`, `role=mcp_ingress`,
`agent_id`, and `source_session_id`. Those are operator inputs for a disposable
TEST project, and Primary Users leave any such hook disabled until an
independent reviewer approves the exact head.

The only database object the read composition calls is
`public.source_session_live_v1`, defined in
[`sql/liveness/source_session_live_v1.sql`](../../sql/liveness/source_session_live_v1.sql).
It is not a migration and nothing here applies it. The read composition calls
it with Token B before every dispatch; anything other than JSON `true` fails
closed. The bare adapter has no liveness check. The check is not a revocation
receipt. No live probe was run for this change.

## Still open

- Upstream authority denial. This check does not make PostgREST, Storage, GraphQL,
  or Realtime reject a bearer. Data API capability of a presented credential is
  not closed.
- Token B custody. The read composition holds grant B in process memory only;
  there is no durable custody, and the bare adapter stays fail-closed.
- Live OAuth issuance and a real MCP client are not in this slice.

This is not acceptance and not direct-API separation.

G5: a stock single-grant BYO-MCP path that forwards the inbound JWT to the Data API
is not MCP `2026-07-28` conformant. Since `@supabase/server` 1.9.2, `withSupabase` builds
that same-bearer user client and the admin client lazily, on first access. G2 does not
access either client. The user client's `fetch` throws `downstream_credential_unresolved`
if invoked. No secret key is configured: explicit `env` carries an empty `secretKeys` set,
so the library never reads `SUPABASE_SECRET_KEY(S)` from the process environment, and
reading the admin client would fail. The earlier non-credential admin placeholder is
removed; a test proves verified dispatch works without it.

Same-bearer passthrough is not the finished design. The MCP-side audience check
above does not close upstream Data API denial. Token B comes from a separate
grant, not from this check.

## Preserved

Stdio startup, the fixed read-only tools, governors, verified-principal propagation on the
existing stdio client, bounds (`65,536` byte ingress, `2,000` ms body deadline), and
secret-free fail-closed receipts stay in place. The bare HTTP adapter does not replace them
and does not attach tool execution; only the opt-in read composition does, with grant B.

## Residual gaps (G3)

- Do not point Data API calls at the library user client. Data API calls use grant B
  from the read composition only.
- Live access-token revocation is not performed. An unexpired revoked JWT reaches the
  fail-closed `403` instead of a revocation denial.
- The bare fetch handler does not mount the read-only `McpServer`. The read composition
  mounts it per request with grant B.
- Hosted OAuth, consent, dynamic client registration, Pages, and DNS are out of scope.
  Issue #62 remains incomplete.
