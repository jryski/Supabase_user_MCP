# ADR-0006: No supported non-passthrough Data API credential yet

- **Status:** Accepted as a recheck; remote data dispatch stays fail-closed
- **Date:** 2026-09-22
- **Owners:** Maintainers
- **Milestone:** M4 implementation
- **Related:** [ADR-0002](0002-remote-identity-chain.md), [ADR-0005](0005-dual-resource-data-api-binding.md). This ADR does not supersede either. It records a dated recheck and the proof bar for the next mechanism. It does not authorize a broker.

## Context

Issue #62 wants a remote HTTP MCP profile that reaches the existing fixed `memory_*` tools under
the caller's RLS. [ADR-0005](0005-dual-resource-data-api-binding.md) already rejected forwarding
the inbound MCP bearer and left dispatch fail-closed. A 2026-09-06 review found no native
Supabase RFC 8693 exchange from an MCP resource token to a Data API token, and treated a
dual-grant broker as an unapproved architecture.

This recheck asks whether, as of 2026-09-22, a supported mechanism now yields a second
short-lived user-bound Data API credential with the same subject and server-controlled client,
without forwarding the inbound MCP bearer and without `service_role` or owner-key minting.

## Current paths

### Stdio

`startReadOnlyStdioFromEnvironment` reads `SUPABASE_USER_MCP_ORIGIN` and one protected credential
file. `loadLocalCredentials` accepts exactly `projectPublishableKey` and `userAccessToken`.
`createFixedSupabaseClient` sends that user access token as `Authorization: Bearer` plus the
publishable key as `apikey` to fixed `/rest/v1` RPCs and `GET /auth/v1/user`. Postgres RLS sees
`auth.uid()` from that JWT. `policy_lab.verified_client_id()` reads top-level `client_id`, else
`app_metadata.client_id`, never `user_metadata`. The credential is process-scoped and represents
one user. This path stays the only data-capable profile.

### Remote HTTP

`createRemoteHttpProfile` verifies the inbound bearer (issuer, `role=authenticated`, subject,
configured `client_id`, dual `aud`/`resource`, live revocation) and then returns
`403 downstream_credential_unresolved`. It does not construct a fixed Supabase client and does
not call `/rest/v1`. Wrong binding, wrong client, and revocation fail at verification with `401`
before that response.

## Security constraints

- The inbound MCP bearer is not a Data API credential.
- No `service_role`, JWT signing secret, secret key, or database-owner credential in the remote
  request path.
- A downstream credential, if one is later proven, must keep the same verified subject and
  server-controlled client and must not broaden database authority.
- `user_metadata` is not an authorization source.
- This ADR does not implement or approve a new authorization server, token store, or broker.

## Decision drivers

- MCP `2026-07-28` access-token privilege restriction.
- Documented Supabase OAuth 2.1 server grant types.
- Current `supabase/auth` master token and OAuth-server handlers.
- Same-subject, same-client RLS, with cross-principal denial.
- No invented exchange and no privileged mint.

## Recheck evidence (2026-09-22)

| Source | What it shows |
| --- | --- |
| Supabase docs `ef0f7f2b3d8cd2075c48b7d94b2badd59c4721b9` (`apps/docs/content/guides/auth/oauth-server/oauth-flows.mdx`, blob `f67a2951508e574b984f9908cac89393b2c57293`) | OAuth 2.1 server grants are `authorization_code` (PKCE) and `refresh_token` only. The page says other grant types such as `client_credentials` and `password` are not supported. Its "token exchange" section is the authorization-code redemption, not RFC 8693. |
| Same docs tree, `mcp-authentication.mdx` blob `bcd2c53c5df2e0e6c687618935310cc2bb2c2c5c` | The guide says the MCP server sends Supabase-issued access tokens to Supabase APIs like any other OAuth client. That is inbound-bearer use at the API, not a second credential. |
| Same docs tree, `token-security.mdx` blob `ad5b1025876f25810f2f52ac6b613f191d806079` | RLS uses `client_id` on the issued JWT. Custom Access Token Hooks can change `aud` on that same token. A hook does not mint a second token. |
| Same docs tree, `enterprise-mcp-authentication.mdx` blob `e70cc5997bb839c450732a09315cfb291588988e` | ID-JAG is for Supabase's operated management MCP server. Custom MCP servers backed by Supabase Auth are directed to the MCP authentication guide. |
| `supabase/auth` `ce9a8eee0cc042be8c7a42981a7ddae631e41d91` (2026-09-22), `internal/api/token.go` | `POST /token` accepts `password`, `refresh_token`, `id_token`, `pkce`, and `web3`. No token-exchange case. No `token_exchange.go` on that tree. |
| Same commit, `internal/api/oauthserver/handlers.go` | The OAuth server token handler accepts `authorization_code` and `refresh_token` only, then `unsupported_grant_type`. |
| [supabase/auth#2609](https://github.com/supabase/auth/pull/2609) (open, not merged) | Proposed RFC 8693 grant is provider access-token sign-in (Facebook). It looks up an existing identity and issues a user session. It is not an exchange of an MCP resource token for a Data API token, and it is not on master. |
| [MCP authorization security considerations, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#access-token-privilege-restriction) | If the MCP server calls an upstream API, that call uses a separate token issued for the upstream API. The server must not pass through the token it received from the MCP client. |

Refreshing the MCP grant does not qualify. Refresh returns another token for the same
authorization and resource. This server does not hold the MCP client's refresh token. Holding
it and presenting the server as a second OAuth client is the dual-grant broker, not a refresh
optimization.

## Options

### Option 1 — Native MCP-to-Data-API token exchange

Preferred if Supabase documents and ships it. Not available on the sources above.

Proof required before any request-path code uses it:

1. The grant is on the OAuth 2.1 server token endpoint, or an equally documented Auth facility,
   and the docs name MCP resource tokens as an accepted `subject_token`.
2. The issued access token value differs from the inbound MCP bearer.
3. `sub` matches the verified MCP subject. Server-controlled `client_id` (top-level or
   `app_metadata`, never `user_metadata`) matches the pre-registered client.
4. The downstream token is acceptable to the Data API (`role=authenticated`, `aud` includes
   `authenticated`) and is not presented back to the MCP resource as if it were the MCP token.
5. Lifetime is shorter than or equal to the inbound token. Revoking either credential denies
   the next call. No project JWT signing secret, `service_role`, secret key, or owner key is
   present in the MCP process.
6. Tests show one authorized `memory_get` / `memory_list_recent` / `memory_search` under RLS,
   cross-principal denial, zero `/rest/v1` requests carrying the inbound bearer, and B
   (`missing_resource_binding`) plus C (`wrong_resource`) denied with `401` before dispatch.
7. An ADR-0002 token trace records issuer, subject, client, audience, resource, recipient,
   storage, expiry, and revocation for both tokens.

### Option 2 — Dual-grant broker

A separate MCP-facing authorization boundary issues the token the client presents here. A
distinct Supabase authorization-code and refresh grant, started with user consent, supplies the
Data API token. The two credentials stay separate.

This can satisfy token separation in principle. It adds an authorization server or proxy,
refresh-token custody, subject and client correlation, consent for both boundaries, revocation,
and crash recovery. It is a new architecture. This ADR does not approve it.

Proof required before implementation, in addition to every Option 1 test:

- Distinct issuer, audience, recipient, and lifetime for the MCP token and the Supabase token.
- Explicit consent at both boundaries, with exact redirect URIs and no Dynamic Client Registration
  in the first slice.
- Subject correlation that does not trust `user_metadata`.
- The downstream RLS `client_id` is the pre-registered Supabase client, not an unqualified shared
  broker client that collapses per-client policy.
- Encrypted refresh custody, rotation, reuse detection, revocation, and isolation between
  concurrent users. No process-global user token.
- MCP-facing verification without putting the project HMAC/JWT signing secret in the remote
  request path.
- A written custody decision naming the local disposable lab and the single pre-registered client
  before any code stores a refresh token.

### Option 3 — Stay fail-closed

Keep discovery, PKCE, consent, resource binding, and revocation testable. After a valid MCP
bearer, return `downstream_credential_unresolved` and make no Data API call. Stdio remains the
only profile that reads `memory_*`. This is not completion of issue #62.

### Rejected without new evidence

- Forwarding the inbound MCP bearer, including a dual-audience JWT. Already rejected in ADR-0005.
- `service_role`, owner-key, or issuer HMAC impersonation.
- Treating open PR supabase/auth#2609, ID-JAG, or a Custom Access Token Hook as the missing
  credential.
- Calling refresh on the MCP grant a second upstream token.

## Decision

No supported path exists that this repository can implement without a new broker architecture.
Do not add a fake downstream credential. Keep Option 3.

`DOWNSTREAM_CREDENTIAL_RECHECK_2026_09_22` freezes that observation for tests. Remote tool
execution against the Data API stays disabled. Issue #62 stays open until Option 1 is proven or
a later ADR accepts Option 2 and its proof.

## Consequences

### Positive

- The 2026-09-06 conclusion is re-pinned to current docs and Auth source instead of assumed.
- B/C binding denial is asserted on the HTTP profile, before fail-closed dispatch.
- Stdio and M2 behavior are unchanged.

### Negative

- Remote `memory_*` tools still do not execute.
- Multi-user Data API access through this remote profile remains blocked on a platform grant
  or an explicit broker decision.

## Validation

- Contract test locks `DOWNSTREAM_CREDENTIAL_RECHECK_2026_09_22`.
- `remote-http-profile` tests reject a source that constructs a Data API client, mentions
  `service_role`, or mentions the RFC 8693 grant URN.
- HTTP profile tests: a valid PKCE bearer returns `403 downstream_credential_unresolved` with no
  `/rest/v1` call; missing resource binding and a conflicting `resource` return `401` with no
  outbound `Authorization` and without the fail-closed error.

## Revisit when

- Supabase documents an Option 1 grant and this lab can capture the token trace above.
- Maintainers accept a separate ADR for Option 2 custody and correlation.
- MCP authorization guidance changes the upstream-token rule.

## References

- [ADR-0002](0002-remote-identity-chain.md)
- [ADR-0005](0005-dual-resource-data-api-binding.md)
- [Issue #62 evidence](../evidence/ISSUE_62_REMOTE_OAUTH_HTTP.md)
- [OAuth 2.1 flows](https://supabase.com/docs/guides/auth/oauth-server/oauth-flows)
- [MCP authentication](https://supabase.com/docs/guides/auth/oauth-server/mcp-authentication)
- [Token security and RLS](https://supabase.com/docs/guides/auth/oauth-server/token-security)
- [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)
