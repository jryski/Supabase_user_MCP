# ADR-0005: Dual resource and Data API binding for remote HTTP

- **Status:** Accepted for the experimental local remote-HTTP profile
- **Date:** 2026-09-06
- **Owners:** Maintainers
- **Milestone:** M4 implementation
- **Supersedes (narrowly):** the unresolved Option A–C mechanism in [ADR-0002](0002-remote-identity-chain.md). ADR-0002's stdio-first and production-remote-block decisions remain in force.

## Context

ADR-0002 required a demonstrated token trace before any remote HTTP profile could claim a
downstream credential chain. MCP `2026-07-28` requires intended-resource/audience validation.
Supabase Data API authorization continues to require `aud` to include `authenticated`.
Upstream token-security examples that store `read_only` in `user_metadata` are not acceptable
authorization inputs: `user_metadata` is user-editable.

Local CLI OAuth 2.1 (`[auth.oauth_server]`) can issue authorization-code + PKCE tokens with a
top-level `client_id`. Those tokens do not, by default, bind the MCP resource. Hosted live OAuth
is a separate interoperability gate and is not claimed here.

## Security constraints

- Intended-resource validation is mandatory, not optional.
- `aud=authenticated` alone is not proof of MCP resource binding.
- `client_id` alone is not proof of resource binding.
- The same JWT may be sent to the fixed local Data API only after MCP dual-binding succeeds.
- No `service_role`, secret key, or other privileged credential is used in the user request path.
- Access-token revocation is a live check, distinct from grant revoke and refresh rotation.
- Process-global principal-scoped rate-limit counters must survive request-scoped client rebuilds.

## Decision drivers

- MCP RFC 8707 / RFC 9728 resource binding.
- Supabase Data API JWT audience compatibility.
- Local disposable-lab OAuth fixtures without tunnels, hosted projects, or persistent credentials.
- Canonical/server-controlled client identity only.

## Options considered

### Option A — Dual-bound shared JWT (selected)

Require JWT `aud` to include `authenticated` **and** an exact MCP resource URI (`aud` array
and/or `resource` claim). Send that same JWT to the fixed Data API origin. A local Custom Access
Token Hook adds the lab MCP resource for OAuth tokens that already carry top-level `client_id`.

### Option B — Token exchange

No supported Supabase token-exchange facility is available in this lab. Rejected for this slice.

### Option C — Privileged impersonation

Rejected. Ambient `service_role` in the user path is forbidden.

## Decision

Accept Option A for the **experimental local** remote HTTP profile:

1. Pre-registered public OAuth clients, PKCE S256, exact redirect URIs, explicit consent.
   Dynamic Client Registration stays disabled.
2. MCP verifies signature, issuer, `role=authenticated`, subject, server-controlled `client_id`
   (`client_id` else `app_metadata.client_id`), dual audience/resource, and live revocation.
3. `user_metadata` is never an authorization source. SQL `policy_lab.verified_client_id()`
   matches that rule.
4. Request-scoped `FixedSupabaseClient` + `createReadOnlyServer` per HTTP request. No process-global
   user bearer cache. Rate-limit maps remain process-global.
5. Hosted/live OAuth, public listeners, and tunnels remain an unmet gate.

## Consequences

### Positive

- Resource binding and Data API compatibility are both proven locally.
- Same-user/different-client and different-user RLS cases remain mechanically enforced.

### Negative

- Local GoTrue tokens need the in-lab hook to carry the MCP resource.
- Hosted JWKS/asymmetric signing and live third-party MCP clients are not exercised.

## Revisit when

- A hosted project completes the same PKCE/consent/resource trace.
- Supabase documents a different mandatory audience topology for OAuth access tokens.

## References

- [ADR-0002](0002-remote-identity-chain.md)
- [Official CLI OAuth-server setup](https://supabase.com/docs/guides/auth/oauth-server/getting-started)
- MCP `2026-07-28` authorization (RFC 9728, RFC 8707)
