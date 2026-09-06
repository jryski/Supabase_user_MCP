# ADR-0005: Dual resource binding does not authorize MCP bearer passthrough

- **Status:** Unresolved — Option A rejected as a downstream-credential mechanism
- **Date:** 2026-09-06
- **Owners:** Maintainers
- **Milestone:** M4 implementation
- **Related:** [ADR-0002](0002-remote-identity-chain.md) remains the blocking identity-chain decision.

## Context

ADR-0002 required a demonstrated token trace before any remote HTTP profile could claim a
downstream credential chain. MCP `2026-07-28` requires intended-resource/audience validation
**and** [forbids forwarding the inbound MCP access token to an upstream API](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#access-token-privilege-restriction).
A multi-audience JWT is not that separate credential.

Locutus recorded this on issue #62 (comment 5562283720) and on PR #64 (comments 5562394217
and 5562411647). Independent 4MiB ingress reproduction of unbounded pre-auth buffering was
also recorded at comment 5562411647.

## Security constraints

- Intended-resource validation is mandatory, not optional.
- `aud=authenticated` alone is not proof of MCP resource binding.
- `client_id` alone is not proof of resource binding.
- Dual `aud`/`resource` does **not** authorize sending the inbound MCP bearer to the Data API.
- No `service_role`, HMAC JWT signing secret, secret key, or other privileged credential is
  used in the normal remote request-serving configuration.
- Access-token revocation is a live check, distinct from grant revoke and refresh rotation.
- Process-global principal-scoped rate-limit counters must survive request-scoped rebuilds
  (stdio / future dispatch). HTTP ingress must bound size, deadline, and cancellation before
  handler execution.
- Wrong-client bearers fail before tool/data dispatch.

## Decision drivers

- MCP RFC 8707 / RFC 9728 resource binding.
- MCP access-token privilege restriction (no upstream passthrough).
- Supabase Data API JWT audience compatibility.
- No supported short-lived token-exchange or on-behalf-of facility for MCP→Data API in this lab.
  GoTrue's RFC 8693 grant is provider-login, not a second Data API credential.
- Local disposable-lab OAuth fixtures without tunnels, hosted projects, or persistent credentials.

## Options considered

### Option A — Dual-bound shared JWT forwarded to the Data API (rejected)

Rejected. Restricting the same JWT to a local lab does not meet the MCP upstream-token
separation rule.

### Option B — Token exchange

No supported Supabase MCP-to-Data-API token-exchange facility is available in this lab.
GoTrue's `urn:ietf:params:oauth:grant-type:token-exchange` grant is a provider access-token
sign-in path, not a downstream Data API mint. Not proven.

### Option C — Privileged impersonation

Rejected. Ambient `service_role` or issuer HMAC signing authority in the user path is forbidden.

## Decision

Keep useful remote scaffolding and **fail-close data dispatch** until a supported separate
short-lived downstream credential with the same verified subject/client and no broader
database authority can be demonstrated:

1. Pre-registered public OAuth clients, PKCE S256, exact redirect URIs, explicit consent.
   Dynamic Client Registration stays disabled.
2. MCP verifies signature via JWKS (not HMAC), issuer, `role=authenticated`, subject,
   configured `client_id`, dual audience/resource, and live revocation.
3. `user_metadata` is never an authorization source.
4. After a valid MCP bearer, the remote handler returns
   `downstream_credential_unresolved` and must not create a Data API client with that bearer.
5. Normal remote CLI rejects HMAC/JWT signing secrets and privileged project keys. Synthetic
   HMAC remains confined to the in-process authorization-server fixture.
6. HTTP ingress enforces the 65,536-byte frame ceiling and 2,000 ms deadline with cancellation
   before unbounded buffering.
7. Hosted/live OAuth, public listeners, tunnels, external MCP-client OAuth UI, and the
   downstream credential remain unmet. This is **not** completion of issue #62.

## Remaining gate

A supported separate short-lived downstream credential that:

- is not the inbound MCP bearer;
- retains the same verified user and client restrictions;
- does not use privileged minting or invented token exchange.

Until that gate is proven, remote tool execution against the Data API stays disabled.

## Consequences

### Positive

- MCP resource binding, JWKS verification, PKCE/consent, revocation, wrong-client denial,
  and bounded ingress can be tested without claiming a false token chain.
- Stdio, RLS, and process-global rate limits remain unchanged.

### Negative

- Remote `memory_*` tools do not execute over HTTP.
- Issue #62 remains incomplete.

## Revisit when

- Supabase documents and this lab can prove a supported MCP→Data API credential that is not
  bearer passthrough.
- MCP authorization guidance changes its upstream-token requirements.

## References

- [ADR-0002](0002-remote-identity-chain.md)
- [Official CLI OAuth-server setup](https://supabase.com/docs/guides/auth/oauth-server/getting-started)
- MCP `2026-07-28` authorization and access-token privilege restriction
