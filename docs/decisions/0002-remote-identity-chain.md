# ADR-0002: Remote identity and downstream token chain

- **Status:** Accepted blocking decision; downstream mechanism unresolved
- **Date:** 2026-08-17
- **Owners:** Maintainers
- **Milestone:** M0 decision; M4 implementation

## Context

The project wants a remote HTTP MCP service that authenticates users through Supabase Auth
and preserves RLS when calling the Supabase Data API.

Supabase documents an MCP flow in which its OAuth server issues access tokens and the MCP
server sends Supabase Auth access tokens to Supabase APIs on the user's behalf. The current
MCP authorization specification also requires an HTTP MCP server to validate that its
inbound token is intended for the MCP resource and prohibits accepting or transiting
tokens intended for other resources. General MCP security guidance warns against bearer
token pass-through to upstream APIs.

The original project phrase “pass the identity token through as-is” is therefore not an
acceptable remote architecture until the intended resource, audience, and downstream use
are demonstrated to satisfy both systems.

## Security constraints

- The MCP endpoint validates exact issuer and resource/audience.
- A token is never sent to an unintended origin or resource.
- The service does not hold a project-wide `service_role`, secret key, PAT, database-owner
  credential, or role with `BYPASSRLS` for user tool calls.
- Postgres receives a trustworthy per-request user and client context for RLS.
- Revocation behavior and credential storage are explicit and testable.
- Caller input cannot influence discovery origins, JWKS origins, or downstream origins.

## Decision drivers

- Conformance with the current MCP HTTP authorization specification.
- Conformance with documented Supabase Auth and Data API behavior.
- RLS enforcement under the real calling identity.
- Minimal ambient authority and contained server compromise.
- Compatibility with common MCP clients.
- MCP `2026-07-28` stateless request semantics and required `server/discover` support.
- Reconciliation of MCP's RFC 7591 Dynamic Client Registration deprecation in favor of
  Client ID Metadata Documents with public Supabase guidance that still presents dynamic
  registration as an option.
- RFC 9207 issuer validation and authorization-server-scoped client credential storage.

## Options under investigation

### A. One Supabase-issued token intentionally valid for the shared resource boundary

Determine whether the MCP endpoint and Data API can be modeled as one protected resource
with an audience accepted by both, without violating resource-indicator and token-transit
requirements. This is simplest operationally but must not rely on one service accepting a
token intended only for another.

### B. OAuth token exchange or on-behalf-of credential

The MCP server validates its inbound resource token and exchanges it for a separate,
short-lived Supabase API token. This matches the clean resource-server model, but a
supported Supabase token-exchange facility has not yet been identified.

### C. Co-locate the MCP execution boundary with a Supabase-native resource

Host the MCP tool execution where the verified Supabase request context reaches the Data
API without crossing a second bearer-token resource boundary. Exact platform and protocol
semantics require proof.

### D. Stdio-only user credential for the initial release

Keep the access token in a local protected credential source and call the Data API as that
user. This avoids remote MCP OAuth token transit but does not satisfy the hosted,
multi-user product goal.

### E. Privileged server credential with manual claim impersonation

Rejected by default. A compromised server could impersonate arbitrary users, and the
credential would become ambient project authority even if application code attempted to
reconstruct claims carefully.

## Accepted blocking decision

Ship the first identity-preserving proof as a local stdio profile. Do not claim or
implement production-ready remote HTTP support until options A–C are tested and one is
accepted with a complete token trace.

The remote profile remains an explicit M4 gate rather than silently adopting bearer token
pass-through. This acceptance governs the stdio-first and remote-block decisions only.
Options A–C remain unresolved and require K3 review; none is promoted by this status.

## Required validation artifact

The accepted decision must include a sequence diagram and captured synthetic protocol
trace showing, for every token:

- issuer;
- subject and OAuth client;
- exact audience/resource;
- recipient and transport;
- verification method;
- downstream destination;
- storage and logging behavior;
- expiration, refresh, and revocation behavior; and
- behavior for wrong issuer, audience, client, expiry, and redirect.

It must also cite the exact supported Supabase and MCP versions or dated documentation.

## Consequences

### Positive

- Prevents the core product from launching on an ambiguous credential boundary.
- Allows policy and tool work to proceed through the stdio proof.
- Makes protocol conformance independently reviewable.

### Negative

- Defers the hosted multi-user profile.
- May require an authorization broker or different deployment topology.
- Supabase and MCP changes may force the decision to be revisited.

## Revisit when

- Supabase publishes a normative resource/audience topology for downstream Data API use.
- Supabase supports a suitable token-exchange or workload-identity flow.
- MCP authorization guidance changes its upstream-token requirements.
- A prototype demonstrates one option without increasing ambient authority.

## References

- [MCP 2026-07-28 authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [MCP 2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
- [Supabase MCP authentication](https://supabase.com/docs/guides/auth/oauth-server/mcp-authentication)
- [Supabase OAuth token security and RLS](https://supabase.com/docs/guides/auth/oauth-server/token-security)
- [Supabase OAuth flows](https://supabase.com/docs/guides/auth/oauth-server/oauth-flows)
