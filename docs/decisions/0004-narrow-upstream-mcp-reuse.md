# ADR-0004: Reuse upstream Supabase MCP narrowly

- **Status:** Accepted
- **Date:** 2026-08-27
- **Owners:** Maintainers
- **Milestone:** M2

## Context

The official `supabase/mcp` repository now publishes a general Supabase MCP server,
`@supabase/mcp-utils`, and `@supabase/mcp-server-postgrest`. The PostgREST package includes a
local integration test that signs in a synthetic Supabase Auth user and exercises an MCP server
through the upstream in-memory `StreamTransport`.

This project should reuse maintained protocol and identity test seams where they preserve the
user-context boundary. It must not import a generic tool surface that restores caller-selected
methods, paths, schemas, relations, RPCs, or SQL.

## Security constraints

- Production tools remain a closed allowlist with fixed Data API origin and RPC paths.
- The publishable project key and user access token remain separate credentials.
- The MCP request path cannot expose arbitrary SQL, OpenAPI enumeration, or write methods.
- Tool exclusion means non-registration; discovery hiding is not authorization.
- Responses, errors, operational events, concurrency, and byte counts retain local governors.
- Upstream dependencies are exact-pinned and pass compatibility and adversarial upgrade gates.

## Options considered

### Import the general Supabase MCP server

Rejected. It operates with developer/platform authority and exposes a much broader management
surface than the user-scoped data-plane pilot.

### Import the PostgREST MCP server

Rejected for runtime use. Version `0.2.0` exposes a generic `postgrestRequest` tool with
caller-selected HTTP method and path, a `sqlToRest` tool, and an OpenAPI resource. Its current
options also use one `apiKey` value for both the `apikey` and `Authorization` headers. Those
choices conflict with this project's fixed-RPC and separated-credential boundaries.

### Fork the upstream server and remove unwanted tools

Rejected. A long-lived fork would inherit an authority-heavy architecture and create a recurring
security-diff burden. The local server is smaller than the fork boundary and already has stricter
contracts.

### Reuse protocol and identity test seams only

Accepted. This preserves upstream compatibility without importing upstream authority.

## Decision

Keep the production server on the pinned official MCP TypeScript SDK and register only the three
local read tools.

Adopt these upstream seams:

- exact-pinned `@supabase/mcp-utils@0.7.0` `StreamTransport` for compatibility and end-to-end
  tests;
- the test topology demonstrated by `@supabase/mcp-server-postgrest`: synthetic local Supabase
  Auth sign-in, real user JWT, in-memory MCP client/server connection, and real PostgREST/RLS
  evaluation;
- exact-pinned `@supabase/auth-js@2.112.4` from
  `supabase/supabase-js@b3b939a405ae663aea2fabecfa4dfcc6161d155a` for synthetic sign-in and
  operator examples only; the archived standalone `supabase/auth-js` repository is not the source
  coordinate;
- the authenticated PostgREST root OpenAPI document as a non-model-facing M2 census that proves the
  advertised profile remains within the fixed API allowlist; and
- Supabase Auth OAuth 2.1 discovery, PKCE, user approval, and revocation as the preferred future
  remote identity foundation, subject to ADR-0002's audience/resource validation gate.

Do not import the PostgREST server, `postgrestRequest`, `sqlToRest`, its model-visible OpenAPI
resource, or upstream `hidden` behavior into the production capability surface.

## Consequences

### Positive

- Issue #17 can reuse maintained Auth and MCP transport plumbing rather than hand-roll it.
- M2 can inspect the externally advertised PostgREST profile without exposing discovery to the
  model.
- Production authority remains visibly bounded in local registration code.
- Upstream protocol changes are detected by executable compatibility tests.
- Future remote OAuth work follows Supabase's supported identity system.

### Negative

- This project retains its fixed Data API client and tool-registration implementation.
- Upstream package upgrades require source-coordinate review and compatibility evidence.
- Useful upstream features are not inherited automatically.
- Auth's browser/WebAuthn declarations require a narrow Node test adapter under this repository's
  TypeScript 7 and `exactOptionalPropertyTypes` settings; compiler checks are not skipped.

### Follow-up

- Assemble the protected credential loader, fixed client, and three governed handlers in the
  executable stdio server.
- Preserve issue #17's upstream Auth plus `StreamTransport` test topology and add the authenticated
  OpenAPI census before the experimental release.
- Keep prompt-injection acceptance deterministic; do not import upstream arbitrary-SQL model
  tests into the public request path.
- Consider an upstream contribution separating PostgREST `apikey` and bearer-token options, but
  do not place that contribution on the v0.1 critical path.

## Validation

PR #26 freezes upstream `StreamTransport` behavior and characterizes why hidden tools are not an
authorization boundary. On 2026-08-27, maintainers reviewed `supabase/mcp` main and releases
`mcp-utils@0.7.0`, `mcp-server-supabase@0.11.0`, and `mcp-server-postgrest@0.2.0`.

## Revisit when

- The upstream PostgREST server supports a non-bypassable fixed-operation allowlist, separate
  publishable and user credentials, response bounds, and equivalent adversarial evidence.
- The local server adds remote HTTP after ADR-0002 is accepted.
- The pinned MCP SDK or `StreamTransport` behavior changes.

## References

- [Supabase MCP repository](https://github.com/supabase/mcp)
- [PostgREST MCP server source](https://github.com/supabase/mcp/blob/main/packages/mcp-server-postgrest/src/server.ts)
- [PostgREST local Auth integration test](https://github.com/supabase/mcp/blob/main/packages/mcp-server-postgrest/src/server.test.ts)
- [Supabase Auth for MCP](https://supabase.com/docs/guides/auth/oauth-server/mcp-authentication)
- [Issue #25 StreamTransport evidence](../evidence/ISSUE_25_UPSTREAM_STREAM_TRANSPORT.md)
- [ADR-0002: Remote identity and downstream token chain](0002-remote-identity-chain.md)
