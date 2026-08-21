# ADR-0003: Local credential and protocol policy

- **Status:** Accepted
- **Date:** 2026-08-20
- **Owners:** Maintainers
- **Milestone:** M0 decision; M2 implementation

## Context

The first identity-preserving profile is a local MCP server over stdio. It needs a user
access token for the Supabase Data API without making credential bytes available to shell
history, URLs, MCP tool input, Git, fixtures, logs, or errors. The profile also needs a
bounded protocol negotiation rule that matches the version already exercised by the M0
compatibility spike.

This decision freezes policy contracts only. Filesystem access, token parsing and
verification, a Supabase client, and data tools remain unimplemented.

## Security constraints

- The credential represents one Supabase user; it is not a `service_role`, secret key,
  personal access token, database-owner credential, or refresh token.
- Credential bytes never enter CLI arguments, query parameters, MCP tool arguments, Git,
  fixtures, logs, or errors.
- A credential source is rejected before it is read if it is a symbolic link, is not a
  regular file, is owned by another operating-system user, or permits group or other
  access.
- Credential and protocol checks complete before any data tool is registered.
- Failure is denied by default and reports only a stable, non-secret class.

## Decision drivers

- Preserve the user's RLS identity without introducing project-wide ambient authority.
- Keep credential handling reviewable for the local stdio proof.
- Make absence, malformed content, expiry, refresh, revocation, permissions, and protocol
  mismatch deterministic and testable.
- Reuse the protocol version demonstrated by current repository evidence.

## Options considered

### Protected local file with restart-based replacement

Read one operator-selected local file only after metadata checks establish that it is a
regular, non-symlinked file owned by the current effective user with no group or other
permission bits. This is simple, inspectable, and avoids secret-bearing process arguments.
It does not provide seamless refresh.

### Environment variable containing credential bytes

Rejected for this profile. Environment inheritance and process inspection broaden secret
exposure, and the issue requires a protected local file contract.

### CLI, query, or tool argument

Rejected. These transports expose credentials to shell history, process listings, URLs,
JSON-RPC transcripts, client logs, and model-visible tool calls.

### Automatic refresh inside the server

Rejected for the initial profile. Holding a refresh token adds durable credential storage,
rotation, and replay obligations before those controls exist.

## Decision

### Credential source

The only allowed transport is `protected-local-file`. The eventual loader must inspect the
source without following links and accept it only when all of these facts hold:

1. the source exists;
2. it is a regular file and not a symbolic link;
3. its operating-system owner is the current effective user;
4. group and other permission bits grant no access;
5. the current user can read it; and
6. its contents parse as one currently valid Supabase user access token.

The file location is deployment configuration, never caller- or tool-selected. Credential
bytes are not part of the executable observation contract, which contains only validation
metadata and lifecycle state.

### Lifecycle and refresh

The local profile does not accept or store a refresh token and does not refresh in process.
An operator obtains a replacement access token out of band, atomically replaces the
protected file with equally safe ownership and permissions, and restarts the server.
Expiry, a refresh-required state, or known revocation is fail-closed. If revocation is first
learned from a downstream rejection, the same revoked failure class applies and data tools
must no longer be served with that credential.

### Failure classes

| Condition | Stable code |
| --- | --- |
| Forbidden transport | `credential_transport_forbidden` |
| Absent source | `credential_source_absent` |
| Unreadable source | `credential_source_unreadable` |
| Symlink, non-regular file, wrong owner, or unsafe permissions | `credential_source_unsafe` |
| Malformed credential | `credential_malformed` |
| Expired credential | `credential_expired` |
| Revoked credential | `credential_revoked` |
| Replacement and restart required | `credential_refresh_required` |

Errors contain no path, credential content, claims, or upstream response body.

### MCP protocol

The local stdio profile supports exactly MCP `2026-07-28`. Negotiation is exact-match and
an unsupported or malformed version fails before data tool registration with
`mcp_protocol_version_unsupported`. Supporting another version requires compatibility
evidence and a new or superseding decision rather than an implicit fallback.

## Consequences

### Positive

- Credential transport and source safety are explicit executable contracts.
- The server cannot silently broaden into secret-bearing tool or process arguments.
- Refresh and revocation behavior remain simple and fail-closed.
- Protocol policy matches the current `2026-07-28` client/server compatibility evidence.

### Negative

- Access-token replacement requires an operator action and server restart.
- The initial profile cannot offer uninterrupted sessions across expiry.
- Revocation cannot be detected offline unless token validation or a downstream response
  supplies that fact.
- Platform-specific metadata inspection still needs a carefully tested implementation.

### Follow-up

- Implement filesystem inspection and credential loading without link-following or
  time-of-check/time-of-use broadening.
- Validate synthetic token claims and downstream failure normalization before registering
  the M2 read tools.
- Add a Supabase client only after its exact version and redaction behavior are pinned.

## Validation

`packages/contracts/src/local-credential-protocol-policy.test.ts` exercises the allowed
source; forbidden CLI, query, and tool transports; absent, unreadable, symlinked,
non-regular, wrong-owner, and unsafe-permission sources; malformed, expired, revoked, and
refresh-required lifecycle states; and exact protocol negotiation.

The protocol pin is supported by the existing M0 compatibility test and
[compatibility evidence](../evidence/M0_COMPATIBILITY_SPIKE.md), which exercise MCP
`2026-07-28` with the pinned TypeScript SDK.

## Revisit when

- The local profile needs uninterrupted refresh and can protect refresh tokens with an
  accepted storage, rotation, replay, and revocation design.
- A supported platform secret store provides a narrower and testable trust boundary.
- The pinned MCP SDK drops `2026-07-28` or compatibility evidence justifies another
  protocol version.
- The remote HTTP identity-chain decision is accepted; it remains governed separately by
  [ADR-0002](0002-remote-identity-chain.md).

## References

- [M0 compatibility evidence](../evidence/M0_COMPATIBILITY_SPIKE.md)
- [ADR-0002: Remote identity and downstream token chain](0002-remote-identity-chain.md)
- [MCP 2026-07-28 specification](https://modelcontextprotocol.io/specification/2026-07-28)
