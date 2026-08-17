# M0 TypeScript and MCP Compatibility Evidence

- **Status:** Implemented
- **Verified:** 2026-08-17
- **Scope:** Protocol mechanics only; no Supabase, network, credential, read, or write path

## Claim

The selected TypeScript stack can expose a strictly validated MCP tool over stdio using
the modern MCP `2026-07-28` protocol without introducing data-plane authority.

This evidence does not claim that user identity, Supabase RLS, remote HTTP authorization,
or production deployment is implemented.

## Pinned compatibility set

| Component | Version |
| --- | --- |
| Node.js | `22.20.0` |
| npm | `11.19.0` |
| TypeScript | `7.0.2` |
| `@modelcontextprotocol/server` | `2.0.0` |
| `@modelcontextprotocol/client` | `2.0.0` |
| Zod | `4.4.3` |
| Vitest | `4.1.10` |
| Biome | `2.5.8` |

All project dependencies are exact-pinned and recorded in `package-lock.json`.

## Probe contract

The development-only `system_compatibility_probe` tool:

- accepts only `{ "probe": "m0" }` with no additional properties;
- returns a strictly validated structured result;
- declares read-only, non-destructive, idempotent, and closed-world annotations;
- reports `dataAccess`, `networkAccess`, and `writeAccess` as `false`; and
- has no Supabase library, credential source, fetch call, or database dependency.

The stdio entry point rejects legacy MCP negotiation and writes diagnostics only to
stderr.

## Verification

Static verification completed successfully:

```shell
npm run format:check
npm run lint
npm run typecheck
npm run build
```

A wire-level stdio smoke test against the built server produced these observations:

| Check | Observed result |
| --- | --- |
| `server/discover` | Advertised only `2026-07-28` |
| `tools/list` | Returned only `system_compatibility_probe` |
| Valid `tools/call` | Returned `status: ok` and all authority flags `false` |
| Invalid `probe` value | Returned an MCP tool input-validation error |
| Shutdown | Closed the stdio transport on `SIGINT` |

The repository also includes an automated client/server compatibility test. It pins the
client to `2026-07-28`, launches the built stdio server, lists the tool, checks structured
output, and asserts malformed input rejection. CI runs the complete suite with:

```shell
npm ci
npm run check
```

## Local verification note

The initial verification workstation used a restricted Windows sandbox that denied child
process creation from Node.js. Vitest therefore could not launch its worker or the stdio
child process locally, although compilation and direct shell-owned stdio verification
passed. The automated test remains a required CI gate in a normal GitHub-hosted runner;
its CI result should be linked here before merging the implementation pull request.

## Remaining M0 gates

- Decide local user credential loading and refresh behavior.
- Resolve or explicitly defer the remote downstream-token and audience chain.
- Define durable service-agent provisioning, ownership, rotation, and revocation.
- Define the initial principal/capability vocabulary and access-matrix format.
- Draft the three read-tool contracts without connecting them to data.

## Primary references

- [MCP TypeScript SDK protocol versions](https://github.com/modelcontextprotocol/typescript-sdk/blob/main/docs/protocol-versions.md)
- [MCP TypeScript SDK stdio transport](https://github.com/modelcontextprotocol/typescript-sdk/blob/main/docs/serving/stdio.md)
- [MCP TypeScript SDK legacy-client policy](https://github.com/modelcontextprotocol/typescript-sdk/blob/main/docs/serving/legacy-clients.md)
