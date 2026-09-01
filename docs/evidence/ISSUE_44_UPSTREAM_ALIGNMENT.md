# Issue #44: Official Supabase upstream alignment

- **Status:** Unmerged candidate evidence
- **Candidate base:** `dd5ba98a00a3b37003554a14200f789fcb233cac`
- **Scope:** synthetic M2 and operator/test plumbing only
- **Production runtime authority change:** none

## Frozen official coordinates

| Upstream | Coordinate | Package/license | Use |
| --- | --- | --- | --- |
| [`supabase/mcp`](https://github.com/supabase/mcp/tree/30baa1f06a989344619cfbb915b7e46a91921d78) | `30baa1f06a989344619cfbb915b7e46a91921d78` | `@supabase/mcp-utils@0.7.0`, Apache-2.0 | Exact-pinned `StreamTransport` and official MCP test topology |
| [`supabase/mcp`](https://github.com/supabase/mcp/tree/30baa1f06a989344619cfbb915b7e46a91921d78/packages/mcp-server-postgrest) | same commit | `@supabase/mcp-server-postgrest@0.2.0`, Apache-2.0 | Reference-only authenticated Auth/PostgREST test shape and non-model-facing OpenAPI census |
| [`supabase/supabase-js`](https://github.com/supabase/supabase-js/tree/b3b939a405ae663aea2fabecfa4dfcc6161d155a/packages/core/auth-js) | `b3b939a405ae663aea2fabecfa4dfcc6161d155a` | `@supabase/auth-js@2.112.4`, MIT | Synthetic local sign-in only |

The archived standalone `supabase/auth-js` repository is not the source coordinate. Maintained
Auth source lives under `supabase/supabase-js/packages/core/auth-js`.

## Borrowed behavior

- M2 synthetic sessions are minted through the official Auth client rather than a bespoke token
  endpoint request.
- The authenticated PostgREST root OpenAPI document is fetched outside the model-visible MCP tool
  surface with the separate publishable key and user bearer token.
- The census fails closed unless the `memory` profile advertises exactly:
  - `/`;
  - `/rpc/authorized_memory_get_v1`;
  - `/rpc/authorized_memory_list_recent_v1`;
  - `/rpc/authorized_memory_search_v1`.
- The census has a 1 MiB test-only document ceiling, rejects redirects, malformed/non-JSON bodies,
  missing RPCs, extra relations, and extra RPCs.

## Deliberately retained local boundary

The official Auth client does not replace the production fixed identity verifier. Its generic fetch
path does not itself provide this project's per-call timeout/abort, redirect/final-URL enforcement,
response-byte ceiling, strict UUID projection, or stable local error classes. Adding it to production
would retain the security adapter while enlarging the runtime dependency surface.

The official PostgREST MCP is not imported as a public runtime because it exposes caller-selected
HTTP methods and paths plus `sqlToRest`. Direct-invocation tests prove `postgrestRequest` and
`sqlToRest` are not registered and fail as unknown tools.

## TypeScript compatibility boundary

`@supabase/auth-js@2.112.4` publishes browser/WebAuthn declaration references that conflict with the
repository's Node-only TypeScript 7 test profile under `exactOptionalPropertyTypes`. The test helper
loads the package through its supported CommonJS export and declares only the exercised AuthClient
shape. This avoids `skipLibCheck`, avoids adding DOM types to production or test compiler policy, and
still exercises the actual package request behavior.

## Verification entry points

```shell
npx vitest run \
  packages/server/src/postgrest-openapi-census.test.ts \
  test/m2-auth-client.test.ts \
  test/m2-harness-contract.test.ts \
  packages/server/src/read-only-server.test.ts
npm run check
npm run test:m2
```

The real OpenAPI census and official Auth sign-in are accepted only when `npm run test:m2` passes
from a clean exact-head checkout. Unit tests alone do not establish the live advertised surface.

## Claim limits

This candidate does not add remote HTTP/OAuth, writes, production credentials or data, generic
PostgREST tools, a service-role request path, deployment, or production readiness. PostgreSQL RLS
remains the final row-authorization boundary.
