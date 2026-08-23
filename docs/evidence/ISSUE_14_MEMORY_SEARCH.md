# Issue 14: bounded memory search application seam

## Scope

This slice adds an unregistered `createMemorySearch` application function and one fixed Supabase client operation. It makes no live requests in tests and adds no MCP tool registration, database lifecycle work, credentials, SQL, or write support.

## Closed boundaries

- Input and output are parsed with the existing `MemorySearchInputSchema` and `MemorySearchOutputSchema` from `packages/contracts/src/read-tools.ts`.
- The client calls only `POST /rest/v1/rpc/authorized_memory_search_v1`, with the fixed `memory` profile, configured publishable key, and configured user JWT.
- Runtime callers cannot select an origin, schema, relation, RPC, method, headers, token, identity, or candidate/hidden-row count.
- The RPC is the authorization and RLS boundary. The application receives and maps only its returned rows; it neither accepts nor computes a pre-authorization candidate set or total.
- Responses allow only `id`, `title`, `content`, `createdAt`, `provenanceSummary`, and `rank`, plus the application-added literal `contentTrust: "untrusted"`. Unknown response fields are rejected.
- Contract filter, cursor, row, UTF-8 MCP wire-response byte, and 2-second execution ceilings are enforced. Both caller cancellation and the deadline abort the fixed request.
- Upstream bodies and credential values are never included in public or fixed-client errors. Missing and unauthorized data are indistinguishable because absent rows never enter the seam and no total is exposed.

## Synthetic evidence

Focused RED was observed before implementation: `memory-search.ts` was unresolved and `searchMemoryRows` did not exist. After implementation, mocked tests cover positive mapping; strict unknown-key, malformed query, filter, limit, and cursor denial; identity/origin/schema/RPC override denial; authorization-before-ranking and no hidden counts; output row/byte boundaries; cancellation; prompt injection as untrusted data; and fixed path/JWT/schema/method/limit assertions.

Final verification on 2026-08-23:

```text
npm run check
Test Files  14 passed (14)
Tests       133 passed (133)
```

No test uses a real network or database. All transport behavior uses injected `fetch` mocks and all application behavior uses a synthetic `FixedSupabaseClient`.
