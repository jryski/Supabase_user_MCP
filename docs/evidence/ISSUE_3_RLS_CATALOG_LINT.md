# Issue 3: static RLS catalog lint

This slice adds a read-only, deterministic catalog lint for API-reachable PostgreSQL objects. API reachability means an explicit catalog ACL grant to `anon` or `authenticated`; existence in an exposed schema alone is not enough.

The query reads only PostgreSQL system catalogs and emits exactly `(sev, id, obj, det)`, ordered by severity (`CRITICAL`, `HIGH`, `WARN`), then ID and object.

| ID | Severity | Catalog check |
| --- | --- | --- |
| L01 | CRITICAL | API-reachable table has RLS disabled |
| L02 | WARN | RLS-enabled table has zero policies |
| L03 | HIGH | Policy applies to PUBLIC or has no explicit role restriction |
| L04 | WARN | Policy expression references deprecated `auth.role()` |
| L05 | HIGH | Applicable policy has a true or null `USING` expression |
| L06 | HIGH | UPDATE-capable policy is missing `WITH CHECK` |
| L07 | HIGH | API-reachable view lacks `security_invoker=true` |
| L08 | HIGH | API-executable SECURITY DEFINER routine lacks a fixed `search_path` |
| L09 | CRITICAL | API-executable SECURITY DEFINER routine lacks an `auth.uid`, `auth.jwt`, or `request.jwt` source-text marker |

L09 is deliberately a heuristic requiring human review, not a verdict. A marker can be present without sufficient authorization, and a safe routine can delegate identity enforcement elsewhere.

The pgTAP test creates only synthetic objects inside a transaction, covers positive L01-L09 findings and clean controls, and rolls the entire fixture back. The generic runtime policy-matrix helper is outside this slice.

Run the static TypeScript contract with `npx vitest run test/policy-lab/catalog-lint-contract.test.ts`. The controller can run the database fixture with `npm run policy-lab:test:catalog` after starting its disposable local Supabase lifecycle.
