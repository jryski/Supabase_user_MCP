# Issue 3: static RLS catalog lint

This slice adds a read-only, deterministic catalog lint for API-reachable PostgreSQL objects in the `public` and `storage` trust surfaces. API reachability is evaluated as effective privilege for `anon` or `authenticated`, including grants inherited through `PUBLIC`, role membership, and column ACLs.

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
| L10 | CRITICAL | API role has a `TRUNCATE`, `TRIGGER`, or `REFERENCES` table grant |
| L11 | HIGH | API role has an `INSERT` or `UPDATE` table grant without an applicable RLS policy |
| L12 | CRITICAL | API role has effective `USAGE`, `SELECT`, or `UPDATE` on a sequence |

L09 is deliberately a heuristic requiring human review, not a verdict. A marker can be present without sufficient authorization, and a safe routine can delegate identity enforcement elsewhere.

The pgTAP test creates only synthetic objects inside a transaction, covers positive L01-L12 findings and clean controls, and rolls the entire fixture back. It also proves that L10 detects the known default dangerous grants on `storage.objects`, `storage.buckets`, and `storage.buckets_analytics`; this PR reports that durability blocker but does not mutate platform grants. L11 matches policies for the effective API role, including policies that explicitly apply to PUBLIC. The generic runtime policy-matrix helper is outside this slice.

Run the static TypeScript contract with `npx vitest run test/policy-lab/catalog-lint-contract.test.ts`. The controller can run both discovered database matrices with `npm run policy-lab:test:catalog` after starting the disposable loopback-only Supabase lifecycle, or run the full lifecycle with `npm run test:s1`.
