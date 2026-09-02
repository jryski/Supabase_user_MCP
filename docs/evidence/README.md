# Evidence Index

- **Status:** Active index of merged evidence and unmerged candidates
- **Last reviewed:** 2026-09-01

This index maps public claims to exact artifacts. A commit in the merged table means the
named artifact is present on `main`; it does not prove a larger milestone or deployment.
Draft candidates are listed separately and must not be described as merged or accepted.

## Merged evidence on `main`

| Scope | Evidence | Executable seam | Evidence commit |
| --- | --- | --- | --- |
| MCP stdio compatibility | [M0 compatibility spike](M0_COMPATIBILITY_SPIKE.md) | `test/compatibility/stdio-modern.test.ts` | `e3b1af371bd0e231376d32efe1623ed32c011fb3` |
| Pinned upstream transport boundary | [Issue #25 evidence](ISSUE_25_UPSTREAM_STREAM_TRANSPORT.md) | `test/compatibility/upstream-stream-transport.test.ts` | `63269c64bb1d259faf93e7c3e63e3e210e705afc` |
| Authorization vocabulary and access matrix | `packages/contracts/src/authorization.ts` | `packages/contracts/src/authorization.test.ts` | `0b48b72` |
| Bounded read-tool contracts | `packages/contracts/src/read-tools.ts` | `packages/contracts/src/read-tools.test.ts` | `7c930af` |
| Local policy laboratory | `supabase/migrations/20260823000100_policy_lab.sql` | `supabase/tests/database/policy_lab_test.sql` | `83a72f5` |
| RLS catalog lint | [Issue #3 evidence](ISSUE_3_RLS_CATALOG_LINT.md) | `sql/lint/rls_catalog_lint.sql` and `supabase/tests/database/rls_catalog_lint_test.sql` | `7ed3cfb955456dc29bf5ba34ca0d18cea4ca2e89` |
| SECURITY DEFINER pre-grant gate | [Issue #4 evidence](ISSUE_4_SECURITY_DEFINER_GATE.md) | `test/policy-lab/security-definer-gate-contract.test.ts` | `80fcfe32c7378cca2ff81f85d990a89fcad2d1f8` |
| Revocation and audit boundary | [Issue #12 evidence](ISSUE_12_REVOCATION_AUDIT.md) | `supabase/tests/database/revocation_audit_test.sql` | `f7374c7477252f8443b65499188cac01026aadfb` |
| Protected local credential and fixed client | [Issue #13 evidence](ISSUE_13_FIXED_CLIENT.md) | `packages/server/src/local-credential-loader.test.ts` and `fixed-supabase-client.test.ts` | `efba54ef64479b9c056514266efdda1327febe40` |
| Bounded lexical search application seam | [Issue #14 evidence](ISSUE_14_MEMORY_SEARCH.md) | `packages/server/src/memory-search.test.ts` | `3b7121fb0a3cc0b19db6463c17264a00fab706e6` |
| Read governors, get, and recent-list factories | [Issue #16 evidence](ISSUE_16_READ_GOVERNOR.md) | `packages/server/src/read-tool-governor.test.ts`, `read-tool-governor.integration.test.ts`, `memory-get.test.ts`, and `memory-list-recent.test.ts` | `963b342c789a183331a31c7a144cd7cfeaecd25b` |
| Storage/RLS artifact laboratory | [S1 lab evidence](S1-lab.md) | `supabase/tests/run-s1-lab.sh` | `38013ae428c37b4140bfdb6b3cd174e72f0732c0` |
| Verified principal-bound read path | [Issue #17 evidence](ISSUE_17_PRINCIPAL_READ_PATH.md) | `packages/server/src/m2-local-e2e.test.ts` and `supabase/tests/run-m2-memory-lab.sh` | `dd5ba98a00a3b37003554a14200f789fcb233cac` |
| Official Supabase upstream alignment | [Issue #44 evidence](ISSUE_44_UPSTREAM_ALIGNMENT.md) | Official Auth synthetic sign-in and authenticated PostgREST OpenAPI census | `7f2a3fa955a811f97ed4f88e4cfa50ad7e3aa4d4` |
| Executable local stdio/operator package | [Issue #18 operator and release evidence](ISSUE_18_OPERATOR_RELEASE.md) | `packages/server/src/stdio-startup.test.ts` and `test/issue-18-operator-contract.test.ts` | `d59d6967cb276752878baa5c03f57a179ac8e9c0` |
| Governed Artifact Inspection S0 contract | [Issue #34 S0 evidence](ISSUE_34_S0_ARTIFACT_CONTRACT.md) | `packages/contracts/src/artifact-inspection.test.ts` | `6bff150d673055028e19e2202875b8f7d27f4782` |
| S1b deterministic chunk/Merkle calibration | [Issue #34 S1b evidence](ISSUE_34_S1B_CHUNK_MERKLE_CALIBRATION.md) | `packages/server/src/artifact-chunk-manifest.test.ts` and `npm run artifact:calibrate` | `e36418d812a7004f5b9cf1ef14070375cfed7493` |
| S2 fixed read-only artifact inspector | [Issue #34 S2 evidence](ISSUE_34_S2_FIXED_INSPECTOR.md) | `packages/server/src/artifact-inspector.test.ts` | `57ebbf5d836835a7fe8cd2330e46c2696aa1162b` |

## Unmerged candidate evidence

| Candidate | Coordinate/evidence source | What it may support | Open limits |
| --- | --- | --- | --- |
| Issue #34 S4 deterministic text-index spike | [Draft PR #51](https://github.com/jryski/Supabase_user_MCP/pull/51), exact reviewed head `52037d40f2336f4444746d85a7c6c8f6ea505372` | Pure in-memory UTF-8 line and Markdown ATX-heading index primitive | Technically accepted only as an isolated spike; remains draft and blocked on S3, then requires rebase and fresh exact-head review |

Issue #34 S3 MCP registration and Storage containment closure is the next dependency-ready stage. No
S3 implementation branch or PR exists at this documentation coordinate.

Green CI on a draft coordinate proves only that the named workflow passed for that source.
It does not merge the code, satisfy independent review, authorize deployment, or establish
production readiness.

## External review context

- [Phase 1 external AI-assisted documentation review](EXTERNAL_PHASE1_DOCUMENTATION_REVIEW.md)
  records the stale-cache correction, disclosure boundary, K2 normative correction, Section F
  findings, and maintainer responses. It is a public-safe attributed summary, not an official
  Supabase review or a verbatim private transcript.

## Reproduction entry points

```shell
npm ci
npm run check
npm run policy-lab:test
npm run test:m2
npm run test:s1
npm run artifact:calibrate
```

The M2 acceptance command must run from a clean exact-head checkout. Its receipt proves only the
synthetic local profile at that exact Git coordinate.

## Evidence rules

- Use full SHAs for review and acceptance; branch names are mutable.
- Preserve test engine, tool, dependency, fixture, and cleanup scope with every receipt.
- Separate catalog shape, exercised behavior, current data, and production deployment.
- Treat local synthetic evidence as non-production evidence.
- Keep credentials, private payloads, customer evidence, and internal operational details out
  of public artifacts.
