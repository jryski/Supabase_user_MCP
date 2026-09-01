# v0.1 read-only implementation plan

- **Status:** Active planning baseline
- **Tracking epic:** [#19](https://github.com/jryski/Supabase_user_MCP/issues/19)
- **Scope:** local stdio, read-only, synthetic acceptance
- **Historical planning baseline:** `e3b1af371bd0e231376d32efe1623ed32c011fb3`
- **Last reconciled main:** `f691b1a49cabfc6bcf86f6011509db10a7496f90`
- **Last reviewed:** 2026-08-30

## Outcome

Deliver an experimental Supabase User MCP that exposes three bounded read tools through a real MCP client while preserving user/client identity through the Supabase Data API and PostgreSQL RLS path:

- `memory_search`
- `memory_get`
- `memory_list_recent`

This plan is intentionally narrower than the full M0–M6 roadmap. It turns M0, M1, and M2 into contributor-sized work packages without claiming remote or production readiness.

## Explicit exclusions

The v0.1 pilot does not include:

- remote HTTP or OAuth;
- service-agent production identity;
- writes, proposals, approvals, or canonical mutation;
- production or private deployment data;
- `service_role`, project access tokens, or `BYPASSRLS` roles in the public request path;
- arbitrary SQL or caller-selected origins, schemas, tables, views, RPCs, URLs, or HTTP methods.

## Milestones

| Milestone | Purpose | Exit signal |
| --- | --- | --- |
| [M0: Policy and contract foundation](https://github.com/jryski/Supabase_user_MCP/milestone/1) | Freeze identity, capabilities, credential behavior, tool contracts, and fail-closed controls | Machine-readable contracts and decisions are complete; blockers are explicit |
| [M1: Supabase policy laboratory](https://github.com/jryski/Supabase_user_MCP/milestone/2) | Prove RLS/capability/revocation/audit behavior with synthetic identities and records | Complete allow/deny matrix passes; deliberate control failures fail the suite |
| [M2: Read-only pilot](https://github.com/jryski/Supabase_user_MCP/milestone/3) | Implement and accept the three read tools through local stdio | Real MCP client and Supabase/RLS path pass end-to-end acceptance |

## Dependency graph

```text
M0
  #2 T03 rejecting control ───────────────┐
  #8 credential/protocol policy ───┐      │
  #9 identity/capability model ──┐ │      │
  #10 read-tool contracts ─────┐ │ │      │
                              │ │ │      │
M1                            │ │ │      │
  #11 policy lab ◀────────────┘ │ │      │
  #3 policy tester/catalog lint ◀┘ │      │
  #4 SECURITY DEFINER gate ◀───────┘      │
  #12 revocation/audit ◀── #11, #3, #4 ──┘

M2
  #13 credential loader/client ◀── #8, #11, #12
  #14 memory_search ◀────────────── #10, #13
  #15 memory_get/list_recent ◀───── #10, #13
  #16 governors/errors/events ◀──── #13
  #17 end-to-end acceptance ◀────── #14, #15, #16
  #18 operator/release docs ◀────── #17
```

## Work packages

### Current execution order

As of 2026-09-01, issues #11 and #17 are closed after the principal-bound path merged through PR #38,
and issue #44's official-upstream alignment merged through PR #45. The remaining M2 order is:

1. Complete issue #18's executable environment-only stdio entrypoint, synthetic client example,
   operator guide, revoke/rollback procedure, and experimental release checklist.
2. Run exact-head Build/M2/Markdown/Links plus independent review and clean-room reproduction.
3. Reconcile epic #19 and release only with local-stdio/read-only/synthetic-only claim limits.

Use the upstream Auth plus `StreamTransport` test topology selected by
[ADR-0004](decisions/0004-narrow-upstream-mcp-reuse.md). Do not import the generic PostgREST MCP
runtime or its caller-selected request tools.

### Merged foundations on `main`

| Issue | Merged scope | Main commit |
| --- | --- | --- |
| [#2](https://github.com/jryski/Supabase_user_MCP/issues/2) | Authorized-write containment contract | `c162d548e7cf9ece5ed22475f4330854a44f46dc` |
| [#8](https://github.com/jryski/Supabase_user_MCP/issues/8) | Local credential and protocol policy | `c08195fcf8d9064e591b55ec5e6be8c7afb66007` |
| [#9](https://github.com/jryski/Supabase_user_MCP/issues/9) | Authorization vocabulary and access matrix | `0b48b72127e3ac222195eab32f197a7665ba10f6` |
| [#10](https://github.com/jryski/Supabase_user_MCP/issues/10) | Bounded read-tool contracts | `7c930af9ca4c991eabcf0f111dafe3f7dc0fc444` |
| [#25](https://github.com/jryski/Supabase_user_MCP/issues/25) | Pinned upstream StreamTransport seam | `63269c64bb1d259faf93e7c3e63e3e210e705afc` |
| [#11](https://github.com/jryski/Supabase_user_MCP/issues/11) | Core local policy-lab implementation; acceptance tracker closed after merged M2 | `83a72f52cf387c10589ea580e5c4738bf3ce497b` |
| [#3](https://github.com/jryski/Supabase_user_MCP/issues/3) | RLS catalog lint | `7ed3cfb955456dc29bf5ba34ca0d18cea4ca2e89` |
| [#4](https://github.com/jryski/Supabase_user_MCP/issues/4) | SECURITY DEFINER pre-grant evidence contract | `80fcfe32c7378cca2ff81f85d990a89fcad2d1f8` |
| [#12](https://github.com/jryski/Supabase_user_MCP/issues/12) | Revocation and append-only audit boundary proof | `f7374c7477252f8443b65499188cac01026aadfb` |
| [#13](https://github.com/jryski/Supabase_user_MCP/issues/13) | Protected credential loader and fixed client | `efba54ef64479b9c056514266efdda1327febe40` |
| [#14](https://github.com/jryski/Supabase_user_MCP/issues/14) | Bounded memory-search application seam | `3b7121fb0a3cc0b19db6463c17264a00fab706e6` |
| [#15](https://github.com/jryski/Supabase_user_MCP/issues/15) | Governed memory get and recent-list factories | `963b342c789a183331a31c7a144cd7cfeaecd25b` |
| [#16](https://github.com/jryski/Supabase_user_MCP/issues/16) | Process-local governors, errors, and operational events | `963b342c789a183331a31c7a144cd7cfeaecd25b` |
| [#17](https://github.com/jryski/Supabase_user_MCP/issues/17) | Verified principal-bound MCP/Data API/RLS acceptance | `dd5ba98a00a3b37003554a14200f789fcb233cac` |
| [#44](https://github.com/jryski/Supabase_user_MCP/issues/44) | Official Auth test reuse and authenticated OpenAPI census | `7f2a3fa955a811f97ed4f88e4cfa50ad7e3aa4d4` |

### Active and blocked work

| Issue/PR | Current state | Next gate |
| --- | --- | --- |
| [#18](https://github.com/jryski/Supabase_user_MCP/issues/18) | In progress on merged principal/upstream foundation | Exact-head CI, independent review, and clean-room operator reproduction |

## Parallel work lanes

The remaining critical path is issue #18 only. Avoid reopening merged work packages or starting
remote/write surfaces around it. Small independent documentation, denial-test, and evidence-index
fixes may proceed when they do not change the active authority boundary.

## Contributor workflow

1. Pick one issue labeled `status:ready`.
2. Comment on the issue that you are taking it and state the intended files.
3. Create a focused branch named from the issue, for example `feat/14-memory-search`.
4. Open a draft PR early and link the issue.
5. Keep the PR within that issue's named scope; propose extra work in a separate issue.
6. Add the required positive, denial, cross-identity, malformed-input, and boundary tests.
7. Run the exact verification commands below and include the results in the PR.
8. Do not merge your own authority-expanding change without the repository's required review.

A stale claim can be released if the assignee/commenter has shown no activity for seven days and does not respond to a maintainer check. This is coordination policy, not a code lease.

## Baseline development environment

Required by `package.json`:

```text
Node >=22.20.0 <23
npm >=11.19.0 <12
```

Install and verify:

```bash
npm ci
npm run check
```

At reconciled main `7f2a3fa…`, `npm run check` passes 22 test files and 194 tests with four
intentional non-harness skips after exact lockfile installation. Exact M2 CI separately proves the
synthetic Auth/PostgREST/RLS boundary at that coordinate.

## Pull-request acceptance

Every implementation PR must:

- link one work-package issue and any required ADR;
- identify public-contract and authority changes;
- derive identity/ownership from verified context, not tool arguments;
- include positive and paired denial tests;
- include cross-principal/workspace/client tests when applicable;
- include exact row, byte, duration, concurrency, and malformed-input boundaries;
- verify logs/errors/traces contain no credentials or sensitive records;
- document compatibility and rollback;
- pass `npm run check` from a clean lockfile install;
- avoid production-readiness claims beyond the completed milestone.

## Definition of done

The v0.1 read-only pilot is done only when:

1. all issues in epic #19 are closed through reviewed PRs;
2. M0, M1, and M2 exit criteria pass from a clean checkout;
3. a real MCP client executes all three tools against synthetic local Supabase fixtures;
4. two authorized principals see only their permitted intersections;
5. unauthenticated, expired, revoked, wrong-issuer, wrong-audience, wrong-client, and cross-workspace requests are denied without record-existence leakage;
6. deliberately weakened RLS, grants, views, privileged functions, audit controls, and tool ceilings each make acceptance fail;
7. the stored prompt-injection corpus cannot cause writes, authority expansion, or arbitrary network/database access;
8. a machine-readable acceptance receipt and experimental release checklist are generated;
9. documentation explicitly says local stdio, read-only, synthetic acceptance, and not production-ready.

## Later work

M3 governed writes, M4 remote HTTP/OAuth, M5 fleet hardening, and M6 stable v1 remain in `docs/ROADMAP.md`. They do not block delivering or evaluating this local read-only pilot.
