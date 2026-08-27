# v0.1 read-only implementation plan

- **Status:** Active planning baseline
- **Tracking epic:** [#19](https://github.com/jryski/Supabase_user_MCP/issues/19)
- **Scope:** local stdio, read-only, synthetic acceptance
- **Planning baseline coordinate:** `e3b1af371bd0e231376d32efe1623ed32c011fb3`
- **Last reconciled main:** `63269c64bb1d259faf93e7c3e63e3e210e705afc`

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
- production or private Balance EQ data;
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

As of 2026-08-27, issues #2, #8, #9, #10, #25, and the S1 artifact lab are merged. The
remaining read-only pilot work should proceed in this order:

1. Complete exact-head adversarial review of the governed read implementation in PR #36.
2. Assemble the protected credential loader, fixed client, and exactly three governed read tools
   in the executable stdio server. The server currently exposes only the M0 compatibility probe.
3. Complete issue #17 with a real MCP client, synthetic local Auth users and JWTs, Data API calls,
   PostgreSQL RLS, revocation cases, deliberately weakened controls, and a machine-readable receipt.
4. Complete issue #18's synthetic client, operator guide, rollback procedure, and experimental
   release checklist.
5. Reconcile issue labels and close superseded stacked integration PRs only after their unique
   changes are present on `main`.

Use the upstream Auth plus `StreamTransport` test topology selected by
[ADR-0004](decisions/0004-narrow-upstream-mcp-reuse.md). Do not import the generic PostgREST MCP
runtime or its caller-selected request tools.

### Dependency-ready now

| Issue | Work package | Primary area |
| --- | --- | --- |
| [#2](https://github.com/jryski/Supabase_user_MCP/issues/2) | Add a control that proves the T03 containment test can reject a broken implementation | Security/testing |
| [#8](https://github.com/jryski/Supabase_user_MCP/issues/8) | Decide local credential loading, refresh, and protocol-version policy | Identity/MCP |
| [#9](https://github.com/jryski/Supabase_user_MCP/issues/9) | Freeze principal, client, capability, and revocation vocabulary | Identity/security |
| [#10](https://github.com/jryski/Supabase_user_MCP/issues/10) | Freeze read-tool schemas, limits, and non-enumerating errors | MCP/security/testing |

### Begins when dependencies clear

| Issue | Work package | Depends on |
| --- | --- | --- |
| [#11](https://github.com/jryski/Supabase_user_MCP/issues/11) | Pinned local Supabase policy lab and synthetic identities | #9, #10 |
| [#3](https://github.com/jryski/Supabase_user_MCP/issues/3) | Executable policy tester and catalog lint | M0 contracts/policy lab shape |
| [#4](https://github.com/jryski/Supabase_user_MCP/issues/4) | Pre-grant gate for SECURITY DEFINER routines | M1 schema/catalog shape |
| [#12](https://github.com/jryski/Supabase_user_MCP/issues/12) | Revocation and append-only audit boundary proof | #11, #3, #4 |
| [#13](https://github.com/jryski/Supabase_user_MCP/issues/13) | Protected credential loader and fixed Supabase client | #8, #11, #12 |
| [#14](https://github.com/jryski/Supabase_user_MCP/issues/14) | Bounded `memory_search` | #10, #13 |
| [#15](https://github.com/jryski/Supabase_user_MCP/issues/15) | `memory_get` and `memory_list_recent` | #10, #13 |
| [#16](https://github.com/jryski/Supabase_user_MCP/issues/16) | Shared governors, normalized errors, redacted operational events | #13 |
| [#17](https://github.com/jryski/Supabase_user_MCP/issues/17) | End-to-end identity/RLS/adversarial acceptance matrix | #14, #15, #16 |
| [#18](https://github.com/jryski/Supabase_user_MCP/issues/18) | Synthetic client, operator guide, experimental release checklist | #17 |

## Parallel work lanes

Contributors can start #2, #8, #9, and #10 independently. The first implementation lane opens after #9 and #10 settle the policy-lab contract. The tool implementations #14 and #15 may proceed in parallel once #13 lands. #16 should remain shared infrastructure rather than being reimplemented inside each tool.

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

At the planning base, `npm run check` passes with two test files and three tests after exact lockfile installation. Contributors must not treat that compatibility probe as data-plane coverage.

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
