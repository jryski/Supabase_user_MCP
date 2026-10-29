# Lab dual-grant draft: September 23, 2026

Updated September 28, 2026.

This page cites an open draft. It does not merge that draft, change `main`, or
mark remote OAuth complete. It does not pin a `main` commit or the live head
of the draft. Pull request #79 is the live state, and that head may move.
Earlier heads, the September 24 residual-F3 PASS, the September 27 narrow
APPROVE, the September 28 loopback receipt, a September 28 changes request,
and a later September 28 pass stay in this note as dated history.

## Open draft

[Pull request #79](https://github.com/jryski/Supabase_user_MCP/pull/79),
"feat: lab-only dual-grant broker (r2, default off)", is open and still a
draft. Read that pull request for the live head. This note does not record a
current tip.

On 2026-09-28, a reviewer requested changes on that draft
([comment 5870116692](https://github.com/jryski/Supabase_user_MCP/pull/79#issuecomment-5870116692)).
The review examined `527839070b034b4bb7c60ac8f89628ef8e5d9e30`. That review is
not a pass of that commit, and it is not a merge.

On 2026-09-28, a reviewer recorded a pass at a later head,
`0f43a56d8e7110f23f926e88f094077ce06d0981`
([comment 5875470040](https://github.com/jryski/Supabase_user_MCP/pull/79#issuecomment-5875470040)).
That pass covers that commit only. It is not a merge, not a pin of the live
tip, and not a rerun of the loopback M4 receipt. The head may still move.

Dated heads cited below are history:

- `f01b282ecaeffc6e37f16145fb6a18bd14cc60e1`, the head in the first version of
  this note.
- `68639ec21f4c737af991cdb3db1f517ad28cb9a0`, the head cited on the September 23
  update. When the September 27 review was recorded, it was an ancestor of
  `527839070b034b4bb7c60ac8f89628ef8e5d9e30`, not its parent. This note does
  not claim it remains an ancestor of a later tip.
- `b6d83e04508774644c2d20d4ec85314bff333d8a`, the September 24 residual-F3 PASS
  head. When the September 27 review was recorded, it was an ancestor of
  `527839070b034b4bb7c60ac8f89628ef8e5d9e30`. This note does not claim it
  remains an ancestor of a later tip.
- `527839070b034b4bb7c60ac8f89628ef8e5d9e30`, the September 27 narrow APPROVE
  and the September 28 loopback M4 receipt. A reviewer requested changes on
  this commit on 2026-09-28. It is a dated coordinate, not the live tip.
- `0f43a56d8e7110f23f926e88f094077ce06d0981`, a later September 28 pass. It is
  a dated coordinate, not the live tip.

The draft is stacked on the remote-oauth lineage in
[pull request #75](https://github.com/jryski/Supabase_user_MCP/pull/75). Its
base branch is `ariadne/remote-oauth-rebased-20260919`, not `main`. The base
commit recorded with this note is
`fcbaca121d0717ee8ff98df90b2f12475b05bb78`. This note does not pin `main`.
An earlier version named a `main` SHA. That assertion is dropped because
`main` has moved, including the merge of pull request #96.

On that draft, the ordinary remote path stays fail-closed. Dispatch through
the dual-grant broker requires the lab opt-in. Default-off behavior there is
not an enablement switch on `main`.

## September 24, 2026 review lineage

1. **2026-09-24 02:32 UTC.** REQUEST_CHANGES at
   `68639ec21f4c737af991cdb3db1f517ad28cb9a0`. The review found that a thin
   `globalThis.fetch` wrapper was accepted for `.invalid` fixtures.
   [Comment 5806408425](https://github.com/jryski/Supabase_user_MCP/pull/79#issuecomment-5806408425).
2. **2026-09-24 02:48 UTC.** Structural-separation repair at
   `b6d83e04508774644c2d20d4ec85314bff333d8a`. The commit owns the scripted
   responder for `https://*.invalid` coordinates and rejects caller fetch,
   including a thin wrapper around `globalThis.fetch`.
3. **2026-09-24 03:13 UTC.** Reviewer ariryski recorded a lab-only residual-F3
   PASS at that same head, `b6d83e04508774644c2d20d4ec85314bff333d8a`.
   [Comment 5806808083](https://github.com/jryski/Supabase_user_MCP/pull/79#issuecomment-5806808083).
   The review says residual F3 is closed at that exact head. The PASS is
   limited to the lab repair. It is not a result for later heads.

## September 27, 2026 head

1. **2026-09-25 16:18 UTC.** The draft head moved from
   `b6d83e04508774644c2d20d4ec85314bff333d8a` to
   `527839070b034b4bb7c60ac8f89628ef8e5d9e30`. Four lab commits separate those
   heads. The base recorded then was still
   `ariadne/remote-oauth-rebased-20260919` at
   `fcbaca121d0717ee8ff98df90b2f12475b05bb78`.
2. **2026-09-27 01:31 UTC.** Reviewer ariryski recorded a narrow APPROVE on
   pull request #79 at `527839070b034b4bb7c60ac8f89628ef8e5d9e30`.
   [Review 5328415015](https://github.com/jryski/Supabase_user_MCP/pull/79#pullrequestreview-5328415015).
   The review says the approval covers that commit only and a new push needs
   re-review. This page cites that review. It is not itself the independent
   review, and it is not merge readiness.

### September 28, 2026 loopback receipt

[Comment 5869208644](https://github.com/jryski/Supabase_user_MCP/pull/79#issuecomment-5869208644)
records a pass of the disposable loopback dual-grant M4 harness at
`527839070b034b4bb7c60ac8f89628ef8e5d9e30`. That commit is the reviewed head
for this receipt. It is not a pin of the live tip. The comment describes
existing execution evidence re-inspected on this date. It is not a broader
acceptance, a merge of pull request #79, or
completion of
[issue #62](https://github.com/jryski/Supabase_user_MCP/issues/62).

- Reviewed head: `527839070b034b4bb7c60ac8f89628ef8e5d9e30`.
- Tree: `7149476ff9acc3e9db07ae30fa5d9b923b2d23c2`.
- Receipt schema: `supabase-user-mcp.lab-dual-grant-m4.v1`; result `pass`.
- Runtime: Node v22.23.2, npm 12.1.0, Supabase CLI 2.115.0.
- Loopback `127.0.0.1` only; two temporary public clients; memory-only custody.
  The ordinary remote path stays fail-closed. The broker remains lab opt-in
  only.

Nine named lab cases passed:

1. Ordinary fail-closed.
2. Env-and-hook opt-in.
3. In-process MCP SDK / GoTrue / RLS happy path.
4. Alice/Bob RLS isolation.
5. Second OAuth client denial.
6. Broker next-call denial.
7. Provider revoke latency.
8. Data API revoke probe with no SLA claim.
9. Memory-custody cleanup.

The MCP client is in-process `@modelcontextprotocol/client` 2.0.0 with
`externalMcpBinary=false`. This receipt is not an external MCP client binary
and is not T3 full external maintained client acceptance.

Provider revoke returned HTTP 204 in 65 ms. Refresh was denied (probe latency
28 ms). An already-issued Data API JWT still read the synthetic record through
the Data API with HTTP 200 in 6 ms. That still-200 result is not a revocation
SLA. Broker next-call denial is a separate lab case.

Those named cases are lab-scope results at that dated head. T3, T4, T5, T10,
T17, and the adoption and hosted gates remain open as broader gates. No live
M4 expansion is recorded here without the maintainer.

The narrow APPROVE remains
[review 5328415015](https://github.com/jryski/Supabase_user_MCP/pull/79#pullrequestreview-5328415015).
That review covers `527839070b034b4bb7c60ac8f89628ef8e5d9e30` only. It is not
merge readiness. A reviewer requested changes on 2026-09-28 at that same
commit
([comment 5870116692](https://github.com/jryski/Supabase_user_MCP/pull/79#issuecomment-5870116692)).
That review is not a pass of that commit. A later review recorded a pass at
`0f43a56d8e7110f23f926e88f094077ce06d0981`
([comment 5875470040](https://github.com/jryski/Supabase_user_MCP/pull/79#issuecomment-5875470040)).
That pass is a different head from this receipt and is not a merge. The
September 24 residual-F3 PASS at `b6d83e04508774644c2d20d4ec85314bff333d8a`
stays history and is a different result from this receipt.

## September 23, 2026 head, retained

These points were recorded for `68639ec21f4c737af991cdb3db1f517ad28cb9a0`.
When the September 27 review was recorded, that commit was an ancestor of
`527839070b034b4bb7c60ac8f89628ef8e5d9e30`. This note does not claim it remains
an ancestor of a later tip:

- Authenticated lab `initialize` and `tools/list` schemas are present on that
  draft.
- The in-process MCP SDK path was exercised. That is not full T3: no external
  client binary and no live GoTrue.

## Non-claims

- The draft is still a draft. This documentation update is not a merge of
  pull request #79. The narrow APPROVE is not merge readiness.
- The lab-only residual-F3 PASS at `b6d83e04508774644c2d20d4ec85314bff333d8a`
  is not full adoption, is not merge authorization, and is not the September 28
  loopback receipt. That receipt is the citation for
  `527839070b034b4bb7c60ac8f89628ef8e5d9e30`.
- It is not hosted or live activation, and it is not publication approval.
  No live M4 expansion is recorded here without the maintainer.
- It is not encrypted refresh-at-rest.
- The September 28 MCP client is in-process `@modelcontextprotocol/client`
  2.0.0 (`externalMcpBinary=false`). It is not an external MCP client binary
  product claim, and it is not T3 full external maintained client acceptance.
- Provider revoke returned HTTP 204 and refresh was denied. The already-issued
  Data API JWT still returning HTTP 200 is not a revocation SLA.
- [Issue #62](https://github.com/jryski/Supabase_user_MCP/issues/62) (M4:
  remote HTTP + Supabase OAuth 2.1 principal-bound profile) is not complete.
- T3 (external maintained client), T4 (live end-user RLS), T5 (separate
  upstream registration), T10 (measured live revocation), T17 (full-stack
  teardown), and the adoption and hosted gates remain open as broader gates.
  The September 28 lab receipt does not close those gates.
- The ordinary remote path stays fail-closed. Lab opt-in only.
- This documentation update does not change broker behavior or turn any config
  default on.

Public `main` remains the experimental local-stdio, read-only, synthetic-only
profile described in the repository overview. Remote HTTP and Supabase OAuth
2.1 stay a separate gate under issue #62.
