# Lab dual-grant draft: September 23, 2026

Updated September 28, 2026.

This page cites an open draft. It does not merge that draft, change `main`, or
mark remote OAuth complete. The September 28, 2026 subsection below is the
current live-lab citation. Earlier heads, the September 24 residual-F3 PASS,
and the September 27 head note stay in this note as history.

## Open draft

[Pull request #79](https://github.com/jryski/Supabase_user_MCP/pull/79),
"feat: lab-only dual-grant broker (r2, default off)", is open and still a
draft. Its current head is `527839070b034b4bb7c60ac8f89628ef8e5d9e30`.

Earlier heads cited here:

- `f01b282ecaeffc6e37f16145fb6a18bd14cc60e1`, the head in the first version of
  this note.
- `68639ec21f4c737af991cdb3db1f517ad28cb9a0`, the head cited on the September 23
  update. It is an ancestor of the current head, not its parent.
- `b6d83e04508774644c2d20d4ec85314bff333d8a`, the September 24 residual-F3 PASS
  head. It is an ancestor of the current head.

The draft is stacked on the remote-oauth lineage in
[pull request #75](https://github.com/jryski/Supabase_user_MCP/pull/75). Its
base branch is `ariadne/remote-oauth-rebased-20260919`, not `main`. The base
commit recorded with this note is
`fcbaca121d0717ee8ff98df90b2f12475b05bb78`. `main` at this note is
`ab64f58bc29d4dda1620177660c25d4ba71ef831`.

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
3. **2026-09-24 03:13 UTC.** Ariadne lab-only residual-F3 PASS at that same
   head, `b6d83e04508774644c2d20d4ec85314bff333d8a`.
   [Comment 5806808083](https://github.com/jryski/Supabase_user_MCP/pull/79#issuecomment-5806808083).
   The review says residual F3 is closed at that exact head. The PASS is
   limited to the lab repair. It is not a result for later heads.

## September 27, 2026 head

1. **2026-09-25 16:18 UTC.** The draft head moved from
   `b6d83e04508774644c2d20d4ec85314bff333d8a` to
   `527839070b034b4bb7c60ac8f89628ef8e5d9e30`. Four lab commits separate those
   heads. The base is still `ariadne/remote-oauth-rebased-20260919` at
   `fcbaca121d0717ee8ff98df90b2f12475b05bb78`.
2. **2026-09-27 01:31 UTC.** Ariadne recorded a narrow APPROVE on
   pull request #79 at `527839070b034b4bb7c60ac8f89628ef8e5d9e30`.
   [Review 5328415015](https://github.com/jryski/Supabase_user_MCP/pull/79#pullrequestreview-5328415015).
   The review says the approval covers this head only and a new push needs
   re-review. This page cites that review. It is not itself the independent
   review, and it is not merge readiness.

### September 28, 2026 live-lab evidence

[Comment 5869208644](https://github.com/jryski/Supabase_user_MCP/pull/79#issuecomment-5869208644)
records a pass of the disposable loopback dual-grant M4 harness at the current
draft head. The comment describes existing execution evidence re-inspected on
this date. It is not a broader acceptance, a merge of pull request #79, or
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

Those named cases are lab-scope results at this head. T3, T4, T5, T10, T17,
and the adoption and hosted gates remain open as broader gates. No live M4
expansion is recorded here without Primary Users.

The narrow APPROVE remains
[review 5328415015](https://github.com/jryski/Supabase_user_MCP/pull/79#pullrequestreview-5328415015).
That review covers this head only. It is not merge readiness. The September 24
residual-F3 PASS at `b6d83e04508774644c2d20d4ec85314bff333d8a` stays history
and is a different result from this receipt.

## September 23, 2026 head, retained

These points were recorded for `68639ec21f4c737af991cdb3db1f517ad28cb9a0`.
That commit remains an ancestor of the current head:

- Authenticated lab `initialize` and `tools/list` schemas are present on that
  draft.
- The in-process MCP SDK path was exercised. That is not full T3: no external
  client binary and no live GoTrue.

## Non-claims

- The draft is still a draft. This documentation update is not a merge of
  pull request #79. The narrow APPROVE is not merge readiness.
- The lab-only residual-F3 PASS at `b6d83e04508774644c2d20d4ec85314bff333d8a`
  is not full adoption, is not merge authorization, and is not the September 28
  live-lab receipt. That receipt is the citation for
  `527839070b034b4bb7c60ac8f89628ef8e5d9e30`.
- It is not hosted or live activation, and it is not publication approval.
  No live M4 expansion is recorded here without Primary Users.
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
