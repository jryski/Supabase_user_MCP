# Lab dual-grant draft: September 23, 2026

This page cites an open draft. It does not merge that draft, change `main`, or
mark remote OAuth complete. The September 27, 2026 section below is the current
citation. Earlier heads stay in this note as history.

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
2. **2026-09-27 01:31 UTC.** Ariadne (`ariryski`) recorded a narrow APPROVE on
   pull request #79 at `527839070b034b4bb7c60ac8f89628ef8e5d9e30`.
   [Review 5328415015](https://github.com/jryski/Supabase_user_MCP/pull/79#pullrequestreview-5328415015).
   The review says the approval covers this head only and a new push needs
   re-review. This page cites that review. It is not itself the independent
   review, and it is not merge readiness.
3. M4 live evidence is still open and was not re-run on this head. A prior
   loopback receipt is not evidence for `527839070b034b4bb7c60ac8f89628ef8e5d9e30`.
   No live M4 expansion is recorded here without Primary Users.

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
  is not full adoption, is not merge authorization, and is not evidence for
  the current head.
- It is not hosted or live activation, and it is not publication approval.
  M4 live evidence was not re-run on the current head. No live M4 expansion
  is recorded here without Primary Users.
- It is not encrypted refresh-at-rest.
- [Issue #62](https://github.com/jryski/Supabase_user_MCP/issues/62) (M4:
  remote HTTP + Supabase OAuth 2.1 principal-bound profile) is not complete.
- T3 (external maintained client), T4 (live end-user RLS), T5 (separate
  upstream registration), T10 (measured live revocation), T17 (full-stack
  teardown), and the adoption and hosted gates remain open.
- This documentation update does not change broker behavior or turn any config
  default on.

Public `main` remains the experimental local-stdio, read-only, synthetic-only
profile described in the repository overview. Remote HTTP and Supabase OAuth
2.1 stay a separate gate under issue #62.
