# Lab dual-grant draft: September 23, 2026

This page cites an open draft. It does not merge that draft, change `main`, or
mark remote OAuth complete.

## Open draft

[Pull request #79](https://github.com/jryski/Supabase_user_MCP/pull/79),
"feat: lab-only dual-grant broker (r2, default off)", is open and still a
draft. Its head is `f01b282ecaeffc6e37f16145fb6a18bd14cc60e1`.

The draft is stacked on the remote-oauth lineage in
[pull request #75](https://github.com/jryski/Supabase_user_MCP/pull/75). Its
base branch is `ariadne/remote-oauth-rebased-20260919`, not `main`. The base
commit recorded with this note is
`fcbaca121d0717ee8ff98df90b2f12475b05bb78`. `main` at this note is
`ab64f58bc29d4dda1620177660c25d4ba71ef831`.

On that draft, the ordinary remote path stays fail-closed. Dispatch through
the dual-grant broker requires the lab opt-in. Default-off behavior there is
not an enablement switch on `main`.

## Non-claims

- The draft is not merge-ready.
- It is not hosted or live activation.
- It is not encrypted refresh-at-rest.
- [Issue #62](https://github.com/jryski/Supabase_user_MCP/issues/62) (M4:
  remote HTTP + Supabase OAuth 2.1 principal-bound profile) is not complete.
- This documentation update does not merge pull request #79, change broker
  behavior, or turn any config default on.

Public `main` remains the experimental local-stdio, read-only, synthetic-only
profile described in the repository overview. Remote HTTP and Supabase OAuth
2.1 stay a separate gate under issue #62.
