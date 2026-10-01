# DESIGN ONLY — create-only synthetic memory filing

This note is the next component. It is not an implementation. No write tool,
write RPC, or `memory:write` grant is added by the retained read lab.

## Current gap

No create tool and no create RPC exist. `memory.authorized_memory_get_v1`,
`memory.authorized_memory_list_recent_v1`, and
`memory.authorized_memory_search_v1` are read-only. `policy_lab` grants only
`memory:read` and `memory:search`. Callers have no `INSERT`.

## Required behavior

A future create path files one synthetic memory for the authenticated subject
and the native client already on the verified token. The server derives both
with `auth.uid()` and `policy_lab.verified_client_id()`. The caller cannot
pass an owner, subject, or client override.

Filing also requires an independent `memory:write` capability and an active
membership in the target workspace. A foreign workspace is refused. The
stored row is readable afterward only through the existing read RPCs, under
the existing read grant. A write grant alone does not become a read grant.

Fields stay bounded: title, content, provenance summary, and a small tag
set. Provenance is server-stamped. The caller does not supply the memory id
that another workspace already owns, and a retry of the same idempotency key
returns the original row instead of a second insert. Concurrent retries of
that key resolve to one row.

## Changes that would be required later

- A check-constraint extension that adds `memory:write` without granting it
  to existing read callers.
- An insert policy that ignores caller-supplied owner, subject, and client
  columns and requires the verified subject, verified client, active
  membership, and active write grant.
- One `SECURITY INVOKER` RPC, `memory.authorized_memory_create_v1`, with
  `search_path = pg_catalog`, `EXECUTE` only for `authenticated`, and no
  execute for `PUBLIC`, `anon`, or `mcp_ingress`.
- No Data API exposure of `policy_lab` and no raw table insert.
- An MCP tool that calls that RPC with the fixed client's memory profile and
  does not accept owner, subject, or client arguments.
- Tests for the happy path, foreign-workspace refusal, missing write grant,
  caller override rejection, idempotent retry, a concurrent duplicate key,
  and readback through the three existing read RPCs.
- Privilege tests that read callers still lack `INSERT` until this reviewed
  change exists.

Do not treat this note as permission to apply those changes.
