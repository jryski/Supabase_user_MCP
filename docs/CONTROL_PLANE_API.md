# Minimum cross-agent control-plane API

Status: proposed capability profile, discovered through deployment dogfooding on 2026-09-13.

## Problem

Routine coordination still requires agents to choose a store, understand deployment tables, write
SQL, reproduce defaults, supply attribution labels, interpret connector restrictions, and verify
the result. The same operation therefore behaves differently in ChatGPT, Claude, local agents,
and future Ariadne runtimes.

The 2026-09-13 WireSpeed website migration exposed the failure clearly. VAULT planning and model
coordination were writable through privileged database access, but the ChatGPT SQL connector
blocked the requested mutations before PostgreSQL evaluated them. The database was not the failed
component. The missing component was a stable capability interface.

## Boundary

This profile is a deployment control plane. It does not replace the accepted user-context data
plane, bypass authenticated user authorization, or merge HOUSE and VAULT.

- The user-context MCP server remains read-only and never loads a privileged credential.
- The privileged profile is a separate server constructor with exactly two tools in issue #70.
- Tool inputs never accept SQL, relation, schema, URL, HTTP method, role, credential, principal,
  or sender identity.
- Deployment configuration supplies agent attribution. It is provenance, not proof of human
  authority.
- Fixed VAULT RPCs own validation, database constraints, locking, idempotency, and durable audit.
- HOUSE domain functions remain HOUSE capabilities. They are not routed through VAULT or copied
  into this control plane.
- Ariadne is the intended future coordinator. This document does not claim that Ariadne can load
  this profile, hold the required credential, or execute the tools today.

## Proposed stable surface

The target contains ten primitives. Existing deployment RPC names may differ, but every public
tool should preserve these semantics.

| Primitive | Purpose | Current VAULT evidence |
| --- | --- | --- |
| `control_context_get` | Return bounded board state, current item context, available capabilities, and coordination inbox | Composition target; not yet one accepted RPC |
| `work_item_create` | Create one card with required idempotency | Live function definition, receipt, fixed search path, and ACLs verified 2026-09-13 |
| `work_item_claim` | Atomically claim one eligible card and return a lease | `planning.claim_next_work_item` reported in prior deployment investigation; live signature pending refresh |
| `work_item_heartbeat` | Extend one valid lease within deployment limits | `planning.heartbeat_work_item` reported; live signature pending refresh |
| `work_item_note_append` | Append progress without rewriting canonical scope | `planning.add_work_note` reported; live signature pending refresh |
| `work_item_release` | Release one valid lease with a bounded reason | `planning.release_work_item` reported; live signature pending refresh |
| `work_item_submit` | Submit result and evidence for review | `planning.submit_work_item` reported; live signature pending refresh |
| `work_item_review` | Accept, reject, or return submitted work under separate reviewer authority | `planning.review_work_item` reported; live signature pending refresh |
| `model_message_post` | Post one bounded message or reply with database-assigned sequence | Definition, ACLs, service-role invocation, receipt, and single-row effect verified 2026-09-13 |
| `model_message_read` | Read a bounded coordination window without raw table queries | Ariadne signal read exists; general bounded read remains deployment-specific |

Memory search, memory correction, household briefs, calendar delivery, source-control operations,
and model qualification are separate domain capabilities. Adding them to this interface would
blur authority and store ownership.

## Affected systems

| System | Effect in this slice |
| --- | --- |
| `Supabase_user_MCP` | Contracts, fixed RPC client, isolated MCP registration, tests, ADR, and evidence |
| VAULT | Existing RPC and ACL verification; planning/model-channel mutation target; durable progression page |
| HOUSE | Read-only capability inventory and trust-boundary check; no mutation |
| `Household_os_private` | Possible later private architecture cross-reference; no runtime or schema change |
| `sovereign-memory-core` | Later operations-guide correction because current examples still rely on raw SQL/service-role interpretation |
| `sovereign-memory-protocol` | No current implementation dependency |
| Hermes | No current implementation dependency |

## Issue #70 implementation

The first implementation slice exposes `create_work_item` and `post_model_message` from a separate
privileged server profile. The client has fixed PostgREST RPC paths and fixed schema profiles. Work
creation requires an idempotency key. Sender and source-agent attribution come from server
configuration and cannot be replaced in a tool call.

The implementation is not added to the production read-only CLI. A deployment startup and secret
loading decision requires a separate review because it determines where privileged credentials
live and which process Ariadne may invoke.

## Acceptance and claim limits

Synthetic tests must prove strict schemas, exact registration, fixed RPC paths, actor injection,
idempotency-key preservation, concurrent request handling, deterministic invalid-board and
invalid-reply errors, one attempt only, and rejection of direct-DML controls.

Live acceptance additionally requires current function definitions, result shapes, owners,
security mode, search paths, explicit ACLs, PostgREST schema exposure, service-role success,
`anon` denial, `authenticated` denial, and security-advisor review. A migration name or green unit
test does not satisfy that gate.

The 2026-09-13 catalog pass verified the definitions, result shapes, owners, security mode, search
paths, and explicit ACLs. PostgREST exposure of the custom `planning` schema remains a deployment
acceptance gate.

A later live call to `public.post_model_message` failed with PostgreSQL `428C9`: `model_channel.seq`
was `GENERATED ALWAYS`, while the function explicitly inserted its advisory-lock allocation. The
sequence and current maximum were both 1106, so ordinary identity allocation was aligned. Migration
`20260913175421_repair_post_model_message_identity_allocation` corrected the function without adding
an MCP fallback. PostgreSQL now allocates `seq`, and the RPC returns the stored `id` and `seq`.

The repaired RPC was exercised under `service_role` with one bounded synthetic message. It returned
sequence 1108 and UUID `e65c0fd2-f583-4aed-83d7-4c7a94b3cbe2`; exactly one stored row matched both
values, and the identity sequence advanced by one. An invalid reply reference created no row. The
fixed search path, `SECURITY DEFINER` mode, owner, and service-role-only ACL remained unchanged.
