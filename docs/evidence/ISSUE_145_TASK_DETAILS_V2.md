# Issue #145: versioned task-details/activity contract v2 (synthetic, unregistered)

## What this is

This change adds a strict `task-details.v2` read/activity contract, a fail-closed decoder, and an adapter over an injected port. The contract covers a bounded task body, an opaque version, recorded provenance, typed assignment targets and stored notes. Nothing is registered with an MCP server and nothing is exported from a package index. No migration, schema, registry or deployment file changes.

The base is `main` at `181cbf9d`. The change does not depend on, import or copy any code from draft #71.

Files:

- `packages/contracts/src/task-details-v2.ts`: schemas, `clipUtf8`, `decodeTaskDetailsV2`, `decodeTaskMutationReceiptV2`, fixed refusals, the MCP result helper and the frame-size estimator.
- `packages/server/src/task-details-adapter.ts`: `createTaskDetailsAdapter({ port, timeoutMs? })`.
- `packages/contracts/src/task-details-v2.test.ts` and `packages/server/src/task-details-adapter.test.ts`: synthetic contract tests.

## v1 label and negotiation

There is no v1 task-details read. `TASK_DETAILS_V1_LABEL` names the two #71 write receipts: **create_work_item / post_model_message @5ffd0974**. This module does not read, produce or change them. A read that does not negotiate `representation: "task-details.v2"` is refused with `UNSUPPORTED_REPRESENTATION` before the port is called. The v2 decoders also refuse those receipt bytes.

The tests pin those receipt bytes as inline constants. Each constant is labelled as a *synthetic fixture mirroring #71 receipt outputs @5ffd0974*. They are not imported from #71, and they are not a consumer v1 compatibility fixture.

## Missing-contract gate: consumer v1 compatibility

**NAMED MISSING-CONTRACT GATE: consumer v1 compatibility.** No public consumer v1 task-details fixture exists. The #71 receipts and any recollection of a consumer shape do not stand in for one. Until a consumer publishes a v1 fixture, this change makes no claim of byte or shape compatibility with any consumer v1 read. Closing the gate needs that published fixture and a test that pins it.

## v2 shape

- `task.body` and each note `text` are `{ text, clipped, totalBytes, returnedBytes }`.
  - Byte counts are UTF-8, and clipping never splits a code point.
  - The decoder refuses inconsistent coverage, such as a byte count that does not match the text, or `clipped: false` while bytes are missing.
  - Field ceilings are 8192 bytes for the body, 2048 bytes per note, 256 UTF-16 code units for the title and 512 for a citation.
- `task.status` is a v2-owned enum: `inbox`, `backlog`, `ready`, `in_progress`, `blocked`, `review`, `done`, `cancelled`. Reconciling it with a deployed work-item status set is an integration step.
- `task.version` is an opaque printable-ASCII token. Callers compare it for equality only.
- `createdBy`, `lastChangedBy` and every activity `recordedBy` are `{ actorKind: human|agent, actorId, clientId, occurredAt }`, as recorded by the database.
- `assignmentTargets.targets[]` is `{ kind: human|agent, id, status: active|withdrawn }`. It comes from authoritative membership and carries count coverage. There are at most 50 targets.
- `activity.entries[]` is a discriminated union, with at most 50 entries:
  - `note`: bounded text, plus `citation` only when one was stored;
  - `assignment`: a typed assignee.
- Each entry carries an immutable `receiptId`. There are no command payloads and no approval fields.
- All objects are strict. Unknown keys, wrong types and `citation: null` fail with `MALFORMED_REPRESENTATION`. A different `representation` fails with `UNSUPPORTED_REPRESENTATION`.

## Text policy: NUL, controls and surrogates

Text is rejected deterministically and never rewritten. This applies to stored text (title, body, note text, citation) and to written text (note text, citation). Text is rejected when it contains any of these:

- NUL or another C0 control other than tab, line feed and carriage return;
- DEL;
- a lone UTF-16 surrogate.

Stored text is refused as `MALFORMED_REPRESENTATION` and written text as `INVALID_REQUEST`. `clipUtf8` throws `RangeError` for a lone surrogate, because UTF-8 cannot carry one faithfully. It also throws for a limit that is not a non-negative safe integer: `NaN`, `Infinity`, negative or fractional.

## One whole-frame size policy

- **Ceiling.** The limit is 65536 bytes, which is `MAX_RESPONSE_BYTES`. It counts the UTF-8 bytes of the complete JSON-RPC response frame: `{"jsonrpc":"2.0","id":…,"result":…}`, the JSON escaping and the newline delimiter.
- **No duplicate copy.** `createTaskDetailsV2McpResult` emits the payload once, as text with an untrusted-data prefix. There is no `structuredContent` copy.
- **Worst-case request id.** Size is measured with the largest legal request id, a 1024-byte serialized string. A result that is accepted therefore fits for every legal id. A test runs a real in-test SDK server with a throwaway probe tool and checks that the captured frame matches the estimator byte for byte.
- **Field ceilings vs. the frame.** The field and count ceilings cannot all be reached at once inside the frame. The frame budget is authoritative. A decoded result whose frame would exceed 65536 bytes is refused as `RESPONSE_LIMIT_EXCEEDED`, which is not retryable. The message asks the caller to request fewer activity entries.
- **Raw precheck.** A raw payload that serializes above the ceiling is refused before schema parsing, which bounds parse cost.
- **Boundary tests.** Tests cover a frame of exactly 65536 bytes (accepted), 65537 (refused) and 65535 (accepted). They also cover the all-fields-at-maximum result (refused) and the largest legal mutation receipt (fits).
- **Proposed RPC.** The proposed read RPC should fill entries newest-first within the frame budget and report clipped coverage. That keeps a full task readable without a refusal.

## Adapter, authorization, deadline and cancellation

Inputs accept only finite parameters: `taskId`, `activityLimit` (1 to 50, default 20), `expectedVersion`, `idempotencyKey`, note `text`, optional `citation`, and a typed `target`. There is no acting identity, client, session, workstream, role, SQL, relation, URL or credential parameter. The port is injected, and identity and authorization come from the session behind it.

| Port denial | Refusal |
| --- | --- |
| `not_found`, `wrong_workstream`, `wrong_client`, `wrong_session` | `NOT_AVAILABLE` (identical bytes, no detail) |
| `version_conflict` | `VERSION_CONFLICT` |
| `idempotency_conflict` | `IDEMPOTENCY_CONFLICT` |
| `target_unknown`, `target_withdrawn` | `TARGET_UNAVAILABLE` |
| `unavailable`, thrown port error | `UPSTREAM_UNAVAILABLE` (retryable) |
| unknown or prototype-named denial | `INTERNAL_ERROR` |

Port results are decoded strictly and checked against the request:

- a read must match the requested `taskId` and return no more than `activityLimit` entries;
- a receipt must name the requested `taskId`.

Deadline and cancellation:

- `timeoutMs` must be a safe integer from 1 to `MAX_TOOL_EXECUTION_MS`; otherwise construction throws `RangeError`.
- When the deadline passes, the port signal is aborted and the result is `DEADLINE_EXCEEDED`.
- When the caller aborts mid-flight, the port signal is aborted and the call settles promptly with `REQUEST_CANCELLED`.
- A caller signal that is already aborted gets `REQUEST_CANCELLED` with zero port calls.
- Only `DEADLINE_EXCEEDED`, `REQUEST_CANCELLED` and `UPSTREAM_UNAVAILABLE` are retryable.

## Acceptance level

**Synthetic contract tests only.** All data is synthetic, and the tests run against an in-memory port that simulates database-owned session authorization. This is not runtime acceptance against a real database, session, client or user. The adapter is unregistered, and nothing in the runtime calls it.

## Proposed native RPCs (proposal only, no migration)

```text
planning.get_task_details_v2(p_task_id text, p_activity_limit integer) returns jsonb
```

- **Parameters:** `p_task_id` must match the identifier grammar, and `p_activity_limit` must be between 1 and 50. There are no other parameters.
- **Return:** exactly the `task-details.v2` object above, within the frame budget. The database clips text, fills entries newest-first and computes coverage.
- **Authorization:** owned by the database. Actor, client and session come from the authenticated request context, never from parameters. Before reading anything, the RPC checks the session's current membership in the task's workstream and client. It never returns command payloads or private fields.
- **Errors:** one SQLSTATE, `TD404`, covers not found, wrong workstream, wrong client, wrong member and invalid session, so the caller learns nothing more. `22023` covers invalid parameters.
- **Writes:** notes and assignments would bind to proposed native note and assign RPCs. Each takes `p_expected_version`, `p_idempotency_key` and, for assignment, a typed target. They return `TD409` (version), `TD410` (idempotency) and `TD422` (target withdrawn or unknown). No such RPC exists in this repository; each is a separate finite proposal.

## Remaining integration work

- **Build-output import.** The adapter imports the contract from `../../contracts/dist/task-details-v2.js`, the contracts build output, because the contract is deliberately not exported from the contracts index. Running the adapter tests therefore needs `npm run build` (or `npm run check`, which builds) first. Replacing this with a package-index import is part of the export step below.
- **Bind the port.** Bind `TaskDetailsPort` to the proposed RPCs under an authenticated user session, not a privileged key.
- **Export and register.** Export the contract from the contracts index, switch the adapter to the package import, and register a read tool behind explicit v2 negotiation.
- **Status set.** Reconcile `task.status` with the deployed status set.
- **Consumer v1 gate.** Close the consumer v1 compatibility gate with a published fixture.
- **Live acceptance.** Run real read → note → read-back → assign acceptance with human and agent sessions.

Each of these is a separate reviewed change.
