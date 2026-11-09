# Issue #145: task-details v2 against the sanitized portable downstream task contract packet

## What this is

This change is a strict, unregistered `readVersion: 2` contract and an adapter over an injected port. It follows the sanitized portable downstream task contract packet. Nothing is registered with an MCP server and nothing is exported from a package index. No migration, schema, registry, package or lockfile changes.

The qualification base is `main` at `585f5464ec9c498857a928fce16f9b66b2f3817b`.

Files:

- `packages/contracts/src/task-details-v2.ts`
- `packages/contracts/src/task-details-v2.test.ts`
- `packages/server/src/task-details-adapter.ts`
- `packages/server/src/task-details-adapter.test.ts`
- `docs/evidence/ISSUE_145_TASK_DETAILS_V2.md`

## Named missing-contract gate: consumer v1 compatibility

**NAMED MISSING-CONTRACT GATE: consumer v1 compatibility.** The sanitized portable downstream task contract packet says v1 stays the default and that board and event-history remain read-only tools, but it does not supply v1 bytes. This change does not invent a v1 fixture and does not treat any other receipt as v1 evidence. Closing the gate needs a published v1 fixture and a test that pins it. Until then this module makes no consumer v1 byte-shape claim.

## Negotiation and vocabulary

- A call negotiates with `readVersion: 2` only. The decoder and the adapter both refuse any other number with `UNSUPPORTED_REPRESENTATION`. A missing version, a non-object, or an array (including one tagged with version 1, and an oversized array) is `MALFORMED_REPRESENTATION`.
- Task status is exactly `open`, `in_progress`, `blocked`, `done`, `cancelled`. Any other value fails closed.
- Event command is exactly `create`, `update`, `assign`, `transition`, `note`, `submit`, `review`.
- Kinds are exactly `human` or `agent`.
- Returned ids are canonical lower-case UUIDs. Versions are 64 lower-case hex characters, compared for equality only. The contract does not require a UUID version nibble; that constraint is not in the packet.
- Each call accepts at most 10 rows.

## Views

- `task`: one task. The read requires `taskId` and an exact `expectedVersion`. A version mismatch is `VERSION_CONFLICT` and the refusal carries no task data. A provider payload whose version differs from the requested version is `MALFORMED_REPRESENTATION`, also with no data.
- `tasks`: keyset by task id.
- `assignment_targets`: typed principal identity, keyset by principal id. Coverage is exactly `completeLibrary: false` and `eligibleTargetsGrantAuthority: false`.
- `coordination_targets`: the same principal plus a distinct `clientId`, with the same coverage flags.
- `events`: keyset by parsed timestamp plus receipt id, scoped to one `taskId`. Instants are compared after parsing, including fractions below a millisecond, so offset forms and same-millisecond events order chronologically and a cursor does not stick. An instant before 1970 is refused. The packet does not define a cross-task event page; that shape is not implemented. Coverage is exactly `completeHistory: false`, `actualStoredAttributionOnly: true` and `approvalInferred: false`.
- Only `note` and `submit` may carry an evidence segment. Stored attribution is evidence. Approval is not inferred.
- Eligible targets do not grant authority. The packet does not define a withdrawn-target wire field. An unavailable assignment target is a port denial, not a status on the target list.

A null keyset cursor means the provider returned no further key. It is not a claim that a library or a history is complete.

## Segments and bounds

A segment is `{ text, offset, totalChars, nextOffset, complete }`. Offsets count Unicode code points. Coverage must be exact: `nextOffset = offset + returned`, and `complete` is true only when `nextOffset = totalChars`.

The packet does not state per-field character ceilings. `DETAIL_BODY_MAX_CHARS` is 8000 Unicode code points, not 8000 bytes. A body of 8000 4-byte characters can exceed the 27000-byte structured ceiling of the emitted `{ ok: true, value }` wrapper and is refused. List segments are tighter. The largest body that stays under that ceiling wraps without throwing.

Packet ceilings, all enforced:

- request: 2048 bytes
- provider response: 60000 bytes
- structured content: 27000 bytes
- complete result: 60000 bytes
- timeout: no more than 5000ms, and also no more than the shared governor (`MAX_TOOL_EXECUTION_MS`, 2000ms)

Stored text is labelled untrusted. `structuredContent` for a successful read is the wrapper `{ ok: true, value }`, and that wrapper is what the 27000-byte ceiling measures. A mutation result keeps `{ ok: true, receipt }` as its structured content. A refusal is returned as itself and is never labelled `ok: true`. A result that exceeds the structured ceiling or the complete-result ceiling is `RESPONSE_LIMIT_EXCEEDED`.

NUL, other C0 controls except tab, LF and CR, DEL, and lone surrogates are rejected and never rewritten.

## Adapter

The adapter is constructed with `createTaskDetailsAdapter({ port, timeoutMs? })`. The port is injected. Inputs have no caller identity, client, session, workstream, role, SQL, URL or credential. Authorization denials `not_found`, `wrong_workstream`, `wrong_client` and `wrong_session` are the same `NOT_AVAILABLE` bytes.

The adapter copies the input with one JSON snapshot before it measures or parses that input. A throw while unwrapping a port result becomes the frozen `UPSTREAM_UNAVAILABLE` refusal. A throw from a getter inside a value already accepted for decoding becomes the frozen `INTERNAL_ERROR` refusal and is not retryable. A throw while measuring the request becomes `INVALID_REQUEST`. The outer refusal and its inner `refusal` object are both frozen. The thrown text is not returned.

An already-aborted caller makes no port call. A deadline aborts the port signal. A mid-flight cancel aborts the port signal and the abort listener is removed when the call settles.

## Acceptance level

**Synthetic contract tests only.** The port is in-memory. This is not runtime acceptance. The adapter is unregistered.

## Open contract gaps

The packet is silent on these points. They stay fail-closed and are not given invented semantics:

- Consumer v1 bytes, and the board and event-history v1 tool schemas.
- Per-field character ceilings (only the byte ceilings and the tighter list clip are implemented).
- A UUID version nibble.
- A cross-task event page.
- A task-list completeness flag. A null cursor does not claim a complete library.
- A withdrawn-target field on the wire.
- Note and assign write payloads, and a successful idempotent replay flag. Writes that already fail closed remain, and they are not a claim that the packet defined them.

## Proposed native RPCs (proposal only, no migration)

No SQL is shipped. A future database-owned read would take the same finite parameters as the port: identifiers, an exact expected version on a detail read, a page limit of at most 10, and a keyset cursor. Identity would come from the authenticated session, never from parameters. That RPC does not exist in this change.

## Remaining integration work

- Export the contract and register tools only after review.
- Bind the port under an authenticated session.
- Close the consumer v1 gate with a published fixture.
- Run a real read acceptance. That is a separate change.
