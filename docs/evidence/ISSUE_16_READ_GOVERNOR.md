# Issue 16 read governor evidence

## Limiter identity boundary

The read governor does not accept a caller-selected limiter scope. Its invocation context contains
only controller-provided `principalId` and `clientId` identity fields. The executor derives a
namespaced key internally in this order:

1. `principal:<verified principal id>`;
2. `client:<verified client id>` when no principal is available; or
3. `operation:<fixed operation>` when neither identity is available.

Unknown runtime properties are ignored. In particular, adding or changing a `scope` property cannot
create a new budget or collide with another principal's budget. Regression tests cover both attacks.

The third fallback is an explicit pre-M1 safety property. Calls without verified identity share one
conservative bucket per fixed operation. One caller can therefore reduce availability for other
unidentified callers, but cannot increase authority or bypass the global operation budget. Issue #17
must supply verified identity context before claiming per-principal or per-client enforcement.

## State lifetime and exhaustion

Limiter state is process-global by design so reconstructing an executor cannot reset a warm
process's budget. Tracking is bounded to 1,024 identity scopes. Only inactive states may be evicted.
If every tracked state is active, allocation returns no state and execution fails closed with the
tool's non-enumerating unavailable result.

This is an in-process governor, not a distributed quota. Multi-process or horizontally scaled
deployment requires a separately reviewed shared limiter before making fleet-wide rate claims.

## Operational events

Events contain the internally derived scope, a bounded digest of normalized arguments, duration,
row count, outcome, and stable denial class. They do not contain raw tool arguments, records,
credentials, or upstream response bodies. Event-emitter failure cannot alter tool execution.

## Verification

The focused governor suite covers validation, row and wire ceilings, deadlines, concurrency, rate
windows, hostile cyclic arguments, valid error outputs, caller-supplied scope churn, victim-scope
collision, and invalid policy construction. The integration suite proves all three public read
factories pass through validation and event emission.
