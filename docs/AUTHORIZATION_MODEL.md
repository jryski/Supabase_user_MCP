# Authorization Model

- **Status:** Frozen for the M0 read-only pilot
- **Scope:** Identity and access-matrix vocabulary for `memory:search` and `memory:read`

## Security boundary

Authorization is denied by default. An allow decision requires a verified principal, an active
client, an active workspace membership, an active capability grant, an allowed record state,
and the relevant row predicate. Authentication by itself is never sufficient.

Principal, client, and workspace identifiers in this contract are opaque references to verified
context or trusted authorization data. They are not accepted as ownership claims from tool
arguments. Wildcards and unknown fields fail closed.

## Principal kinds

| Kind | Definition |
| --- | --- |
| `human` | An interactive person identified by a verified token subject. |
| `delegated_agent` | A client acting for a human, constrained by both subject and client identity. |
| `service_agent` | A durable non-human principal with an explicit lifecycle and revocation path. |
| `reviewer` | A human authorized for specified review actions without implicit administration rights. |
| `system_worker` | A narrowly scoped backend worker outside the public tool surface. |

Human-readable names, email addresses, profile metadata, owner fields, and tenant fields are not
authorization keys.

## States and capabilities

Membership, client, and grant state each use the same closed vocabulary:

- `active`: eligible for further authorization checks;
- `expired`: no longer eligible because its validity window ended; and
- `revoked`: explicitly disabled before or independently of expiry.

The M0 capability vocabulary is exactly:

- `memory:search`: run a bounded search over rows already authorized for the request context;
- `memory:read`: retrieve an individually addressed row already authorized for the context.

Capabilities are exact strings. `*`, `memory:*`, and every undeclared value are invalid.

Record state is `present` or `absent`. It describes the synthetic fixture presented to the policy
test; it does not let a caller assert ownership or tenancy.

## Access-matrix contract

`AuthorizationAccessRowSchema` is the canonical runtime schema. `AccessMatrixSchema` accepts a
non-empty array of these rows. Every object is strict, and identifiers must match
`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`.

```json
[
  {
    "principal": { "id": "principal-human-1", "kind": "human" },
    "client": { "id": "client-cli-1", "state": "active" },
    "workspace": { "id": "workspace-alpha", "membershipState": "active" },
    "grantState": "active",
    "capability": "memory:read",
    "recordState": "present",
    "expectedResult": { "decision": "allow" }
  }
]
```

Each policy fixture must supply the exact principal, client, workspace, grant state, capability,
record state, and expected result shown by this shape. Negative and cross-identity fixtures use
the same fields and a denied result; they must not add caller-selected `ownerId`, `tenantId`, or
similar authority assertions.

## Expected results and denial classes

Expected results are an unambiguous discriminated union:

- `{ "decision": "allow" }`; or
- `{ "decision": "deny", "denialReason": "<class>" }`.

An allow result cannot carry a denial reason, and a deny result must carry exactly one known
reason. The stable denial classes are:

| Class | Non-enumerating meaning |
| --- | --- |
| `identity_denied` | No eligible verified principal is available. |
| `client_denied` | The client is not eligible for the attempted operation. |
| `membership_denied` | Workspace membership does not authorize the operation. |
| `capability_denied` | The required exact capability is not currently granted. |
| `record_unavailable` | The row is absent or unavailable in the authorized scope. |

Public errors must not distinguish a missing row from a row belonging to another principal,
client, or workspace. Expired and revoked states may be recorded in trusted audit evidence but
must not become row-enumerating response details.

## Fail-closed examples

The contract rejects:

- wildcard principals, clients, workspaces, or capabilities;
- unknown principal kinds, states, capabilities, record states, or denial classes;
- caller-asserted owner or tenant fields;
- extra keys at any object level;
- empty access matrices; and
- ambiguous outcomes such as a deny without a reason or an allow with a denial reason.
