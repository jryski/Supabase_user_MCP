# Authorization Model

- **Status:** Frozen for the M0 read-only pilot
- **Scope:** Identity and access-matrix vocabulary for `memory:search` and `memory:read`

## Security boundary

Authorization is denied by default. An allow decision requires all of these conditions at once:

1. principal identity eligibility is `verified`;
2. client state is `active`;
3. workspace membership state is `active`;
4. capability grant state is `active`; and
5. record state is `present` (the allowed-present condition).

Authentication by itself is never sufficient. `AuthorizationAccessRowSchema` rejects an allow when
any required condition is ineligible; it also rejects a deny whose reason does not match the
trusted state.

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

Principal identity eligibility is an explicit trusted dimension:

- `verified`: trusted identity processing established an eligible principal for this row; and
- `denied`: no eligible verified principal is available, including a cross-principal fixture.

`identityEligibility` is derived from verified request context or trusted authorization data. A
caller cannot promote itself by supplying this field, and an identifier by itself never implies
`verified` eligibility.

Membership, client, and grant state each use the same closed vocabulary:

- `active`: eligible for further authorization checks;
- `expired`: no longer eligible because its validity window ended; and
- `revoked`: explicitly disabled before or independently of expiry.

The M0 capability vocabulary is exactly:

- `memory:search`: run a bounded search over rows already authorized for the request context;
- `memory:read`: retrieve an individually addressed row already authorized for the context.

Capabilities are exact strings. `*`, `memory:*`, and every undeclared value are invalid.

`present` is the only allowed-present record state. `absent` must produce `record_unavailable` when
no higher-precedence boundary already denies the row. Record state describes the synthetic fixture
presented to the policy test; it does not let a caller assert ownership or tenancy.

All exported vocabulary arrays are frozen with `Object.freeze` at runtime as well as typed as
readonly tuples. Consumers cannot broaden a vocabulary by mutating an imported array.

## Access-matrix contract

`AuthorizationAccessRowSchema` is the canonical runtime schema. `AccessMatrixSchema` accepts a
non-empty array of these rows. Every object is strict, and identifiers must match
`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`.

```json
[
  {
    "principal": {
      "id": "principal-human-1",
      "kind": "human",
      "identityEligibility": "verified"
    },
    "client": { "id": "client-cli-1", "state": "active" },
    "workspace": { "id": "workspace-alpha", "membershipState": "active" },
    "grantState": "active",
    "capability": "memory:read",
    "recordState": "present",
    "expectedResult": { "decision": "allow" }
  }
]
```

Each policy fixture must supply the exact principal (including trusted identity eligibility), client,
workspace, grant state, capability, record state, and expected result shown by this shape. Negative
and cross-identity fixtures use different opaque principal, client, or workspace identifiers and
set the corresponding trusted eligibility or lifecycle state to a denied condition. They must not
add caller-selected `ownerId`, `tenantId`, or similar authority assertions.

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

When more than one boundary is ineligible, the schema chooses exactly one denial class in this
fixed precedence order:

1. `identity_denied`;
2. `client_denied`;
3. `membership_denied`;
4. `capability_denied`; and
5. `record_unavailable`.

The expected result must be coherent with that order. An ineligible row must deny with its
highest-precedence reason. A fully eligible row must allow; a deny on a fully eligible row is also
invalid. This makes fixture outcomes deterministic and prevents an expected allow from masking an
expired client, revoked membership or grant, denied identity, or absent record.

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
