# Threat Model

- **Status:** Proposed
- **Method:** asset and abuse-case analysis informed by STRIDE
- **Last reviewed:** 2026-08-20

## Scope

This model covers the MCP transport, identity verification, tool execution, Supabase Data
API boundary, Postgres policies, approval workflow, and audit evidence. It does not claim
to secure the model provider, the user's device, Supabase infrastructure, or an
application schema that ignores the documented integration requirements.

## Assets

- Supabase access and refresh tokens.
- Human, delegated-agent, and service-agent identities.
- Tenant and workspace membership.
- Memory records, embeddings, source documents, and metadata.
- Canonical application state and pending proposals.
- Capability grants and revocation state.
- Audit evidence and correlation identifiers.
- Service configuration, signing material, and dependency supply chain.
- Availability and cost budget of the MCP service and database.

## Adversaries and failure sources

- A malicious authenticated user.
- A compromised or over-permissioned agent.
- An attacker who controls stored content returned to a model.
- A malicious or impersonated MCP/OAuth client.
- An operator configuration mistake.
- A vulnerable dependency or compromised build action.
- A network attacker where HTTPS or redirect validation is incorrect.
- A well-intentioned model producing malformed, excessive, or destructive requests.

## Assumptions

- Supabase Auth signing keys and platform services are not compromised.
- PostgreSQL and PostgREST enforce their documented security semantics.
- Operators protect deployment secrets and enable HTTPS for remote endpoints.
- The integrating application follows the required grants, RLS, view, and function
  guidance.
- AI output and all retrieved content are untrusted.

Assumptions are dependencies, not mitigations. Tests should validate the portions that
can be exercised locally.

## Primary abuse cases

| ID | Threat | Example | Required controls | Verification |
| --- | --- | --- | --- | --- |
| T01 | Cross-tenant object access | Guess another workspace's record ID | Tenant membership plus row predicate; non-enumerating errors | Access-matrix tests |
| T02 | Cross-agent escalation | Reuse a human token from an unapproved OAuth client | Exact issuer/audience/client validation and client-aware RLS | Client-substitution tests |
| T03 | Stored prompt injection | A document instructs the model to exfiltrate secrets | Least privilege, narrow tools, bounded output, no ambient admin key, and authorized-write containment | Planted adversarial fixtures plus read/write closure analysis |
| T04 | Credential transit or confusion | Present a token intended for another resource | Resource indicators, audience validation, separate downstream credential strategy | Token matrix and protocol tests |
| T05 | SSRF and token exfiltration | Put an attacker URL in a tool argument | Fixed upstream origin; no caller-controlled URL or redirect | URL fuzz tests |
| T06 | Generic API escape | Select an arbitrary table, RPC, method, or schema | Domain tools and server-side allowlists | Schema and method fuzz tests |
| T07 | Ownership reassignment | Patch `workspace_id` or `owner_id` | Derive trusted fields; `WITH CHECK`; immutable ownership | Mutation tests |
| T08 | Approval bypass | Agent calls canonical update directly | No direct policy; proposal state machine; exact mutation digest | Direct-write and replay tests |
| T09 | Approval replay | Reuse one approval for a second mutation | Single-use approval bound to payload hash and expiry | Concurrency tests |
| T10 | Audit forgery | Caller inserts or deletes its own audit record | Private append-only storage and trusted database emission | Permission tests |
| T11 | Secret leakage | Token appears in exception telemetry | Structured redaction, log allowlist, secret scanning | Log snapshot tests |
| T12 | Result flooding | Request huge page or broad semantic search | Hard rows/bytes/time bounds and cursor pagination | Boundary and load tests |
| T13 | Query-cost denial | Pathological filters or embedding input exhaust DB | Restricted grammar, timeouts, rate/concurrency limits | Cost-budget tests |
| T14 | Stale authorization | Revoked agent retains a valid JWT | Short lifetime, protected grant lookup, sensitive session checks | Revocation drill |
| T15 | RLS bypass through view/function | Definer view or function executes as owner | Security-invoker views; private hardened definers; advisors | Catalog lint and integration tests |
| T16 | Supply-chain compromise | Mutable action tag or dependency executes malicious code | Lockfile, pinned versions and action SHAs, provenance review | CI policy check |
| T17 | OAuth redirect or mix-up | Code is sent to the wrong issuer or redirect | Exact redirect matching, PKCE, state, issuer validation | OAuth conformance tests |
| T18 | Data inference | Counts or ranking reveal forbidden records | Filter before ranking/aggregation; suppress sensitive totals | Differential-result tests |
| T19 | Authorized-write exfiltration | An agent copies authorized reads into a lower-trust reader's authorized target | Verify every write-target audience against reader closure; enumerate and mediate required cross-audience writes | Static closure analysis plus fixtures proving the payload does not arrive |

## Prompt-injection containment

Prompt injection is treated as an expected input condition. The server cannot guarantee
that a model will ignore instructions embedded in data. It must guarantee that following
those instructions does not create authority the model did not already have.

The containment test corpus will include records that attempt to:

- request arbitrary tables and SQL;
- retrieve another tenant's records;
- reveal environment variables or authorization headers;
- write retrieved secrets into attacker-visible rows;
- bypass human approval;
- disable logging or erase evidence; and
- expand result limits through nested or encoded arguments.

Passing means the unauthorized action is denied or unavailable, not merely that one model
declines to attempt it. For authorized-write exfiltration, passing instead means that the
payload does not arrive in any target readable by a lower-trust audience.

### Authorized-write containment invariant

Containment is a property of composed read and write scope. For a writer principal `P`, let
`R(P)` be its complete read closure. For every target `W` that `P` may write, identify the
full audience `readers(W)` and each reader's complete read closure. A write is contained
only when this invariant holds:

> For every `Q` in `readers(W)`, `R(Q)` is a superset of `R(P)`.

If any target reader lacks any member of the writer's read closure, the policy set creates
an authorized-write exfiltration channel and must fail containment analysis. Product flows
that require such a crossing must enumerate and mediate it explicitly, for example through
the proposal state machine; an incidental authorized write is not containment. Malformed or
ambiguous closure inventories fail closed because an incomplete audience cannot establish
the invariant.

## Trust-boundary review questions

Every feature review answers:

1. Which untrusted values cross a boundary?
2. Which identity and resource is the credential intended for?
3. Can the caller select a destination or database object?
4. Where is authorization enforced if the MCP process is compromised?
5. What is the largest possible read, write, cost, and retry?
6. Can the action be replayed, raced, or partially applied?
7. What evidence remains, and can the caller alter it?
8. How quickly can this identity, client, or capability be revoked?

## Residual risks

Even with all planned controls:

- An authorized agent can misuse data it is legitimately allowed to read through channels
  outside the analyzed database policy set. Authorized writes inside that policy set remain
  subject to the containment invariant above.
- RLS cannot prevent a model from disclosing authorized data through another channel.
- A compromised human account inherits that human's legitimate authority until detected
  or revoked.
- Policy complexity can create authorization mistakes despite tests.
- Semantic search may create subtle inference or resource-exhaustion channels.
- A full compromise of the deployment platform, identity provider, or database owner is
  outside the containment promise.

Documentation and product messaging must state these limitations plainly.

## Review cadence

Review this threat model:

- when a milestone changes trust boundaries;
- before adding a tool, transport, principal type, or privileged function;
- after a security incident or material dependency advisory; and
- before every stable release.
