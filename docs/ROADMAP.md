# Development Roadmap

- **Status:** Active — merged foundations and future evidence gates are distinguished below
- **Planning horizon:** M0 through v1
- **Last reviewed:** 2026-09-02

## Active execution slice

The local-stdio, read-only v0.1 pilot described in
[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) is complete for its experimental synthetic profile;
[epic #19](https://github.com/jryski/Supabase_user_MCP/issues/19) is closed.

The active extension is [issue #34](https://github.com/jryski/Supabase_user_MCP/issues/34),
Governed Artifact Inspection. S0 contracts, the synthetic S1 Storage/RLS laboratory, S1b
chunk/Merkle calibration, the M1 identity prerequisite, the synthetic/local S2 fixed inspector, S3
optional MCP registration/Storage closure, bounded S4 deterministic Markdown line/heading integration,
and synthetic/local S5a deterministic exact search plus an acknowledged append-only receipt-journal
seam are complete at their stated scope. Live S5 operational adoption remains gated on an approved
real Storage adapter and durable evidence backend; S6 semantic summaries have not started. M3–M6
remain separate product roadmap gates.

## How milestones work

Milestones are evidence gates, not dates. Work may be prototyped ahead, but a milestone
is complete only when all required artifacts and tests exist. Security exclusions cannot
be deferred as “hardening” when they are part of the product boundary.

## M0 — Protocol and policy foundation

**Goal:** turn the thesis into reviewable contracts and resolve identity-chain blockers.

### Current progress

| Artifact | State | Evidence |
| --- | --- | --- |
| Product, architecture, feature, security, and threat-model documents | Complete | [Documentation index] |
| Reference language and repository shape | Complete | [ADR-0001] |
| Strict TypeScript workspace and exact dependency lock | Complete | Root workspace and lockfile |
| MCP `2026-07-28` stdio compatibility spike | Complete | [M0 compatibility evidence] |
| Remote downstream token and audience chain | Blocked by design review | [ADR-0002] |
| Service-agent lifecycle, policy vocabulary, and access matrix | Open | M0 deliverables below |

“Complete” in this table applies only to the named M0 artifact; it is not a product
readiness claim.

### Deliverables

- Product definition, architecture, feature catalog, security model, and threat model.
- Accepted ADR for the reference language and repository shape.
- Compatibility spike against the current MCP TypeScript SDK and protocol version.
- Decision on the supported MCP protocol-version policy.
- Decision on local credential loading and refresh behavior.
- Decision on remote downstream token acquisition and audience binding.
- Decision on durable service-agent provisioning, ownership, rotation, and revocation.
- Initial tool schemas for the three read tools.
- Initial principal/capability vocabulary and access-matrix format.
- Local Supabase project bootstrap plan with synthetic-only fixtures.

### Exit criteria

- Every component and trust boundary has an owner and documented failure mode.
- No caller-controlled path exists to an arbitrary host, table, schema, RPC, or SQL text.
- The remote identity-chain ADR has a demonstrated protocol trace or is explicitly kept
  out of the first release.
- Every planned M1–M3 feature maps to a capability and abuse-case tests.
- Documentation checks pass and there are no contradictory production-readiness claims.

### Explicit exclusions

- No production deployment.
- No write tool.
- No claim that remote HTTP identity forwarding is solved.

[ADR-0001]: decisions/0001-reference-implementation-language.md
[ADR-0002]: decisions/0002-remote-identity-chain.md
[Documentation index]: README.md
[M0 compatibility evidence]: evidence/M0_COMPATIBILITY_SPIKE.md

## M1 — Supabase policy laboratory

**Goal:** prove the authorization model in Postgres before relying on server code.

### Deliverables

- Local Supabase configuration pinned to a documented CLI version.
- Migrations for representative security, memory, proposal, and audit schemas.
- Synthetic fixtures for at least:
  - two workspaces;
  - two humans;
  - two delegated clients/agents;
  - one reviewer;
  - one revoked or expired principal/grant; and
  - public, private, shared, canonical, and adversarial records.
- Executable allow/deny access matrix.
- RLS policies for read operations and protected authorization lookups.
- Catalog checks for grants, RLS, views, and privileged functions.
- CI job that starts the local stack and runs policy tests.

### Exit criteria

- Every matrix cell has an assertion and expected reason class.
- Cross-workspace, cross-user, cross-client, revoked, and unauthenticated access is denied.
- Authentication without a capability does not grant row access.
- Policy predicates meet an agreed reference latency on synthetic scale fixtures.
- Supabase security and performance advisor findings are resolved or documented with an
  owner and expiry.
- The database can emit trusted, append-only test audit events without public write
  access to the audit relation.

## M2 — Read-only reference server

**Goal:** prove identity-scoped reads through an MCP client and the real Data API/RLS path.

### Deliverables

- Strict TypeScript server package and reproducible build.
- Stdio transport profile with protected local credential loading.
- `memory_search`, `memory_get`, and `memory_list_recent`.
- Fixed Supabase origin and allowlisted database surface.
- Shared validation, timeout, row, byte, concurrency, and rate-limit governor.
- Structured, non-enumerating error model.
- Redacted operational events and correlation IDs.
- Protocol, integration, boundary, fuzz, and adversarial stored-content tests.
- Example client configuration using synthetic local data only.

### Exit criteria

- Two principals calling the same tool receive only their authorized intersections.
- Invalid, expired, wrong-issuer, wrong-audience, and wrong-client credentials fail.
- Search ranking and counts do not reveal unauthorized rows in the test corpus.
- No public tool accepts a host, schema, relation, function, SQL, or unrestricted operator.
- All responses stay within configured row, byte, and duration ceilings.
- Automated scans find no token or sensitive fixture content in logs and traces.
- The planted prompt-injection corpus cannot cause an action outside the principal's
  available tool and RLS envelope.

### Release

Publish only as an experimental local-development release. It is not a hosted or
production-ready release.

### Current disposition

M2 is complete for the experimental local-stdio, read-only, synthetic-only profile. The accepted
path includes official Auth sign-in in tests, principal/client-bound Data API and RLS acceptance,
three fixed MCP read tools, complete wire budgets, environment-only startup, and operator
revoke/rollback guidance. Remote OAuth, production data, and writes remain outside this completion
claim.

## Governed Artifact Inspection extension

**Goal:** inspect immutable Storage-backed artifacts through opaque IDs and caller-context
authorization without exposing a generic Storage or file-download tool.

| Stage | State | Accepted scope / next gate |
| --- | --- | --- |
| S0 capability, integrity, derivation, and receipt contract | Complete | Strict contracts and mutation-sensitive tests on `main` |
| Synthetic S1 artifact registry and Storage RLS laboratory | Complete | Local synthetic schema/policy evidence only |
| S1b chunk/Merkle worker calibration | Complete | Deterministic in-memory manifests, source verification, bounded proofs, and calibration only |
| M1 non-service user/client identity prerequisite | Complete | Merged principal/client-bound v0.1 read path |
| S2 fixed read-only inspector | Complete | Pure TypeScript synthetic/local `artifact_stat` plus bounded range/text inspection library only; no MCP registration or deployment |
| S3 MCP registration and Storage containment closure | Complete | Optional synthetic/local stat/range/lines registration and executable Storage closure only; default startup remains memory-only |
| S4 Markdown structure/index extraction | Complete | Synthetic/local per-read line/heading integration plus one fixed synthetic Markdown real-SDK demo only; no persistence/publication |
| S5a deterministic exact search and receipt-journal seam | Complete | Synthetic/local raw UTF-8 exact search plus mandatory append acknowledgement only; no persistent backend or live adapter |
| S5 live operational adoption | Next | Select and approve a real caller-context Storage adapter and durable evidence backend |
| S6–S9 semantic, async, vector, and write/publication stages | Future | S6 semantic summaries have not started; separate authority and deployment reviews required |

S3 consumes S2 through an optional fixed registration configuration, derives principal context only
from verified server identity, and closes the Storage data plane in a versioned executable manifest.
S4 extends that optional seam to stat/range/lines/heading and verifies one fixed synthetic Markdown
artifact through the real MCP SDK. S5a adds deterministic exact UTF-8 byte search and requires every
configured source-bound receipt to receive a digest-matching append-only journal acknowledgement
inside the existing deadline before MCP return. The canonical text index and search scan are rebuilt
only in memory after complete-source integrity verification; neither is persisted, published, or
generated at ingest. Default CLI/stdio startup remains exactly three memory tools. The repository has
no persistent receipt-journal backend or live Storage/network adapter. Live S5 adoption requires both
to be selected and approved; S6 semantic summaries do not start here. No hosted resources, Edge
deployment, Storage/database mutation, `service_role`, signed URL, caller-selected coordinate,
listing, ingest persistence, semantic/vector search, canonical write/publication, private data, or
production-readiness claim is included.

## M3 — Safe writes and human authority

**Goal:** support useful writes without giving agents direct authority over canonical
state.

### Deliverables

- `memory_append_observation`, `memory_propose_change`, and `memory_get_proposal`.
- Idempotency store and replay-safe write contract.
- Proposal, approval, rejection, expiry, and application state machine.
- Exact canonical payload and digest format.
- Reviewer policy, separation-of-duty rules, and optional `aal2` requirement.
- Trusted database mutation audit events correlated to MCP requests.
- Concurrency, replay, rollback, and partial-failure tests.
- A selected human-review interface direction.

### Exit criteria

- Read capabilities cannot write.
- Append capability cannot update or delete prior observations.
- Agents cannot directly mutate canonical records through MCP or Data API policies.
- Reusing an idempotency key with another payload is rejected.
- Approval is bound to one exact payload, reviewer, and validity window.
- Proposal authors cannot self-approve by default.
- Application is single-use and transactional; audit failure follows the documented
  fail-closed policy.

## M4 — Remote HTTP and OAuth profile

**Goal:** provide standards-compliant multi-client remote access without creating a
credential-confusion or transit vulnerability.

### Dependencies

- Accepted [ADR-0002](decisions/0002-remote-identity-chain.md).
- Confirmed compatibility between the chosen Supabase Auth behavior and the current MCP
  specification.

### Deliverables

- Current MCP HTTP transport implementation.
- OAuth Protected Resource Metadata and discovery.
- PKCE-compatible client flow and selected client-registration strategy.
- Exact issuer, resource, audience, scope, and client validation.
- Demonstrated downstream Supabase credential chain.
- HTTPS, origin, redirect, CORS, CSRF, proxy, and forwarded-header policy.
- Stateless authorization and multi-instance integration tests.
- Per-principal and per-client quotas.

### Exit criteria

- A protocol trace proves each token's issuer, audience, holder, destination, storage, and
  lifetime.
- Tokens intended for another resource or client are rejected.
- No inbound MCP bearer token is sent to an unintended upstream resource.
- Redirect and authorization-server mix-up tests pass.
- Revoking one OAuth client prevents new requests within the documented bound.
- Horizontal replicas produce consistent authorization and idempotency outcomes.

### Release

Remote deployment remains experimental until M5. Production usage is still unsupported.

## M5 — Fleet and adversarial hardening

**Goal:** make compromise containment and operations measurable for a fleet of agents.

### Deliverables

- Principal inventory with owner, purpose, environment, expiry, and last-use metadata.
- Provision, rotate, suspend, revoke, and decommission workflows.
- Revocation checks and incident runbook.
- Metrics, traces, alerts, privacy-safe audit queries, and retention controls.
- Load and query-cost budget tests.
- Expanded prompt-injection and inference corpus.
- Dependency update, provenance, SBOM, and release-signing workflow.
- Backup, recovery, and audit-integrity exercise.

### Exit criteria

- One principal or client can be revoked without rotating fleet-wide credentials.
- Revocation and incident drills meet their documented bounds.
- Load tests cannot exceed configured database cost and response ceilings.
- Operators can reconstruct a synthetic incident without access to bearer tokens or raw
  sensitive content in telemetry.
- Dependency and build provenance checks pass from a clean environment.
- Residual risks and deployment assumptions are reviewed and published.

## M6 — Stable v1

**Goal:** publish a supportable security and compatibility contract.

### Deliverables

- Independent architecture and security review.
- Remediation of all release-blocking findings.
- Stable tool schemas and compatibility policy.
- Deployment, upgrade, rollback, backup, and incident documentation.
- Reference Supabase integration with versioned migrations.
- Signed release artifacts, SBOM, provenance, and checksums.
- Maintainer and vulnerability-response plan.

### Exit criteria

- All prior milestone gates pass from a clean checkout.
- No unresolved critical or high-severity finding remains.
- Stable APIs have contract and migration tests.
- The production-readiness checklist is signed off by maintainers and an independent
  reviewer.
- Documentation states the exact supported deployment profile and residual risks.

## Workstream map

| Workstream | M0 | M1 | M2 | M3 | M4 | M5 | M6 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Protocol and transport | Decide | — | Stdio | — | Remote HTTP | Harden | Stabilize |
| Identity and authorization | Model | Prove policies | Verify reads | Gate writes | OAuth chain | Fleet lifecycle | Review |
| Tool surface | Specify reads | API fixtures | Read tools | Write tools | Remote parity | Harden | Freeze v1 |
| Audit and operations | Specify | DB proof | Operational events | Dual-layer audit | Multi-instance | Incident drills | Support |
| Adversarial testing | Design corpus | Policy cases | Read containment | Write/replay | OAuth abuse | Full suite | Independent review |

## Backlog policy

New features enter the roadmap only when they include a user, capability, trust-boundary
analysis, bounded contract, milestone, and observable acceptance criteria. Features that
expand generic access or administrative authority require an ADR and are presumed out of
scope.
