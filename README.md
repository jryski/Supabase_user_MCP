# Supabase User MCP

[![Documentation](https://github.com/jryski/Supabase_user_MCP/actions/workflows/docs.yml/badge.svg)](https://github.com/jryski/Supabase_user_MCP/actions/workflows/docs.yml)
[![CI](https://github.com/jryski/Supabase_user_MCP/actions/workflows/ci.yml/badge.svg)](https://github.com/jryski/Supabase_user_MCP/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Give every human and agent its own bounded application-data identity path.**

Supabase User MCP is an independent, security-first data-plane MCP server for applications built on Supabase. It is designed to let AI clients work with application data as a specific user or agent while PostgreSQL Row Level Security (RLS) remains the final authorization authority.

> [!WARNING]
> This repository is still pre-release. The experimental local-stdio, read-only, synthetic-only
> user-context path is implemented and accepted on `main`; production deployment, remote OAuth,
> writes, hosted artifact inspection, and privileged credentials remain unsupported. Do not connect
> this project to production data merely because the local and CI acceptance suites are green.

## Why this exists

Supabase's hosted MCP server is a developer control-plane tool. Supabase User MCP explores the complementary **application data-plane** problem:

| | Supabase hosted MCP | Supabase User MCP |
| --- | --- | --- |
| Primary user | Developer/operator | Application user or bounded agent |
| Plane | Project control plane | Application data plane |
| Typical actions | Schema, migration, project operations | Fixed domain capabilities |
| Authorization | Developer/project authority | User, client, tenant, capability, RLS |
| Database boundary | Administrative tooling | RLS must remain effective |
| Intended environment | Development and operations | Production only after identity/security gates pass |

The goal is not to make prompt injection impossible. The goal is to make the blast radius of a compromised model no larger than the mechanically enforced authority of its verified principal/client capability.

## Relationship to the Sovereign Memory program

This repository owns **authenticated application data-plane capability**, not the protocol and not a deployment.

- **Sovereign Memory Protocol (SMP)** defines implementation-neutral provenance, custody, authority, verification, portability, and claim semantics.
- **Sovereign Memory Core** is the PostgreSQL reference runtime for SMP semantics.
- **Supabase User MCP** provides a bounded user/agent capability seam into Supabase-backed application data while preserving caller identity into RLS.
- **Deployments** decide which principals, clients, tools, and data surfaces are actually enabled.

The dependency direction is one way: this project may implement SMP-compatible semantics, but it must not redefine SMP through Supabase-specific mechanisms.

A related proposed protocol lane is the **Agent Access Integrity Boundary**: establish a forward evidence boundary before agents are introduced to existing systems in situ. This repository can eventually provide one identity/capability mechanism for such deployments, but it does not itself establish the protocol claim.

## Target security thesis

This is the required end-state boundary. It is not a claim that every hop is accepted on
`main` today.

```text
MCP client
    │ verified request context
    ▼
Supabase User MCP
    ├── exposes a small, allowlisted tool surface
    ├── preserves verified principal/client context
    ├── enforces validation, byte/time/rate bounds
    ▼
Supabase Data API / fixed RPC surface
    ▼
PostgreSQL + RLS
    ├── principal/client policy
    ├── tenant/capability policy
    └── row/operation policy
```

Non-negotiable principles:

1. **No master key in the user request path.** `service_role`, privileged database credentials, and admin Storage credentials do not prove user authorization.
2. **The database makes the final authorization decision.** Application checks improve usability; RLS/constraints enforce access.
3. **Tools are capabilities, not a generic REST console.** Public tools do not accept arbitrary SQL, tables, schemas, RPC names, URLs, buckets, or HTTP methods.
4. **Caller-supplied actor/principal labels are not identity proof.** Identity is derived from the verified request/session context.
5. **Reads and writes are different authorities.** Canonical or irreversible changes require separate governed proposal/approval semantics.
6. **Untrusted content stays data.** Tool results are bounded and explicitly rendered as untrusted model-visible content.
7. **Claims require evidence.** Positive, negative, cross-identity, broken-control, and adversarial tests are part of the boundary.

## Current state

Current `main` contains the reviewed local foundation and merged principal-bound read path:

- strict TypeScript/MCP contracts and exact dependency lock;
- synthetic local Supabase Auth/JWT + RLS policy laboratory;
- cross-schema catalog lint for dangerous grants and SECURITY DEFINER review conditions;
- revocation/audit policy evidence;
- protected local credential loader and fixed Supabase client seam;
- bounded `memory_search`, `memory_get`, and `memory_list_recent` factories;
- verified Auth identity before read-only server registration;
- exact principal-scoped limiter and operational-event attribution;
- complete dual-representation JSON-RPC frame and request-ID ceilings;
- real MCP client -> fixed Data API -> PostgreSQL RLS acceptance;
- environment-only verified read-only stdio startup plus operator, revoke, and rollback guidance;
- a synthetic Storage/RLS artifact registry laboratory;
- the accepted Governed Artifact Inspection S0 capability, receipt, and integrity contracts; and
- deterministic S1b source-manifest, chunk, and Merkle-proof calibration; and
- an S2 synthetic/local fixed inspector library for `artifact_stat`, bounded byte ranges, and
  bounded UTF-8 line reads through injected authorization and immutable-version dependencies; and
- optional S3 synthetic/local MCP registration for those three operations plus a deeply frozen,
  executable Supabase Storage containment manifest.

The consolidated read path merged through
[PR #38](https://github.com/jryski/Supabase_user_MCP/pull/38) at
`dd5ba98a00a3b37003554a14200f789fcb233cac`. PR #40's base-binding and E2E-skip repairs are
absorbed in that tree. Read-only server construction verifies the protected user credential through
the fixed Supabase Auth user endpoint before registering tools, then supplies the verified principal
and exact SDK request ID to every governor call. One contracts-owned renderer defines both the
emitted dual-representation result and complete JSON-RPC byte estimator. The
[MCP tools specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
says structured results **SHOULD** also provide serialized JSON text for compatibility; it is not a
MUST. This implementation retains full dual representation and measures the selected complete frame.
Unit and transport tests cover exact/one-over byte boundaries, request-ID escaping, hostile-content
escaping, and bounded denial instead of oversized success. A read-only transport guard closes
oversized inbound or outbound frames before dispatch/send, including denial paths with hostile
request IDs. Serialized request IDs are separately capped at 1,024 bytes so bounded errors can echo
them safely. Exact-head and post-merge Build/M2/Markdown/Links workflows passed.

The experimental local v0.1 pilot is complete. Official Auth test reuse and the authenticated
PostgREST OpenAPI census merged through [PR #45](https://github.com/jryski/Supabase_user_MCP/pull/45),
and the executable environment-only stdio/operator package merged through
[PR #46](https://github.com/jryski/Supabase_user_MCP/pull/46). `npm start` launches the verified
read-only stdio server; `npm run start:compatibility` retains the no-data M0 probe. Exact-head and
post-merge Build, M2, Markdown, and Links checks passed. This is an experimental local-development
profile, not a production or hosted deployment claim.

The intended local path is:

```text
local Auth/JWT
  -> strict MCP tool
  -> fixed Data API/RPC
  -> RLS
  -> authorized intersection
```

Passing CI on a draft head is reproducible test evidence for that coordinate. It is not
merge, deployment, production-readiness, or security acceptance.

## Planned product surface

Initial read capabilities:

- `memory_search`
- `memory_get`
- `memory_list_recent`

Later governed write capabilities are planned separately, including append-only observations and proposal/approval workflows. See [feature catalog](docs/FEATURES.md).

### Current scope limits

- The first profile is local stdio with one protected Supabase user access token. Remote
  HTTP/OAuth remains blocked on a standards-compliant downstream-token and audience design.
- The v0.1 tools expose one fixed allowlisted field projection. They do not provide
  per-principal column entitlements; RLS remains a row boundary.
- The current database search candidate is lexical. `semantic` mode does not establish an
  approximate-nearest-neighbor implementation or semantic quality, recall, latency, or
  multitenant isolation.
- The 65,536-byte response ceiling is a project-defined safety budget, not an MCP protocol
  limit. It must cover the complete serialized outbound frame, including the selected
  compatibility representations and protocol overhead.
- Production data, deployment credentials, and project-wide privileged keys remain outside
  this repository's accepted test profile.

### Governed Artifact Inspection

Issue #34 tracks a related Storage/Edge capability: agents inspect durable artifacts through opaque
IDs, caller-context RLS, bounded reads, integrity/provenance receipts, and a small supported-profile
registry rather than receiving generic Storage access.

The current design keeps:

- MCP as the agent capability surface;
- Edge as a bounded inspection/execution surface;
- Postgres/RLS as authorization;
- Storage as byte custody.

Current repository evidence includes:

- **S0:** strict capability, complete-wire, integrity, derivation, and receipt contracts;
- **synthetic S1:** immutable artifact registry, derivation tables, approved-client policy, and
  Storage RLS laboratory; and
- **S1b:** deterministic raw/source hashes, domain-separated Merkle leaves, bounded proofs,
  full-source verification, and mutation-sensitive calibration; and
- **S2:** a pure TypeScript synthetic/local fixed inspector library with strict runtime adapter
  validation, distinct client/capability-grant custody, exact-version disappearance handling,
  redacted dependency failures, and schema-valid immutable receipts; and
- **S3:** optional fixed MCP registration for stat/range/lines plus executable Storage authorization,
  byte-read, immutable-version, integrity, retry, listing, credential, and write closure accounting;
  and
- **S4 primitive:** a pure in-memory deterministic UTF-8 line and Markdown ATX-heading index with
  exact source-byte offsets, strict consumed-index validation, bounded reads, and collision-resistant
  heading identifiers.

The M1 non-service user/client identity prerequisite is satisfied by the accepted v0.1 read path.
S3 completes only an optional synthetic/local registration seam. The S4 primitive is also local and
model-free: it is not exported through the server barrel, connected to the S2 inspector, registered
through MCP, run automatically on ingest, or demonstrated against an approved artifact. The next S4
gate is that bounded integration/demo. Default CLI/stdio startup remains memory-only. No Edge or
hosted deployment, Storage/database mutation, signed URL, `service_role`, caller-selected Storage
coordinate, listing, ingest, semantic analysis, exact search, write, private-data access, or
production-readiness claim is accepted.

## Roadmap

| Milestone | Outcome | Current interpretation |
| --- | --- | --- |
| M0 | Protocol/policy/repository foundation | Foundation landed |
| M1 | Local Auth/RLS policy laboratory | Complete for the synthetic reference profile |
| M2 | Read-only stdio reference server | Complete for the experimental local synthetic profile |
| M3 | Idempotent writes and canonical approval | Future |
| M4 | Remote HTTP/OAuth profile | Future; downstream-token/audience proof required |
| M5 | Operations/adversarial hardening | Future |
| M6 | Stable v1 contract | Future |

The active extension now includes the isolated S4 deterministic text-index primitive. Bounded
inspector/MCP integration and one approved synthetic Markdown artifact remain the next S4 gate.
Detailed sequencing and claim limits live in
[docs/ROADMAP.md](docs/ROADMAP.md); the completed v0.1 execution baseline remains archived in
[epic #19](https://github.com/jryski/Supabase_user_MCP/issues/19).

## Local development

Prerequisites and exact versions are documented in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

```shell
npm ci
npm run check
npm run build
```

Local Supabase policy tests use synthetic fixtures only. Do not point the harness at a
private, restricted, customer, or production project.

## Documentation

- [Product definition](docs/PRODUCT.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Feature catalog](docs/FEATURES.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Roadmap](docs/ROADMAP.md)
- [Implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Development guide](docs/DEVELOPMENT.md)
- [Experimental local stdio operator guide](docs/evidence/ISSUE_18_OPERATOR_RELEASE.md)
- [Governed Artifact Inspection S0 contract](docs/evidence/ISSUE_34_S0_ARTIFACT_CONTRACT.md)
- [S1b chunk/Merkle calibration](docs/evidence/ISSUE_34_S1B_CHUNK_MERKLE_CALIBRATION.md)
- [S2 synthetic/local fixed inspector](docs/evidence/ISSUE_34_S2_FIXED_INSPECTOR.md)
- [S3 optional MCP registration and Storage closure](docs/evidence/ISSUE_34_S3_MCP_STORAGE_CLOSURE.md)
- [Architecture decisions](docs/decisions/README.md)
- [Program context and plane ownership](docs/PROGRAM_CONTEXT.md)
- [Evidence index](docs/evidence/README.md)

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) and [GOVERNANCE.md](GOVERNANCE.md). Security reports belong in the private process described in [SECURITY.md](SECURITY.md), not in a public issue.

## Project status and independence

Supabase User MCP is an independent open-source project. It is not an official Supabase product and is not endorsed by Supabase, Inc. "Supabase" identifies compatibility with the Supabase platform.

Licensed under the [Apache License 2.0](LICENSE).
