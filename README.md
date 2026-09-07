# Supabase User MCP

Maintained as part of the WIRE SPEED COMPUTING LLC program led by Jesse Ryski.
[Website](https://www.wirespeedcomputers.com/) |
[Program guide](https://github.com/WireSpeedComputing/sovereign-ai-os).
Existing license terms and contributor rights are unchanged.

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

The [`v0.1.0-alpha.1` release candidate](docs/releases/v0.1.0-alpha.1.md) packages the
accepted local principal-bound read path. Remote HTTP and Supabase OAuth 2.1 remain a separately
gated next profile under [issue #60](https://github.com/jryski/Supabase_user_MCP/issues/60).

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

| Area | Accepted scope | Still missing |
| --- | --- | --- |
| Memory tools | Local stdio, read-only, synthetic data; three fixed tools under user-context RLS | Production deployment and remote OAuth acceptance |
| Artifact inspection | Synthetic/local bounded reads, exact search and receipt interfaces | Live Storage adapter, persistent receipt backend and semantic summaries |
| Release candidate | Alpha.1 package and runtime metadata merged in [PR #65](https://github.com/jryski/Supabase_user_MCP/pull/65) | Publication approval; version metadata is not a published package |
| Remote access | Work under [draft PR #64](https://github.com/jryski/Supabase_user_MCP/pull/64) | Reviewed separate credentials and complete supported-client authorization evidence |

The local read path merged through [PR #38](https://github.com/jryski/Supabase_user_MCP/pull/38).
Official Auth test reuse followed in [PR #45](https://github.com/jryski/Supabase_user_MCP/pull/45);
environment-only stdio startup and operator guidance followed in
[PR #46](https://github.com/jryski/Supabase_user_MCP/pull/46).

The reference path verifies the user's identity before registering tools.
Reads use fixed Data API/RPC routes, principal-scoped limits and database
permissions. Responses include structured data and JSON text, with a
65,536-byte complete-frame ceiling and bounded request IDs.

The [evidence index](docs/evidence/README.md) records the detailed acceptance
scope. A passing check applies to its tested revision, not every deployment.
Local prototype approval is not remote-profile acceptance, a merge or a release.

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

[Issue #34](https://github.com/jryski/Supabase_user_MCP/issues/34) covers
bounded artifact access through opaque identifiers and caller-context policy.

| Stage | Synthetic/local result |
| --- | --- |
| S0 and S1 | Capability and receipt contracts; artifact registry and Storage/RLS lab |
| S1b | Source manifests, chunk hashes and Merkle-proof calibration |
| S2 and S3 | Fixed stat/range/line inspectors and optional MCP registration |
| S4 | Markdown heading reads and a real-SDK synthetic demonstration |
| S5a | Exact UTF-8 search and an acknowledged receipt-journal interface |

Default stdio startup still exposes only the three memory tools. Artifact
support uses injected dependencies; it does not include a live Storage adapter
or persistent journal backend. Live adoption requires separate review.
Semantic summaries, signed URLs, arbitrary listing, writes and production
access are not accepted capabilities. Detailed stage receipts are linked below.

## Roadmap

| Milestone | Outcome | Current interpretation |
| --- | --- | --- |
| M0 | Protocol/policy/repository foundation | Foundation landed |
| M1 | Local Auth/RLS policy laboratory | Complete for the synthetic reference profile |
| M2 | Read-only stdio reference server | Complete for the experimental local synthetic profile |
| M3 | Idempotent writes and canonical approval | Future |
| M4 | Remote HTTP/OAuth profile | Draft work; separate credentials and supported-client proof remain open |
| M5 | Operations/adversarial hardening | Future |
| M6 | Stable v1 contract | Future |

The active extension has completed the bounded synthetic/local S5a exact-search and acknowledged
receipt-journal seam. Live S5 operational adoption is next and remains gated on approving a real
caller-context Storage adapter and durable evidence backend; S6 semantic summaries have not started.
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
- [S4 bounded Markdown integration and SDK demo](docs/evidence/ISSUE_34_S4_MARKDOWN_INTEGRATION.md)
- [S5a deterministic exact search and acknowledged receipt journal](docs/evidence/ISSUE_34_S5_EXACT_SEARCH_RECEIPT_JOURNAL.md)
- [Architecture decisions](docs/decisions/README.md)
- [Program context and plane ownership](docs/PROGRAM_CONTEXT.md)
- [Evidence index](docs/evidence/README.md)

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) and [GOVERNANCE.md](GOVERNANCE.md). Security reports belong in the private process described in [SECURITY.md](SECURITY.md), not in a public issue.

## Project status and independence

Supabase User MCP is an independent open-source project. It is not an official Supabase product and is not endorsed by Supabase, Inc. "Supabase" identifies compatibility with the Supabase platform.

Licensed under the [Apache License 2.0](LICENSE).
