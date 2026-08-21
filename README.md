# Supabase User MCP

[![Project status: M0 active](https://img.shields.io/badge/status-M0%20active-f59e0b)](docs/ROADMAP.md)
[![Documentation](https://github.com/jryski/Supabase_user_MCP/actions/workflows/docs.yml/badge.svg)](https://github.com/jryski/Supabase_user_MCP/actions/workflows/docs.yml)
[![CI](https://github.com/jryski/Supabase_user_MCP/actions/workflows/ci.yml/badge.svg)](https://github.com/jryski/Supabase_user_MCP/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Give every human and agent its own database identity boundary.**

Supabase User MCP is an independent, security-first data-plane MCP server for
applications built on Supabase. It is designed to let AI clients work with
application data as a specific user or agent while PostgreSQL Row Level Security
(RLS) remains the final authorization authority.

> [!WARNING]
> This repository is in active M0 development. It contains only a zero-authority
> protocol probe—not a deployable user-data server—and must not be connected to
> production data.

## Why this exists

Supabase's hosted MCP server is a developer control-plane tool. It manages projects,
schemas, migrations, functions, and operational resources under a developer's
authority. Supabase explicitly recommends using that server for development and
testing rather than exposing it to customers or production data.

Supabase User MCP explores the complementary data-plane problem:

| | Supabase hosted MCP | Supabase User MCP |
| --- | --- | --- |
| Primary user | Developer | Application user or bounded agent |
| Plane | Project control plane | Application data plane |
| Typical actions | Schema, migration, project operations | Domain-specific reads and writes |
| Authorization | Developer account and project scope | User, client, tenant, capability, and row |
| Database boundary | Administrative tooling | RLS must remain effective |
| Intended environment | Development and test | Production only after the security gates pass |

The goal is not to make prompt injection impossible. The goal is to ensure that a
compromised model cannot exceed the authority of the identity and capability it was
given.

## Security thesis

```text
MCP client
    │ authenticated request
    ▼
Supabase User MCP
    ├── validates identity and request context
    ├── exposes a small, allowlisted tool surface
    ├── enforces limits, approval states, and audit metadata
    ▼
Supabase Data API / PostgREST
    ▼
PostgreSQL + RLS
    ├── caller and OAuth-client policy
    ├── tenant and capability policy
    └── row and operation policy
```

The project follows six non-negotiable principles:

1. **No master key in the MCP request path.** A public tool handler must never use a
   `service_role` or secret key to perform user actions.
2. **The database makes the final decision.** Application checks improve usability;
   RLS and database constraints enforce authorization.
3. **Tools are capabilities, not a generic REST console.** The initial server will not
   expose arbitrary SQL, tables, schemas, RPC names, URLs, or HTTP methods.
4. **Reads and writes are different authorities.** Canonical or irreversible changes
   use a database-enforced proposal and approval workflow.
5. **Untrusted content stays data.** Tool results are bounded and marked as untrusted;
   prompt injection is tested as a containment problem.
6. **Claims require evidence.** A milestone is complete only when its positive,
   negative, cross-identity, and adversarial tests pass.

## Planned product surface

The first useful release is deliberately narrow:

- `memory_search` — bounded full-text or semantic search over authorized records
- `memory_get` — retrieve one authorized memory record by opaque identifier
- `memory_list_recent` — list authorized recent records with a hard page limit
- `memory_append_observation` — append non-canonical information idempotently
- `memory_propose_change` — stage a canonical mutation for human review
- `memory_get_proposal` — inspect approval status without applying the change

The names describe the reference sovereign-memory implementation. Adapters may later
map the same capability model to other Supabase application schemas. See the complete
[feature catalog](docs/FEATURES.md).

## Current phase

The project is in **M0: protocol and policy foundation**. Active contributor work is
organized under [epic #19](https://github.com/jryski/Supabase_user_MCP/issues/19)
and the [v0.1 read-only implementation plan](docs/IMPLEMENTATION_PLAN.md).
Before server code is treated as viable, M0 must resolve two identity questions:

- How a remote HTTP MCP server obtains a downstream Supabase token without violating
  MCP audience-binding and token-transit requirements.
- How durable non-human principals are provisioned and revoked, given that Supabase's
  OAuth server currently documents authorization-code and refresh-token grants rather
  than a `client_credentials` grant.

These are architecture gates, not implementation details. The local stdio proof and the
remote HTTP service are tracked as separate deployment profiles until the remote identity
chain is demonstrated end to end.

The executable M0 spike now proves a strict TypeScript workspace, MCP `2026-07-28`
stdio negotiation, structured input/output validation, and a deliberately non-authoritative
tool. It has no Supabase client, credentials, network access, or data operations. See the
[compatibility evidence](docs/evidence/M0_COMPATIBILITY_SPIKE.md).

## Try the M0 compatibility probe

Prerequisites: Node.js `22.20.0` and npm `11.19.0`.

```shell
npm ci
npm run check
npm run build
npm start
```

`npm start` launches a JSON-RPC stdio server for an MCP `2026-07-28` client; it is not an
interactive terminal application. The only exposed tool is `system_compatibility_probe`,
which performs no network or data operation. Exact versions and verification commands are
documented in the [development guide](docs/DEVELOPMENT.md).

## Roadmap

| Milestone | Outcome | Release gate |
| --- | --- | --- |
| M0 | Protocol, identity, policy, and threat-model decisions | Architecture review is complete |
| M1 | Local policy laboratory with representative principals and records | Access matrix passes |
| M2 | Read-only stdio reference server | RLS isolation is proven end to end |
| M3 | Idempotent writes and canonical approval workflow | Direct canonical mutation is impossible |
| M4 | Standards-compliant remote HTTP and OAuth profile | Audience and downstream-token chain pass review |
| M5 | Fleet operations, observability, and adversarial hardening | Revocation and containment drills pass |
| M6 | Stable v1 contract | Independent security review and release checklist pass |

Each milestone has deliverables, dependencies, exclusions, and measurable exit criteria
in the [development roadmap](docs/ROADMAP.md).

## Documentation

- [Product definition](docs/PRODUCT.md) — users, jobs, boundaries, and success measures
- [Architecture](docs/ARCHITECTURE.md) — components, trust boundaries, and deployment profiles
- [Feature catalog](docs/FEATURES.md) — proposed tools and platform capabilities
- [Security model](docs/SECURITY_MODEL.md) — identities, capabilities, RLS, and approvals
- [Threat model](docs/THREAT_MODEL.md) — assets, attackers, abuse cases, and mitigations
- [Roadmap](docs/ROADMAP.md) — implementation sequence and release gates
- [Development guide](docs/DEVELOPMENT.md) — pinned stack, layout, and engineering standards
- [M0 compatibility evidence](docs/evidence/M0_COMPATIBILITY_SPIKE.md) — pinned versions and protocol proof
- [Architecture decisions](docs/decisions/README.md) — consequential decisions and open gates

## Contributing

The highest-value contributions today are adversarial reviews, prior art, policy-test
cases, and small documentation corrections. Please read [CONTRIBUTING.md](CONTRIBUTING.md)
and [GOVERNANCE.md](GOVERNANCE.md) before opening a pull request. Security reports belong
in the private process described in [SECURITY.md](SECURITY.md), not in a public issue.

## Project status and independence

Supabase User MCP is an independent open-source project. It is not an official Supabase
product and is not endorsed by Supabase, Inc. “Supabase” is used to identify compatibility
with the Supabase platform.

Licensed under the [Apache License 2.0](LICENSE).
