# Program role: Supabase User MCP

> **Program:** Sovereign AI OS  
> **Role class:** principal-bound runtime data plane  
> **Program context:** [`Sovereign AI OS`](https://github.com/jryski/sovereign-memory-core/blob/main/docs/ecosystem/SOVEREIGN_AI_OS.md)  
> **Repository status authority:** [`docs/ROADMAP.md`](docs/ROADMAP.md)

## Mission

Supabase User MCP gives each human and agent a bounded runtime path to Supabase application data while PostgreSQL Row Level Security remains the final authorization authority.

It is the bridge from today's privileged build process to household and business deployments where users, children, employees, teams, contractors, and service agents must not share one administrative identity.

## This repository owns

- trusted derivation and propagation of human and agent identity;
- narrow, allowlisted MCP capabilities;
- user-, client-, tenant-, capability-, row-, and operation-aware request handling;
- revocation, expiry, rate limits, idempotency, audit metadata, and containment tests;
- proposal and approval paths for consequential writes;
- local and remote deployment profiles that preserve database enforcement.

## This repository does not own

- the household or business ontology;
- the canonical memory protocol or Core schema;
- a generic SQL, REST, table, RPC, or URL proxy;
- model selection or agent orchestration;
- project administration, DDL, migrations, recovery, or secret management;
- business or household policy that belongs in deployment repositories.

## Upstream dependencies

- trusted authentication and token-validation behavior;
- PostgreSQL and Supabase RLS semantics;
- domain capability contracts supplied by the consuming application;
- versioned identity, delegation, proposal, and receipt contracts.

## Downstream consumers

- private household deployments;
- multi-user business deployments;
- bounded agent runtimes such as Hermes;
- planning, review, knowledge, and action applications.

## Planning and work-plane relationship

The planning plane is a first-class consumer. Both household and business deployments need safe capabilities to inspect boards, claim work, heartbeat a lease, record progress, submit evidence, and review outcomes.

A card marked `ready`, a claimed agent name, a claim token, or a self-declared capability list is not sufficient authorization. The runtime must bind the operation to trusted principal and agent identity, then allow database policy to decide whether that identity may see the board, claim the card, submit the result, or approve the work.

See [`docs/PLANNING_DATA_PLANE_PROFILE.md`](docs/PLANNING_DATA_PLANE_PROFILE.md).

## Build/control plane separation

The hosted Supabase MCP is the privileged build/control plane used for schemas, migrations, repair, and administration. Supabase User MCP is the ordinary application data plane.

They are complementary, not interchangeable. The control-plane credential must never become the permanent household, child, employee, team, or production-agent credential.

RLS activation is a coordinated cutover dependency. Policy design and isolated tests should happen before v1; live multi-principal claims require the stable User MCP path and verified database enforcement.

## Agent boundary

Do not weaken identity, RLS, or tool constraints to make a domain workflow easier. Add a domain-specific capability and synthetic acceptance cases instead. Never claim a milestone from positive-path behavior alone; include negative, cross-identity, revoked, expired, malformed, and adversarial evidence.
