# ADR-0001: Use TypeScript for the reference server

- **Status:** Accepted
- **Date:** 2026-08-17
- **Owners:** Maintainers
- **Milestone:** M0

## Context

The project needs a reference implementation that can track a rapidly evolving MCP
specification, validate JSON contracts at runtime, integrate with Supabase APIs, and be
reviewed by a broad open-source contributor base.

## Security constraints

- External input must be validated at runtime rather than trusted from static types.
- Credential and request context must remain request-scoped.
- Dependencies and the runtime must be pinned and auditable.
- The stack must support protocol, policy, integration, and adversarial tests.

## Decision drivers

- First-class support from the official MCP project.
- Mature Supabase libraries and web-platform security primitives.
- Strong schema-validation and testing ecosystem.
- Contributor accessibility and package-distribution ergonomics.
- Ability to share exact contracts between server implementation and tests.

## Options considered

### TypeScript

Provides a Tier 1 MCP SDK, strong JSON-schema ergonomics, broad Supabase usage, and a large
contributor ecosystem. It requires strict compiler settings and runtime validation to
avoid confusing types with security checks.

### Python

Also has a Tier 1 MCP SDK and strong prototyping ergonomics. It is viable, but sharing
runtime schemas and maintaining one authoritative reference implementation is more
valuable than supporting two languages initially.

### Rust or Go

Offer strong deployment and type-safety properties, but would increase early protocol and
contributor friction without eliminating the need for runtime boundary validation.

## Decision

Use TypeScript for the reference MCP server, contracts, and integration test harness. Use
SQL for database migrations and policy tests. Do not create parallel server
implementations before v1.

The M0 compatibility spike pins Node.js `22.20.0`, npm `11.19.0`, TypeScript `7.0.2`,
the split MCP TypeScript SDK `2.0.0` packages, and Zod `4.4.3`. A Supabase client is
deliberately deferred until the M1 policy laboratory.

## Consequences

### Positive

- Direct access to current MCP TypeScript SDK behavior.
- Runtime and static schemas can remain close together.
- Lower contribution barrier for Supabase application developers.
- Straightforward stdio and HTTP transport support.

### Negative

- Supply-chain surface requires exact dependencies, lockfiles, scanning, and provenance.
- TypeScript types alone do not secure runtime input.
- Long-running Node.js services require explicit resource and concurrency controls.

### Follow-up

- Create the minimal strict workspace during M0.
- Pin runtime and package-manager versions.
- Add schema, redaction, dependency, and clean-build checks before M2.

## Validation

Completed on 2026-08-17. The spike implements one strict, zero-authority no-op tool,
negotiates the MCP `2026-07-28` modern era over stdio, verifies structured input/output
validation, and rejects malformed input. See the
[M0 compatibility evidence](../evidence/M0_COMPATIBILITY_SPIKE.md).

## Revisit when

- The official TypeScript SDK cannot meet a required security or protocol property.
- Runtime overhead prevents documented service limits after measurement.
- A stable v1 contract justifies additional language implementations.

## References

- [MCP SDKs](https://modelcontextprotocol.io/docs/sdk)
- [Supabase JavaScript reference](https://supabase.com/docs/reference/javascript/introduction)
