# OSS Scanner threat model: Supabase User MCP

This document is scanner-specific orientation, not evidence of a production release. The authoritative project threat model is [docs/THREAT_MODEL.md](../docs/THREAT_MODEL.md), with supported-version posture in [SECURITY.md](../SECURITY.md).

## Supported surface

The public main branch is a pre-release, synthetic-only, local-stdio MCP reference implementation. Remote HTTP, deployed OAuth 2.1, production operation, and privileged live-tenant writes are not currently supported by the public runtime. Treat design documents and unreleased candidates as future-facing rather than implemented attack surfaces. Do not use real Supabase projects or credentials in tests.

## Trust boundaries and attacker input

- Untrusted MCP arguments, identifiers, filters, pagination cursors, and protocol frames.
- Auth and principal context for synthetic tests, client and tenant boundaries, JWT-derived claims, expiry and revocation states.
- Database-returned text and model output, which must never become instructions granting more authority.
- Dependency/build inputs and error or logging paths that could expose tokens.
- A malicious authenticated tenant or compromised agent trying to read, infer, or write outside its authorized application scope.

## High-value code and tests

- MCP server, tools, transport and policy code in `packages/`.
- PostgreSQL schema, policy, authorization and synthetic fixtures in `supabase/`.
- Access-matrix and protocol tests in `test/`, plus `npm run check`.
- Existing design and attack catalog in `docs/SECURITY_MODEL.md` and `docs/THREAT_MODEL.md`.

The Dockerfile builds and runs `npm run check` with pinned Node and npm versions. The scan itself is offline.

## Severity guidance

- **Critical:** demonstrated pre-authenticated arbitrary code execution; cross-tenant disclosure or mutation of sensitive application data through a supported exposed interface with broad impact; compromise of a privileged identity from a lower-trust entry point.
- **High:** reproducible violation of principal/client/tenant isolation, RLS bypass, token leakage, effective revocation bypass, unauthorized mutation, or attacker-controlled upstream selection in a supported path.
- **Medium:** bounded authenticated denial of service, side-channel inference of low-sensitivity metadata, or a failure requiring substantial user interaction without proven authority crossing.
- **Low / informational:** hardening, documentation mismatches, or security concerns in planned features without an implemented exploit path.

Base severity on reproducible impact and required privileges. Don't label a theoretical flaw in a planned OAuth/remote feature as exploitable on the existing public runtime.

## Safety and reports

Use only synthetic fixtures and an isolated environment. Never attempt real-user, real-tenant, hosted-system, or production exploitation. Provide affected commit, exact input, preconditions, and a self-contained synthetic reproduction. Treat vulnerability details as confidential under the service agreement and the project's security policy.
