# Development Guide

**Status:** Implemented for the M0 TypeScript/MCP compatibility surface; Supabase data
integration remains planned.

## Engineering posture

The reference implementation optimizes for reviewability, explicit contracts, and
security tests. Convenience abstractions are welcome only when they preserve visible
identity and database boundaries.

No command in this guide should be run against a production Supabase project. Development
fixtures must be synthetic.

## Pinned M0 stack

| Component | Version | Role |
| --- | --- | --- |
| Node.js | `22.20.0` | Pinned runtime |
| npm | `11.19.0` | Pinned package manager |
| TypeScript | `7.0.2` | Strict compiler and project references |
| MCP server SDK | `@modelcontextprotocol/server@2.0.0` | Modern stdio server |
| MCP client SDK | `@modelcontextprotocol/client@2.0.0` | Compatibility harness |
| Zod | `4.4.3` | Runtime input/output contracts |
| Vitest | `4.1.10` | Unit and stdio compatibility tests |
| Biome | `2.5.8` | Formatting and linting |

The root workspace and runtime dependencies use exact versions; `package-lock.json` is
committed. The Supabase JavaScript client and Supabase CLI remain intentionally absent
until the M1 policy laboratory selects and tests their exact versions.

## Local workflow

From a clean checkout with the pinned Node.js and npm versions:

```shell
npm ci
npm run check
npm run build
```

Individual checks are available as `npm run format:check`, `npm run lint`,
`npm run typecheck`, `npm run test`, and `npm run test:compatibility`. `npm start` runs
the built, modern-only MCP stdio probe. The process communicates over stdin/stdout; human
diagnostics go to stderr so they cannot corrupt JSON-RPC messages.

## Repository layout

```text
.
├── .github/                  # Collaboration templates and CI
├── docs/                     # Product, architecture, security, and ADRs
├── packages/
│   ├── server/               # MCP transports, tools, guards, and error model
│   ├── contracts/            # Versioned tool schemas and shared types
│   └── policy-testkit/       # Principal fixtures and access-matrix runner
├── supabase/
│   ├── migrations/           # Generated, reviewed schema changes
│   ├── seed.sql              # Synthetic development fixtures only
│   └── tests/                # RLS, grants, view, and function tests
├── test/
│   ├── integration/          # MCP-to-Data-API behavior
│   ├── adversarial/          # Stored-content and authorization abuse cases
│   └── fixtures/             # Synthetic identities and records
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
└── README.md
```

Only directories required by completed or active milestones are created. The M0 scaffold
currently implements `packages/contracts`, `packages/server`, and the compatibility tests;
database and policy-testkit directories arrive with M1.

## Configuration principles

- Environment variables are parsed once into a validated configuration object.
- Production and development configuration use the same schema.
- The Supabase origin is operator-configured, normalized, HTTPS-only outside local
  development, and never overridable by a tool call.
- Credentials are loaded from protected environment or platform secret storage, never
  command arguments, URLs, committed files, or example values that resemble real tokens.
- `service_role`, secret keys, PATs, and direct database-owner credentials are rejected in
  the public tool execution profile.
- Safe global ceilings exist for query length, filters, rows, bytes, duration, rate,
  concurrency, and retries.

## Database workflow

The exact CLI commands will be added after a Supabase CLI version is pinned and discovered
through its `--help` output.

Required workflow properties:

1. Start a clean local Supabase stack.
2. Apply migrations through the supported local migration workflow.
3. Load synthetic fixtures only.
4. Run grant, RLS, view, function, and access-matrix tests.
5. Run Supabase security and performance advisors.
6. Generate and review schema diffs rather than hand-editing migration history.
7. Verify the local migration list before committing.

Every table in an exposed schema must have RLS enabled before API grants are introduced.

## Test layers

### Unit

- Configuration parsing and secret rejection.
- Tool input/output schemas.
- Capability mapping.
- Cursor and canonical-payload encoding.
- Error normalization and redaction.

### Database policy

- Each allow/deny matrix cell.
- Grants independently from RLS.
- `SELECT`, `INSERT`, `UPDATE USING`, `UPDATE WITH CHECK`, and delete behavior.
- View invoker behavior and function execution grants.
- Proposal transitions and append-only audit behavior.

### Integration

- Real MCP call through the selected transport to local PostgREST and Postgres.
- Multiple identities and clients against the same inputs.
- Token expiry, audience, issuer, subject, and client failures.
- Timeouts, pagination, result limits, retry, and idempotency.

### Adversarial

- Stored prompt injection.
- Cross-tenant identifiers.
- Filter/operator manipulation.
- SSRF and arbitrary-object attempts.
- Approval replay and concurrent application.
- Audit forgery and telemetry secret scanning.
- Ranking, count, and timing inference probes.

### Compatibility

- Supported MCP protocol and client fixtures.
- Supported Node.js and PostgreSQL versions.
- Pinned Supabase CLI and local stack.
- Signing-key rotation and JWKS cache behavior.

## Definition of done

A change is done when:

- its contract and threat impact are documented;
- code is formatted, linted, type-checked, and tested;
- positive, negative, malformed, and cross-identity cases exist where applicable;
- no new public tool authority is implicit;
- logs and errors are checked for sensitive content;
- database changes pass advisors and policy tests;
- changelog and user documentation are updated; and
- the pull request identifies rollback and compatibility impact.

## Continuous integration

The repository currently checks formatting, linting, strict compilation, unit contracts,
and the MCP stdio compatibility path from a clean checkout. Documentation has separate
Markdown and link checks. Later milestones add:

- local Supabase policy tests;
- integration and adversarial suites;
- dependency and secret scanning;
- action and dependency pin checks; and
- build and package provenance.

Required checks must run from a clean checkout without developer-global configuration.

## Release discipline

- Pre-1.0 releases may change contracts but must document migrations and security impact.
- Stable releases follow Semantic Versioning for public tool schemas and configuration.
- Release artifacts are generated by CI, not from a maintainer workstation.
- Stable artifacts include checksums, an SBOM, provenance, and signed tags or attestations.
- A release cannot describe a deployment profile as supported until its roadmap exit gate
  passes.

## Documentation discipline

- Use primary official sources for normative MCP, Supabase, OAuth, PostgreSQL, and package
  behavior.
- Date architecture reviews where external behavior can change.
- Capture consequential choices in ADRs.
- Use “planned” or “proposed” for unimplemented behavior.
- Never present a model's refusal as a security control.
