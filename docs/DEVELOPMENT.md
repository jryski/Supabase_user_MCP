# Development Guide

**Status:** Implemented through the accepted experimental local-stdio M2 path and deterministic S1b
artifact chunk/Merkle calibration. Production, hosted, remote, write, and inspector deployment
profiles remain unsupported.

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
| Supabase Auth client | `@supabase/auth-js@2.112.4` | Synthetic M2 sign-in only |
| Supabase CLI | `2.115.0` | Synthetic local Auth/PostgREST/RLS lifecycle |
| Zod | `4.4.3` | Runtime input/output contracts |
| Vitest | `4.1.10` | Unit and stdio compatibility tests |
| Biome | `2.5.8` | Formatting and linting |

The root workspace and runtime dependencies use exact versions; `package-lock.json` is committed.
Official Auth is test/operator-only and is not a production runtime replacement for the fixed
identity verifier.

## Local workflow

From a clean checkout with the pinned Node.js and npm versions:

```shell
npm ci
npm run check
npm run build
```

Individual checks are available as `npm run format:check`, `npm run lint`, `npm run typecheck`,
`npm run test`, and `npm run test:compatibility`. `npm start` runs the built verified read-only
stdio server. `npm run start:compatibility` runs the M0 no-data probe. Both communicate over
stdin/stdout; human diagnostics go to stderr so they cannot corrupt JSON-RPC messages.

`npm run artifact:calibrate` builds and runs the deterministic synthetic S1b chunk/Merkle matrix.
It accepts no source path or network input and does not ingest or deploy artifacts. The command
prints a stable machine-readable receipt for the accepted calibration profile.

The read-only server accepts no command arguments. It requires
`SUPABASE_USER_MCP_ORIGIN` and `SUPABASE_USER_MCP_CREDENTIAL_FILE`. See the
[experimental operator guide](evidence/ISSUE_18_OPERATOR_RELEASE.md).

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

Only directories required by completed or active milestones are created. M0 through the synthetic
M2 read path and issue #34 S0/S1/S1b foundations are represented in the current repository. The
next gate is S2 fixed read-only inspection; later writes, remote access, and fleet profiles are not
implemented.

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

The pinned synthetic lifecycle is available through `npm run test:m2`; focused policy checks are
available through the `policy-lab:*` scripts. The artifact registry/Storage laboratory is exercised
through `npm run test:s1`, while `npm run artifact:calibrate` exercises deterministic manifest and
Merkle-proof behavior without Storage or hosted access.

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

The repository currently checks formatting, linting, strict compilation, unit contracts, the MCP
stdio compatibility path, and synthetic M2 Auth/PostgREST/RLS acceptance from a clean checkout.
Documentation has separate Markdown and link checks. Later milestones add:

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
