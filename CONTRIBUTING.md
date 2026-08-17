# Contributing to Supabase User MCP

Thank you for helping build a safer application data plane for AI clients. The project
is early enough that careful disagreement is more valuable than volume.

## Before contributing

1. Read the [product definition](docs/PRODUCT.md), [architecture](docs/ARCHITECTURE.md),
   and [security model](docs/SECURITY_MODEL.md).
2. Check the [roadmap](docs/ROADMAP.md) and existing issues before proposing overlapping
   work.
3. Use the private process in [SECURITY.md](SECURITY.md) for vulnerabilities. Never put
   exploit details, credentials, or production data in a public issue.
4. Read [GOVERNANCE.md](GOVERNANCE.md) for decision rights and architecture gates.

## Good first contributions

- Add a denied case to the policy access matrix.
- Identify an undocumented trust boundary or confused-deputy path.
- Improve a feature's acceptance criteria.
- Reproduce a Supabase Auth, PostgREST, RLS, or MCP compatibility edge case.
- Correct documentation with a primary-source reference.
- Add a focused test for a previously documented invariant.

## Proposing a change

Use a GitHub issue for work that changes public behavior, identity semantics, security
boundaries, or milestones. Small corrections may go directly to a pull request.

An effective proposal states:

- the user and problem;
- the smallest useful behavior;
- the trust boundaries it crosses;
- failure and rollback behavior;
- observable acceptance criteria; and
- alternatives considered.

Changes to a consequential architectural decision require an Architecture Decision
Record (ADR). Copy [the ADR template](docs/decisions/0000-template.md), assign the next
number, and keep the decision focused.

## Pull requests

Keep pull requests small enough to review as one coherent change. A pull request should:

- link its issue or ADR when applicable;
- explain user-visible and security-visible behavior;
- include positive and negative tests;
- preserve denied-by-default behavior;
- update documentation and the changelog when contracts change;
- avoid unrelated formatting churn; and
- pass all required checks.

Draft pull requests are welcome for early design feedback. Mark unresolved security
questions explicitly; do not imply that an unverified path is production-ready.

## Engineering conventions

- Prefer TypeScript with strict compiler settings for the reference server.
- Validate external input at every boundary.
- Derive identity, tenant, and ownership fields from verified context rather than tool
  arguments.
- Do not log tokens, credentials, raw authorization headers, or sensitive record bodies.
- Pin runtime dependencies and commit the lockfile.
- Pin GitHub Actions to full commit SHAs.
- Keep database migrations reversible where PostgreSQL semantics permit.
- Treat security tests as product tests, not optional hardening.

The planned local workflow and repository layout are documented in
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Commit messages

Use short imperative subjects. Conventional Commit prefixes are encouraged:

```text
docs: define delegated-agent identity
feat: add bounded memory search tool
test: deny cross-workspace proposal approval
security: reject mismatched token audience
```

## Review standard

Reviewers prioritize, in order:

1. authorization and data-safety invariants;
2. protocol correctness and interoperability;
3. failure behavior and observability;
4. tests and maintainability; and
5. ergonomics and style.

By contributing, you agree that your contributions are licensed under the repository's
[Apache License 2.0](LICENSE).
