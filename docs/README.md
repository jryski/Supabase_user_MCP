# Documentation

This directory is the design source of truth for Supabase User MCP. The root README is
the project overview; documents here define the contracts that implementation and tests
must satisfy.

## Start here

| Document | Question answered |
| --- | --- |
| [Product definition](PRODUCT.md) | Who is this for, and what problem is in scope? |
| [Architecture](ARCHITECTURE.md) | What are the components and trust boundaries? |
| [Feature catalog](FEATURES.md) | Which tools and platform capabilities are planned? |
| [Security model](SECURITY_MODEL.md) | How is authority represented and enforced? |
| [Threat model](THREAT_MODEL.md) | What can go wrong, and what contains it? |
| [Roadmap](ROADMAP.md) | In what order will the project prove its claims? |
| [Development guide](DEVELOPMENT.md) | How will the repository be built and verified? |
| [Program context](PROGRAM_CONTEXT.md) | Which program plane owns which contracts and claims? |
| [M0 compatibility evidence](evidence/M0_COMPATIBILITY_SPIKE.md) | What does the executable protocol spike prove? |
| [Architecture decisions](decisions/README.md) | Why were consequential choices made? |

## Document status labels

- **Proposed** — a reviewable direction, not an implementation commitment.
- **Accepted** — the current project decision.
- **Blocked** — cannot proceed until a named uncertainty is resolved.
- **Implemented** — code and tests demonstrate the described contract.
- **Superseded** — retained for decision history but no longer current.

No document should use “secure,” “production-ready,” or “compliant” as a release claim
without linking to the evidence and acceptance gate that supports it.

## Sources of truth

When documents disagree, use this precedence order:

1. security invariants and accepted ADRs;
2. milestone exit criteria;
3. feature contracts;
4. architecture descriptions; and
5. overview prose.

Open an issue or pull request to resolve inconsistencies rather than silently choosing
the less restrictive interpretation.
