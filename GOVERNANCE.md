# Project Governance

Supabase User MCP is currently maintained by the repository owner. This document makes
decision rights visible while the contributor community develops.

## Roles

### Contributor

Anyone who improves issues, reviews, documentation, tests, designs, or code under the
project's contribution and conduct policies.

### Maintainer

A trusted contributor with repository authority and sustained responsibility for review,
releases, security response, and community health. Maintainers are listed in CODEOWNERS.

### Security reviewer

A maintainer or invited specialist responsible for reviewing a specific security model,
milestone gate, or release. This role may be temporary and does not automatically grant
repository administration.

## Decision process

- Small, reversible changes use normal pull-request review.
- Public contracts, trust boundaries, identity semantics, and consequential dependencies
  require an ADR.
- Maintainers seek evidence-backed consensus and document material objections.
- If consensus is not possible, maintainers decide and record the tradeoff in the ADR or
  pull request.
- Security invariants may block a feature regardless of popularity or schedule.
- A blocked architecture gate cannot be waived through README wording or an experimental
  label; it needs the evidence named in its milestone.

## Changes in authority

Adding a tool, capability, credential type, exposed relation, privileged function,
transport, or supported deployment profile is treated as an authority change. The review
must identify the new blast radius, denial cases, observability, revocation, and rollback.

## Releases

Maintainers may publish a release only after its roadmap gate passes. Stable releases also
require the independent review and provenance evidence specified for M6.

No maintainer can privately redefine a stable security contract. Emergency fixes may ship
under coordinated disclosure, followed by public documentation when safe.

## Becoming a maintainer

Maintainers are invited based on sustained, constructive contribution; sound security
judgment; reliable review; respect for project boundaries; and willingness to share
operational responsibility. Repository access follows least privilege and is reviewed
periodically.

## Amendments

Material governance changes use a public pull request with a clear transition plan. As the
project grows, this model may be replaced with a broader maintainer council and formal
voting rules.
