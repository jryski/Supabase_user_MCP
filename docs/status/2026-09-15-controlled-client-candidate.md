# Controlled-client candidate: September 15, 2026

This page describes an unreleased candidate, not a deployment announcement.
Do not use synthetic test results as permission to connect production data.

## What changed

The candidate adds two optional tools to the existing read-only server. Both are
disabled by default and require the programmatic `registerDraftTwoTools: true`
option. The production CLI has no new enablement switch in this candidate.

| Tool | Candidate behavior | Important limit |
| --- | --- | --- |
| `memory_retrieve` | Composes bounded search and exact-record retrieval | A found record is not proof that its contents are current or authoritative |
| `session_capabilities_get` | Describes registered tools and declared evidence | A listed tool is not a permission grant or proof that its data source is reachable |

Default startup still exposes `memory_search`, `memory_get` and
`memory_list_recent`. Existing optional artifact inspection is a separate path.

Retrieval distinguishes found, ambiguous, paginated partial, scoped no-match and
error results. It rejects contradictory states and uses one continuation cursor.
No-match describes only the searched scope, not the absence of information
everywhere. Completeness and provenance currentness remain unknown.

The tools reuse the existing input parser and MCP error renderer. They do not
accept a model-supplied principal, arbitrary SQL or a caller-selected database.
Capability metadata marks unproven verification, qualification, authorization and
availability as unknown. Execution checks remain separate from discovery.

## Startup correction

Fresh-process testing found a pre-existing stdio integration defect. The server
factory returned a connect/close-only wrapper, but the installed SDK also needed
the underlying protocol server for discovery and negotiation.

The candidate returns the actual SDK server and retains the bounded transport
around its connection. It does not downgrade the protocol or remove frame limits.

## Reproduce the synthetic checks

Use the repository's [development setup](../DEVELOPMENT.md) and pinned toolchain.
From a checkout containing this candidate, run:

```sh
npm ci
npm run check
npx --no-install vitest run packages/server/src/process-stdio.integration.test.ts
```

`npm run check` builds and checks formatting, lint, types and tests. The focused
command uses the build produced by that check. Test fixtures provide synthetic
identity and record responses; they do not load a live user's credentials.

The six process scenarios cover default registration, found, empty, ambiguous,
partial and unavailable results through fresh client/server processes. They also
check discovery and invalid input. These are SDK client tests, not evidence of
acceptance in Cursor desktop, Claude mobile or ChatGPT mobile.

Independent validation on September 15 recorded 743 passing tests and four
credential-gated skips. Six fresh-process scenarios and eight additional boundary
checks also passed. Counts describe that validation run, not a permanent guarantee
for later revisions. The eleven earlier contract counterexamples have executable
regressions in the candidate.

## What is not established

- Live Vault or Household authorization for this candidate.
- Cross-user isolation or revocation through a real authenticated deployment.
- Production or phone-client readiness.
- Automatic selection between separate stores or their historical aliases.
- General semantic retrieval, automatic conflict resolution or current-truth proof.
- New write tools, a general SQL gateway or a live Storage adapter.

Storage access through the same connector remains a roadmap objective; this
candidate does not enable it. See the [feature catalog](../FEATURES.md) for the
separate artifact inspection work and its limits.

## Next acceptance steps

1. Review the exact candidate and land it through the normal repository gates.
2. Identify the existing isolated authenticated test deployment and test accounts.
   Do not substitute an administrator SQL connection for the user path.
3. Verify allowed and denied reads, cross-user isolation, revocation and source
   failure with synthetic records through that deployment.
4. Validate the actual client connection and approve any enablement separately.
5. Update published status with the resulting evidence and remaining limitations.

Do not wipe a restore lab, create broad policies or reuse privileged credentials
merely to make a test pass. Record failures as failures rather than empty answers.
