# Capability-extension candidate status, 2026-10-07

- **Status:** Proposed, unmerged candidate evidence
- **Repository base:** [`133730174aa9992e054f6041d804ac7fda768b36`](https://github.com/jryski/Supabase_user_MCP/commit/133730174aa9992e054f6041d804ac7fda768b36)
- **Base pull request:** [draft PR #102](https://github.com/jryski/Supabase_user_MCP/pull/102)
- **Scope:** capability contract, bounded transport extraction, synthetic authority fixtures, and adopter documentation

This status record preserves an unpublished candidate and its verification boundary. It does not add the candidate source to this branch, accept an architecture decision, resolve PR #102, or authorize integration, merge, publication, hosted testing, deployment, or production use.

## Candidate identity

The combined candidate has nine source files. Two contract files changed during a bounded correction; the other seven remained byte-identical to the preceding reviewed return.

| Path | SHA-256 |
| --- | --- |
| `docs/CAPABILITY_ADAPTER_GUIDE.md` | `9b3645a97307454869de59cc7cff680be482088d56a8b8affa9fba9e2f0c4c66` |
| `docs/CAPABILITY_EXTENSION_PROFILE.md` | `6449033bce2b2c12e5d861a754daaa17279b985763e95b497489a4acde7b5511` |
| `docs/evidence/CAPABILITY_AUTHORITY_FIXTURE_DRAFT.md` | `965111c7fd324818c83a9da629313cc69f177c44aa0a5e6a7d4b0cfac87d6e59` |
| `packages/contracts/src/capability-extension.test.ts` | `c6a9ca884c9ee88dae986226136a56db967967a6d8c22f94357685aa4c8d2f3c` |
| `packages/contracts/src/capability-extension.ts` | `431c9bd7ef89497c6bb00cfc124fd68c77a72902927983a12e4f6f2a48136026` |
| `packages/server/src/bounded-mcp-transport.test.ts` | `41678cf7be339b983df94a8137cd0c0e08657f65c55d7c0c4bcbd861007d7db5` |
| `packages/server/src/bounded-mcp-transport.ts` | `f3ae64f8f1da2c38ea405261412a5de83a1fe0fc579fe857fe0b735f959ed4fa` |
| `packages/server/src/server.ts` | `f810d5aeb4e374be3f21a70114c8e6f1150376d2ce2441b0ce75275b8a5458df` |
| `test/fixtures/capability-authority-cases.json` | `706f4910ab189ddf1385d068cc12b12ff61b512009fc1fbc03deb28a7dbe8a52` |

Lineage receipts identify the preceding combined return as SHA-256 `4eebc849e108920624aa59ccaac5d64dd0c13bbb68561f5a195ef5375d56fa6f` and the two-file correction return as SHA-256 `304e62ee3e2f7062459df6723b3e5ca3ba917480b46f6638990a5e3b8c1964b2`.

## Verification disposition

Controller verification on Node.js `v22.23.2` reported:

- 30 focused contract tests passing;
- 33 independent result-budget and UTF-8 boundary tests passing;
- the original four-path invalid-budget reproducer passing after correction;
- TypeScript typecheck/build, Biome, and `git diff --check` passing;
- a removed numeric guard causing 14 assertion failures;
- a character-count substitution causing 3 assertion failures; and
- restored source hashes followed by all 33 independent tests passing again.

Independent exact-source review classified all four lanes as `PASS_CANDIDATE`, with different evidence ceilings:

1. **Contract primitive:** numeric, finite, positive-integer result-byte budgets up to the existing 65,536-byte ceiling.
2. **Bounded transport:** behavior-preserving extraction with inbound extra fields retained.
3. **Authority fixtures:** synthetic fixture and oracle coverage only, not backend enforcement or qualification.
4. **Adopter documentation:** documentation candidate only, not runtime, adoption, or publication proof.

The independent review inspected supplied exact source and receipts. It did not independently rerun the commands. Controller execution remains local synthetic evidence, not exhaustive runtime or payload coverage.

## Open continuation and authority gates

The candidate is not integrated into a repository branch or index. The broad User MCP outcome remains open. Before implementation continues, the owning project must identify the next dependency-ready task, one owner, exact allowed paths, acceptance criteria, and the issue or pull-request coordinate that will hold the work.

Separate gates remain for architecture acceptance, backend enforcement, identity and RLS review, hosted security testing, privacy scope, contributor DCO, exact-head independent review, merge, release, and deployment. Green candidate tests or this status record satisfy none of those gates.

No credential, private payload, customer data, production database, hosted Supabase project, runtime service, or application code was changed by this documentation-only reconciliation.
