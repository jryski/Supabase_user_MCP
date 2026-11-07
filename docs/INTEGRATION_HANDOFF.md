# Multi-user MCP integration handoff

Updated November 6, 2026. This is the maintainer entrypoint for the reusable
multi-user implementation.

## Checkout coordinate

| Coordinate | Value |
| --- | --- |
| Canonical repository | [jryski/Supabase_user_MCP](https://github.com/jryski/Supabase_user_MCP) |
| Integration PR | [#147](https://github.com/jryski/Supabase_user_MCP/pull/147) |
| Integration branch | `codex/multiuser-completion-20261104` |
| Stacked base | `grok/mcp-native-first`, [#139](https://github.com/jryski/Supabase_user_MCP/pull/139), baseline `3b7cf86685836227f5ede9e31ed4c85aa85ecb53` |
| Previously qualified implementation | `4459c635374da7350b6fe70e896ea243e259fd89`, tree `33664db99cb1b65446a24d1b06c7fb8928323920` |
| Fork mirror | [Balance-EQ integration branch](https://github.com/Balance-EQ/Supabase_user_MCP/tree/codex/multiuser-completion-20261104) |

Use PR #147's current head for integration. The previously qualified SHA above
is the immutable evidence coordinate, not a request to discard newer commits.
The fork branch is a delivery mirror; contribute to the canonical PR to avoid
splitting the implementation across repositories.

```sh
git remote add mcp-upstream https://github.com/jryski/Supabase_user_MCP.git
git fetch mcp-upstream codex/multiuser-completion-20261104
git switch --create mcp-multiuser --track mcp-upstream/codex/multiuser-completion-20261104
git rev-parse HEAD
```

If the remote or local branch already exists, reuse it. Fetch and inspect the
current PR head before applying changes; do not force-push over maintainer work.
Checking out `main` alone does not include this stacked implementation.

## What to integrate

| Area | Source / contract |
| --- | --- |
| Finite capability descriptors | [contracts](../packages/contracts/src/capability-registration.ts), [registration contract](CAPABILITY_REGISTRATION.md) |
| Compiled approval loader and startup profile | [release approvals](../packages/server/src/capability-release-approvals.ts) |
| Bounded caller-scoped RPC registration | [capability registration](../packages/server/src/capability-mcp-registration.ts) |
| Native application composition and handler | [native composition](../packages/server/src/native-user-mcp.ts), [handler](../packages/server/src/native-user-mcp-read-handler.ts), [composition guide](MULTI_USER_APPLICATION_COMPOSITION.md) |
| Host-mounted own-account consent | [GET/POST handler](../packages/server/src/hosted-oauth-consent.ts), [host contract](HOSTED_OAUTH_CONSENT.md) |
| Isolation and transport evidence | [application integration tests](../packages/server/src/native-user-mcp-application.integration.test.ts), [evidence](evidence/MULTI_USER_APPLICATION_2026_11_04.md) |
| Native-first storage foundation | Base PR #139 and [its branch](https://github.com/jryski/Supabase_user_MCP/tree/grok/mcp-native-first) |

PR #126 supplied the design contract implemented in #147. PR #135 is the
separate ADR0008 client-binding lane; it is not the application-registry PR.
Review #139 before merging this stacked change or deliberately retarget it after
that base merges. This handoff does not change the base or approve either PR.

## Security dependency relationship

[PR #148](https://github.com/jryski/Supabase_user_MCP/pull/148) merged into
`main` as `585f5464ec9c498857a928fce16f9b66b2f3817b`.
The #147 implementation already pinned MCP SDK 2.4.0 and Zod 4.6.7.
This handoff commit carries the remaining #148 root toolchain and lockfile delta
(Vitest 4.1.12, Vite 8.2.4 and source-map-js 1.2.2) into the integration branch,
preserving its native-first dependencies. It is a dependency backport, not a
merge of all other `main` changes.

## Verification and deployment boundary

The previous implementation head `4459c635` passed the recorded Windows
check/build/typecheck/format checks (1457 tests, six skipped), Linux CI and
documentation workflows. Its Linux local-stack M2 receipt reports 18 synthetic
acceptance cases. See the evidence document and PR for immutable run links.
Those results belong to that head. The new handoff/dependency commit uses its
own GitHub checks; check their status on PR #147 before merging.

The shipped application approval list is empty. Default/read-only entrypoints
remain bounded. Descriptor approval, a host's actual consent mounting and
durable downstream-grant custody, deployment qualification and real own-user
storage/tool isolation acceptance remain deployment responsibilities. Passing
source CI does not activate tools, grant access or prove a hosted deployment.

Company-specific broker composition, policy SQL and host execution materials
belong in the consuming organization's private repository. They are not
included in either public fork. Keep runtime configuration, credentials,
grant custody and live receipts out of public integration patches.
