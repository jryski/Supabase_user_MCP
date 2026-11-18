# Multi-user MCP integration handoff

Use [PR #149](https://github.com/jryski/Supabase_user_MCP/pull/149) for the
integrated native candidate. The local stdio profile on `main` remains the
alpha release baseline.

## Checkout

```sh
git remote add mcp-upstream https://github.com/jryski/Supabase_user_MCP.git
git fetch mcp-upstream codex/mcp-release-candidate-20261107
git switch --create mcp-multiuser-review --track mcp-upstream/codex/mcp-release-candidate-20261107
git rev-parse HEAD
```

Reuse the upstream remote if already configured. Compare the checkout SHA to
PR #149 before testing. Pin an immutable revision when citing test results.

PRs [#139](https://github.com/jryski/Supabase_user_MCP/pull/139) and
[#147](https://github.com/jryski/Supabase_user_MCP/pull/147) are earlier
implementations in the integration branch's history. The
[compatibility review](https://github.com/jryski/Supabase_user_MCP/pull/136#issuecomment-6451572362),
[changes requested](https://github.com/jryski/Supabase_user_MCP/pull/139#pullrequestreview-5674027521),
and [consumer follow-up](https://github.com/jryski/Supabase_user_MCP/pull/139#issuecomment-6472688057)
remain review inputs for the current candidate.

## What to integrate

| Area | Source / contract |
| --- | --- |
| Finite capability descriptors | [contracts](../packages/contracts/src/capability-registration.ts), [registration contract](CAPABILITY_REGISTRATION.md) |
| Compiled approval loader and startup profile | [release approvals](../packages/server/src/capability-release-approvals.ts) |
| Bounded caller-scoped RPC registration | [capability registration](../packages/server/src/capability-mcp-registration.ts) |
| Native application composition and handler | [native composition](../packages/server/src/native-user-mcp.ts), [handler](../packages/server/src/native-user-mcp-read-handler.ts), [composition guide](MULTI_USER_APPLICATION_COMPOSITION.md) |
| Host-mounted own-account consent | [GET/POST handler](../packages/server/src/hosted-oauth-consent.ts), [host contract](HOSTED_OAUTH_CONSENT.md) |
| Isolation and transport evidence | [application integration tests](../packages/server/src/native-user-mcp-application.integration.test.ts), [evidence](evidence/MULTI_USER_APPLICATION_2026_11_04.md) |
| Native-first storage foundation | [PR #139 history](https://github.com/jryski/Supabase_user_MCP/pull/139) |

PR #126 supplied the capability registry design. PR #135 holds the separate
client-bound RLS decision. Evaluate optional task details v2 in PR #150 as a
separate unregistered adapter.

## Verification

Revision `4ab54df026fcbdc8f64190e5587952b7e0a39069` passed
[Linux Build and M2](https://github.com/jryski/Supabase_user_MCP/actions/runs/42401052924),
[documentation](https://github.com/jryski/Supabase_user_MCP/actions/runs/42401053018), and
[trusted LEAK-01](https://github.com/jryski/Supabase_user_MCP/actions/runs/42401051009).
The build reported 1,526 passed tests and six skips. The source includes
the dependency updates from PR #148, fixed-schema UUID memory support, and the
opt-in [SQLite consent challenge store](SQLITE_HOSTED_CONSENT_STORE.md).

The November 4 evidence and qualification at `4459c635` document an earlier
integration. Review the current PR head and its checks before adoption.

## Deployment boundary

The shipped application approval list is empty. Default/read-only entrypoints
remain bounded. Descriptor approval, a host's actual consent mounting and
durable downstream-grant custody, deployment qualification and real own-user
storage/tool isolation acceptance remain deployment responsibilities. Passing
source CI does not activate tools, grant access or prove a hosted deployment.

Company-specific broker composition, policy SQL and host execution materials
belong in the consuming organization's private repository. They are not
included in either public fork. Keep runtime configuration, credentials,
grant custody and live receipts out of public integration patches.
