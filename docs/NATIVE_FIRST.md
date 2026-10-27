# Native-first application access

- **Direction:** project-lead-directed integration, recorded 2026-10-27.
- **Delivery state:** source candidates and local compatibility evidence, not a released or deployed profile.
- **Scope:** reuse maintained Supabase/MCP components; finish bounded application capabilities.

## Decision and supersession

Use the official Supabase application-MCP components wherever they preserve this
project's authority boundaries. Do not continue a parallel implementation of OAuth
discovery, ordinary JWT cryptography, MCP transport, or a consent-screen framework
merely because earlier plans assumed those pieces were missing.

This refocus supersedes the old priority to expand custom authentication scaffolding.
It does not discard useful source, replace application-specific authorization, accept
an unresolved ADR, or expand the supported profile on `main`. The local read-only
implementation plan remains historical completion evidence, not the current work queue.

The vendor's new **application MCP** path is distinct from its developer-management MCP.
Do not substitute project-administration credentials for an application's user identity.

## Borrow, retain, and do not build

**Borrow from maintained upstream:**

- Supabase Auth OAuth infrastructure and supported consent component.
- `withOAuthProtectedResource` discovery and authentication challenges.
- Native JWT verification primitives and request-scoped client construction.
- Official MCP SDK transport, lifecycle and fixed-tool registration.

**Retain in this application:**

- Explicit issuer, intended-resource, principal and client binding.
- Capability/delegation policy and database-enforced authorization.
- Current-session/grant checks, expiry, revocation and non-enumerating errors.
- Fixed memory and storage tools, strict schemas, audit and idempotency semantics.
- Input, output, time, rate and concurrency budgets and cross-identity denial tests.

**Do not add as part of this pivot:** another identity provider, generic SQL/REST tool,
a new control plane, a second server, privileged runtime fallback, or an automatic
hosting migration. Reuse the intended application sign-in flow; the vendor consent
block assumes sign-in already exists.

## Source and compatibility evidence

The repaired [candidate #136](https://github.com/jryski/Supabase_user_MCP/pull/136),
reviewed here at `e1335cfd87af5d2c0169486bb1587418991a8dd2`, already imports
`@supabase/server@1.7.2` in the **server workspace**, including the native discovery
and authentication helpers. Root-manifest absence was not evidence that the candidate
lacked the dependency. The work is integration and simplification, not a native rewrite.

A detached compatibility check of that exact candidate exercised:

- `@supabase/server@1.9.2` and explicit `@supabase/middleware@1.0.0`;
- split `@modelcontextprotocol/server@2.4.0`;
- contracts `zod@4.6.7`, retaining `@supabase/supabase-js@2.117.2`;
- Node 22.23.2 and npm 11.19.0.

The original and upgraded complete checks each returned **971 passed, 4 skipped**, with
three existing lint warnings. The sole initial upgraded failure was a static assertion
expecting library 1.7.2; updating the matching version constant and assertion restored
the suite without removing security assertions. Production-dependency audit of the
upgraded compatibility lockfile reported zero known findings. These are not results
for an unchanged `main` lockfile or a completed native-first implementation.

The [public compatibility receipt](https://github.com/jryski/Supabase_user_MCP/pull/136#issuecomment-6451572362)
records the five-file patch identity and limitations. Separate synthetic tests exercised
the actual published middleware and SDK: discovery, authenticated calls, concurrent
caller isolation, expiry/signature denial, explicit issuer/audience constraints and
credential forwarding behavior. A mocked Data API proves request construction, not
real database policy or a hosted OAuth flow.

Do not copy obsolete starter pins uncritically. The
[SDK resource-exhaustion advisory](https://github.com/advisories/GHSA-46jr-4wx8-v453)
requires configured `maxRequestBodySize` and `maxToolInputElements` as well as a
patched version. Keep the existing stricter application budgets. Zero audit findings
are not security acceptance. The template's per-request server factory is not the
shared-instance pattern covered by
[GHSA-jm63-cq47-j5jp](https://github.com/advisories/GHSA-jm63-cq47-j5jp).

## Remaining identity decision

The vendor's ordinary scoped client forwards the incoming user bearer to the Data API.
The existing adapter deliberately blocks that client path and uses a distinct downstream
credential. Current [MCP token restrictions](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#access-token-privilege-restriction)
still require intended-resource validation and prohibit forwarding the received bearer
to an upstream API. A vendor example does not itself settle this project's accepted
credential boundary.

Preserve that boundary while reviewing the exact topology. An explicit, separately
reviewed decision is required before changing it; the native-first direction does not
approve same-bearer forwarding, a client-claim migration or a live RLS cutover.
The separate [client-binding decision candidate #135](https://github.com/jryski/Supabase_user_MCP/pull/135)
remains a decision candidate, not approved database behavior.

Supabase documents signed top-level OAuth `client_id`; OIDC scopes do not constrain
database access. Check the actual token hooks, fallback rules and policy composition.
Neither a bare client identifier nor mutable user metadata proves authorization.

## Refocused delivery order

1. Use the repaired source as one integration candidate. Reuse/upgrade native components
   and applicable key-safety fixes; retain all security invariants and configured bounds.
2. Integrate or stage the vendor consent component on the existing frontend route.
   Distinguish source integration, frontend handoff, configuration and real client use.
3. Reuse the read-side storage candidate and existing bounds for
   [storage issue #123](https://github.com/jryski/Supabase_user_MCP/issues/123).
   Complete database capability/RLS enforcement and bounded put/delete. A storage
   schema draft is not end-to-end acceptance.
4. Continue the application-write capability work in
   [epic #111](https://github.com/jryski/Supabase_user_MCP/issues/111), keeping domain
   implementations in their owning components. Do not reset prior client evidence or
   substitute another read-only demonstration for write acceptance.

Keep one implementation owner and a different independent reviewer. Support work
should return useful tests or artifacts, not duplicate research and parallel rewrites.
Do not serialize dependency upgrades or synthetic domain tests behind a production
decision that they do not require.

## Acceptance and unchanged gates

The integrated source needs an exact-head independent review, repository checks and
LEAK-01, accurate docs and a reproducible lockfile. Useful storage acceptance additionally
requires two users across distinct clients: own-object list/get/put/delete succeeds;
cross-principal and unauthorized-client calls fail; expired and revoked grants fail;
path escapes, disallowed types and over-limit inputs fail; cleanup is demonstrated.

A signed URL already issued can remain usable until its own expiry. Denying the next
MCP request is not retroactive URL revocation. Record that distinction in tests and UI.

No live credentials, production/private payloads, project settings, public endpoint,
new key, merge, deployment or RLS rollout is authorized by this planning document.
Source, synthetic tests, merge, deployment and actual client acceptance remain separate.

## Official references

- [Supabase application MCP announcement](https://supabase.com/blog/give-your-supabase-app-its-own-mcp-server).
- [Deploy MCP servers and native auth](https://supabase.com/docs/guides/ai-tools/byo-mcp).
- [Official MCP starter registry](https://supabase.com/library/r/mcp.json): identity tool and composition, not the project's domain tools.
- [OAuth consent component](https://supabase.com/library/docs/nextjs/oauth-consent).
- [Token security and client-specific RLS](https://supabase.com/docs/guides/auth/oauth-server/token-security).
