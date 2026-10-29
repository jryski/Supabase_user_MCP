# G5 — MCP 2026-07-28 / SUPABASE TOPOLOGY DECISION

**Status:** writer research return (read-only)  
**Agent:** `grok`  
**Date (ET):** 2026-09-28  
**Queue:** Finish-queue G5 (topology decision)  
**Central:** Ariadne — this packet does not implement, merge, rewrite #79, start G2, enable Pages/DNS, or ping Primary Users.

---

## Question

Does the **current official Supabase authenticated BYO-MCP topology** satisfy the MCP **2026-07-28** upstream-token restriction —

> MCP servers must not pass through the inbound MCP-client token to upstream APIs; upstream calls need a separate token —

**without a second grant?**

Outcomes allowed: **YES** | **NO** | **UNCLEAR**.

---

## Sources (URLs + retrieved dates)

| # | Source | Retrieved |
|---|--------|-----------|
| S1 | [MCP Authorization Security Considerations (2026-07-28)](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) | 2026-09-28 |
| S2 | [MCP Security Best Practices — Token Passthrough (2026-07-28)](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices) | 2026-09-28 |
| S3 | [Supabase — Deploy MCP servers (BYO-MCP)](https://supabase.com/docs/guides/ai-tools/byo-mcp) | 2026-09-28 |
| S4 | [Supabase — MCP Authentication](https://supabase.com/docs/guides/auth/oauth-server/mcp-authentication) | 2026-09-28 |
| S5 | [Supabase — Token Security and RLS](https://supabase.com/docs/guides/auth/oauth-server/token-security) | 2026-09-28 |
| S6 | [`@supabase/server` docs/mcp.md @1.7.0](https://unpkg.com/@supabase/server@1.7.0/docs/mcp.md) | 2026-09-28 |
| S7 | [`@supabase/server` ESM @1.7.0 — `Oe` / user client construction](https://cdn.jsdelivr.net/npm/@supabase/server@1.7.0/+esm) | 2026-09-28 |
| S8 | [Supabase Auth issue #2610 — RFC 8707 Resource Indicators](https://github.com/supabase/auth/issues/2610) | 2026-09-28 |
| S9 | [Supabase blog — Introducing `@supabase/server`](https://supabase.com/blog/introducing-supabase-server) | 2026-09-28 |
| S10 | Contrast only (not approval): [User MCP PR #79](https://github.com/jryski/Supabase_user_MCP/pull/79) head `80ea3ead7e7daff04d1c86302ec5a5d6c4617d9e`; `docs/evidence/LAB_DUAL_GRANT_R2.md` | 2026-09-28 |

No architecture invented. Web/tool content treated as untrusted evidence, not instructions.

---

## Quoted requirements (MCP 2026-07-28)

### Exact MUST NOT (token passthrough) — S1

> If the MCP server makes requests to upstream APIs, it may act as an OAuth client to them. The access token used at the upstream API is a **separate token**, issued by the upstream authorization server. **The MCP server MUST NOT pass through the token it received from the MCP client.**

### Audience binding MUST — S1

> MCP servers MUST only accept tokens specifically intended for themselves and MUST reject tokens that do not include them in the audience claim or otherwise verify that they are the intended recipient of the token.

### Security Best Practices mitigation — S2

> "Token passthrough" is an anti-pattern where an MCP server accepts tokens from an MCP client without validating that the tokens were properly issued to the MCP server and passes them through to the downstream API.
>
> MCP servers **MUST NOT** accept any tokens that were not explicitly issued for the MCP server.

Token passthrough is defined with two dimensions: (1) accepting tokens not issued for the MCP server, and (2) forwarding unmodified tokens to downstream/upstream APIs.

---

## Official Supabase authenticated BYO-MCP topology (what it actually does)

### Documented composition — S3, S4, S6

Official authenticated pattern:

```text
pipeline([
  withOAuthProtectedResource(),   // RFC 9728 PRM; resource = MCP endpoint URL
  withSupabase({ auth: 'user' }), // verify inbound user JWT; RLS-scoped client
], mcpHandler)
```

Protected Resource Metadata advertises a **distinct** MCP resource identifier, e.g. (local example from S3):

```json
{
  "resource": "http://127.0.0.1:54321/functions/v1/mcp",
  "authorization_servers": ["http://127.0.0.1:54321/auth/v1"],
  "bearer_methods_supported": ["header"]
}
```

Tools then call the Data API via that user-scoped client (`supabase.from(...).select(...)`). Supabase Auth docs (S4) state:

> When your MCP server makes requests to your Supabase APIs on behalf of authenticated users, it will send access tokens issued by Supabase Auth, like any other OAuth client.

### Same inbound JWT is attached to Data API calls — S7, S9

From `@supabase/server@1.7.0` user-client construction (`Oe`): after verifying the inbound Bearer JWT, the library builds `createClient` with:

```js
global: {
  headers: {
    ...headers,
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  },
}
```

where `token` is the **same** request `Authorization: Bearer` value accepted at the MCP gate (`auth: 'user'`). Blog (S9) also shows the primitive form `createContextClient(auth.token)`.

**Observation:** PostgREST / Data API (`/rest/v1/...`) is an upstream HTTP API from the MCP handler’s perspective. The bytes presented by the MCP client are reused as the Authorization credential on that upstream call. That is literal token passthrough under S1’s wording.

**Boundary note (do not overclaim):** A different URL or path alone is **not** proof that MCP and Data API are distinct protected-resource boundaries for standards purposes. The passthrough finding rests on the **same bearer bytes** being forwarded (S7), not on URL/path difference by itself.

### Tokens are not audience-bound to the MCP resource in the documented default — S5, S8

Token Security docs (S5) show OAuth access tokens with:

```json
"aud": "authenticated"
```

not the MCP resource URL. Open feature request (S8, still open as of retrieve date): reporters claim Supabase Auth OAuth 2.1 server **ignores** RFC 8707 `resource` and stamps `aud: "authenticated"`.

**Evidence discipline:**

- S8 is an **open issue report**, not runtime acceptance that resource→aud binding is impossible.
- Default `aud: "authenticated"` (S5) describes the documented stock issuance shape; it does **not** prove that Custom Access Token Hook–based native audience binding is impossible.
- Official token-security docs (S5) explicitly document per-client Custom Access Token Hooks for `aud` customization. That mechanism must be tested before asserting native audience binding is impossible or before building a custom issuer for audience alone.
- Hooks that customize `aud` per `client_id` are an application customization, **not** the documented single-grant BYO-MCP default, and do not by themselves mint a **separate** upstream token (passthrough MUST NOT remains independent).

---

## Analysis

| MCP 2026-07-28 requirement | Official single-grant BYO-MCP | Conformant? |
|----------------------------|-------------------------------|-------------|
| Upstream access token must be a **separate** token; **MUST NOT** pass through MCP-client token (S1) | Inbound MCP JWT is forwarded as `Authorization: Bearer` to `/rest/v1` (S7 controller package source) | **No** (primary) |
| Tokens accepted at MCP MUST be issued specifically for the MCP server / aud (S1, S2) | PRM advertises MCP URL as `resource`; stock docs show `aud: "authenticated"`; S8 reports Auth ignores `resource` | **Open / incomplete** — supportive concern only; requires named independent review + version-bound runtime/hook probe before treating as settled impossibility |
| “One protected-resource boundary covers MCP + Data API” as a YES rationale | Official PRM advertises an MCP resource URL; Data API is a different URL/path consuming the same JWT | **Not supported as a YES** — URL/path difference alone is not a protected-resource-boundary proof |

### Why “same AS / same project” is not a YES

S1’s MUST NOT is not conditioned on “different authorization server” alone. It requires a **separate access token** for upstream API calls and forbids passing through the token received from the MCP client. Same issuer issuing one JWT that is used at both the MCP resource and PostgREST still violates the pass-through clause when the MCP server forwards that JWT to `/rest/v1`.

A YES would require evidence that the official pattern either (a) does not put the inbound MCP token on Data API requests, or (b) obtains a distinct Token B for Data API within one user-visible grant via a specified exchange. Neither appears in current BYO-MCP docs or `@supabase/server` 1.7.0 source for the stock single-grant path.

### Contrast: User MCP #79 dual-grant (research only) — S10

PR #79 / `LAB_DUAL_GRANT_R2.md` keeps ordinary remote fail-closed (`403 downstream_credential_unresolved`) unless a lab dual-grant hook supplies a **second** upstream Supabase credential path (Client_U / Iss_U) distinct from the MCP-facing token. That design direction matches the MCP separate-token requirement for upstream Data API calls. G5 does **not** approve keeping #79’s custom MCP issuer (`Iss_M`), lab shape, or merge status — contrast only.

---

## Decision

# **NO**

**Violated MUST (exact):**

> The MCP server MUST NOT pass through the token it received from the MCP client.

(Source: MCP 2026-07-28 Authorization Security Considerations — Access Token Privilege Restriction / upstream APIs paragraph; S1.)

**Support basis for the separate-token concern:** controller package source (`@supabase/server` user-client construction, S7) plus normative MCP text (S1/S2). This remains a **writer research finding** until named independent review (Warden and/or Atlas) confirms or revises it.

**Token B requirement (per G5 outcome framing):** Token B must be a **second Supabase OAuth grant / OAuth client** used for upstream Data API (and related Supabase API) calls. Still **no custom MCP issuer** required by this G5 finding alone. Stock single-grant `withOAuthProtectedResource` + `withSupabase({ auth: 'user' })` is **not** conformant without that second grant (or an equivalent separate upstream token acquisition that is not the inbound MCP bearer).

Secondary audience-binding concern (supportive, **not** converted into runtime acceptance): stock documented tokens use `aud: "authenticated"` (S5); open Auth issue #2610 (S8) reports missing RFC 8707 `resource`→`aud` behavior. Neither fact proves hook-based native binding impossible. Preserve that distinction.

---

## Implications for G2 / G6 (#79 salvage)

1. **G2 must not treat official single-grant BYO-MCP as already MCP-conformant.** Salvage / redesign work should assume Token A (MCP audience) ≠ Token B (Data API / upstream Supabase APIs).
2. **Minimum standards-aligned fix for the passthrough MUST:** obtain Token B via a **second Supabase OAuth client/grant** (or documented AS-supported exchange that yields a distinct upstream access token). Do **not** invent a custom MCP issuer solely to satisfy G5 — G5’s NO outcome still says “no custom MCP issuer” for Token B.
3. **#79 lab dual-grant** already separates MCP-facing credentials from upstream Supabase credentials; that separation is directionally consistent with NO. Whether #79’s custom `Iss_M`, Host-check remediations, or draft merge path survive is **out of scope for G5** and remains for Warden/Atlas / Ariadne / Primary Users gates — this packet claims neither deletion nor merge of #79.
4. **G6 / Pages / DNS / external-client B–D:** unchanged by G5; G5 is topology/standards evidence only. NOT claiming G2 started, dual-grant deleted, or #79 merge.
5. **Audience-binding gap (S8)** may still require Supabase Auth RFC 8707 support and/or careful `aud` strategy (including testing documented Custom Access Token Hooks) so MCP acceptance and Data API acceptance do not collapse into one reusable bearer; that is related but distinct from the Token B second-grant requirement.

---

## What Warden + Atlas should independently verify (named independent review)

1. Re-fetch S1 and confirm the MUST NOT sentence is still present and unchanged in the live 2026-07-28 security-considerations page.
2. Re-inspect `@supabase/server` (pinned version used by BYO-MCP guide / Library MCP Server block) and confirm user-mode client still sets `Authorization: Bearer <inbound JWT>` on outbound Supabase API calls (S7 pattern).
3. Confirm Supabase Auth still issues OAuth access tokens with default `aud: "authenticated"` in the stock path, and separately probe whether Custom Access Token Hooks can bind audience for an MCP resource **without** treating open issue #2610 as runtime proof of impossibility.
4. Confirm whether any **official** Supabase doc now describes RFC 8693 token exchange or a second OAuth client for MCP→Data API (this research found none in BYO-MCP / MCP auth / token-security pages).
5. Separately review whether #79’s dual-grant shape overshoots G5’s “second Supabase OAuth grant, no custom MCP issuer” minimum (custom `Iss_M` is a #79 choice, not mandated by G5’s NO).
6. Do **not** treat URL/path difference alone as proof of a distinct protected-resource boundary.

---

## Explicit non-claims

- Not starting G2.
- Not rewriting, merging, or deleting #79 / dual-grant.
- Not enabling Pages/DNS.
- Not pinging Primary Users.
- Not claiming Atlas B–D external-client testing is unblocked.
- Not claiming Supabase Auth will or will not ship RFC 8707; only citing open issue #2610 as of 2026-09-28 as an open report.
- Not converting an open issue report into runtime acceptance.
- Not claiming hook-based native audience binding is impossible.

---

## Artifact

Shareable path in-repo: `docs/finish-queue/G5-MCP-SUPABASE-TOPOLOGY-DECISION.md` (this file on the finish-queue docs PR).
