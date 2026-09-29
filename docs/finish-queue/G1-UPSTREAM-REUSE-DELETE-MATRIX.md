# G1 — UPSTREAM REUSE / DELETE MATRIX

| Field | Value |
| --- | --- |
| Packet | Finish-queue G1 (upstream reuse/delete matrix) |
| Writer | `grok` (research/docs only) |
| Central | Ariadne |
| Subject PR | https://github.com/jryski/Supabase_user_MCP/pull/79 |
| Exact head | `80ea3ead7e7daff04d1c86302ec5a5d6c4617d9e` |
| Tree | `ba8c3a230dea7286184362235b1dcc315d7d3398` |
| Repo | `jryski/Supabase_user_MCP` (Apache-2.0) |
| Upstream baseline | Official Supabase authenticated BYO-MCP / OAuth 2.1 stack as of **2026-09-28** |
| Non-claims | Not a merge. Not G2 code. Not issuer deletion executed. Not Pages/DNS. Not Primary Users ping. |

## Upstream sources pinned (2026-09-28)

| Source | Version / locator | License |
| --- | --- | --- |
| `@supabase/server` | `^1.6.0` (docs examples); published `1.7.0` docs at unpkg (`docs/mcp.md`) | MIT |
| `@supabase/middleware` | `^0.5.0` (pipeline composition in MCP docs) | MIT (package family) |
| Supabase Auth OAuth 2.1 | Project Auth issuer `https://<ref>.supabase.co/auth/v1` | Hosted product (GoTrue) |
| Docs: MCP Authentication | https://supabase.com/docs/guides/auth/oauth-server/mcp-authentication | Docs |
| Docs: OAuth 2.1 flows | https://supabase.com/docs/guides/auth/oauth-server/oauth-flows | Docs |
| Docs: Getting started | https://supabase.com/docs/guides/auth/oauth-server/getting-started | Docs |
| Docs: `withOAuthProtectedResource` | https://supabase.com/docs/reference/server/middleware-withoauthprotectedresource | Docs |
| MCP SDK used by #79 | `@modelcontextprotocol/server@2.0.0`, `jose@6.2.9` | Apache-2.0 / MIT |

### Upstream authenticated BYO-MCP shape (official)

```ts
pipeline(
  [withOAuthProtectedResource(), withSupabase({ auth: 'user' })],
  async (req, { supabase }) => mcpHandler(req, supabase),
)
```

Prerequisites stated by upstream MCP docs: OAuth 2.1 server enabled; DCR available for self-registering MCP clients; asymmetric signing (ES256/RS256); app-hosted consent UI; Edge Function `verify_jwt = false` so discovery is unauthenticated.

**First-proof policy (this matrix):** first acceptance proof uses **pre-registered synthetic clients** and **isolated test consent only**. Upstream DCR may exist later; it is not required or authorized for the first proof. No Household-OS deployment and no website/Pages consent hosting are needed or authorized by this packet.

Issuer / endpoints (cloud):

| Endpoint | URL |
| --- | --- |
| Issuer | `https://<ref>.supabase.co/auth/v1` |
| Authorize | `…/auth/v1/oauth/authorize` |
| Token | `…/auth/v1/oauth/token` |
| JWKS | `…/auth/v1/.well-known/jwks.json` |
| AS discovery | `https://<ref>.supabase.co/.well-known/oauth-authorization-server/auth/v1` |
| PR metadata | `GET {resource}/oauth-protected-resource` (RFC 9728 via `withOAuthProtectedResource`) |

Grant types: `authorization_code` + PKCE S256, `refresh_token` only. No RFC 8693 MCP→Data-API exchange on master (ADR-0006 recheck still holds for that gap).

## #79 subsystem inventory at head `80ea3ead`

Primary implementation files (PR delta + supporting tree):

| Path | Role at head |
| --- | --- |
| `packages/server/src/lab-dual-grant-broker.ts` | In-process dual-grant broker: Iss_M + Iss_U, consent HTML, JWKS, revoke, mapping, lifecycle epoch, receipts |
| `packages/server/src/lab-dual-grant-*.test.ts` / `m4.e2e.test.ts` | Lab matrices + disposable live harness |
| `packages/server/src/synthetic-oauth-lab.ts` | In-memory fake AS (HS256) for unit tests |
| `packages/server/src/live-gotrue-lab-upstream.ts` | Loopback GoTrue adapter for live M4 |
| `packages/server/src/authorization-server-metadata.ts` | Homemade AS metadata pointing at local issuer |
| `packages/server/src/remote-token-verifier.ts` | Custom JWT verify (issuer, dual aud/resource, client_id, live revoke bound) |
| `packages/server/src/remote-http-profile.ts` | Discovery + Host check + lab hook + fail-closed Data API |
| `packages/server/src/gotrue-revocation-authority.ts` | `GET /auth/v1/user` session liveness probe |
| `packages/server/src/fixed-supabase-client.ts` | Fixed `/rest/v1` RPC + `/auth/v1/user` client (stdio + lab dispatch) |
| `packages/server/src/local-oauth-pkce-client.ts` | Lab PKCE client helper |
| `packages/contracts/src/remote-oauth-http-policy.ts` | Freeze constants + `LAB_DUAL_GRANT_R2` |
| `docs/decisions/0006-downstream-credential-recheck.md` | Option 3 fail-closed; Option 2 unapproved for merge |
| `docs/evidence/LAB_DUAL_GRANT_R2.md` | Lab packet evidence |

## Disposition legend

| Disposition | Meaning |
| --- | --- |
| **REUSE UPSTREAM** | Call / configure the named official facility; do not reimplement |
| **ADAPT** | Keep a thin local wrapper or path-specific glue around upstream |
| **RETAIN** | Keep #79 (or successor) logic because **upstream gap is named** |
| **DELETE** | Remove from production / finish path (lab-only copies may remain as test doubles until G2 says otherwise) |

**Counting rule:** each matrix row has exactly **one primary disposition**. Secondary / lab notes are recorded in a separate column and are **not** counted in the summary totals.

---

## Matrix

| # | subsystem | primary disposition | secondary / lab notes | exact source/version/license | reason | test needed |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | **Issuer (MCP-facing custom `Iss_M`, loopback AS)** | **DELETE** | — | Upstream issuer: Supabase Auth `https://<ref>.supabase.co/auth/v1` (OAuth 2.1 server, docs 2026-09-28). #79: `LabDualGrantBroker` `mcpIssuer` in `lab-dual-grant-broker.ts` @ `80ea3ead` (Apache-2.0). | Official BYO-MCP points MCP clients at the **project Auth issuer**, not a second homemade AS. Architecture recheck (public Atlas finish directive / PR #79 research contrast): custom MCP issuer may be unnecessary under Supabase-native finish. Homemade `Iss_M` duplicates authorize/token/jwks/revoke surface. | Discovery URL equals project issuer; no listener serves homemade AS metadata as production issuer; regression that `createAuthorizationServerMetadata(local)` is not wired into ordinary remote. |
| 2 | **Signing key (process-ephemeral ES256 for MCP JWTs)** | **DELETE** | — | Upstream: project asymmetric JWT signing keys (ES256/RS256) required by `@supabase/server` user mode (`docs/mcp.md` @ `@supabase/server@1.7.0`, MIT). #79: ephemeral keypair minted in `LabDualGrantBroker` (`mcpSigningAlg: 'ES256'`). | Upstream verifies against **project JWKS**; library rejects HS256 user tokens. Ephemeral in-process private key is a second issuer crypto root and blocks multi-instance / restart continuity. | No process-local private JWK used to mint MCP access tokens on finish path; tokens verify only via project JWKS. |
| 3 | **JWKS (`GET /.well-known/jwks.json` on lab issuer)** | **DELETE** | Lab unit doubles may **ADAPT** a scripted JWKS (`SyntheticOAuthLab` / broker tests) until replaced | Upstream JWKS: `https://<ref>.supabase.co/auth/v1/.well-known/jwks.json` (OAuth flows docs). #79: `handleJwks` in broker @ `80ea3ead`. | Production clients must fetch **project** JWKS. | Prod profile never binds `signingKey.kind:'jwks'` to loopback homemade JWKS; live verify uses project JWKS URL. |
| 4 | **Protected-resource metadata (RFC 9728)** | **REUSE UPSTREAM** | **ADAPT** path glue only: `resourceServer` / `authorizationServer` (`fromSupabaseUrl`) for non-Edge Node | `@supabase/server` `withOAuthProtectedResource` / `resourceMetadataResponse` (≥1.6.0, MIT; alpha). #79 today: `@modelcontextprotocol/server@2.0.0` `oauthMetadataResponse` + `getOAuthProtectedResourceMetadataUrl` in `remote-http-profile.ts`. | Upstream middleware is the supported BYO-MCP discovery + `WWW-Authenticate` enrichment. | `GET {resource}/oauth-protected-resource` advertises project AS; 401 carries `resource_metadata=`; composition order places PR middleware **outside** auth gate. |
| 5 | **Authorize / token / revoke (MCP-facing homemade routes)** | **DELETE** | — | Upstream: `…/auth/v1/oauth/authorize`, `…/oauth/token`, grant revoke via Auth/user grants API (Getting Started + OAuth flows, 2026-09-28). #79: `GET|POST /oauth/authorize`, `POST /oauth/token`, `POST /oauth/revoke` in broker `handleHttp`. | Homemade AS endpoints duplicate GoTrue. Finish line uses Supabase OAuth 2.1 for client authz code + refresh. Lab-only revoke-of-MCP-token clock is not a hosted product surface. | Ordinary remote does not register `/oauth/authorize|token|revoke` handlers; clients hit project Auth URLs from discovery. |
| 6 | **DCR (dynamic client registration)** | **REUSE UPSTREAM** | First-proof policy: **pre-registered synthetic clients only**; DCR stays off for first proof. Not an authorization to enable DCR, Household, or website consent hosting. | Upstream: dashboard / `config.toml` `allow_dynamic_registration` + `POST` registration on Auth (MCP Authentication docs). #79: **no DCR** — fixed `Client_M` / `Client_U` only. | Upstream MCP guide documents DCR for stock clients, but first proof deliberately uses pre-registered synthetics. ADR-0006 Option 2 historically forbade DCR in the homemade broker slice; that does not expand first-proof scope to open DCR or site hosting. | With DCR off (first proof): unknown client rejected; pre-registered synthetic clients succeed. Do not require DCR-on registration round-trip for first proof. |
| 7 | **Consent** | **ADAPT** | Isolated **test** consent UI only (Auth-backed approve/deny APIs). **Not** Household-OS deployment. **Not** website/Pages consent hosting. | Upstream: app UI + `supabase.auth.oauth.getAuthorizationDetails` / `approveAuthorization` / `denyAuthorization` (`@supabase/supabase-js` / SSR patterns in Getting Started). #79: HTML form + `lab_login_session` cookie + `decision=approve|deny` in broker. | Reuse Auth-backed consent APIs; adapt a minimal isolated test consent surface (not broker-rendered HTML on the MCP process as a product UI). Browser login must remain non-authorizing for tools until code exchange. | Consent approve/deny redirects with code; deny → `access_denied`; replay decision rejected; no tool call authorized by login cookie alone. |
| 8 | **Refresh** | **REUSE UPSTREAM** | **DELETE** homemade MCP-AS refresh endpoint if still present | Upstream: `grant_type=refresh_token` on `…/oauth/token` with rotation (OAuth flows). #79: upstream refresh single-flight in broker; MCP AS **does not** issue MCP refresh tokens (`token_type_hint=refresh_token` no-ops on MCP AT). | Refresh custody belongs to Supabase Auth / client SDK, not a second AS. Broker single-flight refresh is only needed while memory custody of upstream RT exists — see RETAIN lifecycle row if dual custody remains. | Refresh rotation + reuse detection against GoTrue; revoked refresh denies next Data API call; no homemade MCP refresh endpoint in prod. |
| 9 | **Token verification** | **REUSE UPSTREAM** | **ADAPT** resource-binding extras only if finish still requires MCP resource audience beyond `aud=authenticated` (ADR-0005 / `REMOTE_IDENTITY_CLAIM_POLICY`) | Upstream: `withSupabase({ auth: 'user' })` / `withRequiredClaims` JWKS verify (`@supabase/server` ≥1.6.0, MIT). #79: `createRemoteAccessTokenVerifier` (jose) with dual `aud`/`resource`, `client_id`, 5s revoke bound. | Core signature/iss/exp/role verification → upstream. | Valid user JWT passes; HS256 rejected when project is asymmetric; wrong `iss`/`aud`/`client_id` → 401; latency-bound revoke still enforced if retained. |
| 10 | **Callback handling** | **ADAPT** | Lab harness redirects for disposable GoTrue tests only | Upstream: client `redirect_uri` exact match after Auth authorize (OAuth flows). #79: `/lab/oauth/callback` on issuer host + separate MCP client callback port rules (`LAB_DUAL_GRANT_R2.md`). | Production callbacks are the **MCP client's** registered URIs and the **isolated test consent** return path — not a broker `/lab/oauth/callback`. | Exact redirect match; wildcard/userinfo/query/fragment rejected; wrong host/port denied; lab callback not exposed on ordinary `start:remote`. |
| 11 | **RLS client creation** | **REUSE UPSTREAM** | **ADAPT** fixed RPC façade (paths, byte caps, schema profile) fed by verified user access token | Upstream: `ctx.supabase` from `withSupabase({ auth: 'user' })` (MIT `@supabase/server`). #79: `createFixedSupabaseClient` bearer+apikey to fixed memory RPCs; lab dispatch builds credentials from upstream AT. | Prefer upstream user-scoped client for RLS. Keep/adapt `fixed-supabase-client` only as a narrow allowlisted RPC façade — not a second auth stack. | `memory_*` under RLS as `auth.uid()`; cross-principal denial; zero inbound-MCP-bearer forwarding; loopback http allow only under lab flag. |
| 12 | **Grant correlation (MCP subject/client ↔ upstream subject/client)** | **RETAIN** | — | Upstream gap: **no** dual-grant correlation API; MCP Authentication docs describe presenting the **same** Supabase-issued AT to Supabase APIs (single credential), which conflicts with MCP 2026-07-28 privilege restriction + ADR-0005/0006. #79: `TrustedMapping` + `grant_family` / generation in broker @ `80ea3ead`. | Until Option 1 native exchange exists **or** a later ADR accepts a single-token exception with explicit privilege analysis, subject/client correlation across two credentials remains a product gap. If finish collapses to one Supabase AT for both MCP gate and Data API, this row flips to DELETE **only after** ADR supersession — not by this G1 packet. | Mapping rejects `user_metadata` authority; second upstream grant for same principal+client → `grant_family_conflict`; cross-principal dispatch denied; agent-specific RLS must not collapse two agents onto one upstream `client_id`. |
| 13 | **Lifecycle races (epoch, single-flight refresh, local TTL, cleanup)** | **RETAIN** | — | Upstream gap: GoTrue manages **one** grant lifecycle; it does not coordinate MCP-process custody, in-flight code exchange vs cleanup, or `LOCAL_DISPATCH_TTL_MS` (15m) orthogonal to AT `exp`. #79: `lifecycleEpoch`, refresh flights, post-await admission checks (F1–F4 in `LAB_DUAL_GRANT_R2.md`). | Any process that holds upstream refresh or bridges two boundaries needs race closures. Even on a thinner finish path, request-cancel vs refresh settlement and fail-closed ordinary path need explicit tests. | Cleanup during exchange/sign/refresh does not revive tokens; concurrent refresh → 403; local deadline stops `/rest/v1` after TTL; disconnect cancels request only. |
| 14 | **Receipts (`LabDualGrantReceipt` / M4 harness)** | **RETAIN** | — | Upstream gap: **no** receipt schema for lab dual-grant / remote-oauth evidence. #79: `schema: 'supabase-user-mcp.lab-dual-grant-r2.v1'` + `buildLabDualGrantM4Receipt` / scripts under `supabase/tests/`. | Finish queue still needs auditable pass/fail artifacts independent of hosted dashboards. N2 literal `pass` caveat remains (PR body). | Receipt pins head SHA, client name/version, custody flags, opt-in default false; live harness absence ≠ synthetic pass. |
| 15 | **AS metadata helper (`authorization-server-metadata.ts`)** | **DELETE** | — | Upstream: Auth discovery documents (`/.well-known/oauth-authorization-server/auth/v1`, OIDC configuration). #79: `createAuthorizationServerMetadata` hard-codes local `/oauth/*` + JWKS. | Homemade metadata lies about who the AS is once issuer is project Auth. | Metadata issuer/endpoints match project Auth; no local helper advertised on ordinary remote. |
| 16 | **Synthetic OAuth lab (`synthetic-oauth-lab.ts`)** | **DELETE** | Unit double may remain as **ADAPT** test fake (HS256) for verifier/policy tests, or be replaced with local GoTrue | Test double only (HS256 HMAC). Not an upstream product. | Must not ship as issuer / production AS. | `npm test` unit suite does not require homemade prod AS; live path uses GoTrue. |
| 17 | **GoTrue session revocation probe** | **ADAPT** | — | Upstream session liveness via Auth; `#79` `createGoTrueSessionRevocationAuthority` → `GET /auth/v1/user` within 5s bound. `@supabase/server` user mode verifies JWT via JWKS (signature), not this probe. | Signature verify → upstream JWKS path. Keep/adapt live session probe **if** finish still requires revocation-before-`exp` tighter than JWT validity (policy `ACCESS_TOKEN_REVOCATION_POLICY`). | Revoke session → next call denied inside 5s; probe timeout fail-closed; no cache. |
| 18 | **Ordinary remote fail-closed dispatch (`downstream_credential_unresolved`)** | **RETAIN** | Flips only after ADR supersession (not by this packet) | Upstream gap: official MCP guide still documents using the Supabase user AT at Data API (passthrough-shaped). Repo policy ADR-0005/0006 + MCP 2026-07-28 forbid inbound MCP bearer forward; native exchange still unsupported per `DOWNSTREAM_CREDENTIAL_RECHECK_2026_09_22`. #79 ordinary path: 403 + zero `/rest/v1`. | Do not “fix” fail-closed by copying upstream passthrough prose. Finish architecture must either prove Option 1, accept Option 2 under a new ADR, or document an explicit privilege-model change approved by Primary Users / Central — out of scope for G1. | Valid MCP bearer without resolved downstream credential → 403; zero Data API calls; B/C binding → 401 before 403. |
| 19 | **Host check on lab OAuth routes** | **RETAIN** | — | Upstream gap: Edge gateway host derivation ≠ Node `Host` binding rules. #79: Host-check remediation on lab OAuth routes after `hostMatchesResource` (`remote-http-profile.ts`); see https://github.com/jryski/Supabase_user_MCP/pull/79. | Non-Edge finish deployments still need Host/resource alignment; do not regress Host-check bypass. | Authorize/token/revoke/JWKS/callback rejected on wrong Host; discovery policy documented separately. |
| 20 | **Lab opt-in conjunction (`LAB_DUAL_GRANT` env ∧ hook)** | **RETAIN** | Secondary: **DELETE** the opt-in if/when the lab broker itself is removed | #79 env `SUPABASE_USER_MCP_LAB_DUAL_GRANT=1` + explicit hook; `start:remote` omits hook. No upstream equivalent. | Keep while lab broker exists. If G2 deletes broker, delete opt-in too. | Env alone or hook alone → fail-closed; both → lab routes only. |
| 21 | **Fixture transport / `.invalid` coordinates** | **RETAIN** | — | Upstream gap: none (test-only). #79: `fixtureTransport: 'broker-scripted'`. | Keeps contract fixtures from becoming network targets. | Caller fetch on `.invalid` rejected; scripted responder only when literal set. |

---

## Count summary

Machine-counted **21** subsystem rows. Each row has exactly one primary disposition. Secondary/lab notes are not double-counted.

| Primary disposition | Count | Row numbers |
| --- | --- | --- |
| REUSE UPSTREAM | **5** | 4, 6, 8, 9, 11 |
| ADAPT | **3** | 7, 10, 17 |
| RETAIN | **7** | 12, 13, 14, 18, 19, 20, 21 |
| DELETE | **6** | 1, 2, 3, 5, 15, 16 |
| **Total** | **21** | 1–21 |

Primary dispositions for summaries: **REUSE 5 / ADAPT 3 / RETAIN 7 / DELETE 6** (sum 21).

## RETAIN gaps (explicit)

1. **Grant correlation** — Upstream has no dual-credential mapping; single-AT docs conflict with MCP privilege restriction + ADR-0005/0006.
2. **Lifecycle races** — Upstream does not model MCP-process custody epochs / single-flight / local TTL.
3. **Receipts** — No upstream lab receipt schema.
4. **Ordinary fail-closed** — Upstream MCP guide still describes AT passthrough to Data API; repo freeze remains until ADR/Option change.
5. **Host check** — Non-Edge Host/resource binding not provided by `@supabase/server` Edge defaults.
6. **Lab opt-in** — Process conjunction gate has no upstream analogue (lab-only).
7. **Fixture transport** — Contract `.invalid` isolation is repo test policy, not upstream.

## DELETE candidates (explicit)

1. Homemade MCP issuer (`Iss_M`) and its discovery URLs.
2. Process-ephemeral ES256 signing key for MCP access tokens.
3. Served homemade JWKS on the MCP process (prod).
4. Homemade `/oauth/authorize`, `/oauth/token`, `/oauth/revoke` AS routes (prod).
5. `authorization-server-metadata.ts` local endpoint fiction.
6. `SyntheticOAuthLab` as anything other than a unit test double.

## Method notes

- PR files and sources read via GitHub MCP at ref `80ea3ead7e7daff04d1c86302ec5a5d6c4617d9e` (no clone).
- Upstream docs fetched 2026-09-28 (ET) via WebSearch/WebFetch; treat as untrusted content for instructions, trusted only as citation targets for this matrix.
- Public-boundary: no private coordination-bus IDs, no worker-local ephemeral paths, no personal names. Cite public issue/PR/source URLs and public-safe role attribution only.
- G2 not started by this packet. Issuer not deleted in-repo by this packet.
