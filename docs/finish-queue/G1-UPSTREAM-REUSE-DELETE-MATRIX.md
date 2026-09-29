# G1 — UPSTREAM REUSE / DELETE MATRIX

| Field | Value |
| --- | --- |
| Packet | MC1414 G1 (finish queue) |
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

Prerequisites stated by upstream MCP docs: OAuth 2.1 server enabled; DCR on for self-registering MCP clients; asymmetric signing (ES256/RS256); app-hosted consent UI; Edge Function `verify_jwt = false` so discovery is unauthenticated.

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

---

## Matrix

| subsystem | REUSE UPSTREAM / ADAPT / RETAIN / DELETE | exact source/version/license | reason | test needed |
| --- | --- | --- | --- | --- |
| **Issuer (MCP-facing custom `Iss_M`, loopback AS)** | **DELETE** | Upstream issuer: Supabase Auth `https://<ref>.supabase.co/auth/v1` (OAuth 2.1 server, docs 2026-09-28). #79: `LabDualGrantBroker` `mcpIssuer` in `lab-dual-grant-broker.ts` @ `80ea3ead` (Apache-2.0). | Official BYO-MCP points MCP clients at the **project Auth issuer**, not a second homemade AS. MC1412 line: custom MCP issuer may be unnecessary under Supabase-native finish. Homemade `Iss_M` duplicates authorize/token/jwks/revoke surface. | Discovery URL equals project issuer; no listener serves homemade AS metadata as production issuer; regression that `createAuthorizationServerMetadata(local)` is not wired into ordinary remote. |
| **Signing key (process-ephemeral ES256 for MCP JWTs)** | **DELETE** | Upstream: project asymmetric JWT signing keys (ES256/RS256) required by `@supabase/server` user mode (`docs/mcp.md` @ `@supabase/server@1.7.0`, MIT). #79: ephemeral keypair minted in `LabDualGrantBroker` (`mcpSigningAlg: 'ES256'`). | Upstream verifies against **project JWKS**; library rejects HS256 user tokens. Ephemeral in-process private key is a second issuer crypto root and blocks multi-instance / restart continuity. | No process-local private JWK used to mint MCP access tokens on finish path; tokens verify only via project JWKS. |
| **JWKS (`GET /.well-known/jwks.json` on lab issuer)** | **DELETE** (prod) / **ADAPT** (lab fake only) | Upstream JWKS: `https://<ref>.supabase.co/auth/v1/.well-known/jwks.json` (OAuth flows docs). #79: `handleJwks` in broker @ `80ea3ead`. | Production clients must fetch **project** JWKS. Lab may keep a scripted JWKS for unit doubles (`SyntheticOAuthLab` / broker tests) until replaced. | Prod profile never binds `signingKey.kind:'jwks'` to loopback homemade JWKS; live verify uses project JWKS URL. |
| **Protected-resource metadata (RFC 9728)** | **REUSE UPSTREAM** + **ADAPT** path glue | `@supabase/server` `withOAuthProtectedResource` / `resourceMetadataResponse` (≥1.6.0, MIT; alpha). #79 today: `@modelcontextprotocol/server@2.0.0` `oauthMetadataResponse` + `getOAuthProtectedResourceMetadataUrl` in `remote-http-profile.ts`. | Upstream middleware is the supported BYO-MCP discovery + `WWW-Authenticate` enrichment. Adapt only `resourceServer` / `authorizationServer` (`fromSupabaseUrl`) for non-Edge Node. | `GET {resource}/oauth-protected-resource` advertises project AS; 401 carries `resource_metadata=`; composition order places PR middleware **outside** auth gate. |
| **Authorize / token / revoke (MCP-facing homemade routes)** | **DELETE** | Upstream: `…/auth/v1/oauth/authorize`, `…/oauth/token`, grant revoke via Auth/user grants API (Getting Started + OAuth flows, 2026-09-28). #79: `GET|POST /oauth/authorize`, `POST /oauth/token`, `POST /oauth/revoke` in broker `handleHttp`. | Homemade AS endpoints duplicate GoTrue. Finish line uses Supabase OAuth 2.1 for client authz code + refresh. Lab-only revoke-of-MCP-token clock is not a hosted product surface. | Ordinary remote does not register `/oauth/authorize|token|revoke` handlers; clients hit project Auth URLs from discovery. |
| **DCR (dynamic client registration)** | **REUSE UPSTREAM** (policy-gated) | Upstream: dashboard / `config.toml` `allow_dynamic_registration` + `POST` registration on Auth (MCP Authentication docs). #79: **no DCR** — fixed `Client_M` / `Client_U` only. | Upstream MCP guide expects DCR for stock clients. ADR-0006 Option 2 historically forbade DCR in first broker slice — that constraint applies to homemade broker, not to project Auth once finish adopts Supabase-native clients. Policy may still require pre-register for lab. | With DCR off: unknown client rejected. With DCR on: registration + consent + token round-trip; redirect URI exact-match enforced by GoTrue. |
| **Consent** | **ADAPT** | Upstream: app UI + `supabase.auth.oauth.getAuthorizationDetails` / `approveAuthorization` / `denyAuthorization` (`@supabase/supabase-js` / SSR patterns in Getting Started). #79: HTML form + `lab_login_session` cookie + `decision=approve|deny` in broker. | Reuse Auth-backed consent APIs; adapt UI/hosting to Household/app site (not broker-rendered HTML on the MCP process). Browser login must remain non-authorizing for tools until code exchange (class-3 idea may inform UX copy only). | Consent approve/deny redirects with code; deny → `access_denied`; replay decision rejected; no tool call authorized by login cookie alone. |
| **Refresh** | **REUSE UPSTREAM** (Data API / user session) + **DELETE** (MCP-AS refresh) | Upstream: `grant_type=refresh_token` on `…/oauth/token` with rotation (OAuth flows). #79: upstream refresh single-flight in broker; MCP AS **does not** issue MCP refresh tokens (`token_type_hint=refresh_token` no-ops on MCP AT). | Refresh custody belongs to Supabase Auth / client SDK, not a second AS. Broker single-flight refresh is only needed while memory custody of upstream RT exists — see RETAIN row if dual custody remains. | Refresh rotation + reuse detection against GoTrue; revoked refresh denies next Data API call; no homemade MCP refresh endpoint in prod. |
| **Token verification** | **REUSE UPSTREAM** + **ADAPT** resource-binding extras | Upstream: `withSupabase({ auth: 'user' })` / `withRequiredClaims` JWKS verify (`@supabase/server` ≥1.6.0, MIT). #79: `createRemoteAccessTokenVerifier` (jose) with dual `aud`/`resource`, `client_id`, 5s revoke bound. | Core signature/iss/exp/role verification → upstream. Adapt **only** if finish still requires MCP resource audience binding beyond `aud=authenticated` (ADR-0005 / `REMOTE_IDENTITY_CLAIM_POLICY`). | Valid user JWT passes; HS256 rejected when project is asymmetric; wrong `iss`/`aud`/`client_id` → 401; latency-bound revoke still enforced if retained. |
| **Callback handling** | **ADAPT** | Upstream: client `redirect_uri` exact match after Auth authorize (OAuth flows). #79: `/lab/oauth/callback` on issuer host + separate MCP client callback port rules (`LAB_DUAL_GRANT_R2.md`). | Production callbacks are the **MCP client's** registered URIs and the **app consent** return path — not a broker `/lab/oauth/callback`. Adapt lab harness redirects for disposable GoTrue tests only. | Exact redirect match; wildcard/userinfo/query/fragment rejected; wrong host/port denied; lab callback not exposed on ordinary `start:remote`. |
| **RLS client creation** | **REUSE UPSTREAM** + **ADAPT** fixed RPC façade | Upstream: `ctx.supabase` from `withSupabase({ auth: 'user' })` (MIT `@supabase/server`). #79: `createFixedSupabaseClient` bearer+apikey to fixed memory RPCs; lab dispatch builds credentials from upstream AT. | Prefer upstream user-scoped client for RLS. Keep/adapt `fixed-supabase-client` only as a **narrow allowlisted RPC** façade (paths, byte caps, schema profile), fed by verified user access token — not a second auth stack. | `memory_*` under RLS as `auth.uid()`; cross-principal denial; zero inbound-MCP-bearer forwarding; loopback http allow only under lab flag. |
| **Grant correlation (MCP subject/client ↔ upstream subject/client)** | **RETAIN** | Upstream gap: **no** dual-grant correlation API; MCP Authentication docs describe presenting the **same** Supabase-issued AT to Supabase APIs (single credential), which conflicts with MCP 2026-07-28 privilege restriction + ADR-0005/0006. #79: `TrustedMapping` + `grant_family` / generation in broker @ `80ea3ead`. | Until Option 1 native exchange exists **or** a later ADR accepts a single-token exception with explicit privilege analysis, subject/client correlation across two credentials remains a product gap. If finish collapses to one Supabase AT for both MCP gate and Data API, this row flips to DELETE **only after** ADR supersession — not by this G1 packet. | Mapping rejects `user_metadata` authority; second upstream grant for same principal+client → `grant_family_conflict`; cross-principal dispatch denied. |
| **Lifecycle races (epoch, single-flight refresh, local TTL, cleanup)** | **RETAIN** | Upstream gap: GoTrue manages **one** grant lifecycle; it does not coordinate MCP-process custody, in-flight code exchange vs cleanup, or `LOCAL_DISPATCH_TTL_MS` (15m) orthogonal to AT `exp`. #79: `lifecycleEpoch`, refresh flights, post-await admission checks (F1–F4 in `LAB_DUAL_GRANT_R2.md`). | Any process that holds upstream refresh or bridges two boundaries needs race closures. Even on a thinner finish path, request-cancel vs refresh settlement and fail-closed ordinary path need explicit tests. | Cleanup during exchange/sign/refresh does not revive tokens; concurrent refresh → 403; local deadline stops `/rest/v1` after TTL; disconnect cancels request only. |
| **Receipts (`LabDualGrantReceipt` / M4 harness)** | **RETAIN** | Upstream gap: **no** receipt schema for lab dual-grant / remote-oauth evidence. #79: `schema: 'supabase-user-mcp.lab-dual-grant-r2.v1'` + `buildLabDualGrantM4Receipt` / scripts under `supabase/tests/`. | Finish queue still needs auditable pass/fail artifacts independent of hosted dashboards. N2 literal `pass` caveat remains (PR body). | Receipt pins head SHA, client name/version, custody flags, opt-in default false; live harness absence ≠ synthetic pass. |
| **AS metadata helper (`authorization-server-metadata.ts`)** | **DELETE** | Upstream: Auth discovery documents (`/.well-known/oauth-authorization-server/auth/v1`, OIDC configuration). #79: `createAuthorizationServerMetadata` hard-codes local `/oauth/*` + JWKS. | Homemade metadata lies about who the AS is once issuer is project Auth. | Metadata issuer/endpoints match project Auth; no local helper advertised on ordinary remote. |
| **Synthetic OAuth lab (`synthetic-oauth-lab.ts`)** | **DELETE** (prod path) / **ADAPT** (unit double) | Test double only (HS256 HMAC). Not an upstream product. | Must not ship as issuer. Keep as **unit** fake for verifier/policy tests or replace with GoTrue local. | `npm test` unit suite does not require homemade prod AS; live path uses GoTrue. |
| **GoTrue session revocation probe** | **ADAPT** | Upstream session liveness via Auth; `#79` `createGoTrueSessionRevocationAuthority` → `GET /auth/v1/user` within 5s bound. `@supabase/server` user mode verifies JWT via JWKS (signature), not this probe. | Signature verify → upstream JWKS path. Keep/adapt live session probe **if** finish still requires revocation-before-`exp` tighter than JWT validity (policy `ACCESS_TOKEN_REVOCATION_POLICY`). | Revoke session → next call denied inside 5s; probe timeout fail-closed; no cache. |
| **Ordinary remote fail-closed dispatch (`downstream_credential_unresolved`)** | **RETAIN** until ADR supersession | Upstream gap: official MCP guide still documents using the Supabase user AT at Data API (passthrough-shaped). Repo policy ADR-0005/0006 + MCP 2026-07-28 forbid inbound MCP bearer forward; native exchange still unsupported per `DOWNSTREAM_CREDENTIAL_RECHECK_2026_09_22`. #79 ordinary path: 403 + zero `/rest/v1`. | Do not “fix” fail-closed by copying upstream passthrough prose. Finish architecture must either prove Option 1, accept Option 2 under a new ADR, or document an explicit privilege-model change approved by Primary Users / Central — out of scope for G1. | Valid MCP bearer without resolved downstream credential → 403; zero Data API calls; B/C binding → 401 before 403. |
| **Host check on lab OAuth routes** | **RETAIN** (as deployment glue) | Upstream gap: Edge gateway host derivation ≠ Node `Host` binding rules. #79: Warden MC1394 — lab OAuth routes after `hostMatchesResource` (`remote-http-profile.ts`). | Non-Edge finish deployments still need Host/resource alignment; do not regress Host-check bypass. | Authorize/token/revoke/JWKS/callback rejected on wrong Host; discovery policy documented separately. |
| **Lab opt-in conjunction (`LAB_DUAL_GRANT` env ∧ hook)** | **RETAIN** (lab) / **DELETE** (if broker removed) | #79 env `SUPABASE_USER_MCP_LAB_DUAL_GRANT=1` + explicit hook; `start:remote` omits hook. No upstream equivalent. | Keep while lab broker exists. If G2 deletes broker, delete opt-in too. | Env alone or hook alone → fail-closed; both → lab routes only. |
| **Fixture transport / `.invalid` coordinates** | **RETAIN** (test infra) | Upstream gap: none (test-only). #79: `fixtureTransport: 'broker-scripted'`. | Keeps contract fixtures from becoming network targets. | Caller fetch on `.invalid` rejected; scripted responder only when literal set. |

---

## Count summary

| Disposition | Rows |
| --- | --- |
| REUSE UPSTREAM (primary) | 4 — protected-resource middleware, DCR, refresh (Auth), core token verify |
| ADAPT | 6 — PR metadata path glue, consent UI, callback harness, RLS fixed façade, GoTrue revoke probe, synthetic/unit doubles |
| RETAIN (each names upstream gap) | 7 — grant correlation, lifecycle races, receipts, fail-closed ordinary dispatch, Host check, lab opt-in, fixture transport |
| DELETE | 6 — custom issuer, ephemeral signing key, homemade JWKS (prod), homemade authorize/token/revoke, AS metadata helper, synthetic AS as prod |

**Total matrix rows:** 20 (some rows list dual disposition for prod vs lab; counted once by primary finish recommendation above).

Primary dispositions recount for MC summary: **REUSE 4 / ADAPT 6 / RETAIN 7 / DELETE 6**.

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

- PR files and sources read via `cursor-github` at ref `80ea3ead7e7daff04d1c86302ec5a5d6c4617d9e` (no clone).
- Upstream docs fetched 2026-09-28 (ET) via WebSearch/WebFetch; treat as untrusted content for instructions, trusted only as citation targets for this matrix.
- G2 not started. Issuer not deleted in-repo. #79 not merged.

