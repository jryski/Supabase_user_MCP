# G2 — ACCEPTANCE CHECKLIST (vs G1 matrix and G5 = NO)

| Field | Value |
| --- | --- |
| Packet | G2 acceptance checklist (User MCP native Supabase server adapter) |
| Writer role | docs prep only (this packet does not implement G2 and is not an independent review) |
| Central | Ariadne — hard gates below are for Central when a G2 draft PR lands |
| Repo | `jryski/Supabase_user_MCP` (Apache-2.0) |
| G1 + G5 source PR | https://github.com/jryski/Supabase_user_MCP/pull/97 (draft) |
| G1 + G5 exact head | `95ae3a46710134d5a46a57e17fe4a38224c89467` |
| G1 matrix | `docs/finish-queue/G1-UPSTREAM-REUSE-DELETE-MATRIX.md` at that head |
| G5 decision | **NO** — `docs/finish-queue/G5-MCP-SUPABASE-TOPOLOGY-DECISION.md` at that head |
| G5 Token B rule | Token B is a **second Supabase OAuth grant / OAuth client**. G5 does **not** require a custom MCP issuer. |
| G2 implementation base | https://github.com/jryski/Supabase_user_MCP/pull/75 @ `fcbaca121d0717ee8ff98df90b2f12475b05bb78` |
| G2 agent already running | `bc-ede9c9e7-f9b9-5441-8a5f-b217b216b4cf` (do not treat this checklist as that run) |
| #79 | **HOLD** — research history only. https://github.com/jryski/Supabase_user_MCP/pull/79 head researched by G1: `80ea3ead7e7daff04d1c86302ec5a5d6c4617d9e`. Not expanded, not reset, not merged by this packet. |
| Ordinary remote | The finish / ordinary remote path G1 describes: `start:remote` **omits** the lab dual-grant hook. Lab routes, unit doubles, and scripted JWKS are not this path. |
| Marks in this file | Unfilled. A later verifier writes `PASS`, `FAIL`, or `BLOCKED` against the G2 draft PR’s exact head SHA. |

This checklist judges a future G2 draft against the G1 matrix table and the G5 **NO** decision already written at `95ae3a46`. It does not add a topology, an issuer, an exchange, or a privilege exception.

## How this map relates to G1’s count summary

G1’s matrix **table** lists **21** subsystem rows (Issuer through Fixture transport). G1’s count summary says “20” and “REUSE 4 / ADAPT 6 / RETAIN 7 / DELETE 6”. Those bucket totals mention some dual-disposition rows in more than one bucket. Coverage here is the **table**, one checklist row per subsystem, with both clauses kept when a cell names two dispositions.

| Checklist | G1 subsystem | Disposition cell |
| --- | --- | --- |
| G1-01 | Issuer (custom `Iss_M`, loopback AS) | DELETE |
| G1-02 | Signing key (process-ephemeral ES256) | DELETE |
| G1-03 | JWKS on lab issuer | DELETE (prod) / ADAPT (lab fake only) |
| G1-04 | Protected-resource metadata (RFC 9728) | REUSE UPSTREAM + ADAPT path glue |
| G1-05 | Authorize / token / revoke (homemade routes) | DELETE |
| G1-06 | DCR | REUSE UPSTREAM (policy-gated) |
| G1-07 | Consent | ADAPT |
| G1-08 | Refresh | REUSE UPSTREAM (Data API / user session) + DELETE (MCP-AS refresh) |
| G1-09 | Token verification | REUSE UPSTREAM + ADAPT resource-binding extras |
| G1-10 | Callback handling | ADAPT |
| G1-11 | RLS client creation | REUSE UPSTREAM + ADAPT fixed RPC façade |
| G1-12 | Grant correlation | RETAIN |
| G1-13 | Lifecycle races | RETAIN |
| G1-14 | Receipts | RETAIN |
| G1-15 | AS metadata helper | DELETE |
| G1-16 | Synthetic OAuth lab | DELETE (prod path) / ADAPT (unit double) |
| G1-17 | GoTrue session revocation probe | ADAPT |
| G1-18 | Ordinary remote fail-closed dispatch | RETAIN until ADR supersession |
| G1-19 | Host check on lab OAuth routes | RETAIN (deployment glue) |
| G1-20 | Lab opt-in conjunction | RETAIN (lab) / DELETE (if broker removed) |
| G1-21 | Fixture transport / `.invalid` coordinates | RETAIN (test infra) |

Grouped index (same 21 rows; dual rows appear in each clause they carry):

| Disposition | Rows |
| --- | --- |
| DELETE | G1-01, G1-02, G1-03 prod, G1-05, G1-08 MCP-AS refresh, G1-15, G1-16 prod, G1-20 if broker removed |
| REUSE UPSTREAM | G1-04, G1-06, G1-08 Auth refresh, G1-09 core verify, G1-11 user-scoped client |
| ADAPT | G1-03 lab fake, G1-04 path glue, G1-07, G1-09 resource-binding extras, G1-10, G1-11 fixed RPC façade, G1-16 unit double, G1-17 |
| RETAIN | G1-12, G1-13, G1-14, G1-18, G1-19, G1-20 while a lab broker exists, G1-21 |

## G5 constraints that bind the marks

Quoted decision at `95ae3a46` (do not re-litigate it here):

> **NO.** Token B must be a **second Supabase OAuth grant / OAuth client** used for upstream Data API (and related Supabase API) calls. Still **no custom MCP issuer** required by this G5 finding alone. Stock single-grant `withOAuthProtectedResource` + `withSupabase({ auth: 'user' })` is **not** conformant without that second grant.

Violated MUST, as G5 cites MCP 2026-07-28:

> The MCP server MUST NOT pass through the token it received from the MCP client.

Names used below:

| Name | Meaning in G5 / G1 |
| --- | --- |
| Token A | The bearer the MCP client presents to the MCP resource. |
| Token B | A distinct access token from a second Supabase OAuth grant / OAuth client, used on upstream Supabase APIs including `/rest/v1`. |
| Project Auth issuer | `https://<ref>.supabase.co/auth/v1` (cloud shape in the G1 packet). |
| Project JWKS | `https://<ref>.supabase.co/auth/v1/.well-known/jwks.json`. |

Official `withSupabase({ auth: 'user' })` on `@supabase/server@1.7.0`, as G5 read it, attaches the **inbound** Bearer to the user-scoped client. Reuse of that helper is a pass on a REUSE row only when the bearer it sends to `/rest/v1` is Token B. Wiring it to Token A is a hard FAIL (H2), not evidence that “upstream was reused.”

G5’s secondary note (stock `aud: "authenticated"`, Auth issue #2610 / RFC 8707) is **not** a separate hard gate. It is judged inside G1-09. This checklist does not claim Auth has shipped resource-indicator audience binding.

---

## Hard FAIL gates

Leave every box unchecked in this draft. A later verifier checks a box only when that gate is `PASS` on the pinned G2 head. Any `FAIL` fails the packet. `BLOCKED` is not a pass.

- [ ] **H1 — Homemade issuer absent on ordinary remote.** No `Iss_M`. No in-process or loopback authorization server is the production issuer. Discovery for ordinary remote names the project Auth issuer. `createAuthorizationServerMetadata` local `/oauth/*` fiction is not wired into ordinary remote.
- [ ] **H2 — No inbound MCP bearer on `/rest/v1`.** Bytes of Token A are not copied into `Authorization` (or an equivalent credential header) on Data API `/rest/v1` calls. Zero such forwards, including through `withSupabase({ auth: 'user' })` or `createFixedSupabaseClient` when those helpers are fed the MCP client bearer.
- [ ] **H3 — Token A ≠ Token B (second OAuth grant).** Upstream Data API calls that carry a user access token use Token B from a second Supabase OAuth grant / OAuth client (or a documented Auth-supported exchange that yields a **distinct** upstream access token). G5 does not allow a custom MCP issuer as that mechanism. Same-string Token A and Token B is FAIL.
- [ ] **H4 — Ordinary path fail-closed without Token B.** A valid MCP bearer with no resolved downstream credential does not call `/rest/v1`. G1’s ordinary-path result remains the bar: `403` with `downstream_credential_unresolved` and zero Data API calls, unless an ADR supersession named by G1-18 is actually present on the G2 head.
- [ ] **H5 — Project Auth issuer / JWKS for MCP-facing verify.** Ordinary remote verifies MCP-facing access tokens with the project Auth issuer and project JWKS (asymmetric ES256/RS256). No process-ephemeral private JWK mints those tokens. No loopback homemade JWKS is the production verification key set.

| Gate | Mark (`PASS` / `FAIL` / `BLOCKED`) | Evidence (path, test, or command pinned to the G2 head SHA) |
| --- | --- | --- |
| H1 | | |
| H2 | | |
| H3 | | |
| H4 | | |
| H5 | | |

H1 and H2 are the two gates the G2 tasking named for Central. H3, H4, and H5 are the same boundary as G5 = NO plus the G1 DELETE rows for issuer, ephemeral signing key, and homemade JWKS, and the G1 RETAIN row for ordinary fail-closed dispatch. One FAIL among H1–H5 fails acceptance.

---

## Matrix rows

For each row, “G1 test needed” is the test cell of that matrix row at `95ae3a46`. The acceptance line is that cell, plus the G5 binding where the row touches Token A / Token B. Silent deletion of a RETAIN gap is FAIL. Lab-only leftovers are allowed only on the ADAPT / RETAIN-lab clause, and they must be unreachable on ordinary remote.

### DELETE

#### G1-01 — Issuer (MCP-facing custom `Iss_M`, loopback AS)

| Field | Value |
| --- | --- |
| Disposition | DELETE |
| G1 test needed | Discovery URL equals project issuer; no listener serves homemade AS metadata as production issuer; regression that `createAuthorizationServerMetadata(local)` is not wired into ordinary remote. |
| Acceptance | On ordinary remote, MCP discovery advertises project Auth (`https://<ref>.supabase.co/auth/v1` and the Auth discovery document), not a second homemade AS. No listener on that path serves `LabDualGrantBroker` / `Iss_M` authorize, token, JWKS, or revoke as the issuer. Hard-fail link: H1. |
| Mark | |
| Evidence | |

#### G1-02 — Signing key (process-ephemeral ES256 for MCP JWTs)

| Field | Value |
| --- | --- |
| Disposition | DELETE |
| G1 test needed | No process-local private JWK used to mint MCP access tokens on the finish path; tokens verify only via project JWKS. |
| Acceptance | Ordinary remote does not mint MCP access tokens with a process-ephemeral keypair (`mcpSigningAlg: 'ES256'` or any successor in-process private JWK). Verification key material is project JWKS. Hard-fail link: H5. |
| Mark | |
| Evidence | |

#### G1-03 — JWKS (`GET /.well-known/jwks.json` on lab issuer)

| Field | Value |
| --- | --- |
| Disposition | DELETE (prod) / ADAPT (lab fake only) |
| G1 test needed | Prod profile never binds `signingKey.kind:'jwks'` to loopback homemade JWKS; live verify uses project JWKS URL. |
| Acceptance | **Prod / ordinary:** production verification does not use broker `handleJwks` or any MCP-process JWKS as the issuer key set. **Lab fake:** a scripted JWKS may exist only inside a unit double (`SyntheticOAuthLab` or a successor test double). That double is not mounted on ordinary `start:remote`. If no lab double remains, the lab clause is N/A only with evidence the prod clause passes and no homemade JWKS is served. |
| Mark | |
| Evidence | |

#### G1-05 — Authorize / token / revoke (MCP-facing homemade routes)

| Field | Value |
| --- | --- |
| Disposition | DELETE |
| G1 test needed | Ordinary remote does not register `/oauth/authorize`, `/oauth/token`, or `/oauth/revoke` handlers; clients hit project Auth URLs from discovery. |
| Acceptance | Ordinary remote has no homemade `GET`/`POST` authorize, token, or revoke routes. Client authorization-code, refresh, and grant revoke go to project Auth (`…/auth/v1/oauth/authorize`, `…/auth/v1/oauth/token`, Auth/user grants revoke). A lab-only MCP-token revoke clock is not a hosted surface on ordinary remote. |
| Mark | |
| Evidence | |

#### G1-08 (DELETE clause) — MCP-AS refresh

DELETE clause of the same matrix row as G1-08 under REUSE. Do not mark it separately. Both clauses must pass before that row is `PASS`.

Ordinary remote does not issue MCP refresh tokens and does not serve a homemade refresh endpoint. A `token_type_hint=refresh_token` handler on a homemade MCP authorization server is not a product surface.

#### G1-15 — AS metadata helper (`authorization-server-metadata.ts`)

| Field | Value |
| --- | --- |
| Disposition | DELETE |
| G1 test needed | Metadata issuer/endpoints match project Auth; no local helper advertised on ordinary remote. |
| Acceptance | Ordinary remote does not advertise `createAuthorizationServerMetadata` local `/oauth/*` + JWKS. Issuer and endpoints in advertised metadata match project Auth discovery (`/.well-known/oauth-authorization-server/auth/v1` and the OIDC configuration on the project). Overlaps H1; both must pass. |
| Mark | |
| Evidence | |

#### G1-16 (prod clause) — Synthetic OAuth lab as issuer

DELETE clause of the same matrix row as G1-16 under ADAPT. Do not mark it separately.

`synthetic-oauth-lab.ts` (HS256 HMAC fake AS) is not the issuer on any live or ordinary remote path. Live verification and live token issuance use project Auth / GoTrue, not the synthetic lab.

#### G1-20 (DELETE clause) — Lab opt-in when the broker is removed

DELETE clause of the same matrix row as G1-20 under RETAIN. Do not mark it separately.

If the G2 head deletes the lab broker, `SUPABASE_USER_MCP_LAB_DUAL_GRANT` and the lab hook do not register authorize, token, revoke, JWKS, or callback routes. Leaving the conjunction able to open those routes is FAIL. If the broker is still present, this clause is N/A and the RETAIN clause is the one that must pass.

### REUSE UPSTREAM

#### G1-04 — Protected-resource metadata (RFC 9728)

| Field | Value |
| --- | --- |
| Disposition | REUSE UPSTREAM + ADAPT path glue |
| G1 test needed | `GET {resource}/oauth-protected-resource` advertises project AS; 401 carries `resource_metadata=`; composition order places PR middleware **outside** the auth gate. |
| Acceptance | **REUSE:** protected-resource metadata and `WWW-Authenticate` enrichment come from `@supabase/server` `withOAuthProtectedResource` / `resourceMetadataResponse` (≥1.6.0; G1 cited docs at 1.7.0), not a reimplementation of RFC 9728. **ADAPT (only this glue):** non-Edge Node may set `resourceServer` / `authorizationServer` (`fromSupabaseUrl`) so the resource is the MCP endpoint and the authorization server is project Auth. Advertising a homemade issuer is FAIL (H1). `oauthMetadataResponse` from `@modelcontextprotocol/server` may remain only if it is no longer the ordinary-remote PRM implementation; if it is still the production PRM path, that is FAIL against REUSE. |
| Mark | |
| Evidence | |

#### G1-06 — DCR (dynamic client registration)

| Field | Value |
| --- | --- |
| Disposition | REUSE UPSTREAM (policy-gated) |
| G1 test needed | With DCR off: unknown client rejected. With DCR on: registration + consent + token round-trip; redirect URI exact-match enforced by GoTrue. |
| Acceptance | DCR is the project Auth facility (`allow_dynamic_registration` / Auth registration endpoint), not a new registrar inside the MCP process. The verifier records which policy the G2 head ships. **Off:** unknown client rejected, evidenced on that head. **On:** registration, consent, and token round-trip, with GoTrue exact redirect match. The mode not shipped must be stated as policy; leaving both modes untested is BLOCKED, not PASS. ADR-0006’s historical “no DCR” line applied to the homemade broker, not to project Auth, per G1. |
| Mark | |
| Evidence | |

#### G1-08 — Refresh (Data API / user session)

| Field | Value |
| --- | --- |
| Disposition | REUSE UPSTREAM (Data API / user session) + DELETE (MCP-AS refresh, scored above) |
| G1 test needed | Refresh rotation + reuse detection against GoTrue; revoked refresh denies the next Data API call; no homemade MCP refresh endpoint in prod. |
| Acceptance | Refresh custody for the upstream user session is Supabase Auth / the client SDK (`grant_type=refresh_token` on project `…/oauth/token`, with rotation). Revoked refresh denies the next Data API call. The DELETE clause (no homemade MCP refresh) must also pass. If the process still holds an upstream refresh token in memory, single-flight behavior is scored under G1-13, not reimplemented as a second AS. |
| Mark | |
| Evidence | |

#### G1-09 — Token verification

| Field | Value |
| --- | --- |
| Disposition | REUSE UPSTREAM + ADAPT resource-binding extras |
| G1 test needed | Valid user JWT passes; HS256 rejected when the project is asymmetric; wrong `iss` / `aud` / `client_id` → 401; latency-bound revoke still enforced if retained. |
| Acceptance | **REUSE:** signature, issuer, expiry, and role checks use `@supabase/server` `withSupabase({ auth: 'user' })` and/or `withRequiredClaims` against project JWKS. **ADAPT (only if still required):** extra MCP resource audience / `client_id` binding beyond `aud=authenticated` (ADR-0005 / `REMOTE_IDENTITY_CLAIM_POLICY`) may stay as thin glue. Record which choice the head made. Treating stock `aud: "authenticated"` single-grant passthrough as already conformant is FAIL (G5 NO). Dropping the latency-bound revoke clause while G1-17 is still required is FAIL. Hard-fail links: H2 (the verified Token A is not what `/rest/v1` receives), H5. |
| Mark | |
| Evidence | |

#### G1-11 — RLS client creation

| Field | Value |
| --- | --- |
| Disposition | REUSE UPSTREAM + ADAPT fixed RPC façade. One mark for the whole row. |
| G1 test needed | `memory_*` under RLS as `auth.uid()`; cross-principal denial; zero inbound-MCP-bearer forwarding; loopback http allow only under lab flag. |
| Acceptance | **REUSE:** RLS uses an upstream user-scoped Supabase client (`ctx.supabase` from `withSupabase({ auth: 'user' })` or the same facility). The credential on `/rest/v1` is Token B, not Token A. Passing the inbound MCP bearer into that helper is H2 FAIL. **ADAPT:** `createFixedSupabaseClient` may remain only as a narrow allowlisted RPC façade (fixed paths, byte caps, schema profile), fed by Token B, not as a second auth stack. Cross-principal calls are denied. Loopback HTTP is allowed only under an explicit lab flag. |
| Mark | |
| Evidence | |

### ADAPT

Thin glue only. A local reimplementation of the upstream facility named on the row is FAIL (that facility was REUSE or DELETE).

#### G1-03 (lab clause) — Scripted JWKS unit double

Scored with G1-03 above. Pass the lab clause only when the scripted JWKS cannot be reached on ordinary remote.

#### G1-04 (path glue clause) — Non-Edge resource / AS pointers

Scored with G1-04 above. Allowed glue is `resourceServer` / `authorizationServer` (`fromSupabaseUrl`) only.

#### G1-07 — Consent

| Field | Value |
| --- | --- |
| Disposition | ADAPT |
| G1 test needed | Consent approve/deny redirects with code; deny → `access_denied`; replayed decision rejected; no tool call authorized by login cookie alone. |
| Acceptance | Consent uses Auth-backed APIs (`getAuthorizationDetails`, `approveAuthorization`, `denyAuthorization`) on the Household/app site, not broker-rendered HTML on the MCP process (`lab_login_session` plus an in-process approve-or-deny decision is not the ordinary path). Approve redirects with a code; deny returns `access_denied`; a replayed decision is rejected. A browser login cookie alone does not authorize a tool call. |
| Mark | |
| Evidence | |

#### G1-09 (extras clause) — Resource-binding beyond stock `aud`

Scored with G1-09 above. Allowed glue is the extra audience / `client_id` check G1 names, not a second verifier stack and not a homemade issuer.

#### G1-10 — Callback handling

| Field | Value |
| --- | --- |
| Disposition | ADAPT |
| G1 test needed | Exact redirect match; wildcard, userinfo, query, and fragment rejected; wrong host/port denied; lab callback not exposed on ordinary `start:remote`. |
| Acceptance | Production redirect URIs are the MCP client’s registered URIs and the app consent return path. `/lab/oauth/callback` on the broker is not exposed on ordinary `start:remote`. Exact match only. Lab harness redirects may exist for disposable GoTrue tests and must stay off ordinary remote. |
| Mark | |
| Evidence | |

#### G1-11 (façade clause)

Scored only on the G1-11 mark above. Allowed glue is the narrow allowlisted RPC façade fed by Token B. Forwarding Token A through that façade is H2 FAIL.

#### G1-16 (unit clause) — Synthetic OAuth lab as a unit double

| Field | Value |
| --- | --- |
| Disposition | ADAPT (unit double) / DELETE (prod). One mark for the whole row. The prod clause is stated above and must pass with this mark. |
| G1 test needed | `npm test` unit suite does not require a homemade production AS; live path uses GoTrue. |
| Acceptance | The HS256 synthetic lab may remain as a unit fake for verifier/policy tests, or be replaced by local GoTrue. The unit suite must not need a homemade production AS. The double is not mounted on ordinary remote (prod clause). |
| Mark | |
| Evidence | |

#### G1-17 — GoTrue session revocation probe

| Field | Value |
| --- | --- |
| Disposition | ADAPT |
| G1 test needed | Revoke session → next call denied inside 5s; probe timeout fail-closed; no cache. |
| Acceptance | Signature verify stays on the project JWKS path (G1-09 / H5). Adapt `createGoTrueSessionRevocationAuthority` (`GET /auth/v1/user`, 5s bound) only if finish still requires revocation-before-`exp` tighter than JWT validity (`ACCESS_TOKEN_REVOCATION_POLICY`). If retained: revoke session → next call denied inside 5s; probe timeout fail-closed; no cache. If dropped: the head records that this policy no longer requires the probe. Dropping it with no record is FAIL. The probe does not replace project JWKS. |
| Mark | |
| Evidence | |

### RETAIN

Each row names an upstream gap in G1. The gap stays fail-closed, tested, and documented. Removing the behavior without the ADR or documentation G1 requires is FAIL, not a cleanup.

#### G1-12 — Grant correlation (MCP subject/client ↔ upstream subject/client)

| Field | Value |
| --- | --- |
| Disposition | RETAIN |
| Upstream gap (G1) | No dual-grant correlation API. Single-credential docs conflict with MCP 2026-07-28 and ADR-0005/0006. |
| G1 test needed | Mapping rejects `user_metadata` authority; a second upstream grant for the same principal+client → `grant_family_conflict`; cross-principal dispatch denied. |
| Acceptance | Token A and Token B stay correlated without trusting `user_metadata` as authority. A second upstream grant for the same principal and client fails closed with `grant_family_conflict`. Cross-principal dispatch is denied. Collapsing to one Supabase access token for both the MCP gate and the Data API flips this row to DELETE **only after** an ADR supersession on the G2 head. Doing that collapse without the ADR is FAIL. Two tokens and no correlation is FAIL. |
| Mark | |
| Evidence | |

#### G1-13 — Lifecycle races (epoch, single-flight refresh, local TTL, cleanup)

| Field | Value |
| --- | --- |
| Disposition | RETAIN |
| Upstream gap (G1) | GoTrue manages one grant lifecycle. It does not coordinate MCP-process custody, in-flight code exchange versus cleanup, or `LOCAL_DISPATCH_TTL_MS` (15m) orthogonal to access-token `exp`. |
| G1 test needed | Cleanup during exchange/sign/refresh does not revive tokens; concurrent refresh → 403; local deadline stops `/rest/v1` after TTL; disconnect cancels the request only. |
| Acceptance | Whatever still holds upstream refresh material or bridges Token A and Token B keeps race closures: no revival after cleanup, single-flight refresh (concurrent refresh denied), local dispatch deadline stops `/rest/v1` after the documented TTL, disconnect cancels the request only. Deleting epoch / single-flight / local TTL behavior without tests that show the thinner path still fails closed is FAIL. |
| Mark | |
| Evidence | |

#### G1-14 — Receipts (`LabDualGrantReceipt` / M4 harness)

| Field | Value |
| --- | --- |
| Disposition | RETAIN |
| Upstream gap (G1) | No receipt schema for lab dual-grant / remote-oauth evidence. |
| G1 test needed | Receipt pins head SHA, client name/version, custody flags, opt-in default false; live harness absence ≠ synthetic pass. |
| Acceptance | Finish evidence is still an auditable receipt independent of hosted dashboards. The receipt pins the head SHA under test, client name/version, custody flags, and opt-in default false. A missing live harness is not recorded as a synthetic pass. G1’s N2 caveat (literal `pass` constants in the #79 receipt schema) stays in force until a head actually changes that schema and says so; a literal `pass` constant is not live evidence. This row does not ask for a new M4 live run. |
| Mark | |
| Evidence | |

#### G1-18 — Ordinary remote fail-closed dispatch (`downstream_credential_unresolved`)

| Field | Value |
| --- | --- |
| Disposition | RETAIN until ADR supersession |
| Upstream gap (G1) | Official MCP guide still documents using the Supabase user access token at the Data API. Repo policy (ADR-0005/0006, MCP 2026-07-28) forbids forwarding the inbound MCP bearer. Native exchange was still unsupported per `DOWNSTREAM_CREDENTIAL_RECHECK_2026_09_22`. |
| G1 test needed | Valid MCP bearer without a resolved downstream credential → 403; zero Data API calls; B/C binding failure → 401 before 403. |
| Acceptance | Without Token B, ordinary remote stays fail-closed: `403` `downstream_credential_unresolved`, zero `/rest/v1`. Binding failures (G1’s B/C cases) return 401 before that 403. Copying upstream passthrough prose into the ordinary path is H2 FAIL and this row FAIL. Leaving fail-closed is allowed. Opening the Data API is allowed only with Token B as in H3, or with an ADR on this head that supersedes the fail-closed decision the way G1 states (Option 1 proven, Option 2 under a new ADR, or an explicit privilege-model change). No such ADR is created by this checklist. Hard-fail link: H4. |
| Mark | |
| Evidence | |

#### G1-19 — Host check on lab OAuth routes

| Field | Value |
| --- | --- |
| Disposition | RETAIN (deployment glue) |
| Upstream gap (G1) | Edge gateway host derivation is not the Node `Host` binding rule. #79 (Warden MC1394) placed lab OAuth routes after `hostMatchesResource`. |
| G1 test needed | Authorize, token, revoke, JWKS, and callback rejected on the wrong Host; discovery policy documented separately. |
| Acceptance | Non-Edge finish deployments still align `Host` with the resource. Wrong Host is rejected. If homemade authorize/token/revoke/JWKS/callback routes are deleted, those route clauses are N/A only with evidence the routes are unregistered (G1-05, G1-03, G1-10) **and** the remaining Node finish surface still enforces Host/resource alignment. Removing `hostMatchesResource` (or its successor) while those routes still exist, or dropping Host alignment with no documented replacement, is FAIL. |
| Mark | |
| Evidence | |

#### G1-20 — Lab opt-in conjunction (`LAB_DUAL_GRANT` env ∧ hook)

| Field | Value |
| --- | --- |
| Disposition | RETAIN (lab) while the broker exists. DELETE clause is scored above if the broker is removed. |
| G1 test needed | Env alone or hook alone → fail-closed; both → lab routes only. |
| Acceptance | While a lab broker remains: `SUPABASE_USER_MCP_LAB_DUAL_GRANT=1` without the hook, and the hook without the env, stay fail-closed. Both together enable lab routes only, not ordinary `start:remote`. Ordinary remote still omits the hook. If the broker is removed, score the DELETE clause instead and do not leave a live conjunction. |
| Mark | |
| Evidence | |

#### G1-21 — Fixture transport / `.invalid` coordinates

| Field | Value |
| --- | --- |
| Disposition | RETAIN (test infra) |
| Upstream gap (G1) | None (test-only). Named so it is not dropped. |
| G1 test needed | Caller fetch on `.invalid` rejected; scripted responder only when the literal set is selected. |
| Acceptance | Contract fixtures do not become network targets. Caller fetch on `.invalid` is rejected. A scripted responder runs only when the literal scripted set is selected (`fixtureTransport: 'broker-scripted'`). Removing that isolation, or allowing a caller fetch to `.invalid`, is FAIL. |
| Mark | |
| Evidence | |

---

## Explicit non-claims

- Not a merge of #79, #97, or any G2 pull request.
- Not an instruction to the G2 agent `bc-ede9c9e7-f9b9-5441-8a5f-b217b216b4cf`, and not a substitute for that run.
- Not M4 live expansion, not a live loopback receipt, and not a claim that a receipt with literal `pass` constants is a live pass.
- Not Pages, DNS, or external-client B–D unblocking.
- Not a Primary Users ping, and not an approval by Primary Users, Warden, or Atlas.
- Not an ADR supersession, not Option 2 approval, and not a statement that RFC 8707 or RFC 8693 has shipped.
- Not deletion of #79 surfaces in git. DELETE rows are acceptance checks for the G2 finish path when that draft exists.
- The author of this checklist is not the independent verifier. Empty marks are intentional.

## Verification

A later verifier fills marks. This packet does not.

### Pin the G2 head before any mark

1. Confirm a G2 **draft** pull request exists and was not merged by this checklist.
2. Record its URL and **full** head SHA (40 hex characters) in the log below. A branch name without a SHA is not a pin.
3. `git fetch` that SHA. Read the tree at that SHA. Marks against #75 (`fcbaca12`), #79 (`80ea3ead`), #97 (`95ae3a46`), `main`, or this checklist’s own head are invalid.
4. If no G2 draft PR exists yet, set every hard gate and every matrix row to `BLOCKED`, packet result `BLOCKED`, and stop.

### How to mark each gate

| Mark | When |
| --- | --- |
| `PASS` | The pinned G2 head shows the check. Cite a path on that SHA and, where the row names a test, the command and result run on that SHA. |
| `FAIL` | The pinned head shows the forbidden surface on ordinary remote, shows Token A on `/rest/v1`, shows a homemade production issuer or ephemeral MCP signing key, or drops a RETAIN gap without the ADR/documentation that row requires. |
| `BLOCKED` | The SHA cannot be fetched, the check needs a live project / GoTrue / DCR setting the verifier does not have, or the named test is not on that SHA and no other evidence from that SHA is attached. Say what is missing. |

Rules:

- Each of G1-01 through G1-21 has one Mark cell. Headings that say “do not mark it separately” or “scored with” belong to that row. The row is `PASS` only when every clause on it passes.
- Do not upgrade `BLOCKED` to `PASS`.
- N/A is allowed only inside a dual-disposition row, for the clause whose precondition is absent, and only with evidence of that precondition on the pinned SHA. The row mark still follows the clauses that remain.
- Packet result is `FAIL` if any of H1–H5 or G1-01–G1-21 is `FAIL`. Otherwise `BLOCKED` if any of those is `BLOCKED` or still empty. Otherwise `PASS`.
- Ordinary remote means `start:remote` without the lab hook, as G1 defined it. A passing lab-only test does not pass a DELETE prod clause.
- H2/H3 evidence must show the `Authorization` value on `/rest/v1` (or a test double that records that header) and show it is not the inbound MCP bearer. “Uses `@supabase/server`” without that comparison is not H2 PASS.
- Verifier identity is recorded and is not the author of this file and not the G2 implementer.

### Verifier log (fill on the G2 head, not in this draft)

| Field | Value |
| --- | --- |
| G2 draft PR URL | |
| G2 head SHA (full, 40 hex) | |
| G2 base expected | #75 @ `fcbaca121d0717ee8ff98df90b2f12475b05bb78` (record the base the PR actually uses if it differs; a different base does not by itself pass or fail, but it is not silent) |
| G1/G5 head this list was written against | `95ae3a46710134d5a46a57e17fe4a38224c89467` |
| Verifier (not this author, not the G2 implementer) | |
| Date | |
| H1–H5 result | |
| G1-01–G1-21 result | |
| Packet result | `PASS` / `FAIL` / `BLOCKED` |

Suggested read order on the pinned SHA: ordinary remote entry and discovery metadata (H1, H5, G1-01, G1-04, G1-15), token mint/verify (G1-02, G1-03, G1-09), outbound `/rest/v1` header versus inbound bearer (H2, H3, G1-11, G1-18), Auth refresh and DCR policy (G1-06, G1-08), consent and redirects (G1-07, G1-10), then RETAIN gaps (G1-12, G1-13, G1-14, G1-17, G1-19, G1-20, G1-21).
