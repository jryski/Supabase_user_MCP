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
| G2 draft under test | https://github.com/jryski/Supabase_user_MCP/pull/98 (draft, still open) |
| G2 branch | `cursor/supabase-native-user-mcp-g2` |
| G2 base | `ariadne/remote-oauth-rebased-20260919` @ `fcbaca121d0717ee8ff98df90b2f12475b05bb78` (same commit as #75) |
| G2 head read for examples | `67cf73df5390c89697a40295b4cddecbf811881d` — **PRELIMINARY, not final**. The G2 agent is still running. |
| G2 agent already running | `bc-ede9c9e7-f9b9-5441-8a5f-b217b216b4cf` (this checklist does not start another G2) |
| #79 | **HOLD** — research history only. https://github.com/jryski/Supabase_user_MCP/pull/79 head researched by G1: `80ea3ead7e7daff04d1c86302ec5a5d6c4617d9e`. Not expanded, not reset, not merged by this packet. |
| Ordinary remote | The finish / ordinary remote path G1 describes: `start:remote` **omits** the lab dual-grant hook. On this preliminary head that path is still `packages/server/src/remote-http-cli.ts`. The new adapter is `createNativeUserMcpHandler` and is not switched on. |
| Marks in this file | H1 and H2 have a **preliminary reading** of `67cf73df` only. Formal CONTENT for every gate, including H1 and H2, waits until the G2 agent finishes and the #98 head is final. Checkboxes stay unchecked. |

This checklist judges #98 against the G1 matrix table and the G5 **NO** decision already written at `95ae3a46`. Examples below are taken from the #98 PR body, `docs/evidence/G2_NATIVE_USER_MCP.md`, and `packages/server/src/native-user-mcp.ts` at `67cf73df`. It does not add a topology, an issuer, an exchange, or a privilege exception. Formal content acceptance is not this reading.

## Preliminary head (formal CONTENT waits)

`67cf73df5390c89697a40295b4cddecbf811881d` is the current #98 head, not the head to accept. The G2 implementation agent is still running on `cursor/supabase-native-user-mcp-g2`. Do not treat a preliminary reading as `PASS`. When that agent stops, replace the SHA in the verifier log with the final full head and mark every gate again from that tree. Until then the packet result is **CONTENT wait**.

What that head actually contains, used only as examples:

- Adapter pin in `native-user-mcp.ts`: `@supabase/server` `1.7.2`, peer `@supabase/supabase-js` `2.117.2`. Nested form only (`withOAuthProtectedResource` around `withSupabase`). The alpha `pipeline` entry form is not used.
- Token A is the inbound `Authorization: Bearer` JWT. `fromSupabaseUrl` sets the issuer to `{supabaseUrl}/auth/v1`. The handler then requires `role=authenticated`, `aud` containing both `authenticated` and the MCP resource, a server-controlled `client_id`, UUID `sub` and `session_id`, and rejects `user_metadata` used as authority.
- Token B is the constant `unresolved`. A verified Token A returns `403` with `{ "error": "downstream_credential_unresolved" }`. No second Data API client is created.
- `blockedDataApiFetch` is installed as `supabaseOptions.global.fetch` and throws `downstream_credential_unresolved` if called. `NATIVE_USER_MCP_CREDENTIAL_SPLIT.sameBearerPassthrough` is `false`.
- The library still constructs an unused same-bearer user client and an unused admin client before the handler. The admin client uses the placeholder `g2-unused-admin-client-not-a-credential`, not `SUPABASE_SECRET_KEY`. The adapter does not call either client.
- No `Iss_M` and no `LabDualGrantBroker` anywhere in this tree. The new file does not register authorize, token, or revoke routes.
- The existing remote profile is not switched over. `remote-http-cli.ts` still passes `createAuthorizationServerMetadata(issuer)` into that profile. `authorization-server-metadata.ts` still hard-codes local `/oauth/authorize`, `/oauth/token`, `/oauth/revoke`, and a local JWKS URI.

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

Leave every box unchecked. A check is a formal `PASS` and is not allowed while #98’s head is preliminary. H1 and H2 are filled below as a reading of `67cf73df` only. H3, H4, and H5 stay **CONTENT wait**. Any later `FAIL` fails the packet. `BLOCKED` and **CONTENT wait** are not passes.

- [ ] **H1 — Homemade issuer absent on ordinary remote.** No `Iss_M`. No in-process or loopback authorization server is the production issuer. Discovery for ordinary remote names the project Auth issuer. `createAuthorizationServerMetadata` local `/oauth/*` fiction is not wired into ordinary remote.
- [ ] **H2 — No inbound MCP bearer on `/rest/v1`.** Bytes of Token A are not copied into `Authorization` (or an equivalent credential header) on Data API `/rest/v1` calls. Zero such forwards, including through `withSupabase({ auth: 'user' })` or `createFixedSupabaseClient` when those helpers are fed the MCP client bearer.
- [ ] **H3 — Token A ≠ Token B (second OAuth grant).** Upstream Data API calls that carry a user access token use Token B from a second Supabase OAuth grant / OAuth client (or a documented Auth-supported exchange that yields a **distinct** upstream access token). G5 does not allow a custom MCP issuer as that mechanism. Same-string Token A and Token B is FAIL.
- [ ] **H4 — Ordinary path fail-closed without Token B.** A valid MCP bearer with no resolved downstream credential does not call `/rest/v1`. G1’s ordinary-path result remains the bar: `403` with `downstream_credential_unresolved` and zero Data API calls, unless an ADR supersession named by G1-18 is actually present on the G2 head.
- [ ] **H5 — Project Auth issuer / JWKS for MCP-facing verify.** Ordinary remote verifies MCP-facing access tokens with the project Auth issuer and project JWKS (asymmetric ES256/RS256). No process-ephemeral private JWK mints those tokens. No loopback homemade JWKS is the production verification key set.

| Gate | Preliminary reading at `67cf73df` | Formal mark |
| --- | --- | --- |
| H1 | No homemade issuer on the new adapter. `createNativeUserMcpHandler` sets `authorizationServer` to `fromSupabaseUrl(...)` (`{supabaseUrl}/auth/v1`). This tree has no `Iss_M` and no `LabDualGrantBroker`. The new file does not serve authorize, token, revoke, or a process JWKS. Not closed for ordinary remote: `remote-http-cli.ts` still calls `createAuthorizationServerMetadata(issuer)`, and that helper still points at local `/oauth/authorize`, `/oauth/token`, `/oauth/revoke`, and a local JWKS URI. #98 says that existing profile is not switched over. | CONTENT wait |
| H2 | No inbound-token passthrough on the new adapter. Verified Token A hits `respondAfterVerifiedMcpAuth`, which returns `403` `downstream_credential_unresolved` and does not call `/rest/v1`. `blockedDataApiFetch` throws that same error if the library client is invoked. `sameBearerPassthrough` is `false`. Test `verifies Token A then fail-closes without a Data API call` in `native-user-mcp.test.ts` expects `globalThis.fetch` calls to be empty and the response body not to contain the bearer. Not closed as a design: `@supabase/server` still builds an unused same-bearer user client before the handler. The evidence file says not to point Data API calls at that client. | CONTENT wait |
| H3 | Token B is the constant `unresolved`. No second Supabase OAuth grant is implemented on this head. Fail-closed is not a second grant. | CONTENT wait |
| H4 | The new adapter’s verified-Token-A path matches the fail-closed shape (`403`, `downstream_credential_unresolved`, zero fetch in the test above). Not marked: the head is preliminary, and this adapter is not `start:remote`. | CONTENT wait |
| H5 | The new adapter verifies with the caller-supplied asymmetric JWKS or JWKS URL and `issuer` from `fromSupabaseUrl`. `assertJwks` rejects `kty: 'oct'` and `HS256` / `HS384` / `HS512`. It does not mint a process-ephemeral MCP private key. Not marked: ordinary remote still has the local metadata helper’s JWKS URI, and live revocation is explicitly not implemented. | CONTENT wait |

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
| Example at `67cf73df` (not a mark) | New adapter: `authorizationServer: resolved.issuer` with `issuer = fromSupabaseUrl(...)`. No `Iss_M` in the tree. Inherited `remote-http-cli.ts` still installs `createAuthorizationServerMetadata`. See H1. |
| Mark | CONTENT wait |
| Evidence | |

#### G1-02 — Signing key (process-ephemeral ES256 for MCP JWTs)

| Field | Value |
| --- | --- |
| Disposition | DELETE |
| G1 test needed | No process-local private JWK used to mint MCP access tokens on the finish path; tokens verify only via project JWKS. |
| Acceptance | Ordinary remote does not mint MCP access tokens with a process-ephemeral keypair (`mcpSigningAlg: 'ES256'` or any successor in-process private JWK). Verification key material is project JWKS. Hard-fail link: H5. |
| Mark | CONTENT wait |
| Evidence | |

#### G1-03 — JWKS (`GET /.well-known/jwks.json` on lab issuer)

| Field | Value |
| --- | --- |
| Disposition | DELETE (prod) / ADAPT (lab fake only) |
| G1 test needed | Prod profile never binds `signingKey.kind:'jwks'` to loopback homemade JWKS; live verify uses project JWKS URL. |
| Acceptance | **Prod / ordinary:** production verification does not use broker `handleJwks` or any MCP-process JWKS as the issuer key set. **Lab fake:** a scripted JWKS may exist only inside a unit double (`SyntheticOAuthLab` or a successor test double). That double is not mounted on ordinary `start:remote`. If no lab double remains, the lab clause is N/A only with evidence the prod clause passes and no homemade JWKS is served. |
| Mark | CONTENT wait |
| Evidence | |

#### G1-05 — Authorize / token / revoke (MCP-facing homemade routes)

| Field | Value |
| --- | --- |
| Disposition | DELETE |
| G1 test needed | Ordinary remote does not register `/oauth/authorize`, `/oauth/token`, or `/oauth/revoke` handlers; clients hit project Auth URLs from discovery. |
| Acceptance | Ordinary remote has no homemade `GET`/`POST` authorize, token, or revoke routes. Client authorization-code, refresh, and grant revoke go to project Auth (`…/auth/v1/oauth/authorize`, `…/auth/v1/oauth/token`, Auth/user grants revoke). A lab-only MCP-token revoke clock is not a hosted surface on ordinary remote. |
| Mark | CONTENT wait |
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
| Example at `67cf73df` (not a mark) | The new adapter does not call `createAuthorizationServerMetadata`. The inherited helper and `remote-http-cli.ts` still do. Same open item as H1. |
| Mark | CONTENT wait |
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
| Example at `67cf73df` (not a mark) | Nested `withOAuthProtectedResource({ resourceServer, authorizationServer: fromSupabaseUrl(supabaseUrl) }, withSupabase({ auth: 'user', audience, issuer, env }, handler))` at pin `1.7.2`. The alpha `pipeline` form is not used. The metadata test expects `authorization_servers: [ISSUER]` and a `401` `WWW-Authenticate` containing `resource_metadata`. |
| Mark | CONTENT wait |
| Evidence | |

#### G1-06 — DCR (dynamic client registration)

| Field | Value |
| --- | --- |
| Disposition | REUSE UPSTREAM (policy-gated) |
| G1 test needed | With DCR off: unknown client rejected. With DCR on: registration + consent + token round-trip; redirect URI exact-match enforced by GoTrue. |
| Acceptance | DCR is the project Auth facility (`allow_dynamic_registration` / Auth registration endpoint), not a new registrar inside the MCP process. The verifier records which policy the G2 head ships. **Off:** unknown client rejected, evidenced on that head. **On:** registration, consent, and token round-trip, with GoTrue exact redirect match. The mode not shipped must be stated as policy; leaving both modes untested is BLOCKED, not PASS. ADR-0006’s historical “no DCR” line applied to the homemade broker, not to project Auth, per G1. |
| Mark | CONTENT wait |
| Evidence | |

#### G1-08 — Refresh (Data API / user session)

| Field | Value |
| --- | --- |
| Disposition | REUSE UPSTREAM (Data API / user session) + DELETE (MCP-AS refresh, scored above) |
| G1 test needed | Refresh rotation + reuse detection against GoTrue; revoked refresh denies the next Data API call; no homemade MCP refresh endpoint in prod. |
| Acceptance | Refresh custody for the upstream user session is Supabase Auth / the client SDK (`grant_type=refresh_token` on project `…/oauth/token`, with rotation). Revoked refresh denies the next Data API call. The DELETE clause (no homemade MCP refresh) must also pass. If the process still holds an upstream refresh token in memory, single-flight behavior is scored under G1-13, not reimplemented as a second AS. |
| Mark | CONTENT wait |
| Evidence | |

#### G1-09 — Token verification

| Field | Value |
| --- | --- |
| Disposition | REUSE UPSTREAM + ADAPT resource-binding extras |
| G1 test needed | Valid user JWT passes; HS256 rejected when the project is asymmetric; wrong `iss` / `aud` / `client_id` → 401; latency-bound revoke still enforced if retained. |
| Acceptance | **REUSE:** signature, issuer, expiry, and role checks use `@supabase/server` `withSupabase({ auth: 'user' })` and/or `withRequiredClaims` against project JWKS. **ADAPT (only if still required):** extra MCP resource audience / `client_id` binding beyond `aud=authenticated` (ADR-0005 / `REMOTE_IDENTITY_CLAIM_POLICY`) may stay as thin glue. Record which choice the head made. Treating stock `aud: "authenticated"` single-grant passthrough as already conformant is FAIL (G5 NO). Dropping the latency-bound revoke clause while G1-17 is still required is FAIL. Hard-fail links: H2 (the verified Token A is not what `/rest/v1` receives), H5. |
| Example at `67cf73df` (not a mark) | `withSupabase({ auth: 'user', audience, issuer, env })` plus `mcpClaimsRejected`: `role=authenticated`, `aud` includes `authenticated` and the MCP resource, server-controlled `client_id`, UUID `sub` and `session_id`, `user_metadata` rejected. `assertJwks` rejects symmetric keys. The evidence file says live revocation is not performed, so an unexpired revoked JWT reaches the fail-closed `403` instead of a revocation denial. |
| Mark | CONTENT wait |
| Evidence | |

#### G1-11 — RLS client creation

| Field | Value |
| --- | --- |
| Disposition | REUSE UPSTREAM + ADAPT fixed RPC façade. One mark for the whole row. |
| G1 test needed | `memory_*` under RLS as `auth.uid()`; cross-principal denial; zero inbound-MCP-bearer forwarding; loopback http allow only under lab flag. |
| Acceptance | **REUSE:** RLS uses an upstream user-scoped Supabase client (`ctx.supabase` from `withSupabase({ auth: 'user' })` or the same facility). The credential on `/rest/v1` is Token B, not Token A. Passing the inbound MCP bearer into that helper is H2 FAIL. **ADAPT:** `createFixedSupabaseClient` may remain only as a narrow allowlisted RPC façade (fixed paths, byte caps, schema profile), fed by Token B, not as a second auth stack. Cross-principal calls are denied. Loopback HTTP is allowed only under an explicit lab flag. |
| Example at `67cf73df` (not a mark) | The adapter installs `blockedDataApiFetch` on `supabaseOptions.global.fetch` and never calls the library user client. Evidence file: do not point Data API calls at that client. Token B is `unresolved`. This is the H2 shape, not a Token B RLS client. |
| Mark | CONTENT wait |
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
| Mark | CONTENT wait |
| Evidence | |

#### G1-09 (extras clause) — Resource-binding beyond stock `aud`

Scored with G1-09 above. Allowed glue is the extra audience / `client_id` check G1 names, not a second verifier stack and not a homemade issuer.

#### G1-10 — Callback handling

| Field | Value |
| --- | --- |
| Disposition | ADAPT |
| G1 test needed | Exact redirect match; wildcard, userinfo, query, and fragment rejected; wrong host/port denied; lab callback not exposed on ordinary `start:remote`. |
| Acceptance | Production redirect URIs are the MCP client’s registered URIs and the app consent return path. `/lab/oauth/callback` on the broker is not exposed on ordinary `start:remote`. Exact match only. Lab harness redirects may exist for disposable GoTrue tests and must stay off ordinary remote. |
| Mark | CONTENT wait |
| Evidence | |

#### G1-11 (façade clause)

Scored only on the G1-11 mark above. Allowed glue is the narrow allowlisted RPC façade fed by Token B. Forwarding Token A through that façade is H2 FAIL.

#### G1-16 (unit clause) — Synthetic OAuth lab as a unit double

| Field | Value |
| --- | --- |
| Disposition | ADAPT (unit double) / DELETE (prod). One mark for the whole row. The prod clause is stated above and must pass with this mark. |
| G1 test needed | `npm test` unit suite does not require a homemade production AS; live path uses GoTrue. |
| Acceptance | The HS256 synthetic lab may remain as a unit fake for verifier/policy tests, or be replaced by local GoTrue. The unit suite must not need a homemade production AS. The double is not mounted on ordinary remote (prod clause). |
| Mark | CONTENT wait |
| Evidence | |

#### G1-17 — GoTrue session revocation probe

| Field | Value |
| --- | --- |
| Disposition | ADAPT |
| G1 test needed | Revoke session → next call denied inside 5s; probe timeout fail-closed; no cache. |
| Acceptance | Signature verify stays on the project JWKS path (G1-09 / H5). Adapt `createGoTrueSessionRevocationAuthority` (`GET /auth/v1/user`, 5s bound) only if finish still requires revocation-before-`exp` tighter than JWT validity (`ACCESS_TOKEN_REVOCATION_POLICY`). If retained: revoke session → next call denied inside 5s; probe timeout fail-closed; no cache. If dropped: the head records that this policy no longer requires the probe. Dropping it with no record is FAIL. The probe does not replace project JWKS. |
| Example at `67cf73df` (not a mark) | Evidence file, residual gaps: live access-token revocation is not performed. `NATIVE_USER_MCP_CREDENTIAL_SPLIT.liveRevocation` is `not-implemented`. The inherited remote profile still constructs `createGoTrueSessionRevocationAuthority`. |
| Mark | CONTENT wait |
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
| Mark | CONTENT wait |
| Evidence | |

#### G1-13 — Lifecycle races (epoch, single-flight refresh, local TTL, cleanup)

| Field | Value |
| --- | --- |
| Disposition | RETAIN |
| Upstream gap (G1) | GoTrue manages one grant lifecycle. It does not coordinate MCP-process custody, in-flight code exchange versus cleanup, or `LOCAL_DISPATCH_TTL_MS` (15m) orthogonal to access-token `exp`. |
| G1 test needed | Cleanup during exchange/sign/refresh does not revive tokens; concurrent refresh → 403; local deadline stops `/rest/v1` after TTL; disconnect cancels the request only. |
| Acceptance | Whatever still holds upstream refresh material or bridges Token A and Token B keeps race closures: no revival after cleanup, single-flight refresh (concurrent refresh denied), local dispatch deadline stops `/rest/v1` after the documented TTL, disconnect cancels the request only. Deleting epoch / single-flight / local TTL behavior without tests that show the thinner path still fails closed is FAIL. |
| Mark | CONTENT wait |
| Evidence | |

#### G1-14 — Receipts (`LabDualGrantReceipt` / M4 harness)

| Field | Value |
| --- | --- |
| Disposition | RETAIN |
| Upstream gap (G1) | No receipt schema for lab dual-grant / remote-oauth evidence. |
| G1 test needed | Receipt pins head SHA, client name/version, custody flags, opt-in default false; live harness absence ≠ synthetic pass. |
| Acceptance | Finish evidence is still an auditable receipt independent of hosted dashboards. The receipt pins the head SHA under test, client name/version, custody flags, and opt-in default false. A missing live harness is not recorded as a synthetic pass. G1’s N2 caveat (literal `pass` constants in the #79 receipt schema) stays in force until a head actually changes that schema and says so; a literal `pass` constant is not live evidence. This row does not ask for a new M4 live run. |
| Mark | CONTENT wait |
| Evidence | |

#### G1-18 — Ordinary remote fail-closed dispatch (`downstream_credential_unresolved`)

| Field | Value |
| --- | --- |
| Disposition | RETAIN until ADR supersession |
| Upstream gap (G1) | Official MCP guide still documents using the Supabase user access token at the Data API. Repo policy (ADR-0005/0006, MCP 2026-07-28) forbids forwarding the inbound MCP bearer. Native exchange was still unsupported per `DOWNSTREAM_CREDENTIAL_RECHECK_2026_09_22`. |
| G1 test needed | Valid MCP bearer without a resolved downstream credential → 403; zero Data API calls; B/C binding failure → 401 before 403. |
| Acceptance | Without Token B, ordinary remote stays fail-closed: `403` `downstream_credential_unresolved`, zero `/rest/v1`. Binding failures (G1’s B/C cases) return 401 before that 403. Copying upstream passthrough prose into the ordinary path is H2 FAIL and this row FAIL. Leaving fail-closed is allowed. Opening the Data API is allowed only with Token B as in H3, or with an ADR on this head that supersedes the fail-closed decision the way G1 states (Option 1 proven, Option 2 under a new ADR, or an explicit privilege-model change). No such ADR is created by this checklist. Hard-fail link: H4. |
| Example at `67cf73df` (not a mark) | `respondAfterVerifiedMcpAuth` returns `jsonResponse(403, DOWNSTREAM_CREDENTIAL_UNRESOLVED)`. The named test expects that body and an empty `globalThis.fetch` call list. `auth` failures in that test stay `401` and do not contain `downstream_credential_unresolved`. |
| Mark | CONTENT wait |
| Evidence | |

#### G1-19 — Host check on lab OAuth routes

| Field | Value |
| --- | --- |
| Disposition | RETAIN (deployment glue) |
| Upstream gap (G1) | Edge gateway host derivation is not the Node `Host` binding rule. #79 (Warden MC1394) placed lab OAuth routes after `hostMatchesResource`. |
| G1 test needed | Authorize, token, revoke, JWKS, and callback rejected on the wrong Host; discovery policy documented separately. |
| Acceptance | Non-Edge finish deployments still align `Host` with the resource. Wrong Host is rejected. If homemade authorize/token/revoke/JWKS/callback routes are deleted, those route clauses are N/A only with evidence the routes are unregistered (G1-05, G1-03, G1-10) **and** the remaining Node finish surface still enforces Host/resource alignment. Removing `hostMatchesResource` (or its successor) while those routes still exist, or dropping Host alignment with no documented replacement, is FAIL. |
| Mark | CONTENT wait |
| Evidence | |

#### G1-20 — Lab opt-in conjunction (`LAB_DUAL_GRANT` env ∧ hook)

| Field | Value |
| --- | --- |
| Disposition | RETAIN (lab) while the broker exists. DELETE clause is scored above if the broker is removed. |
| G1 test needed | Env alone or hook alone → fail-closed; both → lab routes only. |
| Acceptance | While a lab broker remains: `SUPABASE_USER_MCP_LAB_DUAL_GRANT=1` without the hook, and the hook without the env, stay fail-closed. Both together enable lab routes only, not ordinary `start:remote`. Ordinary remote still omits the hook. If the broker is removed, score the DELETE clause instead and do not leave a live conjunction. |
| Mark | CONTENT wait |
| Evidence | |

#### G1-21 — Fixture transport / `.invalid` coordinates

| Field | Value |
| --- | --- |
| Disposition | RETAIN (test infra) |
| Upstream gap (G1) | None (test-only). Named so it is not dropped. |
| G1 test needed | Caller fetch on `.invalid` rejected; scripted responder only when the literal set is selected. |
| Acceptance | Contract fixtures do not become network targets. Caller fetch on `.invalid` is rejected. A scripted responder runs only when the literal scripted set is selected (`fixtureTransport: 'broker-scripted'`). Removing that isolation, or allowing a caller fetch to `.invalid`, is FAIL. |
| Mark | CONTENT wait |
| Evidence | |

---

## Explicit non-claims

- Not a merge of #79, #97, or #98.
- Not an instruction to the G2 agent `bc-ede9c9e7-f9b9-5441-8a5f-b217b216b4cf`, not a second G2, and not a substitute for that run.
- Not formal content acceptance of #98 head `67cf73df5390c89697a40295b4cddecbf811881d`. That SHA is preliminary.
- Not M4 live expansion, not a live loopback receipt, and not a claim that a receipt with literal `pass` constants is a live pass.
- Not Pages, DNS, or external-client B–D unblocking.
- Not a Primary Users ping, and not an approval by Primary Users, Warden, or Atlas.
- Not an ADR supersession, not Option 2 approval, and not a statement that RFC 8707 or RFC 8693 has shipped.
- Not deletion of #79 surfaces in git. DELETE rows are acceptance checks for the G2 finish path when that draft exists.
- The author of this checklist is not the independent verifier. H1 and H2 preliminary readings are not that review.

## Verification

Formal CONTENT waits until the G2 agent finishes. This packet records a preliminary reading of two hard gates only.

### Pin the final G2 head before any formal mark

1. #98 is the G2 draft: https://github.com/jryski/Supabase_user_MCP/pull/98 on `cursor/supabase-native-user-mcp-g2`, base `ariadne/remote-oauth-rebased-20260919` @ `fcbaca121d0717ee8ff98df90b2f12475b05bb78`. Do not open another G2 PR from this checklist.
2. The head read here is `67cf73df5390c89697a40295b4cddecbf811881d`. It is preliminary. Formal marks use the full head SHA after the G2 agent stops, even if that SHA is the same.
3. `git fetch` that final SHA. Read the tree at that SHA. A preliminary reading does not carry forward if the tree changes.
4. Marks against #75 (`fcbaca12`), #79 (`80ea3ead`), #97 (`95ae3a46`), `main`, or this checklist’s own head are invalid. #98’s preliminary SHA is valid only as the example source named above.

### How to mark each gate

| Mark | When |
| --- | --- |
| `PASS` | The pinned G2 head shows the check. Cite a path on that SHA and, where the row names a test, the command and result run on that SHA. |
| `FAIL` | The pinned head shows the forbidden surface on ordinary remote, shows Token A on `/rest/v1`, shows a homemade production issuer or ephemeral MCP signing key, or drops a RETAIN gap without the ADR/documentation that row requires. |
| `BLOCKED` | The SHA cannot be fetched, the check needs a live project / GoTrue / DCR setting the verifier does not have, or the named test is not on that SHA and no other evidence from that SHA is attached. Say what is missing. |
| `CONTENT wait` | The G2 head is not final, or this row was not part of the preliminary H1/H2 reading. Not a pass. |

Rules:

- Each of G1-01 through G1-21 has one Mark cell. Headings that say “do not mark it separately” or “scored with” belong to that row. The row is `PASS` only when every clause on it passes.
- Do not upgrade `BLOCKED` to `PASS`.
- N/A is allowed only inside a dual-disposition row, for the clause whose precondition is absent, and only with evidence of that precondition on the pinned SHA. The row mark still follows the clauses that remain.
- Packet result is `FAIL` if any formal mark among H1–H5 or G1-01–G1-21 is `FAIL`. Otherwise `CONTENT wait` or `BLOCKED` if any formal mark is `CONTENT wait`, `BLOCKED`, or empty. Otherwise `PASS`. A preliminary reading cannot produce packet `PASS`.
- Ordinary remote means `start:remote` without the lab hook, as G1 defined it. A passing lab-only test does not pass a DELETE prod clause.
- H2/H3 evidence must show the `Authorization` value on `/rest/v1` (or a test double that records that header) and show it is not the inbound MCP bearer. “Uses `@supabase/server`” without that comparison is not H2 PASS.
- Verifier identity is recorded and is not the author of this file and not the G2 implementer.

### Verifier log

| Field | Value |
| --- | --- |
| G2 draft PR URL | https://github.com/jryski/Supabase_user_MCP/pull/98 |
| G2 branch | `cursor/supabase-native-user-mcp-g2` |
| G2 base | `ariadne/remote-oauth-rebased-20260919` @ `fcbaca121d0717ee8ff98df90b2f12475b05bb78` |
| Preliminary head read for H1/H2 examples | `67cf73df5390c89697a40295b4cddecbf811881d` |
| Final G2 head SHA (fill when the agent stops) | |
| G1/G5 head this list was written against | `95ae3a46710134d5a46a57e17fe4a38224c89467` |
| Verifier (not this author, not the G2 implementer) | |
| Date of formal content | |
| H1–H2 preliminary reading | Recorded above. Not formal. |
| H1–H5 formal result | CONTENT wait |
| G1-01–G1-21 formal result | CONTENT wait |
| Packet result | CONTENT wait |

Suggested read order on the pinned SHA: ordinary remote entry and discovery metadata (H1, H5, G1-01, G1-04, G1-15), token mint/verify (G1-02, G1-03, G1-09), outbound `/rest/v1` header versus inbound bearer (H2, H3, G1-11, G1-18), Auth refresh and DCR policy (G1-06, G1-08), consent and redirects (G1-07, G1-10), then RETAIN gaps (G1-12, G1-13, G1-14, G1-17, G1-19, G1-20, G1-21).
