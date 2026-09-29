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
| G2 head (LOCKED) | `67cf73df5390c89697a40295b4cddecbf811881d` |
| G2 tree (LOCKED) | `fba8bae4887b8e311f7ffbe930461751172f0cb2` |
| G2 agent | `bc-ede9c9e7-f9b9-5441-8a5f-b217b216b4cf` (this checklist does not start another G2) |
| #79 | **HOLD** — research history only. https://github.com/jryski/Supabase_user_MCP/pull/79 head researched by G1: `80ea3ead7e7daff04d1c86302ec5a5d6c4617d9e`. Not expanded, not reset, not merged by this packet. |
| Hard gates at this head | **H1 PASS. H2 PASS.** Citation is the #98 delta and `packages/server/src/native-user-mcp.ts` at the locked head. |
| Formal CONTENT | With the independent verifier. This author does not claim content PASS. Matrix rows stay `verifier`. |
| Ordinary remote | G1’s `start:remote` path is the pre-existing profile. The #98 delta does not switch it over. Hard-gate PASS below is the new adapter plus that delta, not a content score of every inherited file. |

This checklist is pinned to locked #98 head `67cf73df5390c89697a40295b4cddecbf811881d` (tree `fba8bae4887b8e311f7ffbe930461751172f0cb2`) and to G1/G5 at `95ae3a46`. It does not add a topology, an issuer, an exchange, or a privilege exception.

## Locked head

Do not wait for another #98 head. `67cf73df5390c89697a40295b4cddecbf811881d` is the acceptance pin. Tree `fba8bae4887b8e311f7ffbe930461751172f0cb2` matches `git rev-parse 67cf73df^{tree}`.

#98 delta against base `fcbaca121d0717ee8ff98df90b2f12475b05bb78` is 10 files: `CHANGELOG.md`, `docs/evidence/G2_NATIVE_USER_MCP.md`, `docs/evidence/README.md`, `package-lock.json`, `packages/server/package.json`, `packages/server/src/index.ts`, `packages/server/src/native-user-mcp.test.ts`, `packages/server/src/native-user-mcp.ts`, `packages/server/tsconfig.json`, `tsconfig.test.json`. That delta contains no `Iss_M`, no `/oauth/authorize`, `/oauth/token`, or `/oauth/revoke` route, and no lab dual-grant broker.

Adapter behavior at that head (`docs/evidence/G2_NATIVE_USER_MCP.md`, `packages/server/src/native-user-mcp.ts`):

- Adapter pin in `native-user-mcp.ts`: `@supabase/server` `1.7.2`, peer `@supabase/supabase-js` `2.117.2`. Nested form only (`withOAuthProtectedResource` around `withSupabase`). The alpha `pipeline` entry form is not used.
- Token A is the inbound `Authorization: Bearer` JWT. `fromSupabaseUrl` sets the issuer to `{supabaseUrl}/auth/v1`. The handler then requires `role=authenticated`, `aud` containing both `authenticated` and the MCP resource, a server-controlled `client_id`, UUID `sub` and `session_id`, and rejects `user_metadata` used as authority.
- Token B is the constant `unresolved`. A verified Token A returns `403` with `{ "error": "downstream_credential_unresolved" }`. No second Data API client is created.
- `blockedDataApiFetch` is installed as `supabaseOptions.global.fetch` and throws `downstream_credential_unresolved` if called. `NATIVE_USER_MCP_CREDENTIAL_SPLIT.sameBearerPassthrough` is `false`.
- The library still constructs an unused same-bearer user client and an unused admin client before the handler. The admin client uses the placeholder `g2-unused-admin-client-not-a-credential`, not `SUPABASE_SECRET_KEY`. The adapter does not call either client.
- No `Iss_M`, no authorize/token/revoke routes, and no lab dual-grant broker are added in the #98 delta. Issuer for the new adapter is `fromSupabaseUrl` (`{supabaseUrl}/auth/v1`).
- The fetch handler does not mount the read-only `McpServer`. Tool dispatch is a G3 residual.

## G3 residuals (still open)

These are open on the locked head. They are not a content PASS, and they do not reverse H1 or H2.

| Residual | Where it is stated at `67cf73df` |
| --- | --- |
| Token B missing | `NATIVE_USER_MCP_CREDENTIAL_SPLIT.tokenB` is `unresolved`. No second Data API client is created. Evidence file: do not point Data API calls at the library user client. |
| Live revocation not implemented | `liveRevocation` is `not-implemented`. An unexpired revoked JWT reaches the fail-closed `403` instead of a revocation denial. |
| Tools not mounted | The existing read-only `McpServer` is not mounted on `createNativeUserMcpHandler`. The handler returns `403` after Token A verifies. |

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

H1 and H2 are checked because those two hard gates **PASS** at the locked head, on the citation in the table. Checking them is not a content PASS. H3, H4, and H5 stay unchecked for the verifier. A later `FAIL` from the verifier fails the packet. `verifier` is not a pass.

- [x] **H1 — No homemade issuer in the #98 delta.** Project Auth issuer via `fromSupabaseUrl` (`{supabaseUrl}/auth/v1`). The delta adds no `Iss_M`, no `/oauth/authorize`, `/oauth/token`, or `/oauth/revoke` route, and no lab dual-grant broker.
- [x] **H2 — No inbound-token passthrough.** Verified Token A returns `403` `downstream_credential_unresolved` and is not forwarded to `/rest/v1`.
- [ ] **H3 — Token A ≠ Token B (second OAuth grant).** Upstream Data API calls that carry a user access token use Token B from a second Supabase OAuth grant / OAuth client (or a documented Auth-supported exchange that yields a **distinct** upstream access token). G5 does not allow a custom MCP issuer as that mechanism. Same-string Token A and Token B is FAIL. On this head Token B is missing (G3).
- [ ] **H4 — Ordinary path fail-closed without Token B.** A valid MCP bearer with no resolved downstream credential does not call `/rest/v1`. G1’s ordinary-path result remains the bar: `403` with `downstream_credential_unresolved` and zero Data API calls, unless an ADR supersession named by G1-18 is actually present on the G2 head.
- [ ] **H5 — Project Auth issuer / JWKS for MCP-facing verify.** Ordinary remote verifies MCP-facing access tokens with the project Auth issuer and project JWKS (asymmetric ES256/RS256). No process-ephemeral private JWK mints those tokens. No loopback homemade JWKS is the production verification key set.

| Gate | Record at locked head `67cf73df` | Mark |
| --- | --- | --- |
| H1 | **PASS.** `createNativeUserMcpHandler` sets `authorizationServer` from `fromSupabaseUrl` (`{supabaseUrl}/auth/v1`). Diff `fcbaca12..67cf73df` adds no `Iss_M`, no authorize/token/revoke route, and no lab dual-grant broker. | PASS |
| H2 | **PASS.** `respondAfterVerifiedMcpAuth` returns `403` `downstream_credential_unresolved`. `blockedDataApiFetch` throws that error if the library client is invoked. `sameBearerPassthrough` is `false`. Test `verifies Token A then fail-closes without a Data API call` expects `globalThis.fetch` calls to be empty and the body not to contain the bearer. The library still builds an unused same-bearer client; the adapter does not call it and does not send Token A to `/rest/v1`. | PASS |
| H3 | Token B is `unresolved`. No second Supabase OAuth grant is in the delta. G3 residual. Not a hard-gate PASS. | verifier |
| H4 | The adapter’s verified-Token-A path is the `403` shape cited under H2. Whether that satisfies G1’s ordinary `start:remote` row is content for the verifier. The delta does not switch `start:remote` over. | verifier |
| H5 | The adapter verifies with the supplied asymmetric JWKS or JWKS URL and the `fromSupabaseUrl` issuer. `assertJwks` rejects `kty: 'oct'` and `HS256` / `HS384` / `HS512`. It does not mint a process-ephemeral MCP key. Live revocation is the G3 residual, not this mark. | verifier |

H1 and H2 are the hard gates recorded PASS at this locked head. H3, H4, H5, and G1-01 through G1-21 are formal CONTENT for the verifier. This packet does not claim content PASS.

---

## Matrix rows

For each row, “G1 test needed” is the test cell of that matrix row at `95ae3a46`. The acceptance line is that cell, plus the G5 binding where the row touches Token A / Token B. Silent deletion of a RETAIN gap is FAIL. Lab-only leftovers are allowed only on the ADAPT / RETAIN-lab clause, and they must be unreachable on ordinary remote. Every matrix Mark is `verifier`: formal CONTENT, not a PASS from this author.

### DELETE

#### G1-01 — Issuer (MCP-facing custom `Iss_M`, loopback AS)

| Field | Value |
| --- | --- |
| Disposition | DELETE |
| G1 test needed | Discovery URL equals project issuer; no listener serves homemade AS metadata as production issuer; regression that `createAuthorizationServerMetadata(local)` is not wired into ordinary remote. |
| Acceptance | On ordinary remote, MCP discovery advertises project Auth (`https://<ref>.supabase.co/auth/v1` and the Auth discovery document), not a second homemade AS. No listener on that path serves `LabDualGrantBroker` / `Iss_M` authorize, token, JWKS, or revoke as the issuer. Hard-fail link: H1. |
| Example at `67cf73df` (not a content mark) | New adapter: `authorizationServer: resolved.issuer` with `issuer = fromSupabaseUrl(...)`. H1 PASS is the #98 delta: no `Iss_M`, no authorize/token/revoke route, no lab dual-grant broker. Inherited base files are outside that delta. |
| Mark | verifier |
| Evidence | |

#### G1-02 — Signing key (process-ephemeral ES256 for MCP JWTs)

| Field | Value |
| --- | --- |
| Disposition | DELETE |
| G1 test needed | No process-local private JWK used to mint MCP access tokens on the finish path; tokens verify only via project JWKS. |
| Acceptance | Ordinary remote does not mint MCP access tokens with a process-ephemeral keypair (`mcpSigningAlg: 'ES256'` or any successor in-process private JWK). Verification key material is project JWKS. Hard-fail link: H5. |
| Mark | verifier |
| Evidence | |

#### G1-03 — JWKS (`GET /.well-known/jwks.json` on lab issuer)

| Field | Value |
| --- | --- |
| Disposition | DELETE (prod) / ADAPT (lab fake only) |
| G1 test needed | Prod profile never binds `signingKey.kind:'jwks'` to loopback homemade JWKS; live verify uses project JWKS URL. |
| Acceptance | **Prod / ordinary:** production verification does not use broker `handleJwks` or any MCP-process JWKS as the issuer key set. **Lab fake:** a scripted JWKS may exist only inside a unit double (`SyntheticOAuthLab` or a successor test double). That double is not mounted on ordinary `start:remote`. If no lab double remains, the lab clause is N/A only with evidence the prod clause passes and no homemade JWKS is served. |
| Mark | verifier |
| Evidence | |

#### G1-05 — Authorize / token / revoke (MCP-facing homemade routes)

| Field | Value |
| --- | --- |
| Disposition | DELETE |
| G1 test needed | Ordinary remote does not register `/oauth/authorize`, `/oauth/token`, or `/oauth/revoke` handlers; clients hit project Auth URLs from discovery. |
| Acceptance | Ordinary remote has no homemade `GET`/`POST` authorize, token, or revoke routes. Client authorization-code, refresh, and grant revoke go to project Auth (`…/auth/v1/oauth/authorize`, `…/auth/v1/oauth/token`, Auth/user grants revoke). A lab-only MCP-token revoke clock is not a hosted surface on ordinary remote. |
| Mark | verifier |
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
| Example at `67cf73df` (not a content mark) | The new adapter does not call `createAuthorizationServerMetadata`, and that helper is not in the #98 delta. H1 PASS does not score this inherited base file. Content mark stays with the verifier. |
| Mark | verifier |
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
| Example at `67cf73df` (not a content mark) | Nested `withOAuthProtectedResource({ resourceServer, authorizationServer: fromSupabaseUrl(supabaseUrl) }, withSupabase({ auth: 'user', audience, issuer, env }, handler))` at pin `1.7.2`. The alpha `pipeline` form is not used. The metadata test expects `authorization_servers: [ISSUER]` and a `401` `WWW-Authenticate` containing `resource_metadata`. |
| Mark | verifier |
| Evidence | |

#### G1-06 — DCR (dynamic client registration)

| Field | Value |
| --- | --- |
| Disposition | REUSE UPSTREAM (policy-gated) |
| G1 test needed | With DCR off: unknown client rejected. With DCR on: registration + consent + token round-trip; redirect URI exact-match enforced by GoTrue. |
| Acceptance | DCR is the project Auth facility (`allow_dynamic_registration` / Auth registration endpoint), not a new registrar inside the MCP process. The verifier records which policy the G2 head ships. **Off:** unknown client rejected, evidenced on that head. **On:** registration, consent, and token round-trip, with GoTrue exact redirect match. The mode not shipped must be stated as policy; leaving both modes untested is BLOCKED, not PASS. ADR-0006’s historical “no DCR” line applied to the homemade broker, not to project Auth, per G1. |
| Mark | verifier |
| Evidence | |

#### G1-08 — Refresh (Data API / user session)

| Field | Value |
| --- | --- |
| Disposition | REUSE UPSTREAM (Data API / user session) + DELETE (MCP-AS refresh, scored above) |
| G1 test needed | Refresh rotation + reuse detection against GoTrue; revoked refresh denies the next Data API call; no homemade MCP refresh endpoint in prod. |
| Acceptance | Refresh custody for the upstream user session is Supabase Auth / the client SDK (`grant_type=refresh_token` on project `…/oauth/token`, with rotation). Revoked refresh denies the next Data API call. The DELETE clause (no homemade MCP refresh) must also pass. If the process still holds an upstream refresh token in memory, single-flight behavior is scored under G1-13, not reimplemented as a second AS. |
| Mark | verifier |
| Evidence | |

#### G1-09 — Token verification

| Field | Value |
| --- | --- |
| Disposition | REUSE UPSTREAM + ADAPT resource-binding extras |
| G1 test needed | Valid user JWT passes; HS256 rejected when the project is asymmetric; wrong `iss` / `aud` / `client_id` → 401; latency-bound revoke still enforced if retained. |
| Acceptance | **REUSE:** signature, issuer, expiry, and role checks use `@supabase/server` `withSupabase({ auth: 'user' })` and/or `withRequiredClaims` against project JWKS. **ADAPT (only if still required):** extra MCP resource audience / `client_id` binding beyond `aud=authenticated` (ADR-0005 / `REMOTE_IDENTITY_CLAIM_POLICY`) may stay as thin glue. Record which choice the head made. Treating stock `aud: "authenticated"` single-grant passthrough as already conformant is FAIL (G5 NO). Dropping the latency-bound revoke clause while G1-17 is still required is FAIL. Hard-fail links: H2 (the verified Token A is not what `/rest/v1` receives), H5. |
| Example at `67cf73df` (not a content mark) | `withSupabase({ auth: 'user', audience, issuer, env })` plus `mcpClaimsRejected`: `role=authenticated`, `aud` includes `authenticated` and the MCP resource, server-controlled `client_id`, UUID `sub` and `session_id`, `user_metadata` rejected. `assertJwks` rejects symmetric keys. The evidence file says live revocation is not performed, so an unexpired revoked JWT reaches the fail-closed `403` instead of a revocation denial. |
| Mark | verifier |
| Evidence | |

#### G1-11 — RLS client creation

| Field | Value |
| --- | --- |
| Disposition | REUSE UPSTREAM + ADAPT fixed RPC façade. One mark for the whole row. |
| G1 test needed | `memory_*` under RLS as `auth.uid()`; cross-principal denial; zero inbound-MCP-bearer forwarding; loopback http allow only under lab flag. |
| Acceptance | **REUSE:** RLS uses an upstream user-scoped Supabase client (`ctx.supabase` from `withSupabase({ auth: 'user' })` or the same facility). The credential on `/rest/v1` is Token B, not Token A. Passing the inbound MCP bearer into that helper is H2 FAIL. **ADAPT:** `createFixedSupabaseClient` may remain only as a narrow allowlisted RPC façade (fixed paths, byte caps, schema profile), fed by Token B, not as a second auth stack. Cross-principal calls are denied. Loopback HTTP is allowed only under an explicit lab flag. |
| Example at `67cf73df` (not a content mark) | The adapter installs `blockedDataApiFetch` on `supabaseOptions.global.fetch` and never calls the library user client. Evidence file: do not point Data API calls at that client. Token B is `unresolved`. This is the H2 shape, not a Token B RLS client. |
| Mark | verifier |
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
| Mark | verifier |
| Evidence | |

#### G1-09 (extras clause) — Resource-binding beyond stock `aud`

Scored with G1-09 above. Allowed glue is the extra audience / `client_id` check G1 names, not a second verifier stack and not a homemade issuer.

#### G1-10 — Callback handling

| Field | Value |
| --- | --- |
| Disposition | ADAPT |
| G1 test needed | Exact redirect match; wildcard, userinfo, query, and fragment rejected; wrong host/port denied; lab callback not exposed on ordinary `start:remote`. |
| Acceptance | Production redirect URIs are the MCP client’s registered URIs and the app consent return path. `/lab/oauth/callback` on the broker is not exposed on ordinary `start:remote`. Exact match only. Lab harness redirects may exist for disposable GoTrue tests and must stay off ordinary remote. |
| Mark | verifier |
| Evidence | |

#### G1-11 (façade clause)

Scored only on the G1-11 mark above. Allowed glue is the narrow allowlisted RPC façade fed by Token B. Forwarding Token A through that façade is H2 FAIL.

#### G1-16 (unit clause) — Synthetic OAuth lab as a unit double

| Field | Value |
| --- | --- |
| Disposition | ADAPT (unit double) / DELETE (prod). One mark for the whole row. The prod clause is stated above and must pass with this mark. |
| G1 test needed | `npm test` unit suite does not require a homemade production AS; live path uses GoTrue. |
| Acceptance | The HS256 synthetic lab may remain as a unit fake for verifier/policy tests, or be replaced by local GoTrue. The unit suite must not need a homemade production AS. The double is not mounted on ordinary remote (prod clause). |
| Mark | verifier |
| Evidence | |

#### G1-17 — GoTrue session revocation probe

| Field | Value |
| --- | --- |
| Disposition | ADAPT |
| G1 test needed | Revoke session → next call denied inside 5s; probe timeout fail-closed; no cache. |
| Acceptance | Signature verify stays on the project JWKS path (G1-09 / H5). Adapt `createGoTrueSessionRevocationAuthority` (`GET /auth/v1/user`, 5s bound) only if finish still requires revocation-before-`exp` tighter than JWT validity (`ACCESS_TOKEN_REVOCATION_POLICY`). If retained: revoke session → next call denied inside 5s; probe timeout fail-closed; no cache. If dropped: the head records that this policy no longer requires the probe. Dropping it with no record is FAIL. The probe does not replace project JWKS. |
| Example at `67cf73df` (not a content mark) | Evidence file, residual gaps: live access-token revocation is not performed. `NATIVE_USER_MCP_CREDENTIAL_SPLIT.liveRevocation` is `not-implemented`. The inherited remote profile still constructs `createGoTrueSessionRevocationAuthority`. |
| Mark | verifier |
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
| Mark | verifier |
| Evidence | |

#### G1-13 — Lifecycle races (epoch, single-flight refresh, local TTL, cleanup)

| Field | Value |
| --- | --- |
| Disposition | RETAIN |
| Upstream gap (G1) | GoTrue manages one grant lifecycle. It does not coordinate MCP-process custody, in-flight code exchange versus cleanup, or `LOCAL_DISPATCH_TTL_MS` (15m) orthogonal to access-token `exp`. |
| G1 test needed | Cleanup during exchange/sign/refresh does not revive tokens; concurrent refresh → 403; local deadline stops `/rest/v1` after TTL; disconnect cancels the request only. |
| Acceptance | Whatever still holds upstream refresh material or bridges Token A and Token B keeps race closures: no revival after cleanup, single-flight refresh (concurrent refresh denied), local dispatch deadline stops `/rest/v1` after the documented TTL, disconnect cancels the request only. Deleting epoch / single-flight / local TTL behavior without tests that show the thinner path still fails closed is FAIL. |
| Mark | verifier |
| Evidence | |

#### G1-14 — Receipts (`LabDualGrantReceipt` / M4 harness)

| Field | Value |
| --- | --- |
| Disposition | RETAIN |
| Upstream gap (G1) | No receipt schema for lab dual-grant / remote-oauth evidence. |
| G1 test needed | Receipt pins head SHA, client name/version, custody flags, opt-in default false; live harness absence ≠ synthetic pass. |
| Acceptance | Finish evidence is still an auditable receipt independent of hosted dashboards. The receipt pins the head SHA under test, client name/version, custody flags, and opt-in default false. A missing live harness is not recorded as a synthetic pass. G1’s N2 caveat (literal `pass` constants in the #79 receipt schema) stays in force until a head actually changes that schema and says so; a literal `pass` constant is not live evidence. This row does not ask for a new M4 live run. |
| Mark | verifier |
| Evidence | |

#### G1-18 — Ordinary remote fail-closed dispatch (`downstream_credential_unresolved`)

| Field | Value |
| --- | --- |
| Disposition | RETAIN until ADR supersession |
| Upstream gap (G1) | Official MCP guide still documents using the Supabase user access token at the Data API. Repo policy (ADR-0005/0006, MCP 2026-07-28) forbids forwarding the inbound MCP bearer. Native exchange was still unsupported per `DOWNSTREAM_CREDENTIAL_RECHECK_2026_09_22`. |
| G1 test needed | Valid MCP bearer without a resolved downstream credential → 403; zero Data API calls; B/C binding failure → 401 before 403. |
| Acceptance | Without Token B, ordinary remote stays fail-closed: `403` `downstream_credential_unresolved`, zero `/rest/v1`. Binding failures (G1’s B/C cases) return 401 before that 403. Copying upstream passthrough prose into the ordinary path is H2 FAIL and this row FAIL. Leaving fail-closed is allowed. Opening the Data API is allowed only with Token B as in H3, or with an ADR on this head that supersedes the fail-closed decision the way G1 states (Option 1 proven, Option 2 under a new ADR, or an explicit privilege-model change). No such ADR is created by this checklist. Hard-fail link: H4. |
| Example at `67cf73df` (not a content mark) | `respondAfterVerifiedMcpAuth` returns `jsonResponse(403, DOWNSTREAM_CREDENTIAL_UNRESOLVED)`. The named test expects that body and an empty `globalThis.fetch` call list. `auth` failures in that test stay `401` and do not contain `downstream_credential_unresolved`. |
| Mark | verifier |
| Evidence | |

#### G1-19 — Host check on lab OAuth routes

| Field | Value |
| --- | --- |
| Disposition | RETAIN (deployment glue) |
| Upstream gap (G1) | Edge gateway host derivation is not the Node `Host` binding rule. #79 (Warden MC1394) placed lab OAuth routes after `hostMatchesResource`. |
| G1 test needed | Authorize, token, revoke, JWKS, and callback rejected on the wrong Host; discovery policy documented separately. |
| Acceptance | Non-Edge finish deployments still align `Host` with the resource. Wrong Host is rejected. If homemade authorize/token/revoke/JWKS/callback routes are deleted, those route clauses are N/A only with evidence the routes are unregistered (G1-05, G1-03, G1-10) **and** the remaining Node finish surface still enforces Host/resource alignment. Removing `hostMatchesResource` (or its successor) while those routes still exist, or dropping Host alignment with no documented replacement, is FAIL. |
| Mark | verifier |
| Evidence | |

#### G1-20 — Lab opt-in conjunction (`LAB_DUAL_GRANT` env ∧ hook)

| Field | Value |
| --- | --- |
| Disposition | RETAIN (lab) while the broker exists. DELETE clause is scored above if the broker is removed. |
| G1 test needed | Env alone or hook alone → fail-closed; both → lab routes only. |
| Acceptance | While a lab broker remains: `SUPABASE_USER_MCP_LAB_DUAL_GRANT=1` without the hook, and the hook without the env, stay fail-closed. Both together enable lab routes only, not ordinary `start:remote`. Ordinary remote still omits the hook. If the broker is removed, score the DELETE clause instead and do not leave a live conjunction. |
| Mark | verifier |
| Evidence | |

#### G1-21 — Fixture transport / `.invalid` coordinates

| Field | Value |
| --- | --- |
| Disposition | RETAIN (test infra) |
| Upstream gap (G1) | None (test-only). Named so it is not dropped. |
| G1 test needed | Caller fetch on `.invalid` rejected; scripted responder only when the literal set is selected. |
| Acceptance | Contract fixtures do not become network targets. Caller fetch on `.invalid` is rejected. A scripted responder runs only when the literal scripted set is selected (`fixtureTransport: 'broker-scripted'`). Removing that isolation, or allowing a caller fetch to `.invalid`, is FAIL. |
| Mark | verifier |
| Evidence | |

---

## Explicit non-claims

- Not a merge of #79, #97, or #98.
- Not an instruction to the G2 agent `bc-ede9c9e7-f9b9-5441-8a5f-b217b216b4cf`, not a second G2, and not a substitute for that run.
- Not a content PASS. H1 and H2 are hard-gate PASS records at locked head `67cf73df5390c89697a40295b4cddecbf811881d`. Formal CONTENT of H3–H5 and G1-01–G1-21 belongs to the verifier.
- Not closure of the G3 residuals (Token B missing, live revocation not implemented, tools not mounted).
- Not M4 live expansion, not a live loopback receipt, and not a claim that a receipt with literal `pass` constants is a live pass.
- Not Pages, DNS, or external-client B–D unblocking.
- Not a Primary Users ping, and not an approval by Primary Users, Warden, or Atlas.
- Not an ADR supersession, not Option 2 approval, and not a statement that RFC 8707 or RFC 8693 has shipped.
- Not deletion of #79 surfaces in git. #79 stays HOLD.
- The author of this checklist is not the independent verifier.

## Verification

The G2 head is locked. This packet records H1 and H2 as PASS at that head. Formal CONTENT is the verifier’s.

### Pin

1. G2 draft: https://github.com/jryski/Supabase_user_MCP/pull/98, branch `cursor/supabase-native-user-mcp-g2`, base `ariadne/remote-oauth-rebased-20260919` @ `fcbaca121d0717ee8ff98df90b2f12475b05bb78`. Do not open another G2 PR from this checklist.
2. Locked head: `67cf73df5390c89697a40295b4cddecbf811881d`. Locked tree: `fba8bae4887b8e311f7ffbe930461751172f0cb2`. Score this SHA, not a later move, unless Central explicitly replaces the pin.
3. `git fetch` that SHA and confirm `git rev-parse 67cf73df^{tree}` is `fba8bae4…`. Marks against #75, #79, #97, `main`, or this checklist’s own head are not marks of #98.
4. H1 and H2 are already recorded PASS from the #98 delta and `native-user-mcp.ts`. The verifier may confirm that citation. The verifier fills H3–H5 and G1-01–G1-21. This author does not.

### How to mark each remaining gate

| Mark | When |
| --- | --- |
| `PASS` | The locked head `67cf73df` shows the check. Cite a path on that SHA and, where the row names a test, the command and result run on that SHA. |
| `FAIL` | That head shows the forbidden surface, shows Token A on `/rest/v1`, shows a homemade issuer added by the G2 delta, or drops a RETAIN gap without the ADR that row requires. |
| `BLOCKED` | The SHA cannot be fetched, or the check needs a live project / GoTrue / DCR setting the verifier does not have. Say what is missing. |
| `verifier` | Set by this packet on rows this author does not score. The verifier replaces it. It is not a pass. |

Rules:

- Each of G1-01 through G1-21 has one Mark cell. Headings that say “do not mark it separately” or “scored with” belong to that row. The row is `PASS` only when every clause on it passes.
- Do not upgrade `BLOCKED` or `verifier` to `PASS` without evidence on `67cf73df`.
- N/A is allowed only inside a dual-disposition row, for the clause whose precondition is absent, and only with evidence of that precondition on the locked SHA.
- Content packet result is the verifier’s. H1 PASS and H2 PASS do not make that result PASS while any row is still `verifier`, `BLOCKED`, or `FAIL`. G3 residuals stay open regardless.
- H2 evidence already cited is the adapter test with an empty `globalThis.fetch` list and a body that does not contain the bearer. “Uses `@supabase/server`” without that comparison is not H2 PASS. The recorded H2 PASS uses that comparison.
- Verifier identity is recorded and is not the author of this file and not the G2 implementer.

### Verifier log

| Field | Value |
| --- | --- |
| G2 draft PR URL | https://github.com/jryski/Supabase_user_MCP/pull/98 |
| G2 branch | `cursor/supabase-native-user-mcp-g2` |
| G2 base | `ariadne/remote-oauth-rebased-20260919` @ `fcbaca121d0717ee8ff98df90b2f12475b05bb78` |
| Locked G2 head | `67cf73df5390c89697a40295b4cddecbf811881d` |
| Locked G2 tree | `fba8bae4887b8e311f7ffbe930461751172f0cb2` |
| G1/G5 head | `95ae3a46710134d5a46a57e17fe4a38224c89467` |
| H1 | PASS (hard gate, #98 delta, `fromSupabaseUrl`, no `Iss_M` / authorize / token / revoke / dual-grant) |
| H2 | PASS (hard gate, Token A → `403` `downstream_credential_unresolved`, no `/rest/v1` forward) |
| H3–H5 | verifier |
| G1-01–G1-21 | verifier |
| G3 residuals | open: Token B missing; live revocation not implemented; tools not mounted |
| Formal CONTENT | with the verifier (not claimed here) |
| Verifier (not this author, not the G2 implementer) | |
| Date of formal content | |
| Content packet result | |

Suggested read order on the pinned SHA: ordinary remote entry and discovery metadata (H1, H5, G1-01, G1-04, G1-15), token mint/verify (G1-02, G1-03, G1-09), outbound `/rest/v1` header versus inbound bearer (H2, H3, G1-11, G1-18), Auth refresh and DCR policy (G1-06, G1-08), consent and redirects (G1-07, G1-10), then RETAIN gaps (G1-12, G1-13, G1-14, G1-17, G1-19, G1-20, G1-21).
