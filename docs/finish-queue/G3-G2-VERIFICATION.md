# G3 — verification of G2 against the G1 DELETE rows

| Field | Value |
| --- | --- |
| Packet | G3 finish-queue verification (docs only) |
| Repo | `jryski/Supabase_user_MCP` |
| This branch base | `main` @ `b678684b9df58105f49696ef0957505fd5c10eae` |
| G1 + G5 source | Draft [#97](https://github.com/jryski/Supabase_user_MCP/pull/97) @ `95ae3a46710134d5a46a57e17fe4a38224c89467` |
| G1 subject (not this tree) | Draft [#79](https://github.com/jryski/Supabase_user_MCP/pull/79) @ `80ea3ead7e7daff04d1c86302ec5a5d6c4617d9e` |
| G2 subject | Draft [#98](https://github.com/jryski/Supabase_user_MCP/pull/98) |
| G2 branch | `cursor/supabase-native-user-mcp-g2` |
| G2 head | `67cf73df5390c89697a40295b4cddecbf811881d` |
| G2 tree | `fba8bae4887b8e311f7ffbe930461751172f0cb2` |
| G2 parent / base | `ariadne/remote-oauth-rebased-20260919` @ `fcbaca121d0717ee8ff98df90b2f12475b05bb78` (tree `0b0a81794d2a98e3c01c5ce969849d10e0d79264`) |
| Method | Read-only inspection of that exact G2 commit (`git rev-parse ^{tree}`, `git ls-tree`, `git grep`, `git show`). This packet does not re-run the suite. |
| Verdicts | **GONE**, **STILL PRESENT (lab-only OK)**, **STILL PRESENT** (not lab-only), or **REGRESSED** |

G2 is one commit, `feat: add fail-closed native-user MCP adapter`, on top of
`fcbaca121d0717ee8ff98df90b2f12475b05bb78`. It is not a descendant of #79. A **GONE**
verdict means the named surface is absent from the G2 finish handler and is not
reintroduced on this tree. It does not mean #79 was edited.

## G2 design confirmed on this head

`packages/server/package.json` pins `@supabase/server` to `1.7.2` and
`@supabase/supabase-js` to `2.117.2`. `createNativeUserMcpHandler` in
`packages/server/src/native-user-mcp.ts` uses only the nested form:

```ts
withOAuthProtectedResource(
  { resourceServer, authorizationServer: fromSupabaseUrl(supabaseUrl) },
  withSupabase({ auth: 'user', audience, issuer, env }, handler),
)
```

`authorizationServer` is the project Auth issuer (`{supabaseUrl}/auth/v1`). The
config-only `pipeline([...])` entry form is not used.

| Bar | On `67cf73df` |
| --- | --- |
| Token A | Inbound `Authorization: Bearer` JWT. `withSupabase({ auth: 'user' })` verifies it against the supplied asymmetric JWKS or JWKS URL, issuer, and MCP resource audience. The handler then requires `role=authenticated`, `aud` containing both `authenticated` and the MCP resource, a server-controlled `client_id`, UUID `sub` and `session_id`, and rejects `user_metadata` used as authority. |
| Token B | Unresolved. `NATIVE_USER_MCP_CREDENTIAL_SPLIT.tokenB` is `'unresolved'`. A verified Token A returns `403` `{ "error": "downstream_credential_unresolved" }`. No second Data API client is created. |
| Homemade issuer | Not added. No authorize, token, revoke, or JWKS routes on the native handler. |
| Same-bearer Data API passthrough | Not the finished design. See the G5 section below. |
| Recorded tests | Draft #98 records `npm test` on this head as **841 passed / 6 skipped / 0 failed**. This packet did not re-execute that run. |

`supabase-user-mcp-remote` is still `packages/server/src/remote-http-cli.ts`. G2 does
not switch that listener over to `createNativeUserMcpHandler`.

## G5 Token B bars

G5 (draft #97, `G5-MCP-SUPABASE-TOPOLOGY-DECISION.md`) decides **NO**: stock
single-grant BYO-MCP that forwards the inbound MCP bearer to the Data API does not
satisfy the MCP 2026-07-28 upstream-token restriction without a second grant. Token B
is that second Supabase OAuth grant, not a second use of Token A.

Confirmed on the G2 finish handler:

- `NATIVE_USER_MCP_CREDENTIAL_SPLIT` sets `sameBearerPassthrough: false`,
  `tokenB: 'unresolved'`, and `dataApi` to `downstream_credential_unresolved`.
- After Token A verifies, `respondAfterVerifiedMcpAuth` returns `403` with
  `downstream_credential_unresolved`. The native module does not reference `ctx.supabase`
  or `ctx.supabaseAdmin`, and it does not call `createFixedSupabaseClient` or `/rest/v1`.
- `@supabase/server` still constructs an unused same-bearer user client and an unused
  admin client before the handler runs. G2 passes `fetch: blockedDataApiFetch`, which
  throws `downstream_credential_unresolved` if invoked. The admin client is built with
  the non-credential placeholder `g2-unused-admin-client-not-a-credential`. Explicit
  `env` is passed so `SUPABASE_SECRET_KEY` in the process environment is not read.
- The adapter test `verifies Token A then fail-closes without a Data API call` expects
  status `403`, body `{ "error": "downstream_credential_unresolved" }`, and zero
  `fetch` calls.

**Same-bearer passthrough is not the finished design.** Token B remains a second-grant
residual. Do not point Data API calls at the library user client.

## G1 DELETE checklist

Primary DELETE rows are the six explicit candidates in
`G1-UPSTREAM-REUSE-DELETE-MATRIX.md` on #97. Two matrix rows also carry a DELETE half
beside another disposition; those halves are listed after the six.

No row is **REGRESSED**. G2 does not put a homemade issuer, ephemeral MCP signing key,
served JWKS, or authorize/token/revoke route back onto the native finish handler.

| # | G1 DELETE row | Verdict | Evidence on G2 tree `fba8bae` |
| --- | --- | --- | --- |
| 1 | Homemade MCP issuer (`Iss_M`, loopback AS, `LabDualGrantBroker`) | **GONE** | `lab-dual-grant-broker.ts` is not in the tree. `git grep` finds no `LabDualGrant`, `mcpIssuer`, or `LAB_DUAL_GRANT`. The native handler sets `authorizationServer` via `fromSupabaseUrl` and does not listen as an authorization server. |
| 2 | Process-ephemeral ES256 signing key for MCP access tokens | **GONE** | `native-user-mcp.ts` does not generate or hold a private JWK. Ordinary remote startup still rejects `SUPABASE_USER_MCP_JWT_HMAC_SECRET` in the process environment. ES256 keypairs in `native-user-mcp.test.ts` only sign fixture Token A values for the verifier. |
| 3 | Served homemade JWKS (`GET /.well-known/jwks.json` on a lab issuer) | **GONE** | No production or native handler serves that path. `git grep` hits for `well-known/jwks` outside tests are URI strings in `authorization-server-metadata.ts` and `synthetic-oauth-lab.ts`, not a key-serving route. Prod clients of the native handler are expected to use project JWKS supplied as `jwks`. |
| 4 | Homemade `/oauth/authorize`, `/oauth/token`, `/oauth/revoke` route handlers | **GONE** | Neither `createNativeUserMcpHandler` nor `createRemoteHttpProfile` registers those routes. After the SDK metadata response, the remote profile returns `404` `not_found` for any other path that is not the MCP resource. Naming those paths inside authorization-server metadata is row 5, not a registered handler. |
| 5 | `authorization-server-metadata.ts` local endpoint fiction | **STILL PRESENT** | Not lab-only. `createAuthorizationServerMetadata` still hard-codes `{issuer}/oauth/authorize`, `{issuer}/oauth/token`, `{issuer}/oauth/revoke`, and `{issuer}/.well-known/jwks.json`. `remote-http-cli.ts` still passes that document into ordinary remote startup, and `index.ts` still exports the helper. The native handler does not call it. This is inherited from base `fcbaca12`; G2 did not delete it and did not adopt it for the new adapter. |
| 6 | `SyntheticOAuthLab` as a production issuer | **STILL PRESENT (lab-only OK)** | `packages/server/src/synthetic-oauth-lab.ts` remains an in-process HS256 unit double. Callers are tests (`synthetic-oauth-lab.test.ts`, `remote-token-verifier.test.ts`, `issue63-*.test.ts`). `native-user-mcp.ts` and `remote-http-cli.ts` do not import it. G1 allows this unit double. It is not a shipped issuer. |

### DELETE halves of dual-disposition rows

| G1 row | DELETE half | Verdict | Evidence |
| --- | --- | --- | --- |
| Refresh | DELETE the homemade MCP authorization-server refresh endpoint (Auth refresh itself stays REUSE UPSTREAM) | **GONE** | No MCP refresh route on the native handler or the remote profile. `synthetic-oauth-lab.ts` still implements `grant_type=refresh_token` inside the unit double (row 6). `local-oauth-pkce-client.ts` calls project Auth `/auth/v1/oauth/authorize` and the Auth token endpoint; that is a client of GoTrue, not a second AS. |
| Lab opt-in | DELETE `SUPABASE_USER_MCP_LAB_DUAL_GRANT` if the broker is removed | **GONE** | The broker file is absent, and the env name does not occur anywhere on this tree. |

### Count

| Verdict | Primary DELETE rows |
| --- | --- |
| GONE | 4 — issuer, ephemeral ES256 MCP signing key, served homemade JWKS, authorize/token/revoke handlers |
| STILL PRESENT (lab-only OK) | 1 — `SyntheticOAuthLab` unit double |
| STILL PRESENT (not lab-only) | 1 — `createAuthorizationServerMetadata` still wired by `remote-http-cli.ts` |
| REGRESSED | 0 |

Both extra DELETE halves are GONE.

## RETAIN residuals still open

These stay open on G2 head `67cf73df`. This packet does not close them.

1. **Token B.** No second Supabase OAuth grant exists. `tokenB` is `'unresolved'`. Verified Token A fail-closes with `403` `downstream_credential_unresolved`. The library's same-bearer user client is not a Token B.
2. **Live revocation on the G2 fetch handler.** `native-user-mcp.ts` does not consult a revocation authority. `NATIVE_USER_MCP_CREDENTIAL_SPLIT.liveRevocation` is `'not-implemented'`. An unexpired revoked JWT that still verifies reaches the fail-closed `403` instead of a revocation denial. The older remote profile still constructs `createGoTrueSessionRevocationAuthority` (`GET /auth/v1/user`); that probe is not attached to the native handler.
3. **`McpServer` is not mounted on the fetch handler.** `createNativeUserMcpHandler` does not import `McpServer` or `createServer` from `packages/server/src/server.ts`. Tool dispatch is not attached. `docs/evidence/G2_NATIVE_USER_MCP.md` records the same gap. Read-only tools remain on the existing stdio path.
4. **Issue #62 is incomplete.** [#62](https://github.com/jryski/Supabase_user_MCP/issues/62) is open. `docs/evidence/ISSUE_62_REMOTE_OAUTH_HTTP.md` on this tree still says issue #62 completion is no, hosted live OAuth is unmet, and the downstream credential is unresolved. `docs/evidence/G2_NATIVE_USER_MCP.md` repeats that this adapter is not #62 completion.

G1 RETAIN rows that this packet does not re-score (grant correlation, lifecycle races,
receipts, Host check, fixture transport) stay where G1 left them. The ordinary
fail-closed dispatch RETAIN is the behavior G2 kept for Token A.

## Explicit non-claims

This packet does not:

- merge draft #79 or draft #98, or treat either head as merged
- mark issue #62 complete
- enable Pages or DNS
- claim hosted Auth, hosted OAuth, consent, dynamic client registration, or a public listener
- delete the surfaces above; it only records what the G2 tree contains
- re-run `npm test` or replace the 841 / 6 / 0 figures recorded on draft #98
- change application code, the remote listener, or #79

## Method notes

- G2 head and tree checked against `origin` on 2026-09-29:
  `67cf73df5390c89697a40295b4cddecbf811881d` has tree
  `fba8bae4887b8e311f7ffbe930461751172f0cb2` and parent
  `fcbaca121d0717ee8ff98df90b2f12475b05bb78`.
- G1 DELETE rows were read from draft #97 at
  `95ae3a46710134d5a46a57e17fe4a38224c89467`
  (`docs/finish-queue/G1-UPSTREAM-REUSE-DELETE-MATRIX.md`).
- G5's NO outcome and Token B second-grant requirement were read from
  `docs/finish-queue/G5-MCP-SUPABASE-TOPOLOGY-DECISION.md` on that same #97 head.
- Inspection was limited to that git tree. No application file on `main` was modified
  to produce this note.
