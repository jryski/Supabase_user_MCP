# Ari TEST synthetic probe packet

Controller packet only. Not executed from this branch. Not acceptance. Not a
merge, Pages, DNS, or publish step.

| | |
| --- | --- |
| Target | `odbcejsuuqdzhabjmozi` (org `pvooiyttujynxquxkqcr`, us-east-1) |
| Forbidden | `lygftpbjgqgvuunkwnxf`, HOUSE, VAULT, and any production project |
| Adapter | Requires `role=mcp_ingress`. Rejects `role=authenticated`. |
| Role SQL | `sql/03-mcp-ingress-role.sql`. Controller applies it on TEST. This agent does not. |
| Hook | `sql/04-hook-v2-for-ariadne.sql` is the review packet. Not installed. `sql/02` must not be applied. |
| Token B | Synthetic user password session. Positive control only. Not wired into MCP. |

## Verdict rules

Explicit permission denial is the only deny. `429`, `5xx`, redirects, transport
failures, and parse failures are `inconclusive` and use a nonzero exit. They
never produce `matrix_held`.

Token B positive controls require the expected status and the expected body.
A success-looking status with the wrong body is not a positive control.
Token B `GET /auth/v1/user` must be `200` with the same `id` as Token A before
any Token A Auth denial counts. Token A Auth denial is `401` or `403`. REST
denial is `401` or `403` with Postgres `42501`. GraphQL denial is HTTP `200`
with `data` present and `ariProbeMarkerCollection` absent, or HTTP `200`
whose `errors` name that collection or an unknown field. Any other GraphQL
status is inconclusive unless it is `401` or `403` with Postgres `42501`.
Storage denial is `404`, or `400`/`403` whose body names `not_found`,
`Object not found`, or `unauthorized`. A `DatabaseError` or any other `400`
is inconclusive. Realtime counts as denial only for an explicit unauthorized
reply. A generic or transport error is inconclusive.

A body with Postgres `22023`, or `role "…" does not exist`, is
`ingress_role_missing` on Auth, GraphQL, and Storage. That is a named
nonzero failure, not a denial. REST `400` with that body stays inconclusive.

Before those rows, Token A must verify: signature, expiry, the exact
registered OAuth client id supplied as `ARI_TEST_EXPECTED_CLIENT_ID`, and the
MCP-edge acceptance path (`403` `downstream_credential_unresolved`). A missing
client id stops with `oauth_client_id_required`. The probe does not substitute
a synthetic client id. A malformed or expired Token A stops before the Data
API. A signed `mcp_ingress` Token A is the validity control: this head's edge
accepts it and fail-closes. That acceptance is not Data API separation.

## L2 — ingress role check, landed in the adapter

The native-user adapter requires `role=mcp_ingress` and rejects
`role=authenticated`. It also rejects a nil or empty `session_id`. That
check is the claim shape only. The adapter has no liveness check.
`sql/03-mcp-ingress-role.sql` is the matching isolated role for the
controller. This agent does not apply it. Hook v2 is
`sql/04-hook-v2-for-ariadne.sql` and is not installed. Do not run the probe
or the consent harness against hosted TEST. Token B custody is still separate.

The probe still refuses to send a `role=authenticated` bearer as Token A
(`role_flip_prerequisite_missing`) and sends no API request in that case.

GoTrue's published hook schema lists `role` as `anon` or `authenticated`. If an
issued OAuth token still has `role=authenticated`, stop and report
`ingress_role_not_issued`. Do not substitute the password session for Token A.

## L4 — Token B custody fallback

Full Token B custody is not ready. The fallback is the throwaway user's own
password login. Label every use `POSITIVE_CONTROL_NOT_MCP`. The probe never
passes Token B to an MCP tool. Token A and Token B must be different strings
for the same `sub`. No `service_role` key is accepted in the probe shell.

## Files

| File | Who runs it |
| --- | --- |
| `sql/00-baseline-public-execute.sql` | Ariadne, read-only, before the fixture |
| `sql/01-synthetic-fixture.sql` | Ariadne, after the throwaway user exists. Do not recreate it. |
| `sql/03-mcp-ingress-role.sql` | Ariadne, on TEST only, one batch with `set_config`. Not this agent. |
| `sql/04-hook-v2-for-ariadne.sql` | Ariadne, only after Warden reviews v2. Not this agent. |
| `sql/02-hook-for-ariadne.sql` | Do not apply. Superseded by `sql/04`. |
| `hook-v2.mjs` | Local decision oracle. Kept only where the PGlite test asserts the same results as `sql/04`. |
| `hook-v2.pglite.test.mjs` | Loads `sql/04` verbatim in `@electric-sql/pglite`. No Docker and no hosted project. |
| `consent-harness.mjs` | `run` consents, exchanges, and calls the probe in one process. `openid-negative` is separate. Receipts are redacted. |
| `oauth-session-cleanup.md` | Reviewed cleanup for the synthetic OAuth session. Not executed from this branch. |
| `probe.mjs` | Not against hosted TEST in this slice. |

Local decision tests, with no network:

```bash
npm run build
node --test docs/evidence/ari-test-probe/decisions.test.mjs
node --test docs/evidence/ari-test-probe/hook-v2.test.mjs
node --test docs/evidence/ari-test-probe/hook-v2.pglite.test.mjs
node --test docs/evidence/ari-test-probe/consent-harness.test.mjs
npm run test:ari-packet
node docs/evidence/ari-test-probe/probe.mjs plan
node docs/evidence/ari-test-probe/consent-harness.mjs plan
```

The MCP-edge test imports `packages/server/dist`. Build first. Do not point
that test at a hosted project.

## Ariadne controller commands

Unset every service-role variable in this shell first. Do not paste tokens
into git, chat, or the receipt.

```bash
unset SUPABASE_SERVICE_ROLE_KEY SUPABASE_SECRET_KEY SERVICE_ROLE_KEY SUPABASE_SERVICE_KEY
export ARI_TEST_PROJECT_REF=odbcejsuuqdzhabjmozi
export ARI_TEST_SUPABASE_URL=https://odbcejsuuqdzhabjmozi.supabase.co
export ARI_TEST_PUBLISHABLE_KEY
export ARI_TEST_EXPECTED_CLIENT_ID   # exact registered OAuth client id
export ARI_TEST_JWKS_JSON   # public JWKS JSON only; no private key material
```

`ARI_TEST_EXPECTED_CLIENT_ID` is the exact client id registered on TEST.
Do not export a synthetic stand-in. The MCP resource is
`https://odbcejsuuqdzhabjmozi.supabase.co/mcp`.

SQL apply order. This agent does not run it.

1. Confirm the dashboard ref is `odbcejsuuqdzhabjmozi`. Stop otherwise.
2. If not already saved, run `sql/00-baseline-public-execute.sql`. Keep the
   SECURITY DEFINER / PUBLIC EXECUTE listing with the review note (L7).
3. If the throwaway user does not already exist, create one Auth user, email
   `ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid`. No real person.
   Do not recreate a user that is already there.
4. If not already applied, run `sql/01-synthetic-fixture.sql`. Do not add
   `ari_probe` to Exposed schemas.
5. In one SQL-editor batch, paste the setting and then the body of
   `sql/03-mcp-ingress-role.sql`. A second run will not see the setting.

   ```sql
   select set_config('ari.project_ref', 'odbcejsuuqdzhabjmozi', false);
   ```

6. Stop before the hook. `sql/03` may be applied by the controller. Do not
   apply `sql/02` or `sql/04` until Warden reviews hook v2. Do not run
   `probe.mjs run` against hosted TEST. Token B custody stays separate.

## Hook v2

`sql/04-hook-v2-for-ariadne.sql` is the install text. It is not installed
from this branch. The same batch must set `ari.project_ref`,
`ari.oauth_client_id` (the exact registered client id), `ari.mcp_resource`,
and `ari.agent_id`. Absent `client_id` returns claims unchanged. `openid`
raises for every OAuth client. An unmapped `client_id` raises. The mapped
client sets `aud` to the configured MCP resource, `role` to `mcp_ingress`,
`session_id` to `gen_random_uuid()` after it is checked non-nil and absent
from `auth.sessions`, `source_session_id` to the original session id, and
`agent_id` from `ari_probe.mcp_client`. Liveness runs on each hook call
only, for token issuance and refresh. It does not run on each MCP call.
The adapter has no liveness check. That check is not a revocation receipt.

Rollback, on the TEST ref only, after the dashboard hook is disabled:

```sql
drop function if exists ari_probe.custom_access_token_hook(jsonb);
drop table if exists ari_probe.mcp_client;
```

Do not drop the synthetic user, the marker fixture, or `mcp_ingress` in
that rollback.

Reviewed session cleanup, after a controller run, is
`oauth-session-cleanup.md`. It deletes one `auth.sessions` row by
`source_session_id` on TEST only. It is not executed from this branch and
it is not a revocation receipt.

## Loopback consent harness

The redirect is `http://127.0.0.1:<port>/callback`. The controller sets the
registered client's redirect and an explicit scope list that does not include
`openid` on the mapped mint. `consent-harness.mjs plan` prints the checklist
and does not dial out. `listenOnce` only records a redacted loopback receipt.
Those two commands do not consent and do not exchange a code.

`performConsent` performs consent: `GET /auth/v1/oauth/authorizations/{id}`
and `POST /auth/v1/oauth/authorizations/{id}/consent` with the synthetic
user's own session. `exchangeAuthorizationCode` and `runConsentExchange`
then `POST /auth/v1/oauth/token` with `grant_type=authorization_code`, the
code, and the S256 verifier. Receipts keep key names and drop token values,
codes, and verifiers. This agent does not run these calls against hosted
TEST.

`buildAuthorizeUrl` still refuses `openid`. The labelled path
`openid_negative` (`buildOpenIdNegativeAuthorizeUrl` and `runOpenIdNegative`)
sends `openid` on purpose. It expects failure and no `id_token`. The receipt
records `rejectionStage` as `authorize` or `exchange`.

`node docs/evidence/ari-test-probe/consent-harness.mjs run` is one process:
authorize, the synthetic user's password login, consent, code exchange, then
`runProbe`. Those consent and exchange steps are private helpers. The
exported consent and exchange functions return redacted receipts only.
Token A is the code-exchange access token. Token B is the password-login
access token. Both stay in memory. The command does not export them and
does not write them to a file. Stdout is only the redacted receipt.

`node docs/evidence/ari-test-probe/consent-harness.mjs openid-negative`
sends `openid` on purpose. It expects failure and no `id_token`. It does
not call `runProbe`.

Do not run either command against hosted TEST from this branch.
`consent-harness.mjs redact` reads a response on stdin and prints key names
only. Do not paste a verifier, authorization code, access token, refresh
token, or `id_token` into chat, git, or an artifact.

Discovery coverage, not fetched by this packet:

- OAuth authorization-server metadata:
  `/.well-known/oauth-authorization-server`. The later controller note is
  whether `code_challenge_methods_supported` includes `S256`.
- OIDC discovery: `/.well-known/openid-configuration`. Recorded only. It does
  not authorize an `id_token`. A body that contains `id_token` fails the
  receipt.

Controls for a later controller run, after hook review:

- Mapped client mint, scope without `openid`, code plus S256 PKCE.
- Token A on Auth routes is HTTP `403` with `error` `session_not_found`.
  That is the fresh session id missing from `auth.sessions`, not a
  revocation proof.
- Label `openid_negative` sends `openid` on purpose. Failure is recorded at
  authorize or at exchange. The receipt has no `id_token`.
- An unmapped `client_id` fails before a token is minted.
- Password login, with no `client_id`, is unchanged.
- Data API: Token A denied, Token B positive, labeled
  `POSITIVE_CONTROL_NOT_MCP`.
- MCP edge for Token A is `403` `downstream_credential_unresolved`.

Password login for Token B, only in that later run. Do not print the body.
Pipe it through redact and then discard it.

```bash
curl -sS -X POST "$ARI_TEST_SUPABASE_URL/auth/v1/token?grant_type=password" \
  -H "apikey: $ARI_TEST_PUBLISHABLE_KEY" \
  -H "content-type: application/json" \
  -d "{\"email\":\"ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid\",\"password\":\"$ARI_TEST_SYNTHETIC_PASSWORD\"}" \
  | node docs/evidence/ari-test-probe/consent-harness.mjs redact
```

Consent uses the synthetic user's session. Exchange uses the code from that
consent response and the S256 verifier from the authorize step. Pipe every
body through redact.

```bash
curl -sS \
  -H "Authorization: Bearer $ARI_TEST_SYNTHETIC_SESSION" \
  -H "apikey: $ARI_TEST_PUBLISHABLE_KEY" \
  "$ARI_TEST_SUPABASE_URL/auth/v1/oauth/authorizations/$ARI_TEST_AUTHORIZATION_ID" \
  | node docs/evidence/ari-test-probe/consent-harness.mjs redact
curl -sS -X POST \
  -H "Authorization: Bearer $ARI_TEST_SYNTHETIC_SESSION" \
  -H "apikey: $ARI_TEST_PUBLISHABLE_KEY" \
  -H "content-type: application/json" \
  -d '{"action":"approve"}' \
  "$ARI_TEST_SUPABASE_URL/auth/v1/oauth/authorizations/$ARI_TEST_AUTHORIZATION_ID/consent" \
  | node docs/evidence/ari-test-probe/consent-harness.mjs redact
curl -sS -X POST \
  -H "apikey: $ARI_TEST_PUBLISHABLE_KEY" \
  -H "content-type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "client_id=$ARI_TEST_EXPECTED_CLIENT_ID" \
  --data-urlencode "redirect_uri=http://127.0.0.1:8787/callback" \
  --data-urlencode "code=$ARI_TEST_AUTH_CODE" \
  --data-urlencode "code_verifier=$ARI_TEST_CODE_VERIFIER" \
  --data-urlencode "resource=https://odbcejsuuqdzhabjmozi.supabase.co/mcp" \
  "$ARI_TEST_SUPABASE_URL/auth/v1/oauth/token" \
  | node docs/evidence/ari-test-probe/consent-harness.mjs redact
```

Label `openid_negative`. This authorize URL sends `scope=openid` on purpose.
If this response is an error, record rejection at authorize and stop. If a
code is issued, run the consent commands above and then the token command.
A failed token response is rejection at exchange. A body that contains
`id_token` fails the receipt.

```bash
curl -sS \
  "$ARI_TEST_SUPABASE_URL/auth/v1/oauth/authorize?response_type=code&client_id=$ARI_TEST_EXPECTED_CLIENT_ID&redirect_uri=http%3A%2F%2F127.0.0.1%3A8787%2Fcallback&scope=openid%20email&code_challenge=$ARI_TEST_CODE_CHALLENGE&code_challenge_method=S256&resource=https%3A%2F%2Fodbcejsuuqdzhabjmozi.supabase.co%2Fmcp&state=openid-negative" \
  | node docs/evidence/ari-test-probe/consent-harness.mjs redact
```

## Probe matrix

| Row | Credential | Hold | Stop |
| --- | --- | --- | --- |
| `GET /auth/v1/user` | Token B | `200` and `id` matches Token A `sub` | any other result stops the matrix |
| `GET /auth/v1/user` | Token A | `401` or `403` | `2xx` is NO-GO; `429`, `5xx`, and redirects are inconclusive |
| `PUT /auth/v1/user` | Token A | `401` or `403` | `2xx` is NO-GO; other statuses are inconclusive |
| `POST /auth/v1/factors` | Token A | `401` or `403` | `2xx` is NO-GO; other statuses are inconclusive |
| `POST /auth/v1/logout` | Token A | `401` or `403` | `2xx` is NO-GO; other statuses are inconclusive |
| REST `/rest/v1/ari_probe_marker` | publishable, Token A, Token B | Token A is `401` or `403` with `42501`; Token B is `200` and a row `marker` | Token A contains the marker, or the status is not that denial |
| GraphQL `/graphql/v1` | same pair | Token A is HTTP `200` with `data` and no collection, or `errors` that name the collection; Token B is `200` and the marker node | Any other Token A GraphQL result, including a bare JSON object |
| Storage `ari-probe-synthetic/marker.txt` | Token B seed is `2xx` or `409`, then the same pair | Token A is `404`, or `400`/`403` naming not found or unauthorized; Token B GET is `200` and the marker bytes | Token A `400` `DatabaseError`, or any other `400` |
| Realtime private topic `ari-probe-synthetic` | Token A, Token B | Token A reply is explicit unauthorized; Token B join is `ok` | Token A join is `ok`, or the error is only transport |

Exit `0` means this matrix held. It does not mean acceptance or Token A
separation. Exit `2` is a target or credential guard. Exit `3` means Token A was not sent because it is still `role=authenticated`,
the registered client id was omitted, or the token is otherwise the wrong
shape. Exit `4` is NO-GO.

The handler on this branch rejects `user_metadata` authority fields. The hook
SQL does not read `user_metadata`.
