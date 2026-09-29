# Ari TEST synthetic probe packet

Controller packet only. Not executed from this branch. Not acceptance. Not a
merge, Pages, DNS, or publish step.

| | |
| --- | --- |
| Target | `odbcejsuuqdzhabjmozi` (org `pvooiyttujynxquxkqcr`, us-east-1) |
| Forbidden | `lygftpbjgqgvuunkwnxf`, HOUSE, VAULT, and any production project |
| Adapter | Requires `role=mcp_ingress`. Rejects `role=authenticated`. |
| Role SQL | `sql/03-mcp-ingress-role.sql`. Controller applies it on TEST. This agent does not. |
| Hook | Documented in `sql/02-hook-for-ariadne.sql`. Not installed. R3 and R4 are still open. |
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
`role=authenticated`. `sql/03-mcp-ingress-role.sql` is the matching isolated
role for the controller. This agent does not apply it and does not install
`sql/02-hook-for-ariadne.sql`. R3 (exact client id in the hook) and R4
(`session_id`) are still open. Do not run the probe against hosted TEST.
Token B custody is still separate.

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
| `sql/03-mcp-ingress-role.sql` | Ariadne, on TEST only, after the dashboard ref check. Not this agent. |
| `sql/02-hook-for-ariadne.sql` | Not in this slice. Blocked on R3/R4. |
| `probe.mjs` | Not against hosted TEST in this slice. |

Local decision tests, with no network:

```bash
npm run build
node --test docs/evidence/ari-test-probe/decisions.test.mjs
node docs/evidence/ari-test-probe/probe.mjs plan
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
5. In that SQL editor session, attest the TEST ref and run
   `sql/03-mcp-ingress-role.sql`:

```sql
select set_config('ari.project_ref', 'odbcejsuuqdzhabjmozi', false);
```

6. Stop. Do not run `sql/02-hook-for-ariadne.sql`. Do not enable
   `ari_probe.custom_access_token_hook`. Do not run `probe.mjs run` against
   hosted TEST. R3, R4, and Token B custody are still open.
7. Later, only after those are reviewed: mint Token A through the registered
   MCP OAuth client. Mint Token B with the publishable key and the throwaway
   user's password:

```bash
curl -sS -X POST "$ARI_TEST_SUPABASE_URL/auth/v1/token?grant_type=password" \
  -H "apikey: $ARI_TEST_PUBLISHABLE_KEY" \
  -H "content-type: application/json" \
  -d "{\"email\":\"ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid\",\"password\":\"$ARI_TEST_SYNTHETIC_PASSWORD\"}"
```

Export `access_token` as `ARI_TEST_TOKEN_B` and the OAuth token as
`ARI_TEST_TOKEN_A`. Discard both when the probe is done.

```bash
export ARI_TEST_TOKEN_A
export ARI_TEST_TOKEN_B
node docs/evidence/ari-test-probe/probe.mjs run
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
