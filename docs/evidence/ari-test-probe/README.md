# Ari TEST synthetic probe packet

Controller packet only. Not executed from this branch. Not acceptance. Not a
merge, Pages, DNS, or publish step.

| | |
| --- | --- |
| Target | `odbcejsuuqdzhabjmozi` (org `pvooiyttujynxquxkqcr`, us-east-1) |
| Forbidden | `lygftpbjgqgvuunkwnxf`, HOUSE, VAULT, and any production project |
| Parent head | `1f021bccf747b778a11203096eada2a31b1885fb` still requires `role=authenticated` |
| Hook | Documented in `sql/02-hook-for-ariadne.sql`. Not installed by this packet. |
| Token B | Synthetic user password session. Positive control only. Not wired into MCP. |

## L2 — ingress role flip, not shipped

Do not install the hook until a reviewed adapter commit requires `mcp_ingress`
and rejects `role=authenticated`. This packet does not make that code change.
The probe refuses to send a `role=authenticated` bearer as Token A
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
| `sql/01-synthetic-fixture.sql` | Ariadne, after the throwaway user exists |
| `sql/02-hook-for-ariadne.sql` | Ariadne, only after Warden review and the role-flip commit |
| `probe.mjs` | Ariadne, only after Token A is actually `mcp_ingress` |

Local decision tests, with no network:

```bash
node --test docs/evidence/ari-test-probe/decisions.test.mjs
node docs/evidence/ari-test-probe/probe.mjs plan
```

## Ariadne controller commands

Unset every service-role variable in this shell first. Do not paste tokens
into git, chat, or the receipt.

```bash
unset SUPABASE_SERVICE_ROLE_KEY SUPABASE_SECRET_KEY SERVICE_ROLE_KEY SUPABASE_SERVICE_KEY
export ARI_TEST_PROJECT_REF=odbcejsuuqdzhabjmozi
export ARI_TEST_SUPABASE_URL=https://odbcejsuuqdzhabjmozi.supabase.co
export ARI_TEST_PUBLISHABLE_KEY   # publishable or anon key only
```

1. Confirm the dashboard ref is `odbcejsuuqdzhabjmozi`. Stop otherwise.
2. Run `sql/00-baseline-public-execute.sql` in the SQL editor. Keep the
   SECURITY DEFINER / PUBLIC EXECUTE listing with the review note (L7).
3. Create one Auth user, email
   `ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid`. No real person.
4. Run `sql/01-synthetic-fixture.sql`. Do not add `ari_probe` to Exposed
   schemas. Do not run `sql/02-hook-for-ariadne.sql` yet.
5. Stop. Wait for the reviewed role-flip commit, then run
   `sql/02-hook-for-ariadne.sql` and enable
   `ari_probe.custom_access_token_hook` on this project only.
6. Mint Token A through the MCP OAuth client. Mint Token B with the
   publishable key and the throwaway user's password:

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
| `GET /auth/v1/user` | Token A | non-2xx | 2xx is NO-GO; no later mutation is sent |
| `PUT /auth/v1/user` | Token A | non-2xx | 2xx is NO-GO |
| `POST /auth/v1/factors` | Token A | non-2xx | 2xx is NO-GO |
| `POST /auth/v1/logout` | Token A | non-2xx | 2xx is NO-GO |
| REST `/rest/v1/ari_probe_marker` | publishable, Token A, Token B | publishable and Token A do not contain the marker; Token B does | Token A contains the marker, or the publishable key does |
| GraphQL `/graphql/v1` | same pair | same marker rule | same |
| Storage `ari-probe-synthetic/marker.txt` | Token B seeds the object; then the same pair | same marker rule | same |
| Realtime private topic `ari-probe-synthetic` | Token A, Token B | Token A join is not `ok`; Token B join is `ok` | Token A join is `ok` |

Exit `0` means this matrix held. It does not mean acceptance or Token A
separation. Exit `2` is a target or credential guard. Exit `3` means Token A
was not sent because it is still `role=authenticated` or otherwise the wrong
shape. Exit `4` is NO-GO.

The handler on this branch rejects `user_metadata` authority fields. The hook
SQL does not read `user_metadata`.
