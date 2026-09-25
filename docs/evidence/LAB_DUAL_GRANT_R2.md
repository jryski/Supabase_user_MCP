# Lab dual-grant broker (custody proposal r2)

- **Packet:** `DUAL_GRANT_R2_PACKET` lab slice only
- **Issue #62 completion:** no
- **Merge to `main`:** no
- **Hosted or live personal data:** no
- **ADR-0006:** unchanged. Ordinary remote dispatch stays fail-closed. This note does not
  move the Option 1 proof bar.

## What the opt-in does

`createRemoteHttpProfile` returns `403 downstream_credential_unresolved` unless a caller
passes an enabled lab hook. Process startup attaches that hook only when
`SUPABASE_USER_MCP_LAB_DUAL_GRANT` is exactly `1`. The ordinary `start:remote` command does
not pass the hook, so the flag alone does not open Data API dispatch.

The lab broker keeps two registrations:

| Registration | Issuer | Client | Presented to |
| --- | --- | --- | --- |
| MCP-facing | `Iss_M` (`http://127.0.0.1`) | `Client_M` | Remote HTTP verifier only |
| Supabase upstream | `Iss_U` | `Client_U` | Fixed `/rest/v1` and `GET /auth/v1/user` |

MCP tokens are ES256, signed with a process-ephemeral key. That key is not the project JWT
HMAC secret. Upstream access and refresh tokens, pending flows, grants, and the signing key
live in memory. Restart drops local usability and does not call provider revoke. There is no
encrypted refresh-at-rest store.

Browser login is credential class 3. It does not authorize `memory_*`. A pending flow binds
state, PKCE S256, the exact `http://127.0.0.1` redirect, issuer, parent flow, login session,
and the expected principal and client. Consume is one-time. `user_metadata` is not a mapping
source. `grant_family` / generation rejects a second upstream grant for the same principal
and upstream client.

Dispatch records upstream `exp` and also stops at `LOCAL_DISPATCH_TTL_MS` (15 minutes).
Refresh is single-flight and replaces the access token and refresh token together. The local
deadline does not move on refresh. Disconnect aborts the request signal only. Broker-local
revoke and provider revoke are separate clocks. The MCP verifier's 5 second bound is not a
Data API guarantee.

Authority is checked again at the outbound Data API fetch. Revoke, local deadline expiry, or
cleanup during `GET /auth/v1/user` does not let a later `/rest/v1` RPC return 200. Cleanup
bumps a lifecycle epoch. An in-flight code exchange, MCP signing admission, or refresh that
finishes after that epoch does not write the access token, refresh token, or mapping back.
Lab coordinates are parsed URLs: the MCP issuer and redirects are `http://127.0.0.1` with the
redirect host and port equal to the issuer, and a Data API origin is either that loopback host
or an `https` `*.invalid` fixture. Those routes stay separate. Loopback coordinates may use a
caller fetch, including the process network fetch. Fixture coordinates reject every caller
fetch. The only fixture selector is the literal `fixtureTransport: 'broker-scripted'`, and the
broker then answers `/auth/v1/user` and the memory RPCs itself. A thin wrapper around
`globalThis.fetch`, a native fetch, a bound fetch, or a missing selector is rejected with
`contract_fixture_not_a_network_target` before the callback runs. Mixing that literal with a
fetch callback, or setting it on loopback coordinates, is the same rejection. A rejected refresh
clears its single-flight entry on both settlement paths so the 403 does not leave an unhandled
rejection.

## F1–F4 repair

Reviewed head `8a43d81e8b6d3db7557cde8daa109e068dfe8c43` failed four fail-closed checks. The
repair closes them in the lab broker only:

| Finding | Closure |
| --- | --- |
| F1 | Current grant generation, revocation, local deadline, mapping, session, and lifecycle epoch are enforced inside the guarded fetch, immediately before `/auth/v1/user` and `/rest/v1`. |
| F2 | `cleanup` / `discardMemoryCustody` increment a lifecycle epoch. Post-await parent, session, and flow checks drop stale exchange, signing, and refresh completions. |
| F3 | Issuer, redirect, upstream, and Data API coordinates use parsed scheme, host, port, and path checks. Prefix lookalikes, userinfo, and non-loopback HTTPS origins are rejected in configuration. `https://*.invalid` fixtures use the broker-owned scripted responder selected by `fixtureTransport: 'broker-scripted'`. Caller fetch callbacks are not that responder. Loopback `http://127.0.0.1` is the runtime transport and may receive a fetch function. |
| F4 | Refresh flight cleanup handles fulfillment and rejection. Concurrent waiters receive HTTP 403. |

Authenticated lab `initialize` and `tools/list` are answered by the same `McpServer` registration
as the local read-only server (`supabase-user-mcp` / `0.1.0-alpha.1`, the three memory tool
schemas). An in-process `@modelcontextprotocol/client` drives `initialize`, then `tools/list`,
then `tools/call`. The receipt records that client's name and version. Ordinary remote without
the lab hook still returns `403` and does not call the Data API. Mock owner filtering is not
RLS. An external MCP client binary was not run. The disposable loopback harness below is the
closest executable form of T3, T4, T5, T10, and T17 against local GoTrue and Postgres RLS.
A synthetic pass is not that receipt.

`https://mcp.loopback.invalid/mcp` stays a contract fixture. The callback listener binds
`127.0.0.1` only.

## How to run

```bash
npm run test:lab-dual-grant
npm run test:lab-dual-grant-m4
```

`test:lab-dual-grant` builds, then runs the broker matrix, the ordinary remote HTTP profile
tests, and the OAuth policy contract tests. It does not start Docker or Supabase.
`npm run test:remote-oauth` remains the separate M4 loopback script and still expects
fail-closed dispatch. It does not set `SUPABASE_USER_MCP_LAB_DUAL_GRANT`.

`test:lab-dual-grant-m4` (`supabase/tests/run-lab-dual-grant-m4.sh`) is the live harness.
It needs Docker and the local Supabase CLI. The stack binds with
`host_binding_ipv4=127.0.0.1`. The script registers two temporary public OAuth clients,
builds `createLabDualGrantBroker` with loopback `fetch`, and passes the profile hook into
remote HTTP startup only together with `SUPABASE_USER_MCP_LAB_DUAL_GRANT=1`. Either control
alone stays fail-closed. If the Docker daemon is not available, the script exits without a
pass receipt. Cursor cloud VMs often cannot run this live path; the harness is still the
command to run on a Docker host such as Locutus. The receipt names the in-process
`@modelcontextprotocol/client` package and version. It is not an external MCP binary, not
hosted Auth, and not issue #62 completion.

## State machine

```text
login_session_open (class 3)
  -> mcp_authorization_pending
  -> upstream_authorization_pending
  -> upstream_grant_active (class 2, memory)
  -> mcp_token_issued (class 1)
  -> local_dispatch | refreshing
  -> request_cancelled (grant kept) | local deadline | reauth_required | locally_revoked
restart -> reauth_required, provider grant untouched
```

## Non-claims

- Not a native Supabase token exchange.
- Not proof, by itself, against a live GoTrue project or real RLS policies. The synthetic
  matrix uses a scripted upstream. Loopback tests in that suite supply a fetch double.
  `.invalid` fixtures use the broker-owned scripted responder and do not treat a caller fetch
  as a no-network proof. `npm run test:lab-dual-grant-m4` is the separate live loopback run.
- Not an external maintained MCP client binary. The in-process SDK client does exercise
  `initialize`, `tools/list`, and `tools/call`. The live receipt pins that package name and
  version when the Docker harness passes. T3 is not an external-binary claim.
- Not encrypted refresh custody, hosted activation, or issue #62 completion.
- Not a merge, and not a claim that F1–F4 closure finishes r2 acceptance.
