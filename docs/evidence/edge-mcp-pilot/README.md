# Edge MCP pilot evidence (synthetic, local only)

This directory holds the source, tests and receipts for the local pilot cited in
[SAME_AUTHORITY_DELEGATION_PROFILE.md](../../SAME_AUTHORITY_DELEGATION_PROFILE.md) §9.

- It is evidence, not product code, and it never contacted a hosted project.
- It was copied from a private pilot repository at commit `5bc6870f37357c467c6621dcab55556008de70c1`.
  That commit applies this repository's Biome formatting to `22b51d3`, with no behaviour change:
  `deno check`, the wrapper tests and the SDK tests were re-run on the formatted files.
- Receipts were produced at `22b51d3`. Biome reformatted the receipt JSON, but its content is
  unchanged.
- Signing keys, the functions `.env` and local stack credentials are excluded.
- Local paths in receipts are replaced with placeholders.

## Environment

- Supabase CLI 2.119.0, Auth v2.197.0, edge-runtime v1.77.1, PostgreSQL 17.11, Deno 2.9.7.
- A local ES256 signing key, the OAuth 2.1 server with dynamic registration, and `jwt_expiry = 90`.
- The `mcp_api` schema is exposed. The SACD Custom Access Token Hook is
  `mcp_cap.custom_access_token_hook`.

## Contents

**Phase 1 authentication-only MCP function:**

- `supabase/functions/mcp/index.ts`, which never forwards the inbound token and builds no admin
  client;
- `supabase/functions/mcp/bounded.ts`, the ingress and response-lifetime bounds.

**SACD minimal proof:** `supabase/migrations/`.

- `..._sacd_roles_tables.sql` and `..._sacd_functions.sql` create:
  - the capability role and the capability owner role;
  - the registry tables and the session policy table;
  - the liveness oracle and the guard;
  - the single capability function `mcp_api.list_own_v1`;
  - the hook.
- `..._positive_control_app.sql` adds an ordinary app table and function. They prove that the
  denial routes are real.
- `..._proof_only_bounds.sql` adds test-only capability functions for the timeout tests. They are
  not part of any real deployment.

**Tests:**

- `tests/phase1.ts`: authentication-only acceptance, run against a complete expected-ID set.
- `tests/sacd-proof.ts`: the SACD minimal proof, run against a complete expected-ID set.
- `tests/bounded_test.ts` and `tests/bounded_lifetime_test.ts`: the wrapper unit tests.
- `tests/sdk_cancellation_test.ts`: the real MCP SDK with a delayed tool, an SSE response and a
  downstream fetch.

## Receipts

**`receipts/phase1-run6.json`.** 16 of 16 checks pass, run through the local gateway and edge
runtime. Its phase 1 clients are declared non-MCP clients, so the hook leaves their tokens
unchanged. `measurements` records the JWKS-only acceptance after revocation. That is a known gap,
and it is not counted as a pass.

**`receipts/sacd-proof-green.json`.** 44 of 44 checks pass. `receipts/sacd-proof-mutants.json`
records six deliberate breakages, each caught:

- no guard call;
- no session check;
- no registry check;
- a hook that maps any client;
- an oracle that ignores the session policy;
- no role timeouts.

**Wrapper tests:**

- `receipts/bounded-red.txt` and `receipts/bounded-green.txt`: the first six wrapper tests, before
  and after the ingress fix.
- `receipts/bounded-mutants.json`: three breakages of the ingress fix.
- `receipts/bounded-lifetime-red.txt` and `receipts/bounded-lifetime-green.txt`: the
  response-lifetime and early-refusal tests, 3 of 4 failing before the fix and 10 of 10 wrapper
  tests passing after.
- `receipts/bounded-lifetime-mutants.json`: three breakages of the lifetime fix.

**Real MCP SDK:**

- `receipts/sdk-cancellation-prefix-red.txt`: run against the wrapper before the lifetime fix. The
  late result was delivered after about 2 s, and the downstream request was never aborted.
- `receipts/sdk-cancellation-green.txt`: run against the fixed wrapper. The stream ended at the
  deadline, and the downstream request was aborted on both the deadline and a disconnect. This
  run used `--unstable-no-legacy-abort`, so a signal abort only means a dropped connection.

**`receipts/gateway-slow-body-probe.json`.** The request body was buffered before it reached the
function. The probe does not isolate whether that happened in the gateway, the runtime or
delivery.

## Limits

- Everything ran on the local stack only, with synthetic users. Realtime and Storage containers
  were not running.
- None of these are hosted or Ari TEST receipts.
- CT-8 (Realtime and the other platform surfaces), CT-11 (writes), CT-17 and CT-18 have not run.
  The MCP function's tools are not yet wired to the capability function.
- The liveness oracle is owned by the migration role. That ownership is a reviewed exception
  (profile SACD-8).

## SHA-256

- `receipts/bounded-green.txt` `bd91b06beb6d6c15b0b03ffb03ce43df778e81c51d8d80ad9efed12e16d59e5b`
- `receipts/bounded-lifetime-green.txt` `84e92cf75517a22429df94e53baf2298236e448a5e43da7bc6879f910991c08e`
- `receipts/bounded-lifetime-mutants.json` `d852286fce0400008ce7eca5bebc79b41718a94307085d47766b626e02113655`
- `receipts/bounded-lifetime-red.txt` `5a436de67b3be1f34c7975f43f9a95d6c3f0dd31a2d78dc33f72d77f521e6583`
- `receipts/bounded-mutants.json` `f7c70617463f4fb30b7fd12ad436dc2b44ce7aae14467871857fc4e57564b4c7`
- `receipts/bounded-red.txt` `8cac6e420ee88cbaa4449d3e3fcc0e1f5a3b9a01f0b1b83e02854376de9a53a0`
- `receipts/gateway-slow-body-probe.json` `0e43b821194d6d40a6abafc504b3857189f4f68333b8d6585668713f3a22edef`
- `receipts/phase1-run6.json` `442bb6534af51a3510af6cb2e718e3ff061fa95e478ea0b89a15a22282da359c`
- `receipts/sacd-proof-green.json` `cef543069f31ff93a504b45a048b9ec138a10ccff247295a1d934c56d4edbca4`
- `receipts/sacd-proof-mutants.json` `9fd37e33bdba7ef2679cd6be657b39b26a76db40969ab6c6d9d637056a3ad82f`
- `receipts/sdk-cancellation-green.txt` `6a2e4779c52b829a3e26d32dbabfe5e7145306ec9089d4f1cc42c72c9f801445`
- `receipts/sdk-cancellation-prefix-red.txt` `3e31ebcb8038682c1580ed6e4f68762cd09258cd62aa16f29e28c0ed7c84bc12`
- `supabase/config.toml` `e7ece50e77500678ac9e547054239c2ed412cf03a81ddb5749ebea3c03238a9b`
- `supabase/functions/mcp/bounded.ts` `9e49c0c85330975c98ee12a11c021b327f33d39d92096c31a0fdf98657f74acc`
- `supabase/functions/mcp/deno.json` `d2ab39f65b3c872258a89d36e8982194646f630a485a80d4526974829864562c`
- `supabase/functions/mcp/index.ts` `e09ff454c059405102f4fb85a459134ad2f9cc8c9609af203a86da11f4c378f0`
- `supabase/migrations/20261004000001_sacd_roles_tables.sql` `8880c4bb96bc87ea651719e4860c30d1dff36714fac2fdd4cdedb2cb9389130c`
- `supabase/migrations/20261004000002_sacd_functions.sql` `42e10746b296b86b24e79fb8c20b64f970a41556635e98884cec105045f1e588`
- `supabase/migrations/20261004000003_positive_control_app.sql` `3a6cb59655b59db481e2918fd78698d33f79c38ef1c87172e2e7f7dbab3d967c`
- `supabase/migrations/20261004000004_proof_only_bounds.sql` `08be98a132927dd08826e26fbe5217e460c2680bbffc5f080f43c8c7b0d6b782`
- `tests/bounded_lifetime_test.ts` `e3b313d0347492bb9a877969c902b0068ae19da8d60685ec0f52d48fae53f66a`
- `tests/bounded_test.ts` `4a9f8764f052475421273311eeb51ab3d049e1bbeb211175898d643fdd22046d`
- `tests/deno.json` `d2ab39f65b3c872258a89d36e8982194646f630a485a80d4526974829864562c`
- `tests/phase1.ts` `86a21002b7a507a6aa154ea17ebe55b39acd769df26bc1d821630cb624d326c3`
- `tests/sacd-proof.ts` `a2bb26db1d9737075f447211d184d6cdb9b41eeb6a4f8793634f9d75e79d45a1`
- `tests/sdk_cancellation_test.ts` `05cb5f0c9e21de5503fc33b443faab4939685defb5c80e6e795a9a33b4efef56`
