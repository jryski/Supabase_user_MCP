# Edge MCP pilot evidence (synthetic, local only)

This directory holds the source, tests and receipts for the local Supabase Edge Function MCP
pilot cited in [SAME_AUTHORITY_DELEGATION_PROFILE.md](../../SAME_AUTHORITY_DELEGATION_PROFILE.md) §9.

- It is evidence, not product code.
- It was copied from a private pilot repository at commit
  `53398f2de3c4873eb37e285aa4728d09e1601cd9`, which is `244b794` with this repository's Biome
  formatting applied. Formatting does not change behaviour: `deno check` and `bounded_test.ts`
  pass on the formatted files.
- `phase1-run5.json` was produced at `244b794`, before formatting. The receipt JSON files were
  reformatted by Biome; their content is unchanged.
- It never contacted a hosted project.
- Signing keys, the functions `.env` and local stack credentials are excluded.
- Local filesystem paths in the receipts are replaced with placeholders.

## Scope

**Phase 1 is authentication only:**

- OAuth discovery, dynamic registration, consent and authentication;
- `whoami` (claims only);
- one data tool that always returns `downstream_credential_unresolved`.

The inbound bearer token is never forwarded, and no admin client is constructed.

**Environment:**

- Supabase CLI 2.119.0;
- Auth v2.197.0;
- edge-runtime v1.77.1;
- Deno 2.9.7;
- local ES256 signing key, OAuth server enabled, `jwt_expiry = 90`.

## Receipts

**`receipts/phase1-run5.json`:** 16/16 checks through the local gateway and edge runtime, after the
ingress fix:

- `as_metadata`, `unauthenticated_401`, `protected_resource_metadata`;
- `oauth_grant_client_a`, `oauth_grant_without_resource`;
- `whoami_oauth_token`, `data_tool_fail_closed`, `oversized_body_413`;
- `first_party_session_refused`, `client_b_not_allowlisted_refused`;
- `unknown_key_refused`, `wrong_issuer_refused`, `wrong_audience_refused`, `expired_refused`;
- `minted_positive_control`, `revocation_observed`.

Runs 1 to 4 were made before the ingress fix. They are not included; their results matched apart
from runner fixes.

**Ingress fix (ATLAS MC1810):**

- `receipts/bounded-red.txt`: 4 of 6 `tests/bounded_test.ts` cases fail against the original
  wrapper. The failures are:
  - the deadline did not cover a slow body;
  - a slow handler was not aborted;
  - an already-aborted client signal was dropped;
  - a client disconnect was not propagated.
- `receipts/bounded-green.txt`: 6/6 pass with `supabase/functions/mcp/bounded.ts`, using Deno's
  default resource sanitizers.
- `receipts/bounded-mutants.json`: three deliberate breakages of the fix, each caught by at least
  one test:
  - starting the timer after the body is read;
  - not passing the signal to the handler;
  - not relaying client aborts.

**Gateway probe:**

- `receipts/gateway-slow-body-probe.json`: a chunked body sent with a 3.5 s gap through the local
  gateway reached the function only once complete.
- The function's 2 s deadline therefore never observed the slow body.
- This was measured on local Kong only; hosted behaviour is unmeasured.

## Limits

- Local stack only, with synthetic users. No Realtime or Storage containers were running.
- These are not hosted, Ari TEST or data-path receipts. None of the SACD data-path tests (CT-5D
  onward) has run.
- The pilot's handler-cancellation proof uses a stub handler. Whether the MCP SDK passes the
  request signal through to tool callbacks is not established here.

## Run locally

From `tests/`:

```sh
deno test bounded_test.ts
```

`phase1.ts` needs a running local stack with the OAuth server enabled and the following
environment variables:

- `PILOT_API`
- `PILOT_ANON_KEY`
- `PILOT_CLIENTS_FILE`
- `PILOT_SIGNING_KEYS`

## SHA-256

- `receipts/bounded-green.txt` `bd91b06beb6d6c15b0b03ffb03ce43df778e81c51d8d80ad9efed12e16d59e5b`
- `receipts/bounded-mutants.json` `f7c70617463f4fb30b7fd12ad436dc2b44ce7aae14467871857fc4e57564b4c7`
- `receipts/bounded-red.txt` `8cac6e420ee88cbaa4449d3e3fcc0e1f5a3b9a01f0b1b83e02854376de9a53a0`
- `receipts/gateway-slow-body-probe.json` `cb06e3d6cd5b0229d68d951a42a92874f915d98e9ff174f4b4ed0ab11a3f9eef`
- `receipts/phase1-run5.json` `78c41825a8db3658f5efd20f4ebd971f74aa0c7fd9e961b92a9c789b03a708b9`
- `supabase/config.toml` `33d7cd8fbfe0042118dce2cd9c759307de93ddbf77c94f8fc25312ad46743046`
- `supabase/functions/mcp/bounded.ts` `eb02d61df933f4ba7d7c9d0be4a02e849697fff1143199dc3b5acaf510311e5c`
- `supabase/functions/mcp/deno.json` `d2ab39f65b3c872258a89d36e8982194646f630a485a80d4526974829864562c`
- `supabase/functions/mcp/index.ts` `e09ff454c059405102f4fb85a459134ad2f9cc8c9609af203a86da11f4c378f0`
- `tests/bounded_test.ts` `4a9f8764f052475421273311eeb51ab3d049e1bbeb211175898d643fdd22046d`
- `tests/deno.json` `d2ab39f65b3c872258a89d36e8982194646f630a485a80d4526974829864562c`
- `tests/phase1.ts` `2fd314a0431e9d5a26e104bb0beed0a36441934ced1cb42bf7a45b5a533ff11c`
