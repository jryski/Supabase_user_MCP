# Memory identifier and fixed-schema compatibility candidate

Status: local, synthetic, uncommitted preparation. No upstream claim, independent
review, merge, deployment or credential/permission change is asserted.

## Source and purpose

[Issue #77](https://github.com/jryski/Supabase_user_MCP/issues/77) reports that
requiring `mem_` identifiers and a fixed `memory` schema prevents a consumer with
existing UUID records and fixed RPC facades from using the reader.

This candidate is stacked on PR #147 at
`4459c635374da7350b6fe70e896ea243e259fd89`. It reuses the four existing commits on
`compat/production-rpc-schema-uuid-ids-77`, ending at
`5f9b16fbea7c1694978a20c3b0cf6b8f6a25de80`:

- `8beacb3`: UUID identifier support;
- `88ee85d`: a UUID contract regression;
- `9a64fb9`: startup-fixed schema configuration;
- `5f9b16f`: stdio environment wiring.

Their original authorship and sign-offs remain in the source repository. The
combined local patch does not make a new contributor certification or transfer
ownership of PR #147.

## Behavior

- Get inputs and get/search/recent output contracts accept canonical hyphenated
  UUIDs with the RFC variant bits, preserving their spelling. The original
  case-sensitive `mem_` prefix and length bounds remain accepted.
- Trusted construction may supply `FixedSupabaseClientConfig.rpcSchema`.
  Omission selects `memory`. After trimming, it must match
  `^[a-z][a-z0-9_]{0,62}$`. Non-string values are refused with the fixed existing
  configuration error before fetching. The client snapshots the schema once.
- Stdio reads the optional `SUPABASE_USER_MCP_RPC_SCHEMA` environment value.
  This does not make native/remote entrypoints consume that variable.
- The three RPC names, exact project origin, user credential, tool arguments,
  response keys, governance and database-owned authorization remain unchanged.
  The fixed client's existing legacy list route uses the same fixed profile.
  Auth verification never receives a schema profile header.
- No generic registry descriptor is approved. In particular, this fixed memory
  seam does not relax ADR-0007's separate generic capability-schema rules.

Two issues found while qualifying the old patch were corrected: its global
case-insensitive flag accidentally admitted `MEM_` identifiers, and `null` or
non-string schema values did not receive the fixed configuration error.

## Verification

Windows, Node 22.23.2, npm 11.19.0; pinned PR #147 lockfile unchanged. Dependencies
were installed into the isolated checkout with lifecycle scripts disabled.
Vitest used one worker.

- New initial 30-case suite on unchanged PR #147: 13 pass, 17 fail, reproducing
  missing UUID/schema behavior. This is a missing-feature control, not a claim
  that main's existing tests fail.
- Same 30 cases on the unchanged original compatibility patch: 26 pass, 4 fail,
  identifying uppercase-prefix and malformed-schema error behavior.
- Final focused suite: 31 pass, 0 fail. The additional case uses the actual MCP
  SDK and registered tools over an in-memory transport, with a synthetic HTTP
  adapter. UUID get/search/recent complete and the three-tool list is unchanged.
- Full repository format, lint and typecheck pass. Lint retains the three
  pre-existing optional-chain warnings in `synthetic-oauth-lab.ts`.
- Full Vitest run: 1,487 pass, 1 fail, 6 existing skips. The failure is the
  listener's 4 MiB chunked-body case: Windows denied its loopback connection
  with `EACCES`. Rechecking that entire 14-test listener file outside the network
  sandbox passes 14/14. No test was removed, weakened or newly skipped.

Tests cover default opaque request/response bytes, uppercase/lowercase UUIDs,
malformed identifiers, schema bounds and refusal, immutable startup routing,
fixed RPCs, rejected tool routing/identity overrides, strict response keys,
unavailable results, unchanged Auth headers and stdio environment composition.

No hosted database, native sign-in, current source policy, real client or live
deployment acceptance was performed. No Docker database or inference was started.

## Integration gates

The repository's steward-recorded claim process still applies before an upstream
code PR. This local candidate is not a claim confirmation. The maintainer must
choose the landing base and review the public-contract change under GOVERNANCE.
PR #147 itself is draft and stacked on #139; neither becomes accepted here.
Independent review and the relevant CI/leak gate remain required at the eventual
submitted commit. No exact-head trusted CI result exists for this local patch.

Native/remote schema selection, a supported operator schema/facade mapping, and
deployment-specific grants require the owning native adapter lane. Do not infer
that an environment variable alone makes a deployed consumer compatible. The
public source does not establish the private consumer's deployed revision.

The current platform direction was checked against the
[Supabase changelog](https://supabase.com/changelog) and the official
[custom schema guide](https://supabase.com/docs/guides/api/using-custom-schemas).
Selecting a profile does not create schema exposure, grants or RLS policies.
