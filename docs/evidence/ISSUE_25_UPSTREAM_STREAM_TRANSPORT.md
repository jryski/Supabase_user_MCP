# Issue 25 upstream StreamTransport boundary

## Decision

Adopt `@supabase/mcp-utils` version `0.7.0` as an exact-pinned test dependency only.
The reviewed upstream source coordinate is
`supabase/mcp@74ebb264c67788da733709a7f713c657c3393fe7`.

The production server remains on the existing fixed `@modelcontextprotocol/server` implementation.
No generic upstream server adapter or PostgREST tool surface is introduced.

## Borrowed seam

The compatibility suite uses upstream `StreamTransport` to exercise a real MCP client and the
existing server in memory. It freezes:

- complete `tools/list` metadata and JSON Schema 2020-12 input/output schemas;
- successful text and structured compatibility-probe output; and
- strict rejection of unknown input keys.

## Rejected seams

A synthetic characterization test proves that upstream `hidden` affects discovery only: the tool
is absent from `tools/list` but remains callable through `tools/call`. Therefore this repository
must never use `hidden` as an authorization boundary or register excluded tools in the first place.

The following upstream surfaces remain excluded:

- generic `postgrestRequest`, `sqlToRest`, and OpenAPI resources;
- arbitrary caller-selected methods, paths, schemas, relations, or RPCs;
- CLI or environment credential loading;
- account-management PAT identity; and
- conflated publishable-key and user-JWT handling.

## Upgrade gate

For any `@supabase/mcp-utils` upgrade:

1. review and record the new upstream source coordinate;
2. retain an exact package pin;
3. run the StreamTransport compatibility and hidden-tool characterization tests;
4. run the complete repository check, Markdown lint, dependency audit, diff check, and changed-line
   security scan; and
5. reject the upgrade if public metadata or compatibility results drift without an accepted contract
   change.

All tests are synthetic and perform no network, PostgREST, credential, database, or production-data
operation.
