# Multi-user application candidate verification

This candidate starts from PR139 head
`3b7cf86685836227f5ede9e31ed4c85aa85ecb53` and ports PR126's contract from
`ad1e847d28c138fb6d0e971b7075c636752d262c`. PR135 is not included. No production
service, project, client, permission, migration or storage bucket was changed.

## Implemented

- Exported finite capability contracts, compiled release-approval loader,
  immutable startup profile, bounded user-scoped Data API adapter and server
  composition. The shipped approval list is empty.
- Explicit native application handler and application server for granted storage
  create/delete and approved proposals. Default/read-only composition clamps
  storage writes even when its storage configuration requests them.
- Hosted own-user OAuth consent GET/POST handler with exact client, callback,
  scope, fresh session and one-time challenge binding. The host must still mount
  the handler with its verified-session and atomic-store adapters.
- Native ingress and tool-governor deadline/cancellation handling, suppression of
  late results and concurrency leases retained until the real provider settles.
- Portable migration-fixture paths, stable boundary-report paths and stronger
  credential-file identity checks. Unsupported Windows ACL verification still
  fails closed.

The native generic capability seam gets its downstream client ID from the
signature-verified B grant. Its current database-policy binding still requires
`app_metadata.client_id`; top-level-only tokens remain refused for that extension.
This is not acceptance of the separate client-binding ADR.

## Actual verification

On Windows with Node22.23.2 and declared npm11.19.0:

```text
npm run check
Test Files 84 passed | 2 skipped (86)
Tests 1457 passed | 6 skipped (1463)
```

The command includes format, lint, full typecheck, build and all repository
Vitest suites. Lint retains three existing optional-chain warnings in the
synthetic OAuth lab; no lint errors. Markdown lint0.20.0 over all67 Markdown
files reported zero errors before this evidence file was added; this file is
included in the final documentation check.

The full run includes the real storage tools and user-scoped HTTP client over
PGlite RLS, cross-principal storage denials, human/delegation revocation,
grant-gated mutation behavior and delete-guard negatives. It is not a hosted
Storage service acceptance result.

New complete native integration tests exercise signed ingress A, separate
one-time B exchange, source liveness, a nonempty synthetically approved startup
profile, SDK tool listing/call, two concurrent users and subsequent revocation.
Production approvals stay empty; the synthetic release is mocked only in tests.

A separate reviewer agent reproduced the original late-storage-result defect,
then verified the corrected compiled code: a cancelled upload returns a timeout;
another call is refused while the underlying upload remains unsettled; its
settlement restores the slot without a late success event. The reviewer also
checked hosted consent, native ingress, client binding and credential-file
changes. This is independent agent review, not maintainer approval or live-user
acceptance.

## Remaining adoption gates

- Maintainer acceptance of ADR0007, reviewed adopter RPCs and exact descriptor
  approvals; proposal RPCs need durable idempotency/receipt reconciliation.
- ADR0009's storage-layout/agent-prefix decision and real-stack storage
  acceptance under the intended users and policies.
- Actual host consent-route mounting and durable downstream credential custody.
  The reference native grant store remains process-memory-only.
- Exact deployment artifact/runtime qualification and own-client
  isolation/revocation acceptance. A passing synthetic suite does not activate
  an application surface or provision a user.

See [application composition](../MULTI_USER_APPLICATION_COMPOSITION.md),
[capability registration](../CAPABILITY_REGISTRATION.md) and
[hosted consent](../HOSTED_OAUTH_CONSENT.md) for integration and rollback details.
