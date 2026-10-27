# ADR-0008: OAuth client id claim for the policy grant check

- **Status:** Proposed — awaiting a decision by Primary Users
- **Date:** 2026-10-27
- **Owners:** Maintainers
- **Milestone:** M4

## Context

The grant check in `policy_lab` reads the calling client from
`auth.jwt() -> 'app_metadata' ->> 'client_id'`
(`supabase/migrations/20260830000100_memory_read_rpc.sql`). Supabase OAuth 2.1 access tokens
carry the OAuth client as a top-level `client_id` claim instead. A Data API token issued
through the OAuth server, such as grant B in the native read composition, may therefore not
match any client row under the current policies.

`supabase/migrations/20260906000100_oauth_client_claim.sql` addresses this for the local lab.
It adds `policy_lab.verified_client_id()`, which returns the top-level `client_id` if present
and otherwise `app_metadata.client_id`, and never reads `user_metadata`. It recreates the
client, membership, grant, memory, and audit policies and `policy_lab.has_active_capability`
on top of that function. It also adds `policy_lab.custom_access_token_hook`, which binds
OAuth access tokens to the lab MCP resource. The migration is unchanged from the change that
introduced it.

## Security constraints

- The client id that the grant check uses must come from a server-controlled claim. Both
  candidate claims are set by Auth; `user_metadata` stays excluded.
- The two-grant split (Token A for MCP, grant B for the Data API) does not change.
- The grant check must stay a single, reviewed definition. Two sources for the client id
  widen what can satisfy it.

## Decision drivers

- The read composition's Data API calls need a grant check that recognises OAuth clients.
- Any change to what the grant check accepts needs explicit review.
- The repair of the read composition must not depend on this change.

## Options considered

### Option A — Keep `app_metadata.client_id` only

No change to the grant check. OAuth-issued Data API tokens may fail the policies unless Auth
also writes `app_metadata.client_id`.

### Option B — Accept top-level `client_id`, fall back to `app_metadata.client_id`

The lab migration as written. Recognises OAuth tokens and keeps password-grant tokens working.
Widens the grant check to two claim sources.

### Option C — Accept top-level `client_id` only for OAuth-issued tokens

Narrower than Option B, but it needs a reliable server-side signal that a token came from the
OAuth server. Not designed yet.

## Decision

None yet. This branch carries Option B unchanged so that Primary Users can review it on its
own. The read composition repair does not include it.

## Consequences

### Positive

- The grant-check change gets a separate review and a separate merge decision.

### Negative

- Until a decision lands, the live local PKCE lab (`npm run test:remote-oauth`) is not part of
  the main line, and hosted grant-B reads may be denied by the policies.

### Follow-up

- Primary Users choose Option A, B, or C before this branch is proposed for merge.

## Validation

- `supabase/tests/database/oauth_client_claim_test.sql` (pgTAP, local lab).
- `npm run test:remote-oauth` (local Supabase CLI lab, synthetic users only).

## Revisit when

- Supabase Auth documents a supported way to place the OAuth client in `app_metadata`, or to
  tell OAuth-issued tokens apart server-side.

## References

- [ADR-0005](0005-dual-resource-data-api-binding.md)
- `supabase/migrations/20260830000100_memory_read_rpc.sql`
- `supabase/migrations/20260906000100_oauth_client_claim.sql`
