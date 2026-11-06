# Hosted OAuth consent adapter

The native MCP adapter verifies inbound Token A, while the existing application
owns its signed-in browser session. `createHostedOAuthConsentHandler` now provides
the missing hosted consent page and decision route over the existing
`createOAuthConsentBlock` and official Supabase `auth.oauth` methods. It neither
creates a login method nor changes Token A / downstream grant B separation.

Mount it at the **exact HTTPS URL** configured as the project's OAuth
authorization path. The same route serves GET and POST. This adapter is an
implementation for the hosting app to mount, not evidence that any deployed
application has mounted it or any person has accepted consent.

```ts
import { createHostedOAuthConsentHandler } from '@supabase-user-mcp/server';

// Both integrations below belong to the existing signed-in hosting app.
// `verifyCurrentSession` must validate with Auth on every request; cookie
// decoding or trusting a browser-supplied user id/getSession is insufficient.
// Its OAuth API must use this same verified user's session, never an admin key.
const handleConsent = createHostedOAuthConsentHandler({
  routeUrl: 'https://portal.example.test/oauth/consent',
  binding: {
    expectedClientId: APPROVED_CLIENT_ID,
    redirectUris: [EXACT_REGISTERED_CALLBACK],
    allowedScopes: ['openid', 'email'],
  },
  getVerifiedSession: async (request, signal) => {
    const verified = await verifyCurrentSession(request, signal);
    if (!verified) return undefined;
    return {
      userId: verified.user.id,
      // An opaque host session identifier. Do not put a bearer token here.
      sessionId: verified.opaqueSessionId,
      oauth: verified.userScopedClient.auth.oauth,
    };
  },
  challenges: existingAtomicConsentChallengeStore,
});

export const GET = handleConsent;
export const POST = handleConsent;
```

The `verifyCurrentSession` and `existingAtomicConsentChallengeStore` names above
are host integration contracts, not new repository APIs. The host retains its
existing cookie/session refresh machinery. Mount using an adapter that preserves
the exact public URL, Origin header and request abort signal. Do not derive the
public URL from untrusted forwarded headers. The handler enforces a fixed
15-second overall deadline, bounds streamed body reads, and passes its deadline
signal to the host verifier. It stops further consent dispatch after deadline or
caller cancellation, even if a provider ignores cancellation. The Supabase OAuth
API does not expose an AbortSignal for these methods: an already-dispatched
decision may still commit after a lost/timed-out response. Its nonce remains
consumed and the response is an unknown outcome, never an automatic retry.
The host should also enforce its usual connection/body and provider timeouts.

The challenge store must implement atomic `putIfAbsent` and destructive `take`
across all instances that can serve the route. It holds only nonce-keyed user ID,
opaque session ID, authorization ID, the viewed-detail SHA256 and expiry. Bound
its total entries and expire stale rows. Store outage fails closed with 503.
There is deliberately no in-memory default or credential-store fallback: a
per-process Map does not establish replay exclusion across multiple instances.
If a store response is lost, preserve its unknown outcome; start a fresh Auth
authorization rather than replaying an old form.

GET checks the one configured OAuth client, exact registered callback, allowed
nonempty scopes and current user before showing the form. No consent is automatically
approved. POST requires exact same-origin Origin, a one-time nonce bound to the
same verified user/session, an unexpired five-minute challenge and the exact
client/name/callback/scopes the person viewed. The decision re-read is checked
against the challenge before the official approve or deny method runs. A changed
account, request or session requires a fresh authorization. Concurrent submissions
can make at most one upstream decision if the store meets its atomic contract.

All responses use `Cache-Control: no-store`, `Referrer-Policy: no-referrer`,
`frame-ancestors 'none'`, a restrictive CSP and `nosniff`. The plain HTML form
requires no third-party assets or JavaScript. Upstream labels are escaped and
bounded. Client binding and user information never come from form fields.
POST bodies are bounded to 2048 bytes; duplicates, extra fields, unsupported
decision values and cross-origin requests are refused.

A successful decision returns a 303 only to the pre-bound callback, preserving
Auth's returned OAuth state. A missing verified session returns 401. A changed,
expired, consumed or unavailable outcome returns 409. Other host/API failures
return fixed 503 text. No upstream error, user/session token or authorization
payload is included in these errors. The nonce is consumed **before** an upstream
decision: a lost decision response is not retried. Restart authorization and let
Auth report the current consent status. Already-recorded consent may redirect to
the bound callback without another approval write.

Denial here rejects the pending OAuth request; it does not revoke every existing
OAuth grant. Existing connection revocation and live-session liveness remain the
separate upstream/native controls. This adapter does not broaden storage grants,
enable the remote pilot's write surface, publish a client or provision users.

## Verification and deployment boundary

The focused suite uses synthetic Auth responses and an atomic in-memory test
fixture, and checks both the hosted route and the existing official OAuth block.
It covers own-account decisions, account/session changes, same-origin checks,
concurrent replay, expiry, lost replies, stalled streams/verification, caller
abort, suppressed late approval, strict bounds, escaping and sanitized
failures. No live credential, hosted route, storage service or actual user
acceptance is exercised. The application owner must mount this route with its
real verified-session and atomic-store adapters, configure Auth's exact URL and
approved client, and perform own-account acceptance before claiming deployment.
