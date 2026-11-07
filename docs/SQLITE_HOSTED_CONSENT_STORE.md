# Persistent consent challenge store

`createSqliteHostedConsentChallengeStore` is an explicit local SQLite adapter for
the [hosted consent route](HOSTED_OAUTH_CONSENT.md). It stores pending form metadata,
not OAuth access tokens, refresh tokens, credentials or business records. It does
not approve consent or change any application/database grant.

The supported profile is multiple processes on one POSIX host using the same
latest database on a local filesystem. Use the existing challenge-store contract
with an appropriate shared atomic backend for a distributed host. Separate files
per process, network filesystems and Windows are outside this adapter's profile.

## Mount with the host's existing session integration

The host must already provide an absolute canonical private directory owned by its
runtime user with mode `0700`, and trusted parent-directory custody. This library
does not create or chmod that directory, provision a mount or configure a service.
The fixed `hosted-consent.sqlite` file is created with mode `0600`; existing
files must have that exact mode, the same owner and one hard link. Symlinks,
untrusted writable ancestors, changed file/directory identities and incompatible
databases are refused.

```ts
import {
  createHostedOAuthConsentHandler,
  createSqliteHostedConsentChallengeStore,
} from '@supabase-user-mcp/server';

const challenges = await createSqliteHostedConsentChallengeStore({
  directory: CONSENT_STATE_DIRECTORY, // Trusted host configuration, never a request value.
  maxEntries: 1024,
});

const handleConsent = createHostedOAuthConsentHandler({
  routeUrl: EXACT_AUTHORIZATION_ROUTE,
  binding: EXISTING_APPROVED_CLIENT_BINDING,
  getVerifiedSession: VERIFY_CURRENT_HOST_SESSION,
  challenges,
});

export const GET = handleConsent;
export const POST = handleConsent;

// After the host has stopped accepting/drained consent requests:
// challenges.close();
```

The route, binding and session verifier retain the
[existing host contract](HOSTED_OAUTH_CONSENT.md). Startup is asynchronous so the
experimental built-in `node:sqlite` module is loaded only when this adapter is
selected. The repository's pinned Node 22 runtime supports that API; no additional
npm dependency is installed. Unused/default entrypoints do not load SQLite.

## Atomicity, bounds and failure behavior

Each insert or destructive take runs in a SQLite `BEGIN IMMEDIATE` transaction.
Deletion commits before a challenge is returned to the route, so separate
connections/processes can consume one nonce at most once. Restarting with the
same database retains both pending forms and committed consumption. A missing
nonce returns `undefined`; a duplicate insert or full store returns `false`.
Existing live forms are not evicted to make room.

Only SHA-256 nonce keys and the five declared metadata fields are stored: user
ID, opaque host session ID, authorization ID, viewed-detail digest and expiry.
Excess fields and malformed values are refused. The host must supply an opaque
session identifier, never its bearer token. New challenges may live at most five
minutes. Expired challenges are never returned and are removed lazily on writes
or when individually consumed; idle expired metadata can remain on disk until
the next operation.

The default limit is 1024 entries, with a maximum of 4096. The chosen capacity is
persisted and must match across processes. Stored metadata and database files are
bounded, with a 16 MiB database-file ceiling. SQLite extension loading is disabled,
trusted-schema behavior is disabled, and commits request full synchronization.
The lock wait is capped at 250 ms; a busy or unavailable backend fails closed.
This synchronous local adapter does not establish a deadline for a stalled
underlying filesystem; qualify the actual local volume and host request budget.

Native/OS/SQL errors are replaced by the fixed
`SQLITE_CONSENT_STORE_UNAVAILABLE` error without paths or record contents.
The hosted route turns backend failures into its existing fixed 503 response.
A lost reply is an unknown outcome: restart authorization and inspect Auth's
current state. Never retry an approval automatically, recreate a consumed form,
or restore an older database snapshot. Use the latest database across all host
processes; deleting it invalidates pending forms, and restoring an old copy can
resurrect forms that were already consumed.

The database contains personal metadata in plaintext inside the private
directory. This is not encryption or protection from the host owner, root,
backups or a compromised runtime. Secure deletion reduces ordinary freed-cell
retention; it does not promise forensic erasure. The host retains responsibility
for volume custody, backup/retention policy and deployment qualification.

## Verification and limits

The source suite uses temporary synthetic private directories and actual SQLite
connections. It checks restart, collision/capacity/expiry behavior, strict
metadata, private storage/refusal, busy-backend failure, three real Node processes,
and the actual hosted consent handler across independent connections, including
lost approval replies and replay after restart. These tests do not establish
hosted mounting, real-user consent or deployment acceptance.

API reference: [Node 22 SQLite documentation](https://nodejs.org/download/release/latest-jod/docs/api/sqlite.html).
