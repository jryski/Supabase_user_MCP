# Issue #18: Experimental local stdio operator package

- **Status:** Unmerged candidate
- **Profile:** local stdio, read-only, synthetic acceptance
- **Production-ready:** no
- **Remote HTTP/OAuth:** excluded
- **Writes:** excluded

## What this candidate changes

`npm start` launches the verified principal-bound read-only server instead of the M0 compatibility
probe. The M0 probe remains available through `npm run start:compatibility` and the compatibility
test suite.

The production entrypoint:

1. rejects every command argument;
2. reads exactly two trusted environment variables;
3. loads the existing protected credential file;
4. constructs the fixed Supabase client;
5. verifies the user through fixed `/auth/v1/user` before stdio starts;
6. exposes only `memory_search`, `memory_get`, and `memory_list_recent`;
7. reports only generic secret-free startup, transport, and shutdown failures.

## Supported operator profile

The initial executable profile is POSIX-only because the credential loader can directly verify owner
and mode bits there. Windows reports permission inspection as unsupported and therefore fails closed.
A future Windows profile requires a separately reviewed ACL inspector. Do not weaken or bypass this
check merely to start the server.

## Exact prerequisites

| Component | Version |
| --- | --- |
| Node.js | `22.20.0` |
| npm | `11.19.0` |
| Supabase CLI for synthetic M2 | `2.115.0` |
| MCP server/client | `2.0.0` |

Use a clean checkout and synthetic/local Supabase project only.

## Build and verify

```shell
npm ci
npm run clean
npm run check
npm run build
```

For the full synthetic Auth, MCP, PostgREST, and RLS acceptance:

```shell
npm run test:m2
```

The M2 command owns its local containers, emits an exact-head receipt, and stops the stack on exit.
It must never target production or private deployment data.

## Create a protected credential file

Create a JSON file outside the repository with exactly these two fields:

```json
{
  "projectPublishableKey": "<publishable-key>",
  "userAccessToken": "<user-access-token>"
}
```

The key and user token are different credentials. Do not use `service_role`, a project access token,
a database password, or a JWT-shaped project key. The user token must be unexpired.

On POSIX, restrict the file to its owner:

```shell
chmod 600 /absolute/path/to/protected-credentials.json
```

Never commit the file, pass it as a command argument, paste it into an MCP client definition, or
print it in diagnostics.

## Configure the MCP client

Copy [the synthetic example](../../examples/local-stdio-client.example.json) into the client's local
configuration and replace only:

- the absolute built CLI path;
- the fixed HTTPS Supabase origin;
- the absolute protected credential-file path.

The server accepts no CLI arguments. The environment names are fixed:

- `SUPABASE_USER_MCP_ORIGIN`
- `SUPABASE_USER_MCP_CREDENTIAL_FILE`

## Start and exercise

Start the server through the MCP client. On successful startup, stderr contains only:

```text
Supabase User MCP read-only stdio server ready.
```

List tools and confirm exactly:

- `memory_get`
- `memory_list_recent`
- `memory_search`

Use synthetic records for the first exercise. Confirm another synthetic principal cannot retrieve the
same private record. Missing and unauthorized records must retain the same public unavailable shape.

## Fail-closed checks

The process must exit nonzero with the same generic startup message when:

- any command argument is present;
- either environment value is absent;
- the origin is not one exact HTTPS origin;
- the credential file is missing, linked, oversized, malformed, insecure, unsupported, or expired;
- Auth rejects the user;
- stdio setup fails.

Raw paths, URLs, tokens, keys, upstream response bodies, and thrown errors must not appear on stderr.

## Stop

Ask the MCP client to close the server, or send `SIGINT`/`SIGTERM`. Repeated signals share one close
operation. A close failure produces a generic message and nonzero exit status.

## Revoke and remove access

1. Stop the MCP process.
2. Revoke the user session through the deployment's supported Supabase Auth session-management path.
3. Delete the protected local credential file.
4. Remove the MCP client entry.
5. Confirm the old token can no longer pass `/auth/v1/user` or M2-equivalent verification.

Do not rotate a project-wide privileged credential to revoke one user session.

## Rollback

Runtime rollback is local and does not require database changes:

1. stop the read-only server;
2. remove the MCP client entry;
3. delete the protected credential file;
4. use `npm run start:compatibility` only for protocol diagnostics with no data access;
5. return to the prior reviewed Git coordinate if the read-only entrypoint itself must be removed.

No migration, RLS, grant, RPC, or data rollback is introduced by this candidate.

## Experimental release checklist

- [ ] Exact source head and tree recorded.
- [ ] Node/npm/Supabase versions match the declared coordinates.
- [ ] `npm run check` passes from a clean checkout.
- [ ] `npm run test:m2` passes and emits one exact-head receipt.
- [ ] The credential file is external, owner-only, and absent from Git.
- [ ] Tool listing contains exactly three fixed read tools.
- [ ] Positive, cross-principal, revoked, expired, malformed, and hostile-content cases pass.
- [ ] Generic `postgrestRequest`, `sqlToRest`, arbitrary SQL/path/method/RPC/origin remain unavailable.
- [ ] Stop, session revoke, local-file deletion, and client-config rollback are exercised.
- [ ] Logs and changed files pass secret/private-data scans.
- [ ] Documentation says local stdio, read-only, synthetic-only, experimental, and not production-ready.

## Claim limits

This package proves a bounded experimental local operator path. It does not prove remote OAuth,
horizontal scaling, production deployment, write authority, semantic search quality, Storage access,
fleet lifecycle, or stable v1 compatibility.
