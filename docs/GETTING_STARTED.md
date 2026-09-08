# Try Supabase User MCP

Start here if you arrived from Glama or M8ven. This is an experimental, read-only
developer preview. The public source supports a local POSIX stdio profile with
synthetic data. There is no public hosted endpoint, one-click installer, or published
npm install command. A directory listing does not provision a database or user account.

## Choose your path

| Goal | Available path |
| --- | --- |
| Evaluate authorization without sharing data | Run the synthetic acceptance suite below on a disposable Linux/POSIX development environment |
| Configure a local MCP client | Use the operator setup below after provisioning the fixed schema and a synthetic user credential |
| Use native Windows Claude Desktop | Not supported by the public credential loader; do not bypass its permission check |
| Add a remote URL to Claude | No public hosted User MCP URL is available |
| Read production data or enable writes | Not an accepted profile |

## 1. Run the reproducible demo

You need Git, Docker with Linux containers, Bash, Node.js **22.20.0**, and npm
**11.19.0**. Use a dedicated clean checkout. The database harness resets its local
project and stops that project's containers on exit; do not reuse a working database.

```shell
git clone https://github.com/jryski/Supabase_user_MCP.git
cd Supabase_user_MCP
node --version
npm --version
npm ci
npm run check
npm run test:m2
```

`npm ci` installs the pinned Supabase CLI. Run the commands from this repository;
you do not need a production project, database password, or model subscription for
this evaluation. The suite uses synthetic users, starts the local stack, applies
the fixtures, and exercises real MCP calls through Auth, PostgREST, and RLS.

Success means the command exits zero and emits its acceptance receipt. It checks
allowed reads and denied cross-user reads; a successful connection alone is not
the acceptance criterion. The stack is stopped when the command finishes, so this
demo is not a persistent Claude installation. See the [development guide](DEVELOPMENT.md)
for the pinned environment and individual checks.

## 2. Connect a local client

This is operator-assisted setup, not automatic provisioning. The operator must
provide the fixed memory RPC/schema, reviewed RLS grants, an exact HTTPS Supabase
origin, a publishable key, and an unexpired synthetic user's access token. An
arbitrary Supabase project will not work just because it has a memories table.

Follow the [operator guide](evidence/ISSUE_18_OPERATOR_RELEASE.md) to build the
server and create an owner-only credential file outside the checkout. The credential
file contains `projectPublishableKey` and `userAccessToken`; never substitute a
service-role key, database password, or project access token.

Use [the client configuration example](../examples/local-stdio-client.example.json).
Replace the Node command with its absolute path if the desktop client cannot find
Node, and replace the CLI path, origin, and credential-file path. Merge the entry
into existing client settings; do not replace other servers. Credentials belong
in the protected file, not in client configuration or a chat message.

For Claude Desktop on a supported POSIX platform, open **Settings → Developer →
Edit Config**, add the entry, fully quit, and relaunch. See
[Claude's local server instructions](https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop).
The configuration is a local stdio server, not a remote custom connector.
This guide does not claim a new macOS Desktop acceptance test.

## 3. Check the actual tool results

The default server must list exactly `memory_get`, `memory_list_recent`, and
`memory_search`. Use the fixture identifiers supplied by your operator:

```text
Use only supabase-user-mcp for this check. List recent memories with a small limit.
Search for the synthetic marker supplied by the operator. Retrieve the permitted
fixture, then the other user's private fixture. Report the actual tool results.
If the connector is unavailable or denies access, stop; do not use an admin connector.
```

The permitted fixture should be returned. The other user's fixture must have the
same unavailable response as a missing record and must not appear in list/search
results. Inspect tool cards, not only the assistant's summary. Use your client's
least expensive suitable model; the automated demo needs no paid model calls.

## Troubleshooting and removal

| Symptom | Next step |
| --- | --- |
| POSIX permission profile unavailable on Windows | Stop; the public native Windows profile is not implemented |
| Node not found / ENOENT | Use an absolute path to the pinned Node executable |
| Startup failed | Check the two environment variables, HTTPS origin, owner-only credential file, and token expiry without printing secrets |
| Connected but reads denied | Check user membership, fixed RPCs, RLS and grant expiry; do not substitute an admin credential |
| Demo rejects the checkout | Use a clean dedicated checkout; do not delete unrelated work to satisfy the check |
| Directory says install, but there is no release | Follow this source-based preview guide; catalog presence is not a hosted release |

To remove the integration, stop the server, revoke the user's session using the
operator procedure, remove only its client entry and protected credential file,
and verify revocation. See the operator guide's revoke and rollback steps.

## Status and help

The [private-alpha status](status/2026-09-08-private-alpha.md) describes separate
hosted experiments. Their results do not make that candidate available from public
`main`. Governed writes, a signed installer, and remote OAuth remain separate work.

For setup help, [open an issue](https://github.com/jryski/Supabase_user_MCP/issues/new)
with your OS, source commit, Node/npm versions, failing step, and redacted error.
Never attach tokens, credential files, or private records. Report vulnerabilities
through [SECURITY.md](../SECURITY.md).
