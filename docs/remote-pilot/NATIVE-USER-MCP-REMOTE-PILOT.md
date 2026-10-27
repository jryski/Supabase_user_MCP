# Native user MCP remote pilot (#110)

Status: **experimental, synthetic, read-only pilot surface.** Not a production
deployment, not a release, and not evidence that #86 is met. Nothing here
authorizes live configuration, client registration, Auth hook, SQL, or real
data access; those belong to the separately approved #109 package.

## What this adds

The existing native read composition is reused unchanged:

1. Claude presents **token A** (resource-only, `mcp_ingress` role, bound to a
   source session, client, and agent). It is verified and never sent to the
   Data API.
2. The server binds a distinct downstream **grant B** for the same user through
   a one-time PKCE handshake.
3. Before every dispatch, **source-session liveness** is checked with B
   (`public.source_session_live_v1`, defined in
   `sql/liveness/source_session_live_v1.sql`). A revoked source session is
   denied, and anything other than JSON `true` fails closed.
4. The fixed read tools (`memory_search`, `memory_get`, `memory_list_recent`)
   run with B only.

Issue #110 adds only:

- an **opt-in entrypoint** (`native-user-mcp-remote-pilot`), built from
  environment names with an explicit opt-in value;
- an **https B callback** accepted behind an operator TLS terminator (exact
  path, exact Host, matching URL host). The default loopback-only rule is
  unchanged for every other caller;
- **authorization surfaced in tool results**: before B exists, Claude can
  connect and list tools, and any tool call returns the B authorization link
  as tool text. Hosted MCP clients do not show a 403 response body to the user,
  so without this the user would never see the link.

## Grant custody (memory only)

- B grants live in process memory. Refresh tokens are discarded at exchange.
- A restart loses every B grant. A B grant ends at its access-token expiry.
  Either way the next tool call returns a new link and the user approves again.
- A link works once. Repeated or parallel tool calls show the same pending
  link; a new one is issued only when less than a minute remains, which
  invalidates the old one.
- No durable production custody is claimed.

## Operator prerequisites (synthetic project only, unverified on any target)

These are inputs, not facts established by this change:

- An https hostname whose TLS terminator forwards to the loopback listener and
  preserves the Host header.
- Client A registered on the project's OAuth server for Claude's connector
  callback, with the Auth hook minting A as described above.
- Client B registered with redirect `https://<host>/oauth/downstream/callback`
  and the same agent claim.
- `public.source_session_live_v1` installed on the target project from
  `sql/liveness/source_session_live_v1.sql`. It is not a migration and nothing
  in this repository applies it; installing it is a separate approved step.
  Where the project's `auth.sessions` has no `oauth_client_id`, the function
  returns false and every dispatch is denied.
- Synthetic users and fixtures only, until real-data use is approved.

## Environment (names only)

| Name | Value shape |
| --- | --- |
| `SUPABASE_USER_MCP_NATIVE_REMOTE_PILOT` | exactly `synthetic-readonly-memory-only-grants` |
| `SUPABASE_USER_MCP_RESOURCE_URI` | `https://<host>/mcp` |
| `SUPABASE_USER_MCP_SUPABASE_URL` | `https://<project>.supabase.co` |
| `SUPABASE_USER_MCP_JWKS_URL` | https JWKS on the project origin |
| `SUPABASE_USER_MCP_PUBLISHABLE_KEY` | project publishable key, exactly `sb_publishable_<token chars>` with no padding |
| `SUPABASE_USER_MCP_A_CLIENT_ID` | client A id |
| `SUPABASE_USER_MCP_B_CLIENT_ID` | client B id (must differ from A) |
| `SUPABASE_USER_MCP_B_REDIRECT_URI` | `https://<host>/oauth/downstream/callback` |
| `SUPABASE_USER_MCP_AGENT_ID` | agent id stamped on A and B |
| `SUPABASE_USER_MCP_LISTEN_PORT` | loopback port |

Startup fails closed on any missing or insecure value, on a redirect off the
resource host, on a JWKS off the project origin, on any argv, and if a
service-role, secret-key, credential-file, or user-bearer variable is set.
The key slot accepts only an `sb_publishable_` key. A secret key (`sb_secret_`
in any letter case), a legacy JWT-shaped anon key, or any other shape fails
startup with a fixed error that never contains the key.

Run after build: `node packages/server/dist/native-user-mcp-remote-pilot-cli.js`.
The listener binds `127.0.0.1` only.

## User steps (Claude web, then Claude mobile)

1. Claude web: **Customize > Connectors > Add custom connector**. Server URL is
   the operator's `https://<host>/mcp`. Use OAuth (client A as the operator
   directs). Leave request headers empty.
2. **Connect** and sign in. Claude now holds token A. Status: Connected.
3. In a new chat, ask Claude to list your recent memories. The first call
   returns a link instead of data. Open it, sign in with the **same** account,
   and approve read access. The page reports `bound: true`.
4. Ask again. The read now runs with grant B after the liveness check.
5. Claude mobile: same account, connector enabled, new chat, same request. If
   the server restarted or B expired, steps 3 and 4 repeat.

## Known limits

- Grant B must be re-approved after any restart or B expiry.
- The authorization link reaches the user through the model's reply. Check that
  the link host is the project's auth origin before signing in.
- Whether Claude mobile re-prompts for A, and the exact connector UI on each
  plan, are unverified.
- Hosted revoked-access denial (#86) still requires a fresh receipt on the
  target. This change preserves the per-dispatch liveness check but does not
  prove it on any hosted project.
