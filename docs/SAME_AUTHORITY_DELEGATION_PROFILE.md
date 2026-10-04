# Same-Authority Capability Delegation (SACD) profile

- **Profile version:** 0.2 (draft; 0.1 amended after an adversarial review, see §9)
- **Status:** Proposed. Not accepted, not deployed, and no data tools are enabled under it.
- **Decision record:** [ADR-0006](decisions/0006-same-authority-capability-delegation.md)
- **Relationship to MCP:** This profile is a **documented deviation** from the literal text of
  MCP `2026-07-28` [Access Token Privilege Restriction](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#access-token-privilege-restriction).
  It is not a claim of strict MCP conformance. The upstream clarification request is
  [modelcontextprotocol#3413](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/3413).
  Deployments that must claim strict MCP conformance use the separate-credential mode
  described in [ADR-0005](decisions/0005-dual-resource-data-api-binding.md).

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are to be
interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in bold.

## 1. Problem statement

Supabase User MCP exists to give an application's own users, through an MCP client such as
Claude or ChatGPT, access to that application's data. Access runs as the user, under Postgres
Row Level Security (RLS), with no privileged key anywhere in the request path.

Two authoritative sources currently disagree about how to build this on Supabase:

1. **MCP `2026-07-28`** says an MCP server **MUST NOT** pass through the token it received
   from the MCP client. If it calls an upstream API, it uses "a separate token, issued by the
   upstream authorization server."
2. **Supabase's first-party guidance** ([Deploy MCP servers](https://supabase.com/docs/guides/ai-tools/byo-mcp),
   [MCP Authentication](https://supabase.com/docs/guides/auth/oauth-server/mcp-authentication))
   runs the MCP server as an Edge Function in the project. It verifies the user's Supabase
   Auth token and sends that same token to the project's Data API so RLS applies.

Neither source addresses the case this project lives in. Here the MCP endpoint and the data it
serves belong to the **same authorization server, the same project and the same user**, and the
"upstream" is not a third party. Our earlier records resolved the conflict conservatively by
requiring a second, separately consented credential. Applied literally, that answer:

- doubles consent for every user;
- turns every deployment into a long-lived credential vault; and
- diverges from the platform vendor's own guidance.

This profile resolves the conflict by asking what the passthrough prohibition protects against.
It then states mechanically checkable conditions under which those protections hold at least as
strongly as with a separate credential.

## 2. Core argument in one paragraph

The passthrough prohibition exists because a forwarded token can carry **more authority at the
downstream API than the MCP server was meant to exercise**. It can also be **trusted by the
downstream for the wrong reasons**, can **bypass controls the MCP server applies**, and can blur
**who did what**. Every one of those harms is a property of the token's authority at the
downstream, not of the act of forwarding.

If the authorization server mints a token whose audience is the MCP resource, the database
enforces a role whose only privileges are the fixed capability functions behind the MCP tools,
and the database also enforces session liveness, bounds and attribution, then:

- the token buys exactly the same capability set whether presented through the MCP endpoint or
  directly;
- the MCP endpoint holds no authority of its own to lend; and
- every control lives where it cannot be bypassed.

At that point the MCP endpoint and its capability backend are one protected resource reached over
two transports, and "the upstream API" is no longer a separate trust domain. A second credential
would add custody risk without adding an authority boundary.

## 3. Terms

- **Authorization server (AS):** the project's Supabase Auth OAuth 2.1 server, identified by one
  exact issuer string, for example `https://<ref>.supabase.co/auth/v1`.
- **MCP endpoint:** the HTTP endpoint MCP clients call, for example the Edge Function
  `https://<ref>.supabase.co/functions/v1/mcp`. Its canonical URL is the **MCP resource
  identifier**.
- **Capability backend:** a fixed, enumerated set of Postgres functions (and, if needed, views)
  in a dedicated schema, reachable through the same project's Data API. It is the only
  database surface the MCP tools use.
- **Capability role:** a Postgres role (`mcp_ingress` in this repository's labs) with
  `NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS`. Its privileges are exactly the capability backend.
- **Approved MCP client:** an OAuth client whose `client_id` is listed in the deployment's
  approved-client registry. Registration (including dynamic registration) does not by itself
  make a client approved.
- **SACD token:** an access token the AS issues to an approved MCP client for a user under this
  profile.
- **Composite protected resource:** the MCP endpoint together with its capability backend,
  treated as one resource for authorization purposes.

## 4. Requirements

Each requirement has an identifier so that tests, reviews and deviations can cite it exactly.

### 4.1 Authority and issuance

- **SACD-1 Single authority.** The MCP endpoint and the capability backend **MUST** be protected
  by the same AS issuer (exact string match) in the same project. A capability backend on another
  project, issuer or vendor is out of scope: use the separate-credential mode.
- **SACD-2 Audience binding.** The AS **MUST** issue SACD tokens whose `aud` contains the MCP
  resource identifier. SACD tokens **MUST NOT** carry the general Data API audience
  (`authenticated`) or any other audience. On Supabase this is done with a Custom Access Token
  Hook keyed on `client_id`, because Supabase Auth currently ignores the RFC 8707 `resource`
  parameter (observed locally with Auth v2.197.0; see §8). The hook **MUST** apply identically
  to every token-minting event, including the `refresh_token` grant. A deployment where any
  issuance path bypasses the hook **MUST NOT** use this profile.
- **SACD-3 Capability role.** For approved MCP clients the hook **MUST** set `role` to the
  capability role. Tokens with any other role **MUST** be refused by the MCP endpoint.
- **SACD-4 Client approval.** The hook **MUST** refuse token issuance (a structured 403) when a
  present `client_id` is not approved. Tokens without a `client_id` (ordinary first-party
  sessions) **MUST** pass through the hook unchanged, so the application keeps working, and
  **MUST** be refused by the MCP endpoint.
- **SACD-5 Lifetime.** SACD tokens **SHOULD** expire within 15 minutes. Short lifetime
  complements, and does not replace, SACD-11.
- **SACD-6 No identity tokens.** The OpenID `openid` scope **SHOULD** be refused for MCP clients
  unless a deployment needs ID tokens and has reviewed that need. An MCP client needs an access
  token, not an ID token.

### 4.2 Authority equivalence (the load-bearing section)

- **SACD-7 Exact privilege set.** The capability role **MUST** hold only:
  - `USAGE` on the capability schema;
  - `EXECUTE` on the enumerated capability functions;
  - `SELECT` on any enumerated capability views.

  It **MUST NOT** hold privileges on any table, sequence or other schema. Default privileges that
  would grant future objects to it **MUST** be revoked.

  The set that matters is the role's **effective** privileges, not only its direct grants. Every
  Postgres role also holds whatever is granted to `PUBLIC`, regardless of `NOINHERIT`, and
  Postgres grants `EXECUTE` on new functions to `PUBLIC` by default. Therefore:
  - `EXECUTE` **MUST** be revoked from `PUBLIC` on every function in every schema the Data API
    exposes, including the capability schema, `public` and any extension-installed functions,
    except functions explicitly listed as safe for `PUBLIC`;
  - default privileges **MUST** be altered so new functions in those schemas are not granted to
    `PUBLIC`;
  - extension schemas (for example network-capable extensions such as `pg_net`) **MUST NOT** be
    exposed to the Data API, and their functions **MUST NOT** be executable by the capability role;
  - the capability role **MUST** have no role memberships (`pg_auth_members`) and no other role may
    be granted to it.

  This **MUST** be verified mechanically by a catalog lint that computes the effective privilege
  set (direct grants plus `PUBLIC` grants plus memberships) over every exposed schema and every
  installed extension, and compares it with the declared list. Visual review is not enough.
- **SACD-8 Invoker semantics.** Capability functions **MUST** be `SECURITY INVOKER`, so RLS applies
  as the calling user. Any `SECURITY DEFINER` exception **MUST** pass the repository's
  security-definer gate and **MUST** derive the principal only from `auth.uid()` and verified
  claims, never from arguments.
- **SACD-9 RLS stays authoritative.** The capability role is a ceiling, and RLS still makes the
  per-row decision. Policies that should restrict MCP clients beyond ordinary users **MUST** be
  `RESTRICTIVE`. A narrower permissive policy cannot restrict a broader permissive one.
  Capability views **MUST** be created with `security_invoker = true`, so privileges and RLS are
  checked as the calling user rather than the view owner. Every table a capability function or view
  reads **MUST** have RLS enabled. Where the owner of a function, view or table could otherwise be
  exempt from RLS, that table **MUST** also use `FORCE ROW LEVEL SECURITY`. The catalog lint
  (SACD-7) **MUST** check these properties.
- **SACD-10 Bounds at the authority layer.** Every bound the MCP tools promise **MUST** also be
  enforced inside the capability backend: input size, row caps, result size, a statement timeout
  on the capability role and any rate limit the deployment claims. MCP-layer bounds are
  additional defence in depth and are not where the guarantee lives.
- **SACD-11 Live session at the authority layer.** Capability functions (or a restrictive policy
  they depend on) **MUST** verify that the token's `session_id` exists, is unexpired and belongs
  to the same user and approved client in `auth.sessions`. This applies to every call, so
  revoking a grant or signing out takes effect immediately on **both** paths. The same check
  **MUST** read the **current** approved-client registry on every call, not a value captured when
  the session or token was created. Removing a client from the registry therefore stops its
  already-issued tokens immediately, even while their sessions remain live. The repository's
  source-session liveness function (`sql/05`) is the reference pattern.

### 4.3 MCP endpoint

- **SACD-12 Zero ambient authority.** The MCP endpoint **MUST NOT** possess:
  - a service-role or secret key;
  - a database URL or password;
  - a JWT signing key;
  - stored user credentials.

  Its configuration is the project URL, the publishable key, the exact issuer, the MCP resource
  identifier and the approved-client list. It **MUST NOT** construct an admin client, even
  lazily.
- **SACD-13 Fixed forwarding.** The MCP endpoint **MUST** present the inbound SACD token only to
  the enumerated capability functions, at the same project origin as the issuer. It **MUST NOT**:
  - forward the token to any other host, path or method;
  - accept URLs, table names, function names, schemas or SQL from tool arguments;
  - follow redirects with the token.
- **SACD-14 Complete inbound validation before any forwarding.** In order, the MCP endpoint
  **MUST** verify:
  1. the signature against the issuer's JWKS (asymmetric keys only);
  2. `iss` equal to the pinned issuer;
  3. `aud` containing the MCP resource identifier;
  4. `exp` in the future;
  5. `role` equal to the capability role;
  6. `client_id` present and approved;
  7. `session_id` present;
  8. that the token is an access token: ID tokens (whose audience is the client) and any token
     lacking the access-token claims above are refused.

  Any failure **MUST** return 401 (authentication) or 403 (authorization) before tool dispatch,
  with a `WWW-Authenticate` resource-metadata challenge on 401.
- **SACD-15 Attribution.**
  - Every forwarded call **MUST** carry a per-request identifier.
  - The MCP endpoint **MUST NOT** log tokens or token fragments.
  - Where a deployment requires audit, capability functions **SHOULD** record `client_id`, `sub`,
    `session_id` and the request identifier in an append-only journal.
- **SACD-16 Bounded ingress.** The MCP endpoint **MUST** bound request size, deadline and
  cancellation before any handler work (repository default: 65,536 bytes and 2,000 ms).

### 4.4 Consent and disclosure

- **SACD-17 Informed consent.** The consent screen **MUST** show:
  - the client's name, flagged as self-asserted when it came from dynamic registration;
  - that the app will act **as the user** on this project's data;
  - the capability families it receives;
  - where to revoke access.

  Approval **MUST** be an explicit user action.
- **SACD-18 Published profile.** The deployment **MUST** state in its protected-resource
  documentation that it implements SACD, and which version. Clients, auditors and other relying
  parties at the same AS then know the capability backend is part of the protected resource and
  that SACD tokens are capability-restricted.

### 4.5 Activation, fallback and change control

- **SACD-19 Conformance gate.** Data-bearing tools **MUST** stay disabled (`fail-closed`) until
  every test in §6 passes on the exact target deployment. A failing or unrunnable test means
  disabled, not passed.
- **SACD-20 Fallback.** A deployment that cannot satisfy SACD-2, SACD-7 or SACD-11 **MUST NOT**
  enable data tools under this profile. It uses the separate-credential mode instead.
- **SACD-21 Revisit trigger.** If MCP maintainers clarify that same-authority delegation is
  prohibited, or the MCP text changes, this profile **MUST** be re-reviewed before any further
  deployment, and deployments **SHOULD** migrate to the separate-credential mode. The endpoint
  keeps a downstream-credential seam so that migration does not require a redesign.
- **SACD-22 Continuous verification.** The catalog lint (CT-15) and the exhaustive denial tests
  (CT-6, CT-7) **MUST** run in CI on every migration that touches the capability role, the
  capability schema, any exposed schema, any installed extension or any grant. A failure **MUST**
  block the migration or disable data tools (SACD-19). Passing once before activation is not
  enough: the equivalence claim has to be re-proven on every change.

## 5. Why each MCP risk is addressed

Every control below is **designed to be verified** by the cited tests. None of the CT-6 to CT-18
receipts exist yet (§8), so "Residual" describes the design, not observed results. The left
column quotes the risks listed under
[Token Passthrough](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices#token-passthrough)
in the MCP security best practices.

| MCP risk | Why it arises in generic passthrough | SACD controls | Residual |
| --- | --- | --- | --- |
| Audience validation failure: a server accepts tokens issued for other services | The server cannot tell a token meant for it from one meant for something else | SACD-2 binds `aud` to the MCP resource; SACD-14 rejects any token without it; ordinary first-party tokens are refused (SACD-4) | None known in the design, given a correct hook. To be verified by CT-2, CT-3 and CT-19 |
| Confused deputy: the downstream trusts the token "as if it came from the MCP server", or assumes the server validated it | The downstream grants authority based on who forwarded the token, or relies on the proxy's checks | The backend trusts only the token's own claims and re-verifies everything itself: PostgREST signature checks, role privileges, RLS, liveness. The endpoint has zero ambient authority to lend (SACD-12). The classic MCP confused deputy (a proxy with a static client ID at a third-party AS reusing consent cookies) cannot arise, because there is no proxy client or third-party AS and consent is per MCP client at the same AS | None known |
| Security control circumvention: clients use tokens directly and skip the server's controls | Controls live only in the server | Every control lives in the backend (SACD-7, 9, 10, 11), and SACD-22 keeps it re-verified on every migration. Direct use of a SACD token reaches exactly the capability set, bounded the same way | Database rate limiting is coarser than a gateway; the deployment states its real limit (SACD-10) |
| Accountability: the server cannot distinguish clients; downstream logs show the wrong identity | Opaque upstream tokens; the proxy hides the real caller | The token carries `client_id`, `sub` and `session_id`, visible to both layers. The request ID and optional journal tie MCP calls to backend calls (SACD-15) | Direct calls carry no MCP request ID; they are still attributed to the client and user |
| A stolen token is used through the server as an exfiltration proxy | The server forwards without checking claims | Full claim validation (SACD-14). A stolen token has the same capability set and lifetime through or around the server, so the server adds no reach. Revocation is immediate (SACD-11) | Bearer theft remains a risk within token lifetime and capability set, exactly as in any OAuth design |
| Trust boundary: a token accepted by several services lets one compromise spread | Broad audiences and broad roles | `aud` excludes the general Data API audience (SACD-2); the role has no table privileges and no other schemas (SACD-7); tests are designed to show denial at Data API tables, functions, GraphQL, Storage and Auth surfaces (CT-6 to CT-8) | Depends on platform configuration; tested per deployment |
| Future compatibility: a pure proxy later needs controls | Audience separation added late is costly | The profile is versioned; a downstream-credential seam is retained; SACD-21 defines the migration trigger | The cost of migration if MCP rules against the profile |

## 6. Conformance tests

Every test runs against the exact target deployment with synthetic users, and each produces a
receipt. "Direct" means calling the project's Data API with the SACD token and the publishable
key, with no MCP endpoint involved.

| ID | Test | Expected |
| --- | --- | --- |
| CT-1 | Discovery: an unauthenticated MCP request, then the RFC 9728 metadata, then the AS metadata | 401 with a resource-metadata challenge; metadata names the MCP resource and the exact issuer |
| CT-2 | A SACD token's claims (redacted trace) | `aud` contains the MCP resource and nothing else; `role` is the capability role; `client_id` approved; `session_id` present |
| CT-3 | An ordinary first-party session at the MCP endpoint | 403 (no client) |
| CT-4 | An unapproved client (dynamically registered, not in the registry) requests a token | Token issuance refused by the hook |
| CT-5 | Forged key, wrong issuer, wrong audience, expired token, wrong role, an ID token | All refused before tool dispatch |
| CT-6 | Direct: SACD token against every table and view in every exposed schema | Denied (no privilege) |
| CT-7 | Direct: SACD token against every function in every exposed schema, including extension-installed functions, other than the capability functions | Denied |
| CT-8 | Direct: SACD token against GraphQL, and against each Storage operation (list, upload, download, bucket admin) and each Auth endpoint (user, update, logout, admin) separately | Each denied, or limited to what any user may do for their own account, with one receipt per operation |
| CT-9 | Direct: SACD token against every capability function and view for the user's own rows | Same result as the MCP tool |
| CT-10 | Direct and through MCP: every capability function and view asked for another user's rows | Empty or denied under RLS on both paths |
| CT-11 | Writes and denied operations through both paths | Denied unless explicitly a capability |
| CT-12 | Revoke the grant, then use the already-issued token on both paths | Refused immediately on both (SACD-11), not merely at expiry |
| CT-13 | Sign out and session expiry | As CT-12 |
| CT-14 | Oversized inputs and over-cap results, through both paths | Refused or capped by the backend (SACD-10) |
| CT-15 | Catalog lint on the capability role's **effective** privileges (direct, `PUBLIC`, memberships) over every exposed schema and extension; view `security_invoker`; RLS enabled and forced where required | Exactly the declared set; no default or `PUBLIC` grants beyond the safe list; no memberships; all view and RLS properties hold |
| CT-16 | Endpoint secret scan (static and runtime environment) | No service-role, secret, database or signing material read or used |
| CT-17 | Two users and two approved clients in combination | Each sees only their own rows; client restrictions hold |
| CT-18 | Real MCP client end to end (Claude connector): discovery, registration, consent, tool call, revoke | Matches CT-1 to CT-12 |
| CT-19 | Token obtained through the `refresh_token` grant for an approved client | Same claims as CT-2; refused for an unapproved client |
| CT-20 | Remove a client from the approved registry while its session stays live, then use its unexpired token on both paths | Refused immediately on both paths (SACD-11 live registry check), separately from CT-12 |
| CT-21 | CI wiring: a migration that adds a function in an exposed schema without revoking `PUBLIC` | CI fails (SACD-22) |

## 7. What this profile does not claim

- It does not claim conformance with the literal MCP `2026-07-28` text. It is a reasoned,
  documented deviation, and it is submitted upstream for clarification.
- It does not make bearer tokens safe against theft. It makes the server add nothing to what a
  thief already has, and it makes revocation immediate.
- It does not cover capability backends on another project, issuer or vendor.
- It does not cover writes beyond those explicitly enumerated as capabilities. Write
  capabilities need their own review.
- It is not accepted until ADR-0006 is accepted, and data tools stay disabled until §6 passes on
  the target deployment.

## 8. Evidence to date

- **Local phase 1 pilot** (synthetic): an auth-only Edge Function with no forwarding. It passed
  16/16 checks for discovery, registration, consent, the `whoami` tool, fail-closed data and
  refusals. Observed: Supabase Auth v2.197.0 ignored RFC 8707 `resource` (`aud=authenticated`
  with or without it). After grant revocation, JWKS-only verification accepted the
  already-issued token until expiry, while the AS userinfo endpoint returned 403. These two
  findings motivate SACD-2 and SACD-11.
- **Existing laboratory mechanisms this profile formalizes:**
  - the custom access token hook that sets the MCP resource as `aud` and `role` to `mcp_ingress`
    for mapped clients, and refuses unmapped clients (`docs/evidence/ari-test-probe/sql/04`,
    `sql/07`);
  - source-session liveness (`sql/05`);
  - client-aware restrictive RLS (`sql/06`);
  - catalog lint and the security-definer gate (issues #3 and #4).
- **Not yet proven:**
  - whether hosted PostgREST accepts a token whose only audience is the MCP resource;
  - whether the hosted hook runs on every issuance path, including refresh;
  - the end-to-end CT-6 to CT-21 suite;
  - real-client behaviour.

## 9. Review history

- **0.1 to 0.2 (2026-10-04).** An independent, tool-less adversarial review (Claude Sonnet 5)
  returned SOUND_WITH_GAPS. Both findings it rated fatal were missing requirements, and are now
  closed:
  - `PUBLIC` function grants: every role inherits `PUBLIC` privileges, so a lint of direct grants
    alone could miss callable functions (now in SACD-7, CT-7, CT-15 and CT-21);
  - view-owner RLS bypass: views without `security_invoker` check RLS as their owner (now in
    SACD-9, CT-9, CT-10 and CT-15).

  Also adopted:
  - hook coverage of refresh (SACD-2, CT-19);
  - live approved-client registry check (SACD-11, CT-20);
  - access-token-only check (SACD-14, CT-5);
  - SACD-18 raised to MUST;
  - continuous CI verification (SACD-22);
  - per-operation Storage and Auth receipts (CT-8);
  - §5 reworded so that designed controls are not presented as results.

  The reviewer's strongest counterargument is recorded in ADR-0006.
