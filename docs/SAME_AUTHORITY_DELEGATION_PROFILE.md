# Same-Authority Capability Delegation (SACD) profile

- **Profile version:** 0.6 (draft). Each version since 0.1 was amended after a review: an
  adversarial review (0.2), then successive ATLAS reviews (0.3 to 0.6). See §10.
- **Status:** Proposed. Not accepted, not deployed, and no data tools are enabled under it.
- **Decision record:** [ADR-0006](decisions/0006-same-authority-capability-delegation.md)
- **Relationship to MCP:** This profile is a **documented exception** to the literal text of
  MCP `2026-07-28` [Access Token Privilege Restriction](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#access-token-privilege-restriction).
  - It still sends the user's bearer token over a separate HTTP hop to the project's Data API.
    It is not a claim of strict MCP conformance, and not a normative exemption.
  - The argument in §2 is a proposed threat-model justification for the exception. It does not
    remove the hop.
  - Adoption requires the accountable owner's recorded acceptance of this exception (SACD-0).
  - Upstream clarification request:
    [modelcontextprotocol#3413](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/3413).
  - Deployments that must claim strict MCP conformance use the separate-credential mode in
    [ADR-0005](decisions/0005-dual-resource-data-api-binding.md).

New to this proposal? Read the [plain-language overview](SACD_OVERVIEW.md) first.

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

Neither source addresses the case where the MCP endpoint and its data belong to the **same
authorization server, project and user**. Our earlier records required a second, separately
consented credential. That is a sound, conservative answer, but it has real costs:

- a second consent for every user;
- a server-side store of every user's downstream credential;
- divergence from the vendor's guidance.

This profile defines a single-token alternative:

- it states mechanically checkable conditions under which the harms the prohibition names do not
  arise;
- it states plainly where it departs from the text;
- it states what the separate-credential mode still does better (§2.3).

## 2. Argument

### 2.1 What the prohibition protects

The [Token Passthrough](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices#token-passthrough)
risks are properties of a forwarded token's authority and handling:

- the downstream accepts tokens not meant for this server;
- the token carries more downstream authority than the server's purpose needs;
- the downstream trusts the token for the wrong reasons;
- the server's controls can be bypassed;
- actions cannot be attributed.

### 2.2 How SACD addresses them

For approved MCP clients only, the authorization server mints a token with:

- an `aud` that is the MCP resource;
- a `role` that is a capability role.

The capability role can do exactly one thing at the database: call a fixed set of capability
functions. Each function:

- re-validates the token's claims and liveness itself before reading anything (SACD-11);
- reads data through a restricted owner role that RLS still governs (SACD-8, SACD-9).

The intended result is that the token buys the same capability set whether it is presented
through the MCP endpoint or directly to the Data API, and the endpoint holds no authority of its
own to lend. That is the claim the conformance suite (§6) must prove on each deployment, and it
must stay true after every change (SACD-22).

### 2.3 What SACD does not achieve

- **The separate hop remains.** The same bearer crosses a second HTTP hop to the Data API, which
  the literal text forbids. That is why SACD is an exception requiring explicit acceptance.
- **Equal database caps are not equal exposure.** A properly scoped separate-credential design
  (ADR-0005) can share the same database controls and still:
  - keep the data-usable credential out of the MCP client's custody, so a compromised client
    exposes only a token that cannot read data directly;
  - limit where the ingress credential is usable;
  - give the downstream credential its own lifecycle and consent.
- **The separate-credential design has its own costs.** It adds a server-side store of long-lived
  downstream credentials, with refresh, rotation and encryption obligations. Server compromise
  exposes every connected user's downstream credential.
- **The custody risk sits in different places.** SACD places a data-usable token in the MCP
  client. The separate-credential mode places data-usable credentials in the server. **Neither is
  proven globally stronger.** A deployment chooses based on which custody risk it can better
  control.

## 3. Terms

- **Authorization server (AS):** the project's Supabase Auth OAuth 2.1 server, identified by one
  exact issuer string, for example `https://<ref>.supabase.co/auth/v1`.
- **MCP endpoint:** the HTTP endpoint MCP clients call, for example the Edge Function
  `https://<ref>.supabase.co/functions/v1/mcp`. Its canonical URL is the **MCP resource
  identifier**.
- **Capability function:** one of a fixed, enumerated set of Postgres functions that implement the
  MCP tools, reachable through the project's Data API. Version 0.3 starts with **one bounded read
  function** and **no capability views**.
- **Capability role:** the role the Data API switches to for a SACD token (`mcp_ingress` in this
  repository's labs). It is `NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS` and has no role
  memberships.
- **Capability owner role:** a dedicated `NOLOGIN NOSUPERUSER NOBYPASSRLS` role
  (`mcp_capability_owner` below) with these properties:
  - it owns the capability functions;
  - it holds narrowly granted read access to the private tables they need;
  - it does not own those tables;
  - no login or API role can assume it.
- **SACD guard:** a function that every capability function calls first. It validates the
  request's claims and liveness against the database (SACD-11).
- **Approved MCP client:** a client listed in the deployment's server-controlled registry, which
  maps it to exactly one canonical MCP resource. Registration, including dynamic registration,
  does not make a client approved.
- **Declared non-MCP client:** a legitimate OAuth client of the project that is not an MCP client.
  The hook leaves its tokens unchanged, and the MCP endpoint refuses them.
- **SACD token:** an access token the AS issues to an approved MCP client under this profile.

## 4. Requirements

Each requirement has an identifier so that tests, reviews and exceptions can cite it exactly.

### 4.0 Exception acceptance

- **SACD-0 Owner acceptance.** A deployment **MUST NOT** enable data tools under this profile until
  the accountable owner has recorded acceptance of the exception described at the top of this
  document. For this repository that is the repository owner. Permission to draft or test the
  profile is not that acceptance.

### 4.1 Authority and issuance

- **SACD-1 Single authority.** The MCP endpoint and the capability functions **MUST** be protected
  by the same AS issuer (exact string match) in the same project. Anything else is out of scope;
  use the separate-credential mode.
- **SACD-2 Audience binding by server-controlled mapping.** A Custom Access Token Hook **MUST**:
  - set `aud` to the single canonical MCP resource that the server-controlled registry maps to
    the token's `client_id`;
  - do so only for approved MCP clients, never merely because a `client_id` is present;
  - do so identically on initial issuance and on the `refresh_token` grant.

  SACD tokens **MUST NOT** carry the general Data API audience (`authenticated`) or any other
  audience. The `aud` shape **MUST** be one the platform supports. The deployment **MUST** prove
  that the Data API accepts it without widening any existing application audience setting.

  The hook is needed because Supabase Auth currently ignores the RFC 8707 `resource` parameter
  (§9). A hook provides audience binding. It does not cure the upstream-token exception.
- **SACD-3 Capability role.** For approved MCP clients, the hook **MUST** set `role` to the
  capability role.
- **SACD-4 Client classes.** The hook **MUST** treat each class of client explicitly:
  - approved MCP clients receive SACD-2 and SACD-3;
  - declared non-MCP clients are left unchanged;
  - ordinary first-party sessions (no OAuth client) are left unchanged, so the application keeps
    working;
  - any other client is refused with a structured error.

  The refusal of other clients affects the project's whole OAuth server. That matters because
  dynamic registration lets anyone register. A deployment that cannot accept this blanket refusal
  **MUST NOT** enable dynamic registration.

  The platform may record a session as an OAuth-client session while the hook input for its
  refresh lacks `client_id`. Such a refresh **MUST** be refused, never downgraded to an ordinary
  token.
- **SACD-5 Lifetime.** SACD tokens **SHOULD** expire within 15 minutes. Short lifetime
  complements, and does not replace, SACD-11. A documented short-lifetime revocation window is
  acceptable only as a synthetic measurement, never as live revocation.
- **SACD-6 No identity tokens.** The `openid` scope **SHOULD** be refused for MCP clients unless the
  deployment has reviewed a need for ID tokens.

### 4.2 Executable privilege model

- **SACD-7 Capability role privileges.** The capability role's **effective** privileges are its
  direct grants, plus grants to `PUBLIC`, plus memberships. They **MUST** be exactly:
  - `USAGE` on the capability schema;
  - `EXECUTE` on the enumerated capability functions;
  - the safe `PUBLIC` surfaces listed in the deployment's access matrix (§6.1), which **SHOULD**
    be empty.

  It **MUST NOT** hold privileges on any table, view, sequence or other schema. In particular:
  - `EXECUTE` **MUST** be revoked from `PUBLIC` on every function in every Data-API-exposed
    schema, including extension functions, unless the access matrix lists the function;
  - the **global** default privileges of **every role that creates functions** **MUST** be altered so
    new functions are not granted to `PUBLIC` (`ALTER DEFAULT PRIVILEGES FOR ROLE <role> REVOKE
    EXECUTE ON FUNCTIONS FROM PUBLIC`, without `IN SCHEMA`). Per-schema default privileges cannot
    remove the global `PUBLIC EXECUTE` default. Ordinary application roles receive deliberate
    grants instead. The proof showed this concretely: without the global revoke, a function
    created later in an exposed schema was callable with a SACD token;
  - functions created by platform-owned roles that the deployment cannot alter (on Supabase,
    `supabase_admin`) are platform-managed and **MUST** be covered by the catalog lint and the
    deployment fingerprint;
  - extension schemas **MUST NOT** be exposed, and their functions **MUST NOT** be executable by
    the capability role;
  - the capability role **MUST** have no memberships. The API's authenticator role is granted the
    capability role so that it can switch to it, and that is the only grant involving it.

  Recorded exceptions:
  - **Schema barrier.** A platform-owned function that keeps `PUBLIC EXECUTE` but lives in a schema
    where the capability role has no `USAGE` (on Supabase, `graphql_public.graphql`) is
    unreachable. It is recorded as a schema-barrier exception. That barrier is a fingerprint
    dependency.
  - **Migration-role ADMIN.** PostgreSQL 16 and later give the role that creates the two roles
    (the migration role) `ADMIN` on them, without `SET`. This is a privileged migration boundary,
    not an ingress path, and it is recorded as an exception to the membership and grantability
    wording of SACD-7 and SACD-8.
- **SACD-8 Definer functions under a restricted owner.** Invoker functions run with the caller's
  privileges, and the capability role has no table privileges. Capability functions therefore
  **MUST** be `SECURITY DEFINER` functions owned by the capability owner role. Each **MUST**:
  - pass the repository's security-definer gate;
  - set a fixed `search_path` (empty, with schema-qualified references);
  - run fixed queries, with no dynamic SQL built from arguments;
  - call the SACD guard first, and derive the principal only from the guard's validated claims,
    never from arguments.

  The capability owner role:
  - **MUST** have `SELECT` only on the enumerated private tables or columns it needs, in schemas
    the Data API does not expose;
  - **MUST NOT** own those tables;
  - **MUST NOT** have `BYPASSRLS`;
  - **MUST NOT** be grantable to, or assumable by, any login, API or capability role.

  A `postgres`-owned or otherwise RLS-bypassing wrapper **MUST NOT** be used instead.

  **Liveness oracle exception.** The platform may prevent granting the capability owner role
  read access to the session store. On Supabase this is the case: the migration role holds
  `USAGE` on schema `auth` without grant option, so the grant silently does nothing. In that case
  one narrow `SECURITY DEFINER` liveness oracle owned by the migration role **MAY** be used. It
  **MUST**:
  - run one fixed query with an empty `search_path`;
  - take only the session, subject and client, and return only a status word;
  - be executable by the capability owner role alone.

  It **MUST NOT** read application data. It **MUST** refuse (return a non-live status) when the
  session policy row is missing or invalid. A missing row must never mean "no limits". It appears
  in the catalog lint, which checks its grantees across all roles, and it is covered by the
  deployment fingerprint (SACD-22). ATLAS accepted this shape in principle as an architectural
  exception (MC1814). Acceptance of the exact implementation is a separate review.
- **SACD-9 RLS still decides rows.** Every deployment-controlled table that a capability function
  reads **MUST** have RLS enabled and forced. Platform-managed tables such as `auth.sessions` **MUST
  NOT** be modified. They are reached only through the liveness oracle (SACD-8). Policies that apply to the capability owner role:
  - **MUST** restrict rows to the validated principal from the guard's claims;
  - **MUST** be `RESTRICTIVE` where they narrow other policies.

  Capability views are out of scope for version 0.3. A later version that adds them must specify
  their privilege model as precisely as this section does.

### 4.3 Backend validation, liveness and bounds

- **SACD-10 Bounds at the authority layer.** Every bound the MCP tools promise **MUST** also hold
  for direct calls:
  - an input size cap;
  - a row cap and a result byte cap, applied inside the function;
  - bounds that still hold when PostgREST query parameters (`select`, filters, `limit`, `order`)
    are applied to function results;
  - a statement timeout and a lock timeout on the capability role;
  - any per-principal quota the deployment claims.

  Timeouts **MUST** be verified through actual Data API requests after a configuration reload. A
  role setting in the catalog is not an execution receipt. Locally, PostgREST applied the
  capability role's timeouts only after a configuration reload; before that, requests ran with
  the authenticator's 8 s limits. Every capability function **MUST** declare a serialized result
  byte budget and refuse results over it. Truncating silently does not meet this requirement.
  The budget **MUST** hold for the **final response**, whatever representation the caller
  requests. To make that enforceable:
  - capability functions **SHOULD** return one fixed JSON document (a scalar) rather than table
    columns, so the Data API cannot re-project, alias or duplicate columns after the check. With
    a scalar result, column projection is refused;
  - the budget **MUST** be checked against the largest representation the Data API can produce for
    that result. For a scalar JSON result on PostgREST, the observed representations are JSON and
    CSV. CSV adds a header line, quotes the document, and doubles every quote and backslash;
  - the proof **MUST** exercise worst-case content (escaped characters and control characters),
    repeated and long aliases, casts, and every enabled media type.

  Declaring a JSON-only media-type domain did not prevent CSV on the local PostgREST, so it is not
  relied on.
- **SACD-11 Backend guard.** On every capability call, the SACD guard **MUST** read the request
  claims and refuse unless all of the following hold:
  - `iss` is the exact pinned issuer;
  - `aud` is exactly the singleton canonical MCP resource;
  - `role` is the capability role;
  - `exp` is in the future;
  - `client_id` is in the **current** approved-client registry, read at call time;
  - `session_id` names a row in `auth.sessions` whose user is `sub` and whose OAuth client is
    `client_id`;
  - the session is not past its `not_after`, and it satisfies every session timeout mode the
    project configures (time-box, inactivity, single-session).

  A deployment where any configured session mode cannot be evaluated from the database **MUST
  NOT** use this profile. Time-box and inactivity limits are read from a deployment-controlled
  policy table that **MUST** mirror the Auth configuration. The fingerprint (SACD-22) compares the
  two. A missing or invalid policy row **MUST** cause refusal. An intentionally disabled mode is an
  explicit null in a present row.

  The guard is a new one-token function and needs its own review. The repository's `sql/05` is a
  two-grant probe: it expects a separate downstream token and denies the capability role. It is a
  pattern to learn from, not a component to reuse.
- **SACD-11a Meaning of "immediate".** Revocation, sign-out or client removal **MUST** cause
  rejection of every Data API statement whose database snapshot is acquired after that change
  commits. A request that starts after the revoking request has returned acquires such a snapshot.
  It does not:
  - recall data already returned;
  - affect a statement whose snapshot predates the commit, even if its guard runs later in wall
    time.

  The guard **MUST** run in the same statement as the data read, so it cannot use an older
  snapshot than the read. Authorization results **MUST NOT** be cached across requests or reused
  across pooled connections. The following **MUST** be defined and tested (§6):
  - behaviour during an in-flight call;
  - a concurrent refresh and revoke;
  - reuse of pooled connections.

### 4.4 MCP endpoint

- **SACD-12 Zero ambient authority.** The MCP endpoint's configuration is the project URL, the
  publishable key, the exact issuer, the MCP resource identifier and the approved-client list. It
  **MUST NOT** possess:
  - a service-role or secret key;
  - a database URL or password;
  - a JWT signing key;
  - stored user credentials.

  It **MUST NOT** construct an admin client, even lazily.
- **SACD-13 Fixed forwarding.** The MCP endpoint **MUST** present the inbound SACD token only to
  the enumerated capability functions, at the same project origin as the issuer. It **MUST NOT**:
  - forward the token to any other host, path or method;
  - accept URLs, function names, schemas, query parameters or SQL from tool arguments;
  - follow redirects with the token.
- **SACD-14 Inbound validation before any forwarding.**
  - The MCP endpoint **MUST** verify the signature against the issuer's JWKS (asymmetric keys
    only), and **MUST** make every SACD-11 claim check it can make without the database. These
    checks duplicate SACD-11 and do not replace it.
  - It **MUST** refuse ID tokens and tokens with missing or malformed claims.
  - On failure it **MUST** return 401 or 403 before tool dispatch, with a resource-metadata
    challenge on 401.
  - Tools that return identity (for example `whoami`) **MUST** call the SACD guard before
    answering, so a revoked token learns nothing.
- **SACD-15 Attribution.**
  - Every forwarded call **MUST** carry a per-request identifier.
  - The endpoint **MUST NOT** log tokens or token fragments.
  - Where audit is required, capability functions **SHOULD** record `client_id`, `sub`,
    `session_id` and the request identifier in an append-only journal.
- **SACD-16 Bounded ingress and cancellation.** The endpoint **MUST**:
  - start its request deadline before reading the body;
  - bound the body size (repository default: 65,536 bytes and 2,000 ms);
  - on deadline or client disconnect, cancel the body reader and abort handler and downstream
    work through a linked signal;
  - keep the budget active until a streamed response body ends, so the deadline or a disconnect
    terminates the stream and aborts the work behind it;
  - refuse early (for example an oversized declared length) without waiting for the client's
    stream to acknowledge cancellation;
  - prove that the aborted work settles.

  Time spent in the platform gateway before the function runs is outside the function's control
  and **MUST** be measured separately (§9).

### 4.5 Other platform surfaces

- **SACD-17 Cross-product denial.** Every other surface of the project **MUST** either refuse SACD
  tokens or grant them no token-derived authority:
  - **Realtime:** Postgres Changes, public and private Broadcast, and Presence. Realtime caches
    channel authorization instead of re-checking every message, which conflicts with SACD-11a.
    Version 0.3 therefore requires **complete denial** of Realtime to SACD tokens, covering joins
    and already-connected sockets after revocation.
  - **GraphQL,** including introspection and function exposure.
  - **Storage:** object operations, bucket administration and signed-URL creation.
  - **Other Edge Functions** in the project.
  - **Auth account operations.**

  A PostgREST pre-request hook does not apply to Storage or Realtime, so each surface **MUST** be
  verified on its own. Public, unauthenticated content is not a token-derived leak and is recorded
  separately. A SACD token may still be able to perform some own-account actions, such as reading
  the user's own Auth profile. Each one is an exception to the claim that the token has exactly
  the MCP tool authority, and each **MUST** be enumerated in the access matrix.

### 4.6 Consent, disclosure, activation and change control

- **SACD-18 Consent and disclosure.** The consent screen **MUST** show:
  - the client's name, flagged as self-asserted when it came from dynamic registration;
  - that the app will act **as the user** on this project's data;
  - the capability families it receives;
  - where to revoke access.

  Approval **MUST** be an explicit user action. The deployment **MUST** state in its
  protected-resource documentation that it implements SACD, and which version.
- **SACD-19 Conformance gate.** Data-bearing tools **MUST** stay fail-closed until SACD-0 is
  recorded and every test in §6 passes on the exact target deployment. A failing or unrunnable
  test means disabled, not passed.
- **SACD-20 Fallback.** A deployment that cannot satisfy SACD-2, SACD-7, SACD-8, SACD-11 or
  SACD-17 **MUST NOT** enable data tools under this profile. It uses the separate-credential mode
  instead.
- **SACD-21 Revisit trigger.** A maintainer clarification of #3413, or a change to the MCP
  authorization text, **MUST** trigger re-review before any further deployment. The endpoint keeps
  a downstream-credential seam so that migration does not require a redesign.
- **SACD-22 Continuous verification and drift.** The catalog lint and the access-matrix tests
  **MUST** run in CI on every migration. A deployment fingerprint check **MUST** also run against
  the live project, and data tools **MUST** fail closed on any unexpected fingerprint. The
  fingerprint covers:
  - function and view bodies and owners;
  - the hook definition and whether the hook is enabled;
  - the approved-client registry contents;
  - role attributes and memberships;
  - default privileges for every creating role;
  - the Data API's exposed schemas;
  - relevant platform settings: JWT expiry, session modes, Realtime authorization and dynamic
    registration.

## 5. Risk map

Every control below is **designed to be verified** by the cited tests. No CT receipts exist yet
for the data path (§9).

| MCP Token Passthrough risk | SACD controls | Tests | Residual |
| --- | --- | --- | --- |
| Tokens for other services accepted | Hook-set singleton `aud` (SACD-2); audience checks at the endpoint and the backend (SACD-11, SACD-14); first-party tokens refused | CT-2, CT-3, CT-5, CT-5D | Depends on a correct hook and registry; drift-checked (SACD-22) |
| Excess downstream authority | Execute-only capability role (SACD-7); restricted definer owner (SACD-8); forced RLS (SACD-9); cross-product denial (SACD-17) | CT-6, CT-7, CT-8, CT-15 | Enumerated own-account exceptions |
| Downstream trusts the token for the wrong reasons | The backend guard re-validates every claim and liveness itself (SACD-11); the endpoint has no authority to lend (SACD-12) | CT-5D, CT-12, CT-20 | None known in the design |
| Server controls bypassed | All data controls live in Postgres (SACD-8 to SACD-11); bounds hold under direct query parameters (SACD-10) | CT-9, CT-14 | Database quotas are coarser than gateway rate limiting |
| Accountability | `client_id`, `sub` and `session_id` in the token and the guard; request IDs and an optional journal (SACD-15) | CT-2, CT-17 | Direct calls carry no MCP request ID |
| Stolen token used as an exfiltration proxy | The same capability set through or around the server; live revocation (SACD-11) | CT-12, CT-13 | Bearer theft within the token's lifetime and capability set. The separate-credential mode keeps data-usable credentials out of the client (§2.3) |
| Trust boundary spread | Singleton audience; no table privileges; Realtime denied | CT-6 to CT-8 | Platform behaviour, verified per deployment |
| Future compatibility | Versioned profile; downstream-credential seam; revisit trigger (SACD-21) | n/a | Migration cost if MCP rules against the profile |

## 6. Conformance

Every test runs against the exact target deployment with synthetic users and produces a receipt.
"Direct" means calling the project's Data API with the SACD token and the publishable key, with
no MCP endpoint involved.

Before the run, the schema cache **MUST** be reloaded. Every denial request **MUST** use a real
route and a valid signature, so that a malformed request or a stale cache cannot pass as a
denial.

### 6.1 Access matrix

The deployment publishes one matrix. Every object reachable through the Data API falls in exactly
one row.

| Object class | Expected for a SACD token | Proof |
| --- | --- | --- |
| Enumerated capability functions | Allowed after the guard passes; return the user's own fixture rows | Nonempty positive control first (CT-9) |
| The SACD guard and other internal helpers | Not directly callable | Direct call denied (CT-7) |
| Private tables read by capability functions | Not reachable through any route | Direct denial (CT-6) |
| Enumerated safe `PUBLIC` surfaces (ideally none) | As listed, each independently reviewed | Listed individually |
| Test-only capability functions (proof deployments only; absent in real deployments) | Allowed after the guard passes | Listed individually; their absence is fingerprint-checked in real deployments |
| Enumerated own-account exceptions | As listed | Listed individually (CT-8) |
| Everything else in every exposed schema, including extension functions | Denied | Exhaustive enumeration (CT-6, CT-7) |

### 6.2 Tests

| ID | Test | Expected |
| --- | --- | --- |
| CT-1 | Discovery: an unauthenticated MCP request, the RFC 9728 metadata, and the AS metadata at the client-facing path | 401 with a resource-metadata challenge; exact resource and issuer |
| CT-2 | SACD token claims (redacted trace), on initial issuance and on refresh | Singleton `aud` equal to the canonical resource; capability `role`; approved `client_id`; `session_id` present |
| CT-3 | A first-party session token and a declared non-MCP client token, each presented at the MCP endpoint | Refused |
| CT-4 | An unknown client requests a token; an OAuth-client session refreshes with `client_id` missing | Refused; never downgraded |
| CT-5 | At the MCP endpoint: forged key, wrong issuer, wrong or extra audience, expired token, wrong role, ID token, missing or malformed claims | Refused before tool dispatch |
| CT-5D | **Direct** to each capability function: every CT-5 variant that the gateway accepts, plus a mismatched user, session or client, and a stale token after client removal | Refused by the SACD guard |
| CT-6 | Direct: every table, view and private relation in every exposed schema | Denied |
| CT-7 | Direct: every function signature in every exposed schema, including the guard and extension functions, called with valid arguments | Exactly as the access matrix (§6.1) states: capability functions allowed, reviewed safe `PUBLIC` exceptions as listed, everything else refused with a specific authorization error. Unknown-route (`PGRST202`) and argument errors do not count as denials |
| CT-8 | Realtime: Postgres Changes, public and private Broadcast, Presence, joins, and an already-connected socket after revocation. Also GraphQL and its introspection; each Storage operation and signed-URL creation; other Edge Functions; each Auth account operation | Each denied, or listed as a public surface or an own-account exception, with one receipt each |
| CT-9 | Direct and through MCP: each capability function against nonempty own-user fixtures, with and without PostgREST query parameters | The same bounded result on both paths |
| CT-10 | Direct and through MCP: requests aimed at another user's rows | Empty or denied on both paths |
| CT-11 | Writes and other non-capability operations, through both paths | Denied |
| CT-12 | Revoke the grant, then call with the already-issued token on both paths | Refused for every request started after the revoking request returned |
| CT-13 | Session `not_after`, each configured session timeout mode (time-box, inactivity), and a missing policy row | As CT-12; inactivity is measured from the last refresh; a missing policy row refuses |
| CT-14 | Through both paths, after a configuration reload: oversized inputs and over-cap rows; a byte-budget grid (escape and control-character content, several row counts, repeated, long and cast aliases, every enabled media type); slow queries; lock waits; aggregate and filter parameters; concurrent per-principal calls | Refused, capped or timed out by the backend as specified; every allowed response is within the byte budget on the wire |
| CT-15 | Catalog lint: effective privileges of the capability role and the capability owner role; definer properties; forced RLS; global default function privileges for every creating role; oracle grantees across all roles; memberships; exposed schemas. Plus a probe that creates a new function in each exposed schema and calls it with a SACD token | Every property asserted, not just logged, and exactly as declared. New functions are refused |
| CT-16 | Endpoint secret scan, static and at runtime | No privileged material read or used |
| CT-17 | Two users and two approved clients, in combination | Each user sees only their own rows; client restrictions hold |
| CT-18 | A real MCP client end to end (the Claude connector) | Matches CT-1 to CT-12 |
| CT-19 | In-flight and concurrent cases: revoke during a stream of calls; concurrent refresh and revoke; a refresh that completes before a revoke; more calls than pooled connections, before and after revocation | Behaviour matches SACD-11a; no call started after the revoke returned is accepted; a refreshed token is refused after the revoke; no stale authorization on reuse |
| CT-20 | Remove a client from the registry while its session stays live | Refused on both paths at the next guard check |
| CT-21 | Drift: in a disposable project, mutate each fingerprint element in turn (function body or owner, hook, registry, role attribute, default privilege, exposed schema, platform setting) | The CI or fingerprint check fails closed for each |
| CT-22 | Endpoint ingress and response lifetime, including with the real MCP SDK: slow and chunked bodies, declared oversize with stalled cancellation, a client disconnect, timed-out handler work, and a streamed (SSE) response with delayed tool work and a downstream fetch | The deadline covers body ingestion and the response body; reader, handler, tool and downstream work are aborted; early refusals return at once (SACD-16) |

## 7. What this profile does not claim

- It does not claim conformance with the literal MCP `2026-07-28` text, and it is not a normative
  exemption. It is a documented exception that requires owner acceptance (SACD-0), and it has been
  submitted upstream for clarification.
- It does not claim to be stronger than a properly scoped separate-credential design. The two
  designs place custody risk in different places (§2.3).
- It does not make bearer tokens safe against theft. It aims for a server that adds nothing to
  what a thief already has, and for revocation that takes effect at the next guard check.
- It does not cover capability views, writes, or backends on another project, issuer or vendor.

## 8. Minimal first proof

The smallest useful local proof, before any hosted step, covers:

- one capability function returning nonempty own-user fixture data;
- the hook, the capability role, the capability owner role and the SACD guard;
- CT-2, CT-4, CT-5D, CT-6, CT-7, CT-9, CT-10, CT-12, CT-13, CT-15, CT-19 and CT-20 for that
  function, plus the function-relevant parts of CT-14;
- Realtime denial (CT-8), proven separately, because the local stack used so far runs without
  Realtime. This remains an activation prerequisite.

Status: run locally (§9), except Realtime denial.

## 9. Evidence to date

All of this is local and synthetic. The source, tests and receipts are in
[`docs/evidence/edge-mcp-pilot/`](evidence/edge-mcp-pilot/README.md).

**Phase 1 authentication pilot (no forwarding).** 16 of 16 checks pass against a complete
expected-ID set:

- AS metadata, an unauthenticated 401 and protected-resource metadata;
- grants with and without `resource`;
- `whoami`, fail-closed data and an oversized body (413);
- refusal of a first-party session, an unapproved client, an unknown key, the wrong issuer, the
  wrong audience and an expired token;
- a minted positive control;
- the expected Auth observations after revocation, with a positive control taken before the
  revoke.

The JWKS-only acceptance of an already-issued token after revocation is reported as a separate
measurement. It is the known gap SACD-11 closes, and it is not counted as a pass. Supabase Auth
v2.197.0 ignored RFC 8707 `resource`. Userinfo is a protected profile endpoint, not RFC 7662
introspection, and is not used for liveness.

**SACD minimal proof.** 47 asserted checks pass against a complete expected-ID set, and one
observation (PostgREST audience acceptance) is reported separately:

- the hook-issued claims on issuance and refresh;
- positive nonempty own-user rows first, then caps that hold even when query parameters are
  added;
- a byte budget of 32,768 bytes on the final response. A 96-case grid crosses two content
  types (escape-heavy and control-character labels), row counts of 5, 20, 40 and 100, four
  projections (none, repeated aliases, long aliases, casts) and three media types (JSON, CSV,
  single-object). No allowed response exceeded the budget; the largest was 22,275 bytes. Over-budget
  requests were refused, and projections were refused with 400;
- per-user isolation;
- the declared non-MCP, first-party, unknown-client and missing-client-refresh cases;
- 12 guard-specific direct negatives, using tokens signed with the real key, plus 4 cases the
  gateway refuses before the guard;
- exhaustive denial of relations, and of every function signature called with valid typed
  arguments, each with a specific authorization error, against positive controls;
- new functions created in both exposed schemas are refused;
- role timeouts applied through real requests after a configuration reload, with statement and
  lock timeouts enforced;
- `not_after`, time-box, inactivity and a missing policy row;
- registry removal, including refresh;
- grant revocation;
- 30 calls on a 10-connection pool before and after revocation;
- 40 staggered calls with a concurrent revoke, where no call started after the revoke returned
  was accepted;
- a refresh-and-revoke race, and a refresh that completed before a revoke;
- a catalog lint that asserts each required property explicitly:
  - the role attributes;
  - the schema-usage allowlists for both roles;
  - the owner, `SECURITY DEFINER` flag and `search_path` of every function in the capability
    schemas, including the oracle;
  - the exact membership sets;
  - the oracle grantees across all roles;
  - the global default ACL.

Thirteen deliberate breakages were each caught:

- no guard call;
- no session check;
- no registry check;
- a hook that maps any client;
- an oracle that ignores the session policy;
- no role timeouts;
- no global function-default revoke (caught by both the new-function probe and the lint);
- a missing policy row that falls through to live;
- no byte budget;
- a budget that counts only the JSON size;
- a capability role with `INHERIT`;
- extra schema usage for the owner role;
- an oracle that is not `SECURITY DEFINER`.

Before the MC1814 and MC1816 fixes, the same suite showed four real defects:

- a function created later was callable with a SACD token (status 200);
- deleting the policy row disabled the session limits;
- a 58 KB result was returned;
- after the first budget fix, caller-controlled projection still produced allowed responses of up
  to 96 KB (7 of 96 grid cases), and CSV re-encoding produced up to 44 KB.

**Platform findings from the proof:**

- The migration role cannot grant `auth` schema access, which led to the oracle exception in
  SACD-8.
- `graphql_public.graphql` keeps `PUBLIC EXECUTE`. It is owned by `supabase_admin`, and the
  migration role's revoke is a silent no-op. It is unreachable because the capability role has
  no `USAGE` on that schema.
- PostgreSQL 17 gives the creating role `ADMIN` on the new roles, without `SET`.
- The local PostgREST, which has no `PGRST_JWT_AUD` set, accepted the singleton MCP audience,
  including the one-element-array form.
- Revoking a grant deletes the session row.

**Ingress and response lifetime (SACD-16):**

- Ten wrapper tests cover body ingestion, the handler, response-body lifetime, early refusal and
  disconnects. Seven failed before their fixes, and six deliberate breakages were each caught.
- With the real MCP SDK (a delayed tool, an SSE response and a downstream fetch), the old wrapper
  delivered the late result after 2 s and never aborted the downstream request. The fixed
  wrapper ends the stream at the deadline and aborts the downstream request on both the deadline
  and a disconnect.
- A slowly sent request body was buffered somewhere before the function. The probe does not
  isolate whether this happened in the gateway, the runtime or delivery. Hosted behaviour is
  unmeasured.

**Not yet proven:**

- hosted audience acceptance;
- hosted hook coverage;
- Realtime denial;
- Storage, other Edge Functions and Auth account operations (CT-8);
- writes (CT-11);
- the full MCP-endpoint path to the capability function;
- real-client behaviour.

## 10. Review history

- **0.1 to 0.2.** An independent, tool-less adversarial review (Claude Sonnet 5) returned
  SOUND_WITH_GAPS. Changes:
  - closed the two gaps it rated fatal: `PUBLIC` function grants, and view-owner RLS bypass;
  - added refresh hook coverage, a live registry check and continuous CI;
  - reworded designed controls so they no longer read as results.
- **0.2 to 0.3.** The ATLAS architecture review rejected 0.2 for adoption and accepted it as a
  research direction with conditions. Changes:
  - **Executable privilege model:** replaced invoker functions and views lacking table privileges
    with definer functions owned by a restricted, RLS-bound owner role; started with one read
    function; removed capability views.
  - **Backend validation:** added the backend guard and direct-backend negative tests; replaced
    the contradictory tests with one access matrix.
  - **Cross-product denial:** added it, including complete Realtime denial.
  - **Liveness and drift:** defined "immediate"; added in-flight and concurrency tests; widened
    drift coverage to a deployment fingerprint.
  - **Hook rules:** server-controlled client-to-resource mapping, explicit client classes, and no
    missing-client downgrade.
  - **Claims:** removed the claim that a second credential adds no boundary; reframed the profile
    as an exception requiring owner acceptance (SACD-0).
  - **Pilot ingress:** fixed the defects ATLAS reproduced (SACD-16, CT-22).
- **0.3 to 0.4.** The ATLAS scoped re-review accepted the local research direction and the minimal
  proof with conditions. Changes:
  - CT-7 now follows the access matrix, and safe `PUBLIC` exceptions need independent review.
  - Revocation is defined on database snapshots acquired after the commit, with a no-reuse rule
    for authorization across requests and pooled connections.
  - FORCE RLS is limited to deployment-controlled tables.
  - The liveness oracle exception and the session-policy table are recorded.
  - Response-lifetime and early-refusal requirements are added.
  - The local proof and its results are added.
- **0.4 to 0.5.** The next ATLAS re-review (MC1814) continued local research with conditions and
  accepted the oracle shape in principle. Changes:
  - The global function-default revoke is required for every creating role, and the
    platform-managed and schema-barrier exceptions are recorded.
  - A missing policy row now refuses.
  - A serialized result byte budget is required.
  - CT-7 requires specific authorization errors, and CT-15 asserts what it logs.
  - Refresh-then-revoke is covered.
  - The migration-role ADMIN exception is recorded.
  - The proof is updated to 47 asserted checks and nine breakages.
- **0.5 to 0.6.** ATLAS (MC1816) resolved the default-ACL and policy-row defects, accepted the local
  oracle implementation, and found the byte budget still bypassable through projection. Changes:
  - The capability now returns one fixed JSON document, measured against the CSV representation.
  - The byte-budget requirement covers the final response.
  - A 96-case representation grid is added.
  - CT-7 calls every signature with valid typed arguments.
  - CT-15 asserts role attributes, schema allowlists and every function's definer property.
  - The proof is updated to 47 asserted checks and 13 breakages.
