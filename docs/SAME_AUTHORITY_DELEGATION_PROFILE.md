# Same-Authority Capability Delegation (SACD) profile

- **Profile version:** 0.3 (draft). 0.1 was amended after an adversarial review (0.2), and 0.2
  after the ATLAS architecture review (0.3). See §10.
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
  - for **every role that creates objects** in exposed schemas, default privileges **MUST** be
    altered so that new functions are not granted to `PUBLIC`;
  - extension schemas **MUST NOT** be exposed, and their functions **MUST NOT** be executable by
    the capability role;
  - the capability role **MUST** have no memberships. The API's authenticator role is granted the
    capability role so that it can switch to it, and that is the only grant involving it.
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
- **SACD-9 RLS still decides rows.** Every private table a capability function reads **MUST** have
  RLS enabled and forced. Policies that apply to the capability owner role:
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
  role setting in the catalog is not an execution receipt.
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
  NOT** use this profile.

  The guard is a new one-token function and needs its own review. The repository's `sql/05` is a
  two-grant probe: it expects a separate downstream token and denies the capability role. It is a
  pattern to learn from, not a component to reuse.
- **SACD-11a Meaning of "immediate".** Revocation, sign-out or client removal **MUST** cause
  rejection of every call whose guard check runs after that change commits. It does not:
  - recall data already returned;
  - cancel a statement whose guard check already passed under an earlier snapshot.

  Behaviour during an in-flight call, during a concurrent refresh and revoke, and on reuse of a
  pooled connection **MUST** be defined and tested (§6).

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
| Enumerated safe `PUBLIC` surfaces (ideally none) | As listed | Listed individually |
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
| CT-7 | Direct: every function in every exposed schema other than the capability functions, including the guard and extension functions | Denied |
| CT-8 | Realtime: Postgres Changes, public and private Broadcast, Presence, joins, and an already-connected socket after revocation. Also GraphQL and its introspection; each Storage operation and signed-URL creation; other Edge Functions; each Auth account operation | Each denied, or listed as a public surface or an own-account exception, with one receipt each |
| CT-9 | Direct and through MCP: each capability function against nonempty own-user fixtures, with and without PostgREST query parameters | The same bounded result on both paths |
| CT-10 | Direct and through MCP: requests aimed at another user's rows | Empty or denied on both paths |
| CT-11 | Writes and other non-capability operations, through both paths | Denied |
| CT-12 | Revoke the grant, then call with the already-issued token on both paths | Refused for every call whose guard check runs after the revocation commits |
| CT-13 | Sign-out, and each configured session timeout mode | As CT-12 |
| CT-14 | Through both paths, after a configuration reload: oversized inputs, over-cap rows and bytes, slow queries, lock waits, aggregate and filter parameters, and concurrent per-principal calls | Refused, capped or timed out by the backend as specified |
| CT-15 | Catalog lint: effective privileges of the capability role and the capability owner role; definer properties; forced RLS; default privileges for every creating role; exposed schemas | Exactly as declared |
| CT-16 | Endpoint secret scan, static and at runtime | No privileged material read or used |
| CT-17 | Two users and two approved clients, in combination | Each user sees only their own rows; client restrictions hold |
| CT-18 | A real MCP client end to end (the Claude connector) | Matches CT-1 to CT-12 |
| CT-19 | In-flight and concurrent cases: revoke during a running call; concurrent refresh and revoke; reuse of a pooled connection after revocation | Behaviour matches SACD-11a; no stale authorization on reuse |
| CT-20 | Remove a client from the registry while its session stays live | Refused on both paths at the next guard check |
| CT-21 | Drift: in a disposable project, mutate each fingerprint element in turn (function body or owner, hook, registry, role attribute, default privilege, exposed schema, platform setting) | The CI or fingerprint check fails closed for each |
| CT-22 | Endpoint ingress: slow and chunked bodies, client disconnect, and timed-out handler work | The deadline covers body ingestion; the reader and handler work are aborted and settle (SACD-16) |

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

The smallest useful local proof, before any hosted step, is:
- one capability function returning nonempty own-user fixture data;
- the hook, the capability role, the capability owner role and the SACD guard;
- CT-2, CT-4, CT-5D, CT-6, CT-7, CT-9, CT-10, CT-12, CT-15 and CT-20 for that function;
- Realtime denial (CT-8), proven separately, because the local stack used so far runs without
  Realtime.

## 9. Evidence to date

- **Local phase 1 pilot** (synthetic, with no forwarding). It passed 16/16 checks:
  - AS metadata;
  - an unauthenticated 401;
  - protected-resource metadata;
  - grants with and without `resource`;
  - `whoami`;
  - fail-closed data;
  - an oversized body (413);
  - refusal of a first-party session and of an unapproved client;
  - refusal of an unknown key, the wrong issuer, the wrong audience and an expired token;
  - a minted positive control;
  - observation of revocation.
- **Phase 1 observations:**
  - Supabase Auth v2.197.0 ignored RFC 8707 `resource`, issuing `aud=authenticated` either way.
  - After grant revocation, JWKS-only verification accepted the existing token until expiry,
    while the AS userinfo endpoint returned 403. Userinfo is a protected profile endpoint, not
    RFC 7662 introspection, so it is not used as the liveness mechanism here.
- **Ingress defects found by the ATLAS review and fixed in the pilot:**
  - The original wrapper started its deadline only after reading the body, did not cancel handler
    work, and dropped an already-aborted client signal.
  - The fix adds a linked abort signal. Six Deno tests cover it: four failed before the fix, and
    each of three deliberate breakages of the fix was caught.
  - The 16 checks still pass through the local edge runtime.
  - The local gateway buffered a slowly sent request body before invoking the function, so the
    function's deadline never observed it. Hosted gateway behaviour is unmeasured.
- **Laboratory mechanisms this profile draws on.** These are patterns, not drop-in components:
  - the custom access token hook (`sql/04`, `sql/07`);
  - two-grant source-session liveness (`sql/05`);
  - client-aware restrictive RLS (`sql/06`);
  - the catalog lint and the security-definer gate.
- **Not yet proven:**
  - that the Data API accepts a singleton MCP-resource audience;
  - that the authenticator can switch to the capability role;
  - that the hook covers refresh;
  - that session timeout modes can be evaluated in SQL;
  - Realtime denial;
  - the whole data-path suite;
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
