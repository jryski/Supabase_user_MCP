# ADR-0006: Same-authority capability delegation for remote data access

- **Status:** Proposed
- **Date:** 2026-10-04
- **Owners:** Maintainers
- **Milestone:** M4 remote data dispatch
- **Related:**
  - [ADR-0002](0002-remote-identity-chain.md) (identity chain);
  - [ADR-0005](0005-dual-resource-data-api-binding.md) (Option A rejected, remote data dispatch
    fail-closed);
  - normative profile: [SAME_AUTHORITY_DELEGATION_PROFILE.md](../SAME_AUTHORITY_DELEGATION_PROFILE.md);
  - upstream clarification: [modelcontextprotocol#3413](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/3413).
- **Supersedes:** nothing yet. If accepted, it supersedes ADR-0005's fail-closed decision **only**
  for deployments that pass the profile's conformance suite. ADR-0005's rejection of Option A, as
  it was framed there (a dual-audience general token forwarded to the Data API), stands.

## Context

The project's goal is that the owner of a Supabase project can let users add one URL in Claude
or ChatGPT and get user-scoped, RLS-enforced access to that project's application data, with no
privileged key in the request path.

ADR-0005 left remote data dispatch fail-closed. MCP `2026-07-28` says the server "**MUST NOT**
pass through the token it received from the MCP client". It also says that a token used at an
upstream API "is a separate token, issued by the upstream authorization server". ADR-0005 found
no supported way on Supabase to mint that separate downstream credential, except a second,
separately consented OAuth grant held by the server.

Since then:

1. **Supabase ships first-party guidance that forwards the user token.** The [Deploy MCP
   servers](https://supabase.com/docs/guides/ai-tools/byo-mcp) and [MCP
   Authentication](https://supabase.com/docs/guides/auth/oauth-server/mcp-authentication) guides
   run the MCP server as an Edge Function in the project and send the verified user token to the
   Data API. That is a direct conflict with the MCP text, between the platform vendor and the
   protocol.
2. **The MCP text gives no same-authority guidance.** The prohibition and its rationale ([Token
   Passthrough](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices#token-passthrough))
   are written around proxies to third-party APIs. The closest public discussion (#1247) was
   never answered by a maintainer. Public GitHub Discussions in the MCP repository appear closed
   to new posts. We filed #3413 under the spec-ambiguity category.
3. **ATLAS architecture review (MC1807) rejected the literal vendor pattern.** Its reason: no
   normative same-project exemption exists. Its preserved dissent: there is a plausible
   shared-authorization-domain argument, and "a design that truly removes the separate upstream
   API/token hop could be reviewed independently."
4. **The local phase 1 pilot (MC1808) found two platform gaps.**
   - Supabase Auth (v2.197.0) ignores the RFC 8707 `resource` parameter, so tokens carry only
     `aud=authenticated`.
   - With JWKS-only verification, a revoked grant's existing access token keeps working until it
     expires.

The principal (repository owner) has directed that the project define and justify its own
position rather than wait. The reasons: the ecosystem is early, the vendor and protocol disagree,
and the cost of the strict reading falls on every adopter.

## Security constraints

- No `service_role`, secret key, JWT signing secret or database password in the normal request
  path (unchanged from ADR-0005).
- RLS makes the final authorization decision (README thesis).
- Tools are capabilities, not a generic REST console (README thesis).
- Caller-supplied identity labels are never identity proof.
- Intended-resource validation on inbound tokens is mandatory (MCP; ADR-0005).
- Revocation must be live, not merely bounded by expiry (ADR-0005).

## Decision drivers

1. **Real protection, not ritual.** Each security property the MCP prohibition protects must still
   hold. It must be demonstrated by tests on the exact deployment.
2. **No new credential custody.** Every additional long-lived credential the server must hold is
   a new breach target.
3. **Adoptability.** The setup must be one connector URL and one consent for users, and a
   documented install for project owners.
4. **Honesty about conformance.** We must never claim strict MCP conformance for a design that
   departs from its literal text.
5. **Reversibility.** If MCP rules otherwise, migration must not require a redesign.

## Options considered

### Option 1: Separate downstream credential (the "B grant"), the current ADR-0005 direction

The MCP client gets token A, which is audience-bound to the MCP resource and has no data
privileges. A second OAuth client (B) is separately consented by the user. The server stores B's
refresh token encrypted and presents a fresh B access token to the Data API.

- **For:**
  - It matches the literal MCP text.
  - ATLAS accepts it with conditions.
  - Laboratory evidence exists (the N8 gates).
- **Against:**
  - A second consent for every user.
  - The server becomes a store of long-lived refresh tokens, and compromising the server
    compromises every connected user's downstream credential. That is a larger blast radius than
    the problem it solves.
  - Refresh rotation, replay and concurrency must be serialized and proven. The N8 intermittent
    failure in this area remains unexplained.
  - Stateless Edge Functions need durable encrypted storage and key management.
  - **B's own authority still has to be bounded at the database.** A plain B token has role
    `authenticated` and the general Data API audience, which is broader than the MCP tools. So
    the boundary that actually limits authority is the same database-side capability bound that
    Option 3 makes explicit. That holds whichever token carries the capability-role restriction.
    A correctly scoped two-token design is no stronger than SACD on authority, because both rely on
    the same database grants, views and RLS. It is weaker on custody. The second token adds
    custody, not a boundary.

### Option 2: The vendor pattern as published (forward the general user token)

The server verifies the Supabase user token (`aud=authenticated`, `role=authenticated`) and
forwards it to the Data API.

- **For:** simplest, documented by the vendor, and the cheapest to adopt.
- **Against:**
  - The inbound token is not bound to the MCP resource, which fails the MCP inbound MUST.
  - The token carries the user's **full** Data API authority. A thief or a malicious client can
    bypass the MCP tools entirely.
  - Controls applied in the MCP server are bypassable.
  - This is exactly the risk set the MCP prohibition describes.

  **Rejected.** ADR-0005's rejection of Option A stands.

### Option 3: Same-authority capability delegation (SACD)

The authorization server itself mints, for approved MCP clients only:

- a token whose `aud` is the MCP resource;
- with `role` set to a capability role whose only database privileges are the fixed capability
  functions behind the MCP tools.

The database also enforces session liveness, bounds and attribution. The server validates
completely and then presents that token only to those capability functions. It holds no
authority of its own. See the profile for the full normative requirements (SACD-1 to SACD-22) and
the conformance suite (CT-1 to CT-21).

- **For:**
  - Every MCP-listed passthrough risk is neutralized by a database-enforced control, and none
    depends on the server (profile §5).
  - Inbound audience validation is satisfied.
  - There is no stored credential.
  - One consent.
  - Immediate revocation on both the MCP and direct paths, which is stronger than JWKS-only
    Option 1 implementations.
  - It formalizes mechanisms this repository already built and tested in laboratory form:
    - the custom access token hook (`sql/04`, `sql/07`);
    - source-session liveness (`sql/05`);
    - client-aware restrictive RLS (`sql/06`);
    - catalog lint and the security-definer gate.
- **Against:**
  - It departs from the literal text ("separate token") and needs an explicit documented
    deviation.
  - It needs a Custom Access Token Hook and a dedicated role, so it is more setup for project
    owners than Option 2.
  - It depends on platform behaviour that must be verified per deployment, notably whether
    hosted PostgREST accepts a token whose only audience is the MCP resource.
  - Database-level rate limiting is coarser than gateway rate limiting.

### Option 4: The server connects directly to Postgres (`withPostgresClient`) and sets the claims

- **Rejected.** It puts a privileged database credential in the request path, which violates a
  non-negotiable constraint.

### Option 5: Keep remote data dispatch fail-closed indefinitely

- **Rejected as the end state.** Remote users get nothing, and adopters will use Option 2 instead,
  which is worse for everyone. It stays the state of any deployment that has not passed the
  conformance suite (SACD-19).

## Decision (proposed)

Adopt **Option 3, Same-Authority Capability Delegation**, as the project's remote data-access
model for deployments where the MCP endpoint and the data share one authorization server and
project. It is specified normatively in
[SAME_AUTHORITY_DELEGATION_PROFILE.md](../SAME_AUTHORITY_DELEGATION_PROFILE.md).

- Retain **Option 1** as the documented strict-conformance mode, and as the mandatory fallback for
  any deployment that cannot satisfy SACD-2, SACD-7 or SACD-11.
- Keep remote data tools **fail-closed** on any deployment until its conformance suite passes.

### Our position: purpose satisfied, text deviated from

We make two separate claims and keep them separate.

**Claim 1, about purpose.** We read the MCP prohibition as protecting four properties:

1. the server only acts on tokens issued for it;
2. no token carries more downstream authority than the server's purpose requires;
3. downstream controls cannot be bypassed;
4. actions remain attributable.

Under SACD all four are enforced by the authorization server and the database, not by the MCP
endpoint:
- the token's audience is the MCP resource;
- the backend's only grant to the token is the capability role, which exactly matches the MCP
  tool surface;
- the backend re-verifies everything itself.

Presenting the token to the resource's own backend therefore creates none of the harms the rule
names. This claim stands or falls on the conformance suite, and on SACD-22 keeping it true after
every migration.

**Claim 2, about text.** The literal text still does not fit: it says the upstream token "is a
separate token, issued by the upstream authorization server", and SACD uses one token. We do
**not** claim that a correct reading of the text makes SACD conformant. We record a
**deviation**:
- strict-conformance claims are not made;
- the deviation is disclosed in documentation and protected-resource metadata (SACD-18);
- the question is submitted upstream (#3413);
- strict deployments use the separate-credential mode.

### Strongest objection, and our response

An independent adversarial review put the strict case this way, in substance. The rule is a
bright line with no same-authority carve-out. SACD replaces it with an **equivalence claim** ("the
backend allows exactly the tool surface, so there is nothing to bypass"). That claim must be
re-proven against every future migration, function, view, extension and default grant. The
review found two realistic ways the first draft's checks would have missed a breach (default
`PUBLIC` function grants and view-owner RLS bypass). Needing 22 requirements and 21 tests is
itself evidence for the simpler rule.

We accept most of this:
- SACD is only as strong as its continuous verification. That is why SACD-22 makes the
  catalog lint and the exhaustive denial tests a CI gate on every relevant migration, not a
  one-time check.
- Both gaps the review found are now requirements and tests (profile §9).

We do not accept that a second token removes the need for the same proof. A B token minted by
the same Supabase Auth for the same user reaches the same database. Unless it is also
restricted to a capability role, it carries the user's full Data API authority. If it is
restricted, it depends on exactly the same grants, views and RLS, verified the same way. The
strict design keeps every SACD obligation and adds credential custody. The bright line protects
against passthrough to a **separately trusting** API. Here the "upstream" is the same
authority's own database, so the line does not remove the database-side proof obligation.

## Consequences

### Positive

- One connector URL and one consent for users. No credential vault on the server.
- Every security property is enforced in Postgres, where a bypass of the MCP server gains nothing.
- Revocation is immediate on all paths.
- The design generalizes: any project can adopt it with a hook, a role and a capability schema,
  and these can be packaged as a template.
- The argument and tests are public and reusable as input to an MCP clarification or SEP.

### Negative

- It is a documented deviation from the literal MCP text until clarified. Some reviewers will
  reject it on that basis alone, and that is their right.
- It requires per-deployment verification of platform behaviour (PostgREST audience handling,
  hook availability).
- The capability schema becomes security-critical. Errors in grants or `SECURITY DEFINER` use
  become privilege errors, so catalog lint (CT-15) is mandatory and runs in CI on every relevant
  migration (SACD-22).
- The equivalence claim must be re-proven continuously; a lapse in CI coverage is a security
  defect, not a process slip.
- Database-side rate limiting must be designed explicitly.

### Follow-up

1. ATLAS review of this ADR and the profile; Warden review of the conformance suite design.
2. Owner decision (Jesse) to accept, amend or reject.
3. Phase 2, local: implement the hook, capability role, capability schema and liveness for the
   pilot. Run CT-1 to CT-17 and CT-19 to CT-21 locally, including the PostgREST audience question.
4. Phase 3, Ari TEST (owner-gated): deploy, run CT-1 to CT-21 with a real Claude connector, then
   enable read tools.
5. Track #3413 and apply SACD-21 on any maintainer ruling.

## Validation

Acceptance of this ADR requires:

- an independent architecture review recorded on the coordination channel;
- the owner's decision.

Activation on any deployment requires conformance receipts CT-1 to CT-21 against that exact
deployment.

## Revisit when

- MCP maintainers clarify #3413 in either direction, or the MCP authorization text changes.
- Supabase Auth begins honouring RFC 8707 `resource`, or offers a supported downstream token
  exchange. Either would make Option 1 cheaper or make SACD-2 native.
- Any conformance test fails in a way that cannot be fixed within the profile.

## References

- MCP `2026-07-28`, [Access Token Privilege Restriction](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#access-token-privilege-restriction).
- MCP security best practices, [Token Passthrough](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices#token-passthrough)
  and Confused Deputy.
- Supabase, [Deploy MCP servers](https://supabase.com/docs/guides/ai-tools/byo-mcp);
  [MCP Authentication](https://supabase.com/docs/guides/auth/oauth-server/mcp-authentication);
  [Token security and RLS](https://supabase.com/docs/guides/auth/oauth-server/token-security).
- RFC 8707 (Resource Indicators), RFC 9728 (Protected Resource Metadata), RFC 9068 (JWT access
  tokens).
- Repository: ADR-0002, ADR-0005; `docs/evidence/ari-test-probe/sql/04`–`07`;
  `docs/evidence/ISSUE_3_RLS_CATALOG_LINT.md`; `docs/evidence/ISSUE_4_SECURITY_DEFINER_GATE.md`.
- Coordination: ATLAS review MC1807; phase 1 pilot report MC1808.
- Adversarial review of profile 0.1 (SOUND_WITH_GAPS; findings closed in profile 0.2, §9).
