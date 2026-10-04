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
  - The server becomes a store of long-lived refresh tokens. Under a threat model where an
    attacker obtains both the stored ciphertext and the decryption key (for example, full server
    compromise without key isolation), every connected user's downstream credential is exposed.
    Strong key isolation (an external KMS, per-user wrapping, limited decrypt rights) narrows
    this exposure, but it adds operational cost.
  - Refresh rotation, replay and concurrency must be serialized and proven. The N8 intermittent
    failure in this area remains unexplained.
  - Stateless Edge Functions need durable encrypted storage and key management.
  - **B's own authority still has to be bounded at the database.** A plain B token has role
    `authenticated` and the general Data API audience, which is broader than the MCP tools. A
    properly scoped B design therefore needs the same database-side capability bound that Option 3
    makes explicit.
  - In fairness, a properly scoped B design also offers real separation that SACD does not:
    - the data-usable credential stays out of the MCP client's custody, so a compromised client
      exposes only A, which cannot read data;
    - the ingress credential is usable in fewer places;
    - the downstream credential has its own lifecycle and consent.

    Equal database caps do not mean equal breach exposure. The two designs place custody risk in
    different places, and neither is proven globally stronger (profile §2.3).

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

For approved MCP clients only, the authorization server (through a Custom Access Token Hook with
a server-controlled client-to-resource mapping) mints a token with:

- an `aud` that is the single canonical MCP resource;
- a `role` that is an execute-only capability role.

Capability functions are `SECURITY DEFINER` functions owned by a restricted, RLS-bound owner role.
Each calls a backend guard first, which re-validates every claim against the database: the
current client registry and the live session. The server validates inbound tokens and presents
them only to those functions. It holds no authority of its own.

See the profile for:

- the normative requirements (SACD-0 to SACD-22);
- the access matrix and conformance suite (CT-1 to CT-22);
- the minimal first proof (§8).

- **For:**
  - Each MCP-listed passthrough harm maps to a database-enforced control (profile §5), to be
    proven by direct-backend tests.
  - Inbound audience binding is provided by the hook.
  - There is no server-side credential store, and only one consent.
  - Revocation is rejected at the next guard check on both the MCP and direct paths.
  - It builds on patterns this repository already explored in laboratory form (`sql/04` to
    `sql/07`, the catalog lint and the security-definer gate). The one-token guard and the
    definer model are new and need their own review.
- **Against:**
  - It still sends the same bearer over a separate HTTP hop to the Data API. That is an exception
    to the literal text, and it requires owner acceptance (SACD-0).
  - It places a data-usable token in the MCP client (profile §2.3).
  - It needs a hook, a capability role, a capability owner role, a guard and a capability schema.
    That is more setup than Option 2.
  - The blanket refusal of unknown clients affects the project's whole OAuth server.
  - It depends on platform behaviour that must be verified per deployment: audience acceptance,
    the role switch, refresh hook coverage, session modes in SQL, and Realtime denial.
  - The equivalence claim must be re-proven continuously (SACD-22).
  - Database-level quotas are coarser than gateway rate limiting.

### Option 4: The server connects directly to Postgres (`withPostgresClient`) and sets the claims

- **Rejected.** It puts a privileged database credential in the request path, which violates a
  non-negotiable constraint.

### Option 5: Keep remote data dispatch fail-closed indefinitely

- **Rejected as the end state.** Remote users get nothing, and adopters will use Option 2 instead,
  which is worse for everyone. It stays the state of any deployment that has not passed the
  conformance suite (SACD-19).

## Decision (proposed)

Adopt **Option 3, Same-Authority Capability Delegation**, as a **documented exception** for
deployments where the MCP endpoint and the data share one authorization server and project. It is
specified normatively in
[SAME_AUTHORITY_DELEGATION_PROFILE.md](../SAME_AUTHORITY_DELEGATION_PROFILE.md).

- The repository owner's recorded acceptance of the exception is required before adoption
  (SACD-0). Permission to draft this position is not that acceptance.
- Retain **Option 1** as the strict-conformance mode, and as the mandatory fallback for any
  deployment that cannot satisfy SACD-2, SACD-7, SACD-8, SACD-11 or SACD-17.
- Keep remote data tools **fail-closed** on any deployment until SACD-0 is recorded and its
  conformance suite passes.

### Our position: a justified exception, not an exemption

We make two separate claims and keep them separate.

**Claim 1, about harms.** We read the MCP prohibition as protecting these properties:

1. the server acts only on tokens issued for it;
2. no token carries more downstream authority than the server's purpose requires;
3. downstream controls cannot be bypassed;
4. actions remain attributable.

SACD is designed so that the authorization server and the database enforce all four, through:

- the hook-set audience;
- the execute-only capability role;
- the restricted definer owner under forced RLS;
- the backend guard.

The MCP endpoint is not relied on for any of them. This claim stands or falls on the conformance
suite and on SACD-22 keeping it true.

**Claim 2, about text.** SACD does not remove the separate Data API hop, and it uses one token
where the text requires "a separate token, issued by the upstream authorization server". Treating
the endpoint and its backend as one composite resource is a proposed threat-model
interpretation. It is not a normative exemption. It does not meet the condition ATLAS set for
reconsideration (MC1807), which was a design that removes the hop. We therefore record an
**exception**:

- no strict-conformance claim is made;
- the exception is disclosed in documentation and protected-resource metadata (SACD-18);
- the owner must accept it explicitly (SACD-0);
- the question is submitted upstream (#3413);
- strict deployments use the separate-credential mode.

### Strongest objections, and our responses

**The bright-line objection** (independent adversarial review, in substance). The rule has no
same-authority carve-out. SACD replaces it with an **equivalence claim** that must be re-proven
against every future migration, function, extension and default grant. The first draft's checks
would have missed two realistic breaches. Needing this many requirements and tests is itself
evidence for the simpler rule.

We accept most of this. SACD is only as strong as its continuous verification. SACD-22 therefore
makes the catalog lint, the access-matrix tests and a live deployment fingerprint into gates
rather than one-time checks. The gaps found so far are recorded as requirements and tests
(profile §10).

**The custody objection** (ATLAS review). Equal database capabilities do not establish equal
breach exposure, because a properly scoped B design keeps data-usable credentials out of the
client. We accept this. Earlier drafts claimed that a second token "adds custody, not a boundary",
and that claim is withdrawn. The honest comparison is a tradeoff: SACD avoids a server-side
credential store, and Option 1 avoids a data-usable token in the client (profile §2.3).

## Consequences

### Positive

- One connector URL and one consent for users. No server-side credential store.
- Data controls are enforced in Postgres and re-validated on every call, so the MCP endpoint is
  not a load-bearing control.
- Revocation is rejected at the next guard check on all paths.
- The design can be packaged as a template: a hook, two roles, a guard and a capability schema.
- The argument, objections and tests are public and reusable as input to an MCP clarification or
  SEP.

### Negative

- It is a documented exception to the literal MCP text. Some reviewers will reject it on that
  basis alone, and that is their right.
- It places a data-usable token in the MCP client.
- It requires per-deployment verification of platform behaviour.
- The definer functions, the guard and the owner role are security-critical. Errors in them
  become privilege errors, so CT-15 and the fingerprint check are mandatory gates.
- The refusal of unknown clients affects the project's whole OAuth server.
- Database-side quotas must be designed explicitly.

### Follow-up

1. Scoped ATLAS re-review of the amended profile and ADR at a new pinned head.
2. Minimal local proof (profile §8): one capability function, the hook, the roles, the guard,
   positive fixtures and direct-backend negatives.
3. Owner decision (Jesse) on the exception (SACD-0) and on the ADR.
4. Hosted proof on Ari TEST (owner-gated): the full CT-1 to CT-22 suite with a real Claude
   connector, then read tools.
5. Track #3413 and apply SACD-21 on any maintainer ruling.

## Validation

Acceptance of this ADR requires:

- an independent architecture review recorded on the coordination channel;
- the owner's decision.

Activation on any deployment requires the owner's recorded exception acceptance (SACD-0) and
conformance receipts CT-1 to CT-22 against that exact deployment.

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
- Adversarial review of profile 0.1 (SOUND_WITH_GAPS; addressed in 0.2).
- ATLAS review of 0.2 (MC1810; PR #102 review 5407645463): rejected for adoption, accepted as a
  research direction with conditions; addressed in 0.3 (profile §10).
- ATLAS scoped re-review of 0.3 (MC1812; PR #102 review 5408073603): local research direction and
  minimal proof accepted with conditions; addressed in 0.4 (profile §10).
