# External AI-assisted documentation review record

- **Status:** Public-safe attributed review summary
- **Reviewed coordinates:** historical `50f929d55502aba9f3a69391ddccce81a2a23a98`; Phase 1 `f691b1a49cabfc6bcf86f6011509db10a7496f90`
- **Recorded:** 2026-08-31

## Provenance and limits

A project maintainer relayed this repository to an external AI-assisted reviewer through a
Supabase engineer contact. This was not an official Supabase review, statement, endorsement,
or support response. The reviewer was asked to rely on public repository content, public MCP
specifications, and public Supabase documentation.

This document is a maintainer-authored public-safe summary of the interaction, not a verbatim
private-chat transcript. One production-workload anecdote in the first review was explicitly
identified by the reviewer as inappropriate for public reuse and is omitted. No customer data,
private support detail, credential, internal Supabase behavior, or employee-only assertion is
included here.

## Interaction timeline

### 1. Historical README review

The first review produced seven proposed public issues covering:

1. MCP token pass-through and upstream audience binding;
2. row-level versus column-level least privilege;
3. scope containment versus cumulative read volume;
4. RLS bypass surfaces through views, privileged routines, and extensions;
5. authorization-filtered pgvector approximate search;
6. audit timing and identity attribution; and
7. roadmap sequencing for policy and adversarial tests.

The reviewer later determined that its GitHub code-page fetch had been a stale cached response.
The quoted language matched historical README commit `50f929d…`, not current `main`. None of
those seven draft issues was posted.

### 2. Disclosure and K2 corrections

The reviewer proactively identified that one production-workload anecdote in its own first
review should not be published or offered as contribution evidence. The project retired that
material from all public drafts and uses synthetic evidence for future semantic-search work.

The reviewer also corrected the MCP response-budget framing:

- text content plus `structuredContent` is expected compatibility behavior;
- the MCP tools specification says serialized JSON text alongside structured output is
  **SHOULD**, not MUST;
- a semantically equivalent text summary remains an alternative with degraded behavior for
  clients that ignore structured output;
- 65,536 bytes is a project-defined safety budget, not an MCP protocol limit; and
- the enforceable boundary is the selected complete serialized outbound JSON-RPC frame.

README corrections landed through public docs PRs
[#41](https://github.com/jryski/Supabase_user_MCP/pull/41) and
[#42](https://github.com/jryski/Supabase_user_MCP/pull/42).

### 3. Fetch blocker and source bundle

The reviewer could not resolve the new repository SHAs or fetch the requested paths because its
web tool permitted only previously discovered URLs and continued to serve stale GitHub cache.
It refused to invent line numbers and requested uploaded source files instead.

The project supplied a line-numbered corpus and raw-path ZIP containing eleven exact docs from
`f691b1a…`, five public issue threads, active draft PR snapshots, a manifest, and a bounded
Section F response contract. The bundle excluded the retired production anecdote and contained
no unexpected disclosure findings.

### 4. Phase 1 Section F audit

After reading the uploaded corpus, the reviewer returned `REQUEST CHANGES` with nine findings.
The README itself was judged the strongest document and passed on its own. The blocking problem
was contradiction by higher-precedence documents.

| ID | Severity | Finding | Disposition |
| --- | --- | --- | --- |
| F-01 | High | Current public docs and issue bodies contained unnecessary private program labels | Accepted; current tree and issue bodies neutralized |
| F-02 | High | `FEATURES.md` claimed complete-frame byte enforcement that the measured result contradicted | Accepted; feature contract now marks the property intended but unproven |
| F-03 | High | `IMPLEMENTATION_PLAN.md` described a stale probe-only repository and completed work as pending | Accepted; plan reconciled to exact merged and active work |
| F-04 | Medium | Design-document statuses and review dates did not distinguish implemented from proposed sections | Accepted; mixed/active statuses and dates added |
| F-05 | Medium | README named two findings with no public tracker location | Accepted; K1/K2 public finding records added |
| F-06 | Medium | ADR-0002 was proposed but used as the governing remote block | Accepted narrowly; stdio-first/remote-block decision accepted, mechanism unresolved |
| F-07 | Advisory | MCP `2026-07-28` changed remote stateless/discovery and registration assumptions | Recorded as K3 decision drivers, not resolved early |
| F-08 | Advisory | Corrected K2 README wording was accurate | No change required beyond keeping the citation current |
| F-09 | Advisory | Evidence was hard to discover and merged versus draft evidence was not indexed | Accepted; evidence index added |

The reviewer stopped after Section F as requested. K1, K3, and the database-egress/audit topics
were not reviewed in that pass.

## Maintainer response and current public records

- Public issue bodies #11, #17, #18, and #19 use generic deployment wording.
- The current tree contains none of the audited private program labels or deployment codenames.
- PR #38 carries the canonical inherited K1/K2 finding record:
  <https://github.com/jryski/Supabase_user_MCP/pull/38#issuecomment-5472417281>.
- PR #40 carries a scope-correction record preserving its in-scope D1/D2 result:
  <https://github.com/jryski/Supabase_user_MCP/pull/40#issuecomment-5472420979>.
- Draft PR #43 contains the documentation reconciliation:
  <https://github.com/jryski/Supabase_user_MCP/pull/43>.

Independent security review later confirmed K1/K2 are real but inherited from PR #38, not
introduced by PR #40. PR #38 must be repaired before the stacked candidate can be refreshed.
No merge order is accepted; merge remains a separate maintainer decision after repair and
review.

## Authority boundary

External review findings are attributed evidence. They may identify defects, stale claims, or
questions, but they do not authorize merge, deployment, credentials, hosted-project changes,
production data access, or security acceptance. Repository tests, exact-head review, and the
maintainer's explicit decision remain separate gates.
