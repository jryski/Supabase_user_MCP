# G3 — RLS ACCEPTANCE SPEC (Alice/Bob × agentA/agentB)

| Field | Value |
| --- | --- |
| Packet | Finish-queue G3 RLS acceptance design (docs only) |
| Writer | `grok` (integration writer; docs-only) |
| Central | Ariadne |
| Repo | `jryski/Supabase_user_MCP` (Apache-2.0) |
| Scope | Design / acceptance matrix only — no package, lockfile, SQL, harness, or G2 code edits in this PR |
| Related (different artifact) | `docs/finish-queue/G3-G2-VERIFICATION.md` on draft #100 is **not** this packet |
| Non-claims | Not live RLS PASS. Not Token B implemented. Not merge of #79/#98/#100. Not Pages/DNS. Not Primary Users ping. Not HOUSE/website deployment. |

## Purpose

Specify the synthetic multi-user × multi-agent RLS acceptance matrix for User MCP finish:

- Two synthetic human users: **Alice**, **Bob**
- Two distinct agent/client identities: **agentA**, **agentB**
- Positive and negative expectations for each combination
- Clear separation between **MCP/upstream grant-pair clients** and the **two agent identities**
- Trusted mapping must preserve **agent-specific RLS**, not collapse both agents onto one upstream `client_id`

This is a test-design artifact. Integration writer ports accepted tests later onto the G2 candidate.

## Identity planes (do not conflate)

| Plane | What it is | Examples | Must not be confused with |
| --- | --- | --- | --- |
| Human principal | Synthetic end-user (`auth.uid()` / subject) | Alice, Bob | Agent identity; OAuth client registration |
| Agent identity | Distinct MCP-facing client / agent that the human authorizes | agentA, agentB | Upstream Data API client; human principal |
| MCP grant (Token A client) | OAuth client used at the MCP protected resource | `Client_M_A`, `Client_M_B` (or equivalent pre-registered synthetics) | Upstream Token B client |
| Upstream grant (Token B client) | Separate OAuth client/grant used for Data API / Supabase APIs | `Client_U_A`, `Client_U_B` (or equivalent) | MCP Token A client; must not be a single shared upstream client for both agents |
| Trusted mapping | Correlation that binds MCP subject/client ↔ upstream subject/client without elevating via `user_metadata` | Per-agent mapping rows | Collapsing agentA and agentB onto one upstream `client_id` |

**Hard rule:** agentA and agentB remain distinct at the upstream grant plane. A mapping that reuses one upstream `client_id` for both agents is a **fail** for this acceptance matrix, even if both MCP clients verify.

**First-proof policy:** pre-registered synthetic clients and isolated test consent only. No Household-OS or website consent hosting required by this spec.

## Synthetic fixtures (names only; no secrets)

| Fixture | Role |
| --- | --- |
| Alice | Synthetic user A; owns Alice-scoped rows under RLS |
| Bob | Synthetic user B; owns Bob-scoped rows under RLS |
| agentA | Distinct agent / MCP client identity A |
| agentB | Distinct agent / MCP client identity B |
| Row set `alice_private` | Rows insertable/readable only as Alice under RLS |
| Row set `bob_private` | Rows insertable/readable only as Bob under RLS |

No production household payloads. No personal data. Fixtures are disposable lab synthetics.

## Positive cases (must PASS)

| ID | Actor | Agent | Action | Expected |
| --- | --- | --- | --- | --- |
| P1 | Alice | agentA | Read `alice_private` via MCP tools after valid Token A (agentA) + resolved Token B mapped to Alice×agentA | Allowed; rows returned match Alice scope only |
| P2 | Alice | agentB | Read `alice_private` via MCP tools after valid Token A (agentB) + resolved Token B mapped to Alice×agentB | Allowed; Alice scope only; **separate** upstream client/grant from P1 |
| P3 | Bob | agentA | Read `bob_private` via MCP tools after valid Token A (agentA) + resolved Token B mapped to Bob×agentA | Allowed; Bob scope only |
| P4 | Bob | agentB | Read `bob_private` via MCP tools after valid Token A (agentB) + resolved Token B mapped to Bob×agentB | Allowed; Bob scope only; upstream client/grant distinct from P3's agentA mapping |
| P5 | Alice | agentA | Write/insert allowed Alice-scoped synthetic row (if finish tools include write; otherwise mark N/A and keep read-only positives) | Succeeds only within Alice RLS; receipt/audit shows agentA client id |
| P6 | Bob | agentB | Symmetric to P5 for Bob×agentB | Succeeds only within Bob RLS; receipt shows agentB client id |

## Negative cases (must DENY / fail-closed)

| ID | Setup | Action | Expected |
| --- | --- | --- | --- |
| N1 | Alice×agentA authorized | Read `bob_private` | Denied by RLS (empty or 401/403 per tool policy); no Bob row bytes |
| N2 | Bob×agentB authorized | Read `alice_private` | Denied by RLS; no Alice row bytes |
| N3 | Alice×agentA Token A valid; Token B **unresolved** | Any Data API–backed tool call | Fail-closed (`403 downstream_credential_unresolved` or successor); **zero** `/rest/v1` with inbound MCP bearer |
| N4 | Alice×agentA Token A; Token B mapped to **Bob** (cross-principal mapping) | Tool call | Denied; mapping must reject cross-principal correlation |
| N5 | Alice×agentA Token A; attempt to dispatch using **agentB's** upstream grant/client | Tool call | Denied; agent-specific mapping preserved |
| N6 | Valid Alice session; MCP client is **unregistered** / wrong `client_id` | Authorize or tool call | Rejected at Auth/MCP gate |
| N7 | Alice×agentA; inbound MCP bearer forwarded unchanged to Data API (passthrough probe) | Direct or accidental same-bearer upstream call | Must not be the finished design; acceptance records fail if same-bearer passthrough is used as success path |
| N8 | Mapping collapses agentA and agentB onto **one** upstream `client_id` | Any “success” under that collapse | **FAIL this matrix** — agent-specific RLS/grant separation violated |
| N9 | Revoked upstream session/refresh for Alice×agentA (when live revocation is in scope) | Subsequent tool call within revocation bound | Denied; no stale dispatch |
| N10 | Bob tries to use Alice's refresh / grant family | Token or tool call | Denied (`grant_family_conflict` or Auth rejection) |

## Mapping / grant-pair requirements

1. For each (human × agent) pair that is authorized, Token A client and Token B client are **named and distinct** where the finish architecture requires two grants.
2. Trusted mapping keys include at least: human subject, MCP `client_id` (agent), upstream `client_id` (agent-specific), and grant-family / generation as applicable.
3. `user_metadata` is never authority for mapping or RLS.
4. Two agents for the same human still produce **two** upstream client/grant bindings.
5. Evidence receipts (when present) pin head SHA, client ids for both planes, and custody flags — without secrets.

## Out of scope for this document

- Implementing Token B
- Editing G2 package/lockfile/SQL/harness
- Merging #79 / #98 / #100
- Hosted HOUSE or website consent UI
- Claiming live M4 / external-client PASS / issue #62 complete
- Private coordination-bus identifiers or worker-local paths

## Acceptance sign-off (later; not claimed here)

| Gate | Role | Status |
| --- | --- | --- |
| CONTENT (docs) | grok-verifier COMMENT-only | pending after this PR lands |
| Independent security acceptance | Warden / Atlas (named) | not claimed by writer |
| Port tests onto G2 candidate | Integration writer | after CONTENT + Central route |
| Live synthetic run | After Token B + hosted/lab Auth target exists | blocked on those residuals |

## Artifact

In-repo: `docs/finish-queue/G3-RLS-ACCEPTANCE-SPEC.md` (this file).
