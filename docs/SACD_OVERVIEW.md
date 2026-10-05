# Same-Authority Capability Delegation: plain-language overview

This page explains the Same-Authority Capability Delegation (SACD) proposal for readers who have
not followed the project's design history. The precise rules are in the
[normative profile](SAME_AUTHORITY_DELEGATION_PROFILE.md), and the reasoning and alternatives are
in [ADR-0006](decisions/0006-same-authority-capability-delegation.md). Both are drafts and are
marked **Proposed**.

## The goal

A Supabase project owner should be able to let their own users connect an AI assistant, such as
Claude or ChatGPT, to that project's data with the following properties:

- the user adds one URL to their assistant and approves access once;
- the assistant acts **as that user**, and PostgreSQL Row Level Security (RLS) still decides
  which rows they can see;
- no privileged key (such as `service_role`) sits anywhere in the request path;
- the user can revoke access at any time, and revocation takes effect on the next request.

## The problem this proposal addresses

The Model Context Protocol (MCP) authorization specification, version `2026-07-28`, says an MCP
server **must not** pass the token it received from the client on to another API. When it needs
an upstream API, it should use a separate token issued for that API. The rule exists for good
reasons: a forwarded token can carry more authority downstream than the MCP server was meant to
use, and clients could bypass the server's controls.

Supabase's own guides show an MCP server running as an Edge Function. It verifies the user's
token and sends that same token to the project's Data API, so RLS applies. That is simple, and
it is the natural way to build on Supabase, but it is token forwarding.

The two sources disagree, and neither covers the case where the MCP server and the data live in
the **same project, under the same sign-in server, for the same user**. The strictly conformant
alternative works, but it costs every adopter something real:

- users consent a second time, to a second credential;
- the server stores that second credential for every user;
- the setup diverges from the platform vendor's guidance.

We asked the MCP maintainers for clarification in
[modelcontextprotocol#3413](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/3413).
While that question is open, this proposal writes down a careful middle path and tests it.

## The idea, in one paragraph

Instead of forwarding a general-purpose user token, the sign-in server issues approved MCP apps
a token that is **only good for the MCP tools**:

- the token names the MCP server as its audience;
- the token carries a dedicated database role that can do exactly one kind of thing: call the
  fixed functions behind the MCP tools;
- every one of those functions first re-checks the token in the database: issuer, audience,
  role, that the app is still approved, and that the user's session is still live.

The result is that the token gives the same, limited access whether it goes through the MCP
server or straight to the database. There is nothing to gain by going around the server, and the
server holds no extra authority of its own.

```text
AI assistant ──token (audience: MCP server, role: mcp_ingress)──▶ MCP server (Edge Function)
                                                                      │ same token, fixed calls only
                                                                      ▼
                                                     Data API ──▶ capability function
                                                                      │ 1. guard re-checks token and live session
                                                                      │ 2. fixed query, size and row limits
                                                                      ▼
                                                               PostgreSQL + RLS
```

## What this is not

- **It is not a claim of MCP conformance.** The same token still crosses a second HTTP hop, which
  the current text forbids. The proposal treats this as a documented exception, and the project
  owner must accept it explicitly before any deployment uses it.
- **It is not proven stronger than the two-token design.** The two designs keep the risky
  credential in different places. SACD keeps a limited, data-usable token in the AI client. The
  two-token design keeps data-usable credentials on the server. The profile explains this
  tradeoff in §2.3.
- **It is not deployed.** Everything described here has run only on a local Supabase stack with
  synthetic users. Data tools stay disabled in any real deployment.

## The main pieces

| Piece | What it does |
| --- | --- |
| Custom access token hook | For apps on a server-controlled approved list, sets the token's audience to the MCP server and its role to `mcp_ingress`. Unknown apps are refused. Ordinary sign-ins are left unchanged |
| `mcp_ingress` role | The only database role these tokens get. It can call the capability functions and nothing else: no tables, no other functions |
| Capability owner role | A restricted role that owns the capability functions and can read only the private tables they need, still under RLS |
| Guard | A function every capability calls first. It re-checks issuer, audience, role, expiry, current app approval and live session, including configured session timeouts |
| Capability function | A fixed query that returns one JSON document, with row, input and serialized byte limits |
| MCP server | Validates the token, then calls only those capability functions. Bounds request size and time, and cancels work when a request times out or the client disconnects |
| Conformance tests | Prove each property on the actual deployment. Data tools stay off until they pass |

## What has been tested

All tests run on a local Supabase stack (CLI 2.119.0, Auth v2.197.0, PostgreSQL 17) with
synthetic users. Each test that is expected to fail is paired with a positive control, so a
denial cannot come from a broken test. Each protective check was also deliberately broken to
confirm that a test catches it.

- **Database proof: 47 checks pass.** It covers:
  - correct tokens on sign-in and refresh;
  - users seeing only their own rows;
  - refusal of forged and mismatched tokens sent straight to the database;
  - refusal of every other table and function;
  - refusal of functions created later;
  - revocation taking effect on the next call, including under connection pooling and
    concurrent requests;
  - session time limits;
  - query timeouts;
  - a response byte limit that holds across 96 combinations of content, row counts,
    column renaming and output formats;
  - a catalog audit of every role and function property.

  Thirteen deliberate breakages were each caught.
- **MCP server bounds.** Ten tests cover request size, request deadlines, streamed responses and
  client disconnects. A test with the real MCP SDK confirms that a slow tool and its outbound
  request are stopped at the deadline.
- **Sign-in flow: 16 checks pass.** They cover discovery, app registration, consent, identity
  and refusals.

The receipts, source and tests are in
[`docs/evidence/edge-mcp-pilot/`](evidence/edge-mcp-pilot/README.md), with SHA-256 hashes for
every file.

## What has not been tested yet

- The checks that the limited token is refused by every other part of a Supabase project
  (Realtime, Storage, other Edge Functions and the Auth account endpoints). Work on these is in
  progress, and they are prerequisites for any deployment.
- Wiring the MCP server's data tool to the capability function, and comparing it side by side
  with direct calls.
- Behaviour on a hosted Supabase project, and with a real AI client end to end.

## How to read the rest

1. [Normative profile](SAME_AUTHORITY_DELEGATION_PROFILE.md): requirements SACD-0 to SACD-22,
   the access matrix and conformance tests CT-1 to CT-22. Read §2 for the argument, §4 for the
   rules and §9 for the evidence.
2. [ADR-0006](decisions/0006-same-authority-capability-delegation.md): the options considered,
   the strongest objections and how they were answered.
3. [ADR-0005](decisions/0005-dual-resource-data-api-binding.md): the strict two-token design,
   which remains the fallback.
4. [Evidence](evidence/edge-mcp-pilot/README.md): how to run the tests, what each receipt shows,
   and its limits.

## How this was reviewed

The proposal went through:

- an independent adversarial review;
- four rounds of architecture review so far, each recorded as a review on the pull request.

Each round found real problems, and each fix landed with a test that failed first. The profile's
§10 lists what changed and why.

## Glossary

- **Audience (`aud`):** the token field that names who the token is for.
- **RLS:** PostgreSQL Row Level Security, which filters rows per user inside the database.
- **Data API:** Supabase's PostgREST endpoint, which turns HTTP requests into database calls.
- **Definer function:** a database function that runs with its owner's privileges instead of the
  caller's. Here the owner is deliberately restricted.
- **Revocation:** the user withdrawing an app's access. Here the database refuses the next call.
