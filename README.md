# Supabase User MCP

A data-plane MCP server for Supabase that connects **as an identity** — a human or an
agent — so that Row Level Security actually applies.

Status: **pre-alpha / scoping.** Nothing here is production-ready yet.

---

## Why this exists

The official Supabase MCP server is a **control-plane** tool. It is aimed at one
developer working on their own project: it authenticates with a personal access token or
the `service_role` key, it exposes schema and administrative operations, and Supabase's
own documentation is explicit that it is intended for development and testing rather than
production data.

That is a reasonable product with a deliberate boundary. This project is not an argument
that the boundary is wrong. It is an argument that there is a **second, different**
product on the other side of it.

|                   | Official MCP (control plane) | This project (data plane)          |
| ----------------- | ---------------------------- | ---------------------------------- |
| Audience          | One developer                | A team, plus a fleet of agents     |
| Identity          | Project owner / `service_role` | Individual user or agent         |
| Operations        | Schema, admin, migrations    | Read / write business records       |
| Environment       | Branch or staging            | Production, unavoidably             |
| RLS               | Bypassed                     | Enforced                            |
| Blast radius      | Entire project               | Whatever that one identity can do   |

Different audience, different identity model, different threat model.

### The problem in one sentence

Every agent that connects through a `service_role` credential is a full database
compromise waiting for one poisoned document.

This is not hypothetical. A publicly disclosed attack in 2025 showed an agent reading
support tickets through an MCP server, encountering a ticket whose body was written as
instructions to the model rather than as a complaint, and — running with credentials that
bypass RLS — querying a sensitive table and writing the results back where the attacker
could read them. The row was data to the human and a command to the model.

### Why this gets worse, not better

The interesting scale is not three humans. It is agents, which multiply in a way that
people do not. A new workflow means a new agent, and today every one of them is handed the
same master key. A three-person team with a shared credential is an access-control
annoyance. Two dozen agents with a shared credential is a fleet-wide containment failure.

There is currently no answer for that. This is an attempt at one.

### One mechanism, two problems

Per-identity connections solve multi-user access and prompt-injection containment with the
same lever. If an agent connects as itself, an injected instruction can only ever do what
that agent was already permitted to do. Least privilege partitions the team **and** caps
the damage. There is no need to choose.

---

## How Supabase identity actually works

Worth stating plainly, because conflating two separate systems is where most of the
confusion in this space lives.

1. **Postgres roles** are real database users created with `CREATE ROLE`.
2. **Supabase Auth users** are rows in a table. They are *not* Postgres roles.

When a user signs in, Supabase Auth issues a signed JWT containing their user ID. That
token is presented to PostgREST, which connects to Postgres as one of two *shared* roles:
`anon` or `authenticated`. A thousand users all arrive as the same database role.

Individual identity is therefore **not** the database role. It is carried inside the
request as JWT claims, readable mid-query via `auth.uid()` and `auth.jwt()`.

This is the crux: **RLS policies do not ask which database user you are. They ask what is
in the token.** The official MCP server connects with a raw admin credential and never
establishes that token context at all — which is precisely why RLS has nothing to act on.

A related gotcha, and the source of endless confusion in both directions: RLS is enforced
based on the `Authorization` header, not the `apikey` header. A user token in
`Authorization` will override `service_role` supplied as the API key.

---

## Design

A deliberately thin server. It holds no privileged credential of its own.

```
Agent / Claude Desktop
        │
        │  identity token (per agent, per user)
        ▼
  Supabase User MCP  ──── passes token as Authorization header ────▶ PostgREST
        │                                                              │
        │  no service_role. no DDL. no admin surface.                  ▼
        └──────────────────────────────────────────────────────▶  Postgres + RLS
```

Design commitments:

- **No ambient authority.** The server never holds a credential more powerful than the
  caller's.
- **Pass-through, not translate.** The identity token goes to PostgREST as-is so
  `auth.uid()` resolves correctly.
- **Data plane only.** No schema changes, no migrations, no project administration. If a
  tool could alter the shape of the database, it does not belong here.
- **Agents are first-class identities**, not humans sharing a login. An agent gets its own
  identity, its own policies, and its own audit trail.
- **Untrusted content stays untrusted.** Retrieved rows are data. Nothing read from the
  database is ever treated as an instruction.
- **Writes are gated separately from reads.** Read broadly, write narrowly, and require a
  human for anything canonical or irreversible.

### Build vs. fork

The upstream server is Apache 2.0, so forking is permitted and requires no one's
blessing. But the useful surface here barely overlaps with an admin tool, so a clean
implementation is likely simpler than a fork stripped down to nothing. Supabase has also
published guidance for MCP servers that act on behalf of authenticated users and validate
Auth-issued tokens like any other OAuth client — meaning the pattern this project needs is
already a sanctioned one. It is simply meant for MCP servers you write yourself.

---

## Scope

### In scope

- Per-identity connection using Supabase Auth tokens
- Token pass-through such that RLS is enforced on every query
- Read tools (select, filter, semantic search over embedding columns)
- Write tools, separately permissioned from reads
- Distinct agent identities with per-agent policy
- Audit trail: which identity did what, when
- A policy authoring and verification workflow

### Out of scope

- DDL, migrations, schema inspection beyond what a caller may already read
- Project or organization administration
- Anything requiring `service_role`
- Replacing the official MCP server. This complements it; they serve different planes.

### Non-negotiable

Policies are written and verified **before** any identity is issued. Minting identities
that have no defined permissions is how you end up with three accounts that all
accidentally behave like admin.

---

## Roadmap

**M0 — Policy model.** Define the identity taxonomy (human roles, agent classes) and write
RLS policies against it. Verify with the policy tester before a single line of server code.

**M1 — Minimum viable pass-through.** One read tool, one identity, token forwarded
correctly, RLS demonstrably enforced. Prove the mechanism.

**M2 — Write path.** Separately permissioned writes, with human-review gating on canonical
tables.

**M3 — Fleet.** Multiple concurrent agent identities, per-agent policy, audit trail.

**M4 — Injection test suite.** Adversarial content planted in ingested records, with a
proof that containment holds per identity.

---

## Reference deployment

Developed against a live Postgres 17 project with fourteen tables covering supplier
records, procurement history, document indexes, and an embedding-backed knowledge store
that ingests from email and documents.

Two properties of that deployment motivate the whole design. First, RLS is enabled on
every table and there are currently **zero policies** — which means access today is
strictly binary: everything via `service_role`, or nothing. Second, the knowledge store
ingests from untrusted upstream sources, so injected instructions are a live risk rather
than a theoretical one.

That schema already carries the right instincts in places — a cross-model message table
declares its contents untrusted data and flags rows requiring human decision. Those
instincts are currently documented in comments. The point of this project is to make the
database enforce them.

---

## Contributing

Early. The most valuable contributions right now are adversarial: reasons the pass-through
model is unsound, cases where RLS is insufficient, or prior art that makes this redundant.

## License

Apache 2.0, matching upstream.
