# S1 Governed Artifact Inspection Evidence

## Scope

- Prompt: Prompt 1, S1 local user-context enforcement lab.
- Repository: `Supabase_user_MCP`.
- Branch: `chore/smp-s1-lab`.
- Run date: `2026-08-27`.
- Environment: local Supabase CLI `2.116.0`, Docker client `29.7.2`,
  Colima `0.10.3`, Docker Engine `29.5.2`.
- Data: synthetic fixtures only.
- Excluded: hosted Supabase, production resources, credentials, finance data,
  deployment, merge, and public-exposure changes.
- User request path uses a publishable key plus real user JWTs. It never uses
  `service_role`, a Supabase secret key, or a database owner credential.

## Hotel-network safety evidence

Before the final run, macOS Application Firewall reported:

```text
Firewall is enabled. (State = 1)
Firewall has block all state set to disabled.
```

A pre-existing local Supabase project named `stack-smoke` was found publishing
`54321`, `54322`, `54323`, `54324`, and `54327` on `0.0.0.0` and
`::`. Its twelve containers were stopped before this lab continued.

The S1 harness creates or validates a dedicated Docker network:

```bash
docker network create \
  --driver bridge \
  --opt com.docker.network.bridge.host_binding_ipv4=127.0.0.1 \
  supabase-s1-loopback
```

It starts only the services needed for Postgres, Auth, REST, and Storage:

```bash
supabase start \
  --network-id supabase-s1-loopback \
  --exclude realtime,imgproxy,studio,mailpit,edge-runtime,logflare,vector,supavisor
```

Resolved Docker bindings during the passing run:

```text
127.0.0.1:62421 -> local API gateway
127.0.0.1:62422 -> local PostgreSQL
Storage, Auth, and REST -> container-network only
```

The harness stops the S1 project with `supabase stop --no-backup` on every exit.
After the passing run, no process was listening on `62420`, `62421`,
`62422`, `54321`, `54322`, `54323`, `54324`, or `54327`, and
`docker ps --filter name=supabase` returned no running Supabase container.

## Implementation

- Local Supabase config uses custom ports, PostgreSQL 17, disabled Studio and
  Realtime, a fixed result ceiling, and database CIDRs limited to loopback.
- Artifact registry, chunk, derivation, and derivation-input tables use RLS
  with subject and expiry predicates.
- Derivations support multiple source artifacts through
  `derivation_inputs`.
- Update and delete are revoked from non-owner roles on all four artifact
  metadata tables.
- `approved_inspector_clients` has RLS, exposes only the caller's active
  client record, and is non-writable to `anon` and `authenticated`.
- Storage GET requires the exact authenticated-object operation, the fixed
  `artifact-lab` bucket, a visible registry row, and an approved
  `app_metadata.client_id` claim.
- A lab-only uploader claim permits synthetic fixture creation through the
  real Storage API. It does not grant read access.
- Seed data creates five synthetic Auth users, email identities, two private
  buckets, deterministic hashes, six adversarial object scenarios, and a
  two-input derivation.

## Reproduction

```bash
cd /Users/jryski/work/sumcp/Supabase_user_MCP
npm run test:s1
```

The command starts a fresh loopback-only stack, applies both migrations,
loads the seed, mints real password-grant sessions, creates Storage fixtures,
runs the matrix, and stops/removes the local stack.

## Passing test record

`npm run test:s1` exited `0` with 26 named assertions:

1. local services bind only to `127.0.0.1`
2. real Supabase Auth sessions minted for synthetic users
3. fixture upload: authorized
4. fixture upload: wrong-principal
5. fixture upload: expired
6. fixture upload: unregistered
7. fixture upload: mutated
8. fixture upload: outside-bucket
9. authorized read succeeds
10. authorized read returns exact bytes
11. wrong principal denied
12. expired row denied
13. object with no registry row denied
14. object outside fixed bucket denied
15. list enumeration exposes no objects while GET succeeds
16. wrong client capability claim denied
17. absent client capability claim denied
18. direct Storage access with a valid non-inspector user JWT denied
19. missing and unauthorized errors are byte-identical
20. second approved principal reads only its own object
21. many-source derivation supports two inputs
22. mutated object reaches the verifier under authorized RLS
23. object mutated after registration fails hash verification closed
24. artifact metadata is append-only for non-owner roles
25. approved inspector clients table is RLS-protected and non-writable
26. Supabase security advisor reports no warnings or errors

## Claim limits

This proves local Supabase Auth, JWT claim propagation, PostgreSQL RLS,
operation-aware Storage selection, non-enumeration, and deterministic
fail-closed hash comparison using synthetic data.

The mutation verifier is a regression-harness boundary in S1. The production
bounded streaming, chunk inclusion proof, receipt generation, and Edge
execution boundary belong to later prompts. This lab does not claim hosted,
deployed, or production readiness.

## Blockers

No blocker remains for the local Prompt 1 evidence. Review and merge remain
separate maintainer actions.
