# Program Context

_Status: informative project-orientation document; repository code and issue/PR evidence remain authoritative for implementation state._

Supabase User MCP is one plane in a larger Sovereign Memory program. Keeping the planes separate is a security and architecture requirement, not an organizational preference.

## Ownership

| Plane | Owns | Does not own |
| --- | --- | --- |
| Sovereign Memory Protocol | Implementation-neutral provenance, custody, authority, assurance, conformance, portability, claim limits | Supabase/PostgreSQL mechanics, deployment policy |
| Sovereign Memory Core | PostgreSQL reference runtime, perimeter, replay, restore/provider-exit reference evidence | Protocol meaning, private deployment state |
| Supabase User MCP | Verified user/agent application-data capability into Supabase, fixed tool surface, identity-preserving Data API/RLS path | SMP protocol, deployment membership/policy, generic admin/control plane |
| Deployment/application | Principal membership, enabled capabilities, local UI/connectors, operational acceptance | Upstream protocol semantics |

## Current dependency order

1. Prove verified principal/client identity through a non-service user-context path.
2. Prove strict MCP capability registration and bounded execution.
3. Prove the fixed Data API/RPC path reaches RLS as that identity.
4. Only then claim per-principal application-data authorization.
5. Layer deployment policy, governed writes, artifact inspection, and remote profiles above the proven identity path.

## Adjacent active concepts

### Agent Access Integrity Boundary

The protocol project is evaluating a proposed in-situ profile for establishing a forward T0 evidence boundary before agents are granted access to existing systems of record. This repository may eventually supply an identity/capability mechanism for compatible deployments, but it does not define or certify the protocol profile.

### Governed Artifact Inspection

Issue #34 extends the same user-context principle to durable artifacts in Supabase Storage. The intended boundary is:

```text
agent -> bounded MCP capability -> Edge inspector -> caller-context RLS -> Storage bytes
```

Storage is a separate external data plane. It must be included in containment/durability analysis rather than treated as merely another Postgres relation.

## Claim discipline

- `service_role` or privileged database success is not evidence that a user-context path works.
- An MCP annotation such as `readOnly` is descriptive metadata, not authorization.
- Hidden/unlisted tools are not mechanically inaccessible unless invocation is denied.
- RLS tests prove only the evaluated policies/surfaces; they do not prove every reachable write path is closed.
- Storage dangerous grants, remote token/audience binding, and receipt audience are independent gates and must remain explicit until resolved.
