# Planning data-plane profile

> **Status:** design input for the Supabase User MCP roadmap  
> **Applies to:** household, business, and other multi-principal planning deployments  
> **Program context:** [`Sovereign AI OS`](https://github.com/jryski/sovereign-memory-core/blob/main/docs/ecosystem/SOVEREIGN_AI_OS.md)

## Purpose

A shared planning board is useful only when humans and agents can act through it without inheriting administrative database authority.

The planning data-plane profile defines the access behaviors required for boards, work items, dependencies, agent leases, progress, evidence submission, and review. The household and business schemas may differ, but the identity and authority problems are the same.

## Required capability families

Names remain provisional until the general capability contract is versioned.

### Read capabilities

- `planning.board.list`
- `planning.board.get`
- `planning.work_item.list`
- `planning.work_item.get`
- `planning.work_item.activity.read`

Reads must be bounded by board visibility, organization or household scope, principal role, assignment rules, sensitivity, and pagination limits.

### Worker capabilities

- `planning.work_item.claim`
- `planning.work_item.heartbeat`
- `planning.work_item.release`
- `planning.work_item.note.append`
- `planning.work_item.submit`

Worker operations must bind the authenticated agent identity to the lease. An agent ID supplied in a tool argument is display metadata at most; it cannot define the caller.

### Coordination capabilities

- `planning.work_item.create`
- `planning.work_item.edit_scope`
- `planning.work_item.assign`
- `planning.work_item.block`
- `planning.dependency.manage`
- `planning.external_reference.attach`

These capabilities may be separated further by deployment. For example, a child may create an inbox item but not reprioritize the household board. A contractor may update assigned business work but not reassign it across teams.

### Review capabilities

- `planning.work_item.review.accept`
- `planning.work_item.review.rework`
- `planning.work_item.review.cancel`
- `planning.work_item.override_lease`

Review authority must be distinct from worker authority. An agent may not accept its own submitted work merely because it can write to the same table.

## Identity requirements

Every consequential call must be attributable to:

- the authenticated human principal, when one initiated or delegated the request;
- the authenticated agent principal performing the work;
- the OAuth client or application identity where applicable;
- the organization, household, tenant, or board scope;
- the active delegation or capability grant;
- the request and action receipt identifiers.

The server must reject attempts to substitute those values through ordinary tool input.

## Lease semantics

Atomic claims prevent duplicate work but do not replace authorization.

A valid claim should include:

- opaque work-item identifier;
- authenticated agent identity;
- unique attempt or claim identifier;
- issued-at and expiry timestamps;
- bounded heartbeat extension;
- maximum attempt and lease limits;
- optional assignment and capability prerequisites;
- immutable audit attribution.

The database should atomically select an eligible item and create the lease. `FOR UPDATE SKIP LOCKED` is one PostgreSQL implementation pattern, not a protocol requirement.

A stale token must fail after expiry, release, cancellation, completion, revocation, or reassignment. Reclaiming a card must invalidate the prior attempt's ability to submit.

## Scheduling metadata is not authority

Fields such as these improve routing but are untrusted unless derived from accepted policy:

```text
required_capabilities
execution_mode
assigned_to_agent
priority
ready_for_claim
```

An agent cannot grant itself `database_write`, `calendar_write`, or reviewer authority by presenting that label to the MCP. The MCP maps trusted grants to allowlisted tools, and PostgreSQL/RLS makes the final row and operation decision.

## Proposed tool shape

The initial surface should be domain-specific and small, for example:

```text
planning_board_get
planning_work_item_get
planning_work_item_claim
planning_work_item_heartbeat
planning_work_item_note_append
planning_work_item_release
planning_work_item_submit
planning_work_item_review
```

The server must not expose arbitrary table names, SQL, filter expressions, RPC names, URLs, or provider identifiers.

Responses should return bounded context, opaque IDs, policy-relevant state, staleness, and the minimum evidence needed for the next operation.

## Database policy inputs

A planning deployment will likely require policy inputs for:

- board visibility and membership;
- household or organization scope;
- team, role, age, or guardian relationship;
- work-item sensitivity;
- assignment and delegation;
- worker versus reviewer separation;
- principal-private annotations;
- revoked and expired grants;
- service-agent restrictions;
- external-action approval requirements;
- administrative override and emergency recovery.

The exact tables and claims belong to the deployment profile. The User MCP must not hard-code deployment-specific schemas into its core identity machinery.

## Minimum adversarial acceptance matrix

Before claiming planning support, prove at least:

1. A permitted principal can read an allowed board and card.
2. An unrelated principal cannot enumerate the board or infer hidden card existence.
3. A permitted worker can claim one eligible card.
4. Two simultaneous workers cannot both receive the same attempt.
5. A worker cannot claim a card outside its board, tenant, assignment, or capability grant.
6. An expired or revoked agent cannot heartbeat, note, release, or submit.
7. A stale claim token fails after another agent reclaims the card.
8. A worker cannot review its own submission unless an explicit accepted policy allows it.
9. A child or limited household principal cannot cross into parent-private or financial domains.
10. A contractor or team agent cannot cross business tenant or team boundaries.
11. Prompt-injected card content cannot alter tool selection, scope, identity, or SQL behavior.
12. Rate, page, payload, activity, and lease limits fail closed.
13. Audit and action receipts identify requester, agent, client, grant, result, and denial reason.
14. Administrative recovery remains possible without making the admin path available to ordinary agents.

## Household and business differences

The capability families can remain shared while policies differ.

### Household profile examples

- guardian and child relationships;
- age-appropriate board visibility and actions;
- shared household work versus principal-private notes;
- school, activity, chore, maintenance, and event boards;
- calendar and household-display adapters.

### Business profile examples

- organization and team tenancy;
- employee, manager, contractor, reviewer, and service-agent roles;
- project, supplier, customer, compliance, incident, and operational boards;
- separation of worker, approver, and auditor;
- CRM, ERP, commerce, ticketing, source-control, and calendar adapters.

## Release sequencing

Planning support should follow the repository's evidence-first milestone model:

1. synthetic schema and principal matrix;
2. read-only board and work-item access;
3. isolated RLS proof;
4. claim and heartbeat with concurrency tests;
5. append-only notes and idempotent submission;
6. reviewer separation and approval tests;
7. revocation, expiry, and containment drills;
8. deployment-specific household or business adapter;
9. controlled production cutover.

A privileged service-role demonstration is useful during construction, but it is not evidence that this profile is complete.
