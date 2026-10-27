# Issue #111 reconciliation: tool catalog and remaining capabilities

- **Status:** Step 1 of the #111 delivery sequence (catalog confirmation and assignment). No write tool is implemented here.
- **Scope:** Every tool registered in `packages/server/src` on this branch, plus every capability named in [FEATURES.md](../FEATURES.md).
- **Owners:** Roles only. "Delivery lead" sequences and accepts; "technical integration owner" owns schema, RLS and runtime integration; "typed tool implementation" owns contracts, server code and tests.

## How to read the matrix

- **Registered:** `default` means registered by every server profile. `opt-in` means registered only when a named option or injected dependency is present. `no` means no `registerTool` call exists.
- **Bounds:** Input and output limits enforced by the executable contract, not by documentation.
- **DB impl:** The database object the tool reaches through the fixed Data API client. `none` means the tool reads no database object.
- **Idempotency:** What the contract declares and what a retry does.
- **Runtime acceptance:** `local lab` means a synthetic local Supabase run. No tool has hosted or production runtime acceptance.
- **Status:** `done` means the named scope is merged and accepted at the stated level. `this PR` means this branch changes it. `remaining` means #111 still needs work.

## Registered tools

| Tool | Registered | Bounds | DB impl | Idempotency | Runtime acceptance | Status | Owner |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `memory_search` | default | Query at most 512 characters, at most 5 filters, at most 20 rows, 65,536-byte wire response, 2,000 ms | `memory.authorized_memory_search_v1` (RLS and `has_active_capability`) | Read; idempotent, no automatic retry | local lab (M2 principal-bound read path) | done; publishable-key wiring this PR | typed tool implementation |
| `memory_get` | default | Exactly one opaque `mem_` id, at most 1 row, same wire and time ceilings | `memory.authorized_memory_get_v1` | Read; idempotent | local lab | done; publishable-key wiring this PR | typed tool implementation |
| `memory_list_recent` | default | At most 5 tag filters, at most 25 rows, opaque cursor, same ceilings | `memory.authorized_memory_list_recent_v1` | Read; idempotent; fixed ordering | local lab | done; publishable-key wiring this PR | typed tool implementation |
| `memory_retrieve` | opt-in (draft-two tools) | Composes the search and get bounds; same wire and time ceilings | Search then get RPCs above | Read; idempotent; no server snapshot | Unit and integration tests only | remaining (runtime acceptance) | typed tool implementation |
| `session_capabilities_get` | opt-in (draft-two tools) | Empty input; closed output schema | none (projects the registered tool set) | Read; idempotent | Unit tests only | remaining (runtime acceptance) | typed tool implementation |
| `artifact_stat`, `artifact_read_range`, `artifact_read_lines`, `artifact_read_heading`, `artifact_search_exact` | opt-in (injected authorization, byte reader and receipt journal) | Issue #34 S0 contract limits; at most 8,192-byte verified source for exact search | Artifact registry schema migrations; no live Storage adapter | Read; acknowledged append-only receipt before return | Synthetic SDK demo only | done for synthetic/local; live adapter remaining | technical integration owner |
| `system_compatibility_probe` | compatibility entrypoint only | Fixed probe contract | none | Read | Compatibility tests | done (not a product capability) | typed tool implementation |
| `test_marker_get` | opt-in TEST seam | Empty input; one marker row | TEST-only marker relation, not in migrations | Read | TEST profile only | not a product capability; excluded from #111 | technical integration owner |

## FEATURES.md capabilities without a registered tool

| Capability | Registered | Bounds | DB impl | Idempotency | Runtime acceptance | Status | Owner |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `memory_append_observation` (M3, Specified) | no | Not in contracts | none | Specified: required idempotency key; replay returns the original; key reuse with a different payload is rejected | none | remaining | typed tool implementation |
| `memory_propose_change` (M3, Specified) | no | Not in contracts | none (needs proposal table, payload digest and expiry) | Edits create a new revision and invalidate approval | none | remaining | typed tool implementation |
| `memory_get_proposal` (M3, Specified) | no | Not in contracts | none | Read | none | remaining | typed tool implementation |
| Review and application surface (M3, Research) | no | Not specified | none (needs approval state machine) | Approval bound to one payload digest and expiry | none | remaining; interface undecided | delivery lead |
| Stdio user-token profile (M2, Experimental) | Uses the default memory tools | Protected local credential, 16 KiB file cap | n/a | n/a | local lab | done (experimental); publishable-only key this PR | typed tool implementation |
| Remote HTTP OAuth profile (M4, Experimental) | Uses the default memory tools | Ingress body and frame ceilings | Separate downstream grant; inbound bearer never forwarded | n/a | local lab only | remaining (hosted acceptance); publishable-only key this PR | technical integration owner |
| Governed Artifact Inspection (#34) | See artifact rows above | See above | See above | See above | See above | partially done | technical integration owner |
| Principal lifecycle (M4-M5, Research) | no | n/a | Policy lab tables only | n/a | none | remaining | technical integration owner |
| Access-matrix harness and policy catalog checks (M1) | n/a | n/a | Policy lab and RLS catalog lint | n/a | local lab | done | technical integration owner |
| Reference policy pack (M1-M3) | n/a | n/a | Read migrations only | n/a | local lab | remaining (write policies) | technical integration owner |
| Result and cost governor (M2) | n/a | Shared read ceilings | n/a | n/a | local lab | partially done | typed tool implementation |
| Dual-layer audit (M3) | n/a | n/a | Revocation audit table | n/a | local lab | remaining (write events) | technical integration owner |
| Revocation and incident controls (M5, Planned) | no | n/a | n/a | n/a | none | remaining | delivery lead |
| Adversarial corpus (M2-M5) | n/a | n/a | n/a | n/a | Unit tests | partially done | typed tool implementation |

## #111 delivery sequence items with no catalog entry yet

| Item | Registered | Bounds | DB impl | Idempotency | Runtime acceptance | Status | Owner |
| --- | --- | --- | --- | --- | --- | --- | --- |
| School-menu import and correction with readback | no | Not specified | none in this repository | Needs a conflict rule for corrections | none | remaining; needs a contract before code | delivery lead |
| Intended household tool catalog | no | Not specified | Lives in a separate household repository | n/a | none | remaining; reconcile against this matrix | delivery lead |
| User-scoped Storage (list, get, put, delete) | no | Storage path, size and MIME bounds merged in contracts | Not on this branch; list and get are in a separate draft | Put and delete conflict rules not yet specified | none | remaining | typed tool implementation |
| Integrated release with rollback instructions | n/a | n/a | n/a | n/a | none | remaining | delivery lead |

## What this branch changes

Only the publishable-key wiring on the stdio, fixed-client and remote paths, the dependency
upgrades, and the explicit request-size limits. No tool is added, removed or renamed, and no
migration changes.
