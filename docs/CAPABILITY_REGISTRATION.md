# Finite application capability registration

Status: proposed ADR-0007 implementation candidate. The installed release approves
**zero** application capabilities. Nothing here deploys a function, expands a
grant or grants user access.

## Startup and release approval

`createCapabilityRegistrationProfile` snapshots a proposed descriptor registry,
the operator's dedicated adopter-schema allowlist and the server-selected
composition once at startup. It loads approvals only from the compiled
`capability-release-approvals.ts` module. There is no runtime path or environment
override, RPC discovery, hot reload, or approval supplied by a model. Retain the
opaque frozen profile across sessions; do not construct it in a request handler.

The loader parses the release data strictly and emits
`capability_allowlist_sha256=<hex>` to stderr, or a structured startup event when a
trusted logger is supplied. Log failures and invalid registries disable the whole
extension. The fixed memory tools remain available. An omitted registry is empty.
The profile cannot be reconstructed by copying its public fields.

A release reviewer adds exact `(adr, bodySha256)` pairs to the compiled module.
The descriptor's own matching digest is integrity, not approval. CODEOWNERS covers
the module; enforce independent review with repository branch protection. This
implementation cannot certify reviewer independence, ADR acceptance, the behavior
of the database RPC or permissions on an installed release. The release digest
must be recorded alongside the artifact provenance.

## Composition and credentials

`prepareCapabilityMcpRegistration(config, identity, composition)` produces a
finite independent adapter. `composition` defaults to `read-only`. Its profile
must match that composition; a read-only profile refuses every proposal. Only an
explicit application composition may register `proposal`. There is no generic
write, approval, admin, SQL or call-RPC tool. This seam does not itself turn an
existing pilot into a supported production application profile.

The trusted root supplies a fixed HTTPS project origin, downstream client id and
`currentCredential(signal)`. That provider must verify the **current** downstream
user credential and source-session liveness on each call, preserving the existing
issuer/resource/client/agent chain. It must never return MCP ingress token A,
shared credentials or an elevated project key. The adapter never caches a
credential or result and never falls back to another identity.

Before dispatch, the adapter additionally checks the returned verified principal
and client, publishable project-key shape, token subject, authenticated role and
audience, exact project Auth issuer, expiry and `app_metadata.client_id`. A
conflicting top-level `client_id` is refused; a top-level-only claim does not
satisfy this check. These decoded-token checks are advisory defenses: they do not
replace signature verification or source-session liveness by the trusted provider.
PR #135 / ADR-0008's client-claim decision is separate.

Both the startup profile and per-session configuration are server inputs. Tool
arguments cannot select a route, schema, function, URL, method, identity, client,
project key or approval state. Stored descriptions and results remain untrusted
data. Caller-supplied execution context cannot replace the bound principal/client.

## Fixed RPC envelope

Each reviewed adopter RPC takes **one** JSON argument named `input`. Read
descriptors dispatch `GET /rest/v1/rpc/<fixed-function>?input=<encoded-JSON>` with
the fixed `Accept-Profile`. PostgREST runs GET RPCs in a read-only transaction.
Proposal descriptors dispatch POST with both schema profile headers and body
`{"input":{...validated flat scalar arguments...}}`. Routing is fixed by the
validated descriptor; there are no automatic retries or redirects.

The response is exactly `{"result":{...JSON domain data...}}`: no array, null,
extra envelope keys or prototype-bearing objects. Parsing limits depth to 16 and
the total values to 8,192, in addition to the descriptor's byte bound. The MCP
success becomes `{"ok":true,"result":{...},"contentTrust":"untrusted"}` and uses
the existing untrusted-content text framing. Domain errors must not contain raw
credentials; HTTP failure maps to a fixed unavailable error. Malformed output,
network errors, limits and deadlines use the existing fixed error vocabulary;
raw exception messages and SQL diagnostics are never echoed.

The stream and final duplicated MCP text/structured response are bounded.
Fixed error envelopes use the global transport bound even when a descriptor sets
a smaller success limit. The existing per-principal concurrency/rate governor
applies. Every request carries only the fresh caller token and publishable key.

`public` and platform schemas remain forbidden in the generic registry. Fixed
native public storage/session RPCs are separate reviewed plumbing. An existing
application public facade needs retained native user-scoped integration or a
reviewed dedicated adopter-schema facade; do not add a broad public-schema opt-in.

## Cancellation and uncertain proposals

Cancellation/deadline aborts cover credential resolution, transport and streamed
response reads. The adapter races operations that ignore AbortSignal and refuses
late success; a late returned response body is cancelled. A completed call does
not reuse data from a previous call, so database revocation is evaluated again on
the next dispatch.

A POST proposal may commit before the client sees a timeout or disconnect.
`DEADLINE_EXCEEDED` is **not** proof that no effect occurred. The adapter never
retries automatically. Before a release approves a proposal descriptor, its RPC
must provide domain-appropriate durable idempotency/receipts and a permitted
read-back reconciliation path, reviewed with the adopter's authorization rules.
The generic adapter does not inherit a private application's settlement protocol.
Cancellation cannot roll back a transaction that already committed.

## Verification and remaining release work

Synthetic tests cover contract validation, external approval, schema/name/input
denials, startup snapshotting, read-only composition denial, fixed GET/POST
envelopes, credential rotation and two concurrent users, wrong principal/client/
issuer/audience/role/expiry denials, subsequent HTTP revocation, malformed and
oversized/deep responses, ignored cancellation/deadlines, late-body cleanup, and a
real MCP SDK list/call round trip. The default compiled allowlist is separately
tested as empty. These tests do not establish hosted database or human acceptance.

Before approving any adopter capability: accept/revise ADR-0007, independently
review its RPC body/RLS/grants and proposal reconciliation, approve the exact
descriptor digest, build and record the release allowlist digest, qualify the
real transport/database and per-user isolation, then obtain any required exact
deployment/access authorization. Hosted consent, production downstream credential
custody and ADR-0009 storage layout remain separate integration work.

Rollback removes descriptors or release approvals and restarts with an empty
profile. No schema/data migration is performed by this adapter. Database grant
revocation still applies on the next request before restart.
