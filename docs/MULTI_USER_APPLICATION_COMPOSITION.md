# Multi-user application composition

The native-first adapter now has separate read-only and application entrypoints.
Both verify ingress Token A, acquire a distinct downstream grant B, and check the
source session before tool dispatch. Token A is never forwarded to the Data API
or Storage. There is no administrator credential fallback.

## Choose a surface in server code

- `createNativeUserMcpReadHandler(config)` and `createReadOnlyServer(options)`
  always clamp storage to read-only, even if a storage config requests writes.
- `createNativeUserMcpApplicationHandler(config)` and
  `createApplicationServer(options)` permit the existing `storage_put` and
  `storage_delete` tools only when the caller holds the required database grants.
  An explicit `storageReadOnly: true` still clamps the application handler.
- Neither default CLI nor the synthetic remote-pilot entrypoint selects the
  application composition. Selecting it is an application release decision.

Storage still uses the configured fixed bucket and the database-resolved
principal. No tool argument can select a user, principal, bucket or credential.
Create never overwrites; delete is marked destructive. Existing signed download
URLs remain valid until expiry after a grant is revoked. See
[ADR-0009](decisions/0009-storage-rls-option-a.md) for the proposed layout and its
unresolved agent-prefix decision. This change does not approve that ADR or apply
its migrations to an adopter's project.

## Fix the memory RPC schema at startup

Both native handler constructors accept an optional `memoryRpcSchema` in trusted
server configuration. It defaults to `memory`, is validated at construction, and
is snapshotted before any request. The remote pilot reads the same setting from
`SUPABASE_USER_MCP_RPC_SCHEMA`. It uses the stdio compatibility validator: trim
outer whitespace, then require a lowercase SQL identifier of 1–63 characters.
An explicitly empty or malformed value fails startup with a fixed error.

The setting changes only the fixed memory RPCs' profile headers. It does not
select a new RPC, approve a generic capability, configure a Storage schema or
change the public liveness/storage-session RPC profiles. Auth verification gets
no schema header. Memory calls still use the independently bound Token B, and
tool arguments cannot override routing or identity. A configured schema must
already be exposed by the adopter with the correct RPC contracts and grants;
this setting creates no exposure, policy or permission. UUID memory identifiers
and existing opaque identifiers use the same registered tools.

## Register a finite application capability set

Use `createCapabilityRegistrationProfile` once at startup, choosing the
composition and adopter schemas in server code. Pass that immutable profile as
`capabilityProfile` to the matching native handler. The server adapter provides a
fresh downstream credential for each call, obtains the client identity from its
verified B grant, and rechecks source-session liveness and the current user.
No registry, an empty registry, invalid registration or missing release approval
adds no tools.

The shipped approval list is deliberately empty. Adding a descriptor to runtime
configuration cannot approve it. A reviewed release must add the exact descriptor
digest to the compiled list. Read capabilities use fixed GET RPC requests;
proposal capabilities use fixed POST requests only in application composition.
There is no SQL, arbitrary RPC, automatic discovery or runtime allowlist path.
See [capability registration](CAPABILITY_REGISTRATION.md) for the exact envelope,
bounds, review procedure and cancellation/uncertain-outcome rules.

Current database policy binds `app_metadata.client_id`. Generic capabilities keep
that strict binding and reject a conflicting top-level client claim. A native B
token carrying only a top-level client ID cannot satisfy this capability path.
This is a visible adoption prerequisite; it does not silently implement or accept
the separate ADR-0008/PR135 client-binding proposal. Existing fixed native tools
retain their own binding rules.

## Mount own-account consent

The [hosted consent adapter](HOSTED_OAUTH_CONSENT.md) supplies the GET page and
POST decision handler over the existing official user-scoped OAuth API. The host
must mount it at its exact configured HTTPS route and supply freshly verified
browser sessions plus an atomic bounded nonce store. It does not sign in a
different user, accept consent for anyone or create an administrative session.

## Delivery and acceptance

These are executable library integrations, not a claim about a deployed host.
The native downstream grant store remains process-memory-only and discards
refresh tokens. A restart or grant expiry requires reauthorization; using this
reference handler does not replace an adopter's already-reviewed encrypted grant
custody. Real deployment needs that custody integration, the hosted route mount,
the exact reviewed schema/approvals and live own-account acceptance.

For acceptance, use two independently authenticated users and one genuinely
delegated agent. Prove allowed reads and permitted create/get/delete operations;
refuse cross-user object keys and unapproved capabilities; revoke the human grant,
client and delegation and prove the next request is denied. Test both tool
discovery and direct tool calls. Record actual actor, target version and outcomes.
Synthetic SDK/PGlite tests do not establish this live acceptance.

The adopter's existing fixed business tools and durable task-recovery workflow
remain a separate composition. This generic registry does not automatically
approve their RPCs or inherit their idempotency receipts. In particular, `public`
remains forbidden for generic descriptors; native plumbing is not an exception
that permits arbitrary application RPCs.
