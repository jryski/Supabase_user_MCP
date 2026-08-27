# Issue 12: revocation and trusted audit

## Bounded M1 slice

This slice adds a local-only `policy_lab.audit_events` relation for synthetic audit evidence. Each row has a stable event identifier, timestamp, principal, required client and workspace context, a bounded event type, and synthetic non-secret metadata. Metadata is capped at 4,096 serialized bytes and rejects secret-bearing keys recursively, including common token, credential, password, authorization, cookie, and payload names.

The relation is append-only for API callers: `anon` and `authenticated` receive no `INSERT`, `UPDATE`, or `DELETE` privilege. `anon` receives no visibility. `authenticated` receives only `SELECT`, constrained by forced RLS to its verified principal and claimed active client, with a current active membership and `memory:read` grant for the event workspace. Missing or malformed context fails closed.

## Revocation transaction bound

The focused pgTAP fixture proves that an active context reads its own event, then changes the corresponding synthetic grant or membership to `revoked`. The identical request context sees zero rows on its next statement in the same local transaction. Savepoints restore each mutation, and the outer transaction always rolls back.

Every demonstrated allow is paired with denial coverage. Existing seed cases cover revoked client, revoked membership, revoked grant, and another principal. An exact grant census permits only `authenticated:SELECT`; executable probes prove API roles cannot insert, update, delete, or truncate audit rows.

## Trusted guard evidence

Rollback-only negative controls deliberately grant `INSERT` to `authenticated` and weaken the audit RLS predicate. Guard assertions observe both breaks before rolling back to the trusted definition. A final assertion proves policy visibility is restored.

## Exclusions and cleanup

This slice creates no function, RPC, write tool, `SECURITY DEFINER`, service-role path, or `BYPASSRLS` path. It accepts no caller-selected schema, table, or origin. It proves principal-scoped visibility under current authorization; it does not yet provide a durable operational or auditor read surface after authorization is revoked. All data is synthetic, contains no credentials or private payloads, and requires no file outside the mounted `supabase` directory for database execution. The migration can be reversed by dropping `policy_lab.audit_events`; test mutations are rollback-only.
