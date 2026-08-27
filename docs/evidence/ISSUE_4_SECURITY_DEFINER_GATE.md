# Issue 4: pre-grant SECURITY DEFINER gate

This evidence note records the documentation and executable contract for governing issue
`#4`. The accepted rule is fail closed: no `EXECUTE` grant to `anon` or `authenticated` is
added for a `SECURITY DEFINER` routine until the owning review records every gate result.

## Threat and invariant mapping

`SECURITY DEFINER` can turn an API-callable routine into an owner-privileged path that
bypasses row-level controls. The gate protects security invariants 4, 5, 6, and 12: API
reachability is deliberate, authentication alone grants nothing, identity comes from
verified request context rather than caller-supplied principal arguments, and uncertainty
fails closed. It reuses issue #3 checks L08 and L09. L08 flags an unsafe or absent fixed
`search_path`; L09 is only a source-text heuristic and requires human review because a
marker neither proves authorization nor captures every safe delegated design.

## Review questions

- Does the routine derive identity from verified request context, with caller-supplied
  principal arguments removed rather than compared to `auth.uid()`?
- Is the `search_path` fixed to an empty or minimal trusted-schema allowlist?
- Do every revoke and grant name the schema-qualified routine and exact argument types?
- Was default access removed with
  `REVOKE EXECUTE ON FUNCTION schema.name(argument_types) FROM PUBLIC`?
- Were the owner's effective privileges reviewed and unnecessary `LOGIN`, `BYPASSRLS`, role
  memberships, and object privileges removed?
- Do negative and cross-identity tests show that the routine fails closed?
- Does the owning review identify the routine and owner and record the identity source,
  ACL, `search_path`, tests, reviewer, result, and date before any API-role grant?

For pre-existing schemas, review effective ACLs as well as explicit grants. No current API
grant means only inaccessible today; it is not evidence that a routine is safe-to-grant.
Service-role-only routines remain inaccessible until reviewed, and existence or prior
operation is not evidence of safety.

## Rollback

If a review is incomplete, contradicted, or invalidated, immediately revoke the
schema-qualified exact routine signature from `anon` and `authenticated`, confirm effective
ACLs deny both roles, and return the routine to the review queue. Rollback restores
inaccessibility; it does not certify the routine as safe.

## Scope limits

This slice adds no SQL and does not change a database, grants, routine implementations,
lifecycles, credentials, or private payloads. It does not weaken or replace L08/L09 and
does not claim that static lint proves runtime authorization. Database changes and their
operational verification remain future, separately reviewed work.
