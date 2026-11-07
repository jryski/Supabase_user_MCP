-- Issue #123 S4 follow-up: a delegated agent's storage access also requires the delegating
-- human's current authority through the same client: a verified human principal, an active
-- membership for that client, and an active storage grant for the same capability in that
-- membership's workspace. This is the delegator side of the same predicate
-- policy_lab.has_active_capability applies to the caller.
-- Assumes option A; pending RLS layout decision.
-- Additive. Synthetic local lab only. No service role, no SECURITY DEFINER, no UPDATE policy.
--
-- policy_lab.has_active_capability, grant_is_active_context and
-- storage_grant_is_active_context are unchanged. This migration adds three SELECT policies
-- (the delegating human's active storage grants, verified principal row and active
-- memberships, each visible only to an agent holding an active delegation from that human
-- through the current client) and replaces policy_lab.storage_has_capability with the same
-- body plus one delegator check in the delegated branch. Before it, a human whose own grant,
-- membership or identity eligibility was revoked, expired or denied could still be reached
-- through an agent whose delegation was active.

-- 1. A delegated agent may see its delegating human's active storage grants, only for the
--    client of an active delegation and only for capabilities that delegation lists.
--    Permissive policies OR together; existing grant visibility is unaffected.
create policy storage_delegator_grant_is_active_context on policy_lab.capability_grants
  for select to authenticated
  using (
    capability in ('storage:read', 'storage:write')
    and client_id = auth.jwt() -> 'app_metadata' ->> 'client_id'
    and state = 'active'
    and valid_until > now()
    and exists (
      select 1
      from policy_lab.storage_delegations d
      where d.agent_principal_id = auth.uid()
        and d.human_principal_id = capability_grants.principal_id
        and d.client_id = capability_grants.client_id
        and d.state = 'active'
        and d.valid_until > now()
        and capability_grants.capability = any (d.capabilities)
    )
  );

-- 2. The same agent may see its delegating human's principal row while that human is a
--    verified human, and that human's active memberships through the current client. The
--    function below reads them under the caller's RLS; a denied, revoked or expired row is
--    invisible and so fails closed. Existing own-row policies are unaffected.
create policy storage_delegator_principal_is_verified on policy_lab.principals
  for select to authenticated
  using (
    principal_kind = 'human'
    and identity_eligibility = 'verified'
    and exists (
      select 1
      from policy_lab.storage_delegations d
      where d.agent_principal_id = auth.uid()
        and d.human_principal_id = principals.principal_id
        and d.client_id = auth.jwt() -> 'app_metadata' ->> 'client_id'
        and d.state = 'active'
        and d.valid_until > now()
    )
  );

create policy storage_delegator_membership_is_active_context on policy_lab.memberships
  for select to authenticated
  using (
    client_id = auth.jwt() -> 'app_metadata' ->> 'client_id'
    and state = 'active'
    and valid_until > now()
    and exists (
      select 1
      from policy_lab.storage_delegations d
      where d.agent_principal_id = auth.uid()
        and d.human_principal_id = memberships.principal_id
        and d.client_id = memberships.client_id
        and d.state = 'active'
        and d.valid_until > now()
    )
  );

-- 3. Same function as 20261027000100, plus the delegating human's current authority: verified
--    human, active membership through the delegation's client, and an active grant for the
--    required capability in that membership's workspace.
create or replace function policy_lab.storage_has_capability(required_capability text)
returns boolean
language sql
stable
security invoker
set search_path = ''
as $$
  select coalesce(required_capability in ('storage:read', 'storage:write'), false)
    and exists (
      select 1
      from policy_lab.memberships m
      where policy_lab.has_active_capability(required_capability, m.workspace_id)
    )
    and exists (
      select 1
      from policy_lab.principals p
      where p.principal_id = auth.uid()
        and p.identity_eligibility = 'verified'
        and (
          p.principal_kind = 'human'
          or (
            p.principal_kind = 'delegated_agent'
            and exists (
              select 1
              from policy_lab.storage_delegations d
              where d.agent_principal_id = p.principal_id
                and d.client_id = auth.jwt() -> 'app_metadata' ->> 'client_id'
                and d.state = 'active'
                and d.valid_until > now()
                and required_capability = any (d.capabilities)
                and exists (
                  select 1
                  from policy_lab.principals hp
                  join policy_lab.memberships hm
                    on hm.principal_id = hp.principal_id
                   and hm.client_id = d.client_id
                  join policy_lab.capability_grants g
                    on g.principal_id = hp.principal_id
                   and g.client_id = hm.client_id
                   and g.workspace_id = hm.workspace_id
                   and g.capability = required_capability
                  where hp.principal_id = d.human_principal_id
                    and hp.principal_kind = 'human'
                    and hp.identity_eligibility = 'verified'
                    and hm.state = 'active'
                    and hm.valid_until > now()
                    and g.state = 'active'
                    and g.valid_until > now()
                )
            )
          )
        )
    );
$$;

revoke all on function policy_lab.storage_has_capability(text) from public, anon;
grant execute on function policy_lab.storage_has_capability(text) to authenticated;
