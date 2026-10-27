-- Issue #123 S4 follow-up: a delegated agent's storage access also requires the delegating
-- human's own active storage grant for the same capability through the same client.
-- Assumes option A; pending RLS layout decision.
-- Additive. Synthetic local lab only. No service role, no SECURITY DEFINER, no UPDATE policy.
--
-- policy_lab.has_active_capability, grant_is_active_context and
-- storage_grant_is_active_context are unchanged. This migration adds one SELECT policy and
-- replaces policy_lab.storage_has_capability with the same body plus one exists check in the
-- delegated branch. Before it, a human whose own storage grant was revoked or expired could
-- still be reached through an agent whose delegation was active.
--
-- Not covered here (tracked): the human's membership state and identity eligibility are not
-- re-checked for the agent path; only the human's grant row is.

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

-- 2. Same function as 20261027000100, plus the delegating human's own active grant.
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
                  from policy_lab.capability_grants g
                  where g.principal_id = d.human_principal_id
                    and g.client_id = d.client_id
                    and g.capability = required_capability
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
