-- Local-lab OAuth client claim helper. Never reads user_metadata.
-- MCP resource bound by policy_lab.custom_access_token_hook:
-- https://mcp.loopback.invalid/mcp

create or replace function policy_lab.verified_client_id()
returns text
language sql
stable
security invoker
set search_path = pg_catalog
as $$
  select coalesce(
    nullif(auth.jwt() ->> 'client_id', ''),
    nullif(auth.jwt() #>> '{app_metadata,client_id}', '')
  );
$$;

revoke all on function policy_lab.verified_client_id() from public, anon;
grant execute on function policy_lab.verified_client_id() to authenticated;

create or replace function policy_lab.custom_access_token_hook(event jsonb)
returns jsonb
language sql
stable
security invoker
set search_path = pg_catalog
as $$
  select case
    when coalesce(event #>> '{claims,client_id}', '') = '' then event
    else jsonb_set(
      event,
      '{claims}',
      jsonb_set(
        jsonb_set(
          coalesce(event -> 'claims', '{}'::jsonb),
          '{aud}',
          jsonb_build_array('authenticated', 'https://mcp.loopback.invalid/mcp')
        ),
        '{resource}',
        to_jsonb('https://mcp.loopback.invalid/mcp'::text),
        true
      ),
      true
    )
  end;
$$;

revoke all on function policy_lab.custom_access_token_hook(jsonb) from public, anon, authenticated;
grant usage on schema policy_lab to supabase_auth_admin;
grant execute on function policy_lab.custom_access_token_hook(jsonb) to supabase_auth_admin;

drop policy if exists client_is_active_claim on policy_lab.clients;
create policy client_is_active_claim on policy_lab.clients
  for select to authenticated
  using (
    client_id = policy_lab.verified_client_id()
    and state = 'active'
    and valid_until > now()
  );

drop policy if exists membership_is_active_context on policy_lab.memberships;
create policy membership_is_active_context on policy_lab.memberships
  for select to authenticated
  using (
    principal_id = auth.uid()
    and client_id = policy_lab.verified_client_id()
    and state = 'active'
    and valid_until > now()
  );

drop policy if exists grant_is_active_context on policy_lab.capability_grants;
create policy grant_is_active_context on policy_lab.capability_grants
  for select to authenticated
  using (
    principal_id = auth.uid()
    and client_id = policy_lab.verified_client_id()
    and capability in ('memory:search', 'memory:read')
    and state = 'active'
    and valid_until > now()
  );

drop policy if exists memory_read_intersection on policy_lab.memories;
create policy memory_read_intersection on policy_lab.memories
  for select to authenticated
  using (
    exists (
      select 1
      from policy_lab.principals as p
      join policy_lab.clients as c
        on c.client_id = policy_lab.verified_client_id()
      join policy_lab.memberships as m
        on m.principal_id = p.principal_id
       and m.client_id = c.client_id
       and m.workspace_id = memories.workspace_id
      join policy_lab.capability_grants as g
        on g.principal_id = p.principal_id
       and g.client_id = c.client_id
       and g.workspace_id = m.workspace_id
       and g.capability = 'memory:read'
      where p.principal_id = auth.uid()
        and p.identity_eligibility = 'verified'
        and c.state = 'active'
        and c.valid_until > now()
        and m.state = 'active'
        and m.valid_until > now()
        and g.state = 'active'
        and g.valid_until > now()
    )
  );

drop policy if exists audit_event_current_principal_read on policy_lab.audit_events;
create policy audit_event_current_principal_read on policy_lab.audit_events
  for select to authenticated
  using (
    principal_id = auth.uid()
    and client_id = policy_lab.verified_client_id()
    and exists (
      select 1
      from policy_lab.principals as p
      join policy_lab.clients as c
        on c.client_id = audit_events.client_id
      join policy_lab.memberships as m
        on m.principal_id = audit_events.principal_id
       and m.client_id = audit_events.client_id
       and m.workspace_id = audit_events.workspace_id
      join policy_lab.capability_grants as g
        on g.principal_id = m.principal_id
       and g.client_id = m.client_id
       and g.workspace_id = m.workspace_id
       and g.capability = 'memory:read'
      where p.principal_id = audit_events.principal_id
        and p.identity_eligibility = 'verified'
        and c.state = 'active'
        and c.valid_until > now()
        and m.state = 'active'
        and m.valid_until > now()
        and g.state = 'active'
        and g.valid_until > now()
    )
  );

create or replace function policy_lab.has_active_capability(
  required_capability text,
  required_workspace text
) returns boolean
language sql
stable
security invoker
set search_path = pg_catalog
as $$
  select exists (
    select 1
    from policy_lab.principals p
    join policy_lab.clients c
      on c.client_id = policy_lab.verified_client_id()
    join policy_lab.memberships m
      on m.principal_id = p.principal_id
     and m.client_id = c.client_id
     and m.workspace_id = required_workspace
    join policy_lab.capability_grants g
      on g.principal_id = p.principal_id
     and g.client_id = c.client_id
     and g.workspace_id = m.workspace_id
     and g.capability = required_capability
    where p.principal_id = auth.uid()
      and p.identity_eligibility = 'verified'
      and c.state = 'active'
      and c.valid_until > now()
      and m.state = 'active'
      and m.valid_until > now()
      and g.state = 'active'
      and g.valid_until > now()
  );
$$;
