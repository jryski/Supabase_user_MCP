-- Issue #123 S4: Storage database layer.
-- Assumes option A; pending RLS layout decision.
--
-- Option A: one fixed private bucket; object key = `<storage principal uuid>/<relative key>`.
-- The storage principal is the verified human caller, or, for a verified delegated agent, the
-- human named by an active delegation row keyed on auth.uid() + app_metadata.client_id.
-- Synthetic local lab only. No service role, no SECURITY DEFINER, no UPDATE policy.
--
-- Grant-check invariants: policy_lab.has_active_capability and the existing
-- grant_is_active_context policy are reused unchanged. This migration only adds the two
-- storage capability values to the grant CHECK and one SELECT policy that lets a caller
-- see its own active storage grants (same predicate as grant_is_active_context).

-- 1. Capability vocabulary: add storage:read / storage:write to the grant CHECK.
alter table policy_lab.capability_grants
  drop constraint capability_grants_capability_check;
alter table policy_lab.capability_grants
  add constraint capability_grants_capability_check
  check (capability in ('memory:search', 'memory:read', 'storage:read', 'storage:write'));

-- 2. Own active storage grants are visible to the caller under the same predicate as the
--    memory grants. Permissive policies OR together; memory grants are unaffected.
create policy storage_grant_is_active_context on policy_lab.capability_grants
  for select to authenticated
  using (
    principal_id = auth.uid()
    and client_id = auth.jwt() -> 'app_metadata' ->> 'client_id'
    and capability in ('storage:read', 'storage:write')
    and state = 'active'
    and valid_until > now()
  );

-- 3. Delegation: which human's prefix a delegated agent may reach, through which client,
--    and with which storage capabilities (never more than listed here).
create table policy_lab.storage_delegations (
  agent_principal_id uuid not null references policy_lab.principals,
  human_principal_id uuid not null references policy_lab.principals,
  client_id text not null references policy_lab.clients,
  capabilities text[] not null,
  state text not null check (state in ('active', 'expired', 'revoked')),
  valid_until timestamptz not null,
  primary key (agent_principal_id, client_id),
  constraint storage_delegations_distinct_principals
    check (agent_principal_id <> human_principal_id),
  constraint storage_delegations_capabilities_bounded
    check (
      cardinality(capabilities) between 1 and 2
      and capabilities <@ array['storage:read', 'storage:write']::text[]
    )
);

create function policy_lab.storage_delegations_kinds_guard()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if not exists (
    select 1 from policy_lab.principals p
    where p.principal_id = new.agent_principal_id and p.principal_kind = 'delegated_agent'
  ) or not exists (
    select 1 from policy_lab.principals p
    where p.principal_id = new.human_principal_id and p.principal_kind = 'human'
  ) then
    raise exception 'storage delegation must map a delegated_agent to a human'
      using errcode = '23514';
  end if;
  return new;
end;
$$;

revoke all on function policy_lab.storage_delegations_kinds_guard() from public, anon, authenticated;

create trigger storage_delegations_kinds_guard
  before insert or update on policy_lab.storage_delegations
  for each row execute function policy_lab.storage_delegations_kinds_guard();

revoke all on policy_lab.storage_delegations from public, anon, authenticated;
grant select on policy_lab.storage_delegations to authenticated;
alter table policy_lab.storage_delegations enable row level security;
alter table policy_lab.storage_delegations force row level security;

create policy storage_delegation_is_active_context on policy_lab.storage_delegations
  for select to authenticated
  using (
    agent_principal_id = auth.uid()
    and client_id = auth.jwt() -> 'app_metadata' ->> 'client_id'
    and state = 'active'
    and valid_until > now()
  );

-- 4. Storage session functions. All SECURITY INVOKER with a fixed empty search_path, so every
--    lookup runs under the caller's own RLS.

-- Effective storage capability for this session: the caller's own active grant through the
-- current client (policy_lab.has_active_capability, unchanged, in any active membership
-- workspace), and, for a delegated agent, an active delegation that lists the capability.
create function policy_lab.storage_has_capability(required_capability text)
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
            )
          )
        )
    );
$$;

-- The principal whose prefix this session may use, or null (fail closed) when the caller
-- holds no effective storage capability or is not a verified human or delegated agent.
create function policy_lab.storage_principal()
returns uuid
language sql
stable
security invoker
set search_path = ''
as $$
  select case
    when not (
      policy_lab.storage_has_capability('storage:read')
      or policy_lab.storage_has_capability('storage:write')
    ) then null
    else (
      select case p.principal_kind
        when 'human' then p.principal_id
        when 'delegated_agent' then (
          select d.human_principal_id
          from policy_lab.storage_delegations d
          where d.agent_principal_id = p.principal_id
            and d.client_id = auth.jwt() -> 'app_metadata' ->> 'client_id'
            and d.state = 'active'
            and d.valid_until > now()
        )
        else null
      end
      from policy_lab.principals p
      where p.principal_id = auth.uid()
        and p.identity_eligibility = 'verified'
    )
  end;
$$;

-- Active storage capabilities for this session, as a JSON array of strings.
create function policy_lab.storage_session_capabilities()
returns jsonb
language sql
stable
security invoker
set search_path = ''
as $$
  select coalesce(jsonb_agg(c.capability order by c.capability), '[]'::jsonb)
  from (values ('storage:read'), ('storage:write')) as c(capability)
  where policy_lab.storage_has_capability(c.capability);
$$;

-- Relative key shape, mirroring the S1 bounds: 1-8 segments, each starting with an ASCII
-- letter or digit, ASCII letters/digits/._- only, no "..", at most 128 bytes per segment and
-- 512 bytes in total, and an allowlisted extension (case-sensitive).
create function policy_lab.storage_relative_key_ok(relative_key text)
returns boolean
language sql
immutable
security invoker
set search_path = ''
as $$
  select coalesce(
    relative_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*){0,7}$'
      and octet_length(relative_key) <= 512
      and strpos(relative_key, '..') = 0
      and relative_key ~ '[.](txt|md|csv|json|pdf|png|jpg|jpeg|webp)$'
      and not exists (
        select 1
        from unnest(string_to_array(relative_key, '/')) as s(segment)
        where octet_length(s.segment) > 128
      ),
    false
  );
$$;

-- The one seam for the object prefix layout. Option A: agents write under the human's prefix,
-- `<storage principal uuid>/`. Whether agents get a `<human>/agents/<agent>/` sub-prefix is an open
-- question; changing the answer means changing only this function. Null means no access.
create function policy_lab.storage_object_prefix()
returns text
language sql
stable
security invoker
set search_path = ''
as $$
  select policy_lab.storage_principal()::text || '/';
$$;

-- One object name check for every storage.objects policy.
create function policy_lab.storage_object_allowed(object_name text, required_capability text)
returns boolean
language sql
stable
security invoker
set search_path = ''
as $$
  select coalesce(
    policy_lab.storage_has_capability(required_capability)
      and (
        select prefix is not null
          and starts_with(object_name, prefix)
          and policy_lab.storage_relative_key_ok(substr(object_name, length(prefix) + 1))
        from (select policy_lab.storage_object_prefix() as prefix) as resolved
      ),
    false
  );
$$;

revoke all on function policy_lab.storage_has_capability(text) from public, anon;
revoke all on function policy_lab.storage_principal() from public, anon;
revoke all on function policy_lab.storage_session_capabilities() from public, anon;
revoke all on function policy_lab.storage_relative_key_ok(text) from public, anon;
revoke all on function policy_lab.storage_object_prefix() from public, anon;
revoke all on function policy_lab.storage_object_allowed(text, text) from public, anon;
grant execute on function policy_lab.storage_has_capability(text) to authenticated;
grant execute on function policy_lab.storage_principal() to authenticated;
grant execute on function policy_lab.storage_session_capabilities() to authenticated;
grant execute on function policy_lab.storage_relative_key_ok(text) to authenticated;
grant execute on function policy_lab.storage_object_prefix() to authenticated;
grant execute on function policy_lab.storage_object_allowed(text, text) to authenticated;

-- 5. The fixed private bucket. Size and MIME limits mirror the S1 bounds.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'mcp-user-storage',
  'mcp-user-storage',
  false,
  5242880,
  array[
    'text/plain', 'text/markdown', 'text/csv', 'application/json', 'application/pdf',
    'image/png', 'image/jpeg', 'image/webp'
  ]
)
on conflict (id) do nothing;

-- 6. storage.objects policies for the fixed bucket. No UPDATE policy: overwrite and move are
--    denied. Delete needs storage:write and, because Storage reads the row first, storage:read.
create policy mcp_user_storage_select on storage.objects
  for select to authenticated
  using (
    bucket_id = 'mcp-user-storage'
    and policy_lab.storage_object_allowed(name, 'storage:read')
  );

create policy mcp_user_storage_insert on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'mcp-user-storage'
    and policy_lab.storage_object_allowed(name, 'storage:write')
  );

create policy mcp_user_storage_delete on storage.objects
  for delete to authenticated
  using (
    bucket_id = 'mcp-user-storage'
    and policy_lab.storage_object_allowed(name, 'storage:write')
  );
