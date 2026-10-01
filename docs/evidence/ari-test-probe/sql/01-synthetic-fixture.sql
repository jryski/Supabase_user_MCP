-- L1 throwaway fixture. Apply only on project ref odbcejsuuqdzhabjmozi.
-- Forbidden: lygftpbjgqgvuunkwnxf and any HOUSE, VAULT, or production project.
--
-- This file does not create the Auth hook and does not enable it.
-- Do not add schema ari_probe to Exposed schemas.
-- Do not grant ari_probe.agent_binding to authenticated, anon, public, or
-- mcp_ingress. Hook-only authority is supabase_auth_admin (L3).
--
-- Prerequisite: one dashboard user with email
--   ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid
-- Create that user in the Auth dashboard. Do not reuse a real person.
-- No service_role key belongs in a client or in the probe shell.

begin;

do $fixture$
declare
  synthetic_email constant text := 'ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid';
  marker_value constant text := 'ari-probe-marker-odbcejsuuqdzhabjmozi';
  synthetic_id uuid;
  user_count integer;
begin
  select count(*) into user_count
  from auth.users
  where email = synthetic_email;

  if user_count <> 1 then
    raise exception
      'expected exactly one throwaway user %, found %',
      synthetic_email,
      user_count;
  end if;

  select id into synthetic_id
  from auth.users
  where email = synthetic_email;

  create schema if not exists ari_probe;

  revoke all on schema ari_probe from public, anon, authenticated;
  grant usage on schema ari_probe to supabase_auth_admin;

  create table if not exists ari_probe.agent_binding (
    user_id uuid primary key,
    probe_label text not null,
    constraint agent_binding_label_check
      check (probe_label = 'ari-test-synthetic')
  );

  alter table ari_probe.agent_binding enable row level security;
  alter table ari_probe.agent_binding force row level security;

  revoke all on table ari_probe.agent_binding from public, anon, authenticated;
  grant select on table ari_probe.agent_binding to supabase_auth_admin;

  drop policy if exists agent_binding_hook_read on ari_probe.agent_binding;
  create policy agent_binding_hook_read
    on ari_probe.agent_binding
    for select
    to supabase_auth_admin
    using (true);

  if exists (select 1 from pg_roles where rolname = 'mcp_ingress') then
    execute 'revoke all on schema ari_probe from mcp_ingress';
    execute 'revoke all on table ari_probe.agent_binding from mcp_ingress';
  end if;

  insert into ari_probe.agent_binding (user_id, probe_label)
  values (synthetic_id, 'ari-test-synthetic')
  on conflict (user_id) do update
    set probe_label = excluded.probe_label;

  create table if not exists public.ari_probe_marker (
    marker text primary key,
    owner_id uuid not null
  );

  alter table public.ari_probe_marker enable row level security;
  alter table public.ari_probe_marker force row level security;

  revoke all on table public.ari_probe_marker from public, anon;
  grant select on table public.ari_probe_marker to authenticated;

  drop policy if exists ari_probe_marker_owner_read on public.ari_probe_marker;
  create policy ari_probe_marker_owner_read
    on public.ari_probe_marker
    for select
    to authenticated
    using ((select auth.uid()) = owner_id);

  if exists (select 1 from pg_roles where rolname = 'mcp_ingress') then
    execute 'revoke all on table public.ari_probe_marker from mcp_ingress';
  end if;

  delete from public.ari_probe_marker
  where marker = marker_value;

  insert into public.ari_probe_marker (marker, owner_id)
  values (marker_value, synthetic_id);

  insert into storage.buckets (id, name, public)
  values ('ari-probe-synthetic', 'ari-probe-synthetic', false)
  on conflict (id) do update
    set public = false;

  drop policy if exists ari_probe_synthetic_owner_read on storage.objects;
  create policy ari_probe_synthetic_owner_read
    on storage.objects
    for select
    to authenticated
    using (
      bucket_id = 'ari-probe-synthetic'
      and (
        owner = (select auth.uid())
        or owner_id = (select auth.uid())::text
      )
    );

  drop policy if exists ari_probe_synthetic_owner_insert on storage.objects;
  create policy ari_probe_synthetic_owner_insert
    on storage.objects
    for insert
    to authenticated
    with check (
      bucket_id = 'ari-probe-synthetic'
      and (
        owner = (select auth.uid())
        or owner_id = (select auth.uid())::text
      )
    );

  drop policy if exists ari_probe_synthetic_owner_update on storage.objects;
  create policy ari_probe_synthetic_owner_update
    on storage.objects
    for update
    to authenticated
    using (
      bucket_id = 'ari-probe-synthetic'
      and (
        owner = (select auth.uid())
        or owner_id = (select auth.uid())::text
      )
    )
    with check (
      bucket_id = 'ari-probe-synthetic'
      and (
        owner = (select auth.uid())
        or owner_id = (select auth.uid())::text
      )
    );

  if exists (
    select 1
    from pg_class as relation
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
    where namespace.nspname = 'realtime'
      and relation.relname = 'messages'
  ) then
    execute 'drop policy if exists ari_probe_synthetic_realtime_read on realtime.messages';
    execute format(
      $policy$
        create policy ari_probe_synthetic_realtime_read
          on realtime.messages
          for select
          to authenticated
          using (
            (select realtime.topic()) = 'ari-probe-synthetic'
            and (select auth.uid()) = %L::uuid
          )
      $policy$,
      synthetic_id
    );
  end if;

  if has_table_privilege('anon', 'ari_probe.agent_binding', 'select')
    or has_table_privilege('authenticated', 'ari_probe.agent_binding', 'select')
    or has_table_privilege('public', 'ari_probe.agent_binding', 'select')
  then
    raise exception 'agent_binding is client-readable';
  end if;

  if exists (select 1 from pg_roles where rolname = 'mcp_ingress')
    and has_table_privilege('mcp_ingress', 'ari_probe.agent_binding', 'select')
  then
    raise exception 'agent_binding is readable by mcp_ingress';
  end if;

  if has_table_privilege('anon', 'public.ari_probe_marker', 'select')
    or has_table_privilege('public', 'public.ari_probe_marker', 'select')
  then
    raise exception 'marker table is readable by anon or public';
  end if;
end;
$fixture$;

commit;
