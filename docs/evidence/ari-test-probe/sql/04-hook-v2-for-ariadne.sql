-- Hook v2 for Ariadne. This file is not a supabase/migration.
-- This agent does not apply it and does not enable Authentication → Hooks.
-- Do not apply sql/02-hook-for-ariadne.sql. That older function is not v2.
--
-- Forbidden targets: lygftpbjgqgvuunkwnxf and any HOUSE, VAULT, or production
-- project. Confirm the dashboard ref is odbcejsuuqdzhabjmozi first.
--
-- N8: one SQL-editor batch. Paste these settings at the top of the same
-- batch as the rest of this file. A later batch will not see them.
--   select set_config('ari.project_ref', 'odbcejsuuqdzhabjmozi', false);
--   select set_config('ari.oauth_client_id', '<exact registered client id>', false);
--   select set_config('ari.mcp_resource', 'https://odbcejsuuqdzhabjmozi.supabase.co/mcp', false);
--   select set_config('ari.agent_id', '<hook-only agent id>', false);
-- The client id and agent id are parameters. This file has no client-id
-- literal. The MCP resource must be the TEST project's /mcp URL.
--
-- Prerequisite: sql/01 fixture and sql/03 role SQL already applied. Do not
-- recreate the synthetic user. Do not install until Warden has reviewed
-- this file.
--
-- Decisions, matching docs/evidence/ari-test-probe/hook-v2.mjs:
--   absent client_id, including password sessions, returns claims unchanged
--   openid in scope returns a structured error for every OAuth client:
--     {"error":{"http_code":403,"message":"openid_scope_refused"}}
--   a present client_id that is not in ari_probe.mcp_client returns the same
--     structured 403 with message unmapped_client_id
--   a dead or not-live source session returns a structured 401 with message
--     source_session_not_live
--   unexpected faults still raise
--   the one mapped client sets aud to the configured MCP resource,
--   role mcp_ingress, session_id to a fresh uuid, source_session_id to the
--   original session id, and agent_id from the hook-only mapping
-- The fresh session_id must be non-nil and absent from auth.sessions.
-- Liveness runs on each hook call only: token issuance and refresh.
-- It does not run on each MCP call. The adapter has no liveness check.
-- That check is not a revocation receipt.
--
-- Rollback, controller only, on this TEST ref, after the hook is disabled:
--   drop function if exists ari_probe.custom_access_token_hook(jsonb);
--   drop table if exists ari_probe.mcp_client;
-- Do not drop the synthetic user, the marker fixture, or mcp_ingress here.

begin;

do $target$
declare
  project_ref text := current_setting('ari.project_ref', true);
  allowed_ref constant text := 'odbcejsuuqdzhabjmozi';
  forbidden_ref constant text := 'lygftpbjgqgvuunkwnxf';
  v_client_id text := current_setting('ari.oauth_client_id', true);
  v_mcp_resource text := current_setting('ari.mcp_resource', true);
  v_agent_id text := current_setting('ari.agent_id', true);
  expected_resource text;
  synthetic_email constant text := 'ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid';
  user_count integer;
begin
  if project_ref is not distinct from forbidden_ref
    or coalesce(project_ref, '') = ''
    or project_ref is distinct from allowed_ref
  then
    raise exception
      'refusing hook v2 SQL for project ref %; production, HOUSE, and VAULT are forbidden',
      coalesce(project_ref, '<unset>');
  end if;

  select count(*) into user_count
  from auth.users
  where email = synthetic_email;

  if user_count <> 1 then
    raise exception
      'expected exactly one throwaway user %, found %',
      synthetic_email,
      user_count;
  end if;

  expected_resource := 'https://' || allowed_ref || '.supabase.co/mcp';
  if coalesce(v_client_id, '') = '' or v_client_id ~ '\s' then
    raise exception 'ari.oauth_client_id must be the exact registered client id';
  end if;
  if v_mcp_resource is distinct from expected_resource then
    raise exception 'ari.mcp_resource is not the TEST MCP resource';
  end if;
  if coalesce(v_agent_id, '') = '' or v_agent_id ~ '\s' then
    raise exception 'ari.agent_id is required';
  end if;

  create schema if not exists ari_probe;
  revoke all on schema ari_probe from public, anon, authenticated;

  create table if not exists ari_probe.mcp_client (
    client_id text primary key,
    mcp_resource text not null,
    agent_id text not null,
    probe_label text not null,
    constraint mcp_client_label_check
      check (probe_label = 'ari-test-synthetic')
  );

  alter table ari_probe.mcp_client enable row level security;
  alter table ari_probe.mcp_client force row level security;
  revoke all on table ari_probe.mcp_client from public, anon, authenticated;
  grant select on table ari_probe.mcp_client to supabase_auth_admin;

  drop policy if exists mcp_client_hook_read on ari_probe.mcp_client;
  create policy mcp_client_hook_read
    on ari_probe.mcp_client
    for select
    to supabase_auth_admin
    using (true);

  if exists (select 1 from pg_roles where rolname = 'mcp_ingress') then
    execute 'revoke all on schema ari_probe from mcp_ingress';
    execute 'revoke all on table ari_probe.mcp_client from mcp_ingress';
  end if;

  insert into ari_probe.mcp_client (client_id, mcp_resource, agent_id, probe_label)
  values (v_client_id, v_mcp_resource, v_agent_id, 'ari-test-synthetic')
  on conflict (client_id) do update
    set mcp_resource = excluded.mcp_resource,
        agent_id = excluded.agent_id,
        probe_label = excluded.probe_label;

  if (select count(*) from ari_probe.mcp_client) <> 1 then
    raise exception 'expected exactly one mapped oauth client';
  end if;
end;
$target$;

create or replace function ari_probe.custom_access_token_hook(event jsonb)
returns jsonb
language plpgsql
volatile
security invoker
set search_path = pg_catalog, ari_probe
as $hook$
declare
  claims jsonb := event -> 'claims';
  v_client_id text := coalesce(claims ->> 'client_id', '');
  scope_text text := '';
  uid uuid;
  original_session text;
  original_uuid uuid;
  fresh uuid;
  mapped_resource text;
  mapped_agent text;
begin
  if claims is null or jsonb_typeof(claims) <> 'object' then
    raise exception 'hook event is unreadable';
  end if;

  if v_client_id = '' then
    return jsonb_build_object('claims', claims);
  end if;

  if jsonb_typeof(claims -> 'scope') = 'string' then
    scope_text := claims ->> 'scope';
  elsif jsonb_typeof(claims -> 'scope') = 'array' then
    select string_agg(value, ' ') into scope_text
    from jsonb_array_elements_text(claims -> 'scope') as value;
  elsif jsonb_typeof(event -> 'scope') = 'string' then
    scope_text := event ->> 'scope';
  elsif jsonb_typeof(event -> 'scope') = 'array' then
    select string_agg(value, ' ') into scope_text
    from jsonb_array_elements_text(event -> 'scope') as value;
  end if;

  if exists (
    select 1
    from regexp_split_to_table(coalesce(scope_text, ''), '\s+') as item
    where lower(item) = 'openid'
  ) then
    return jsonb_build_object(
      'error', jsonb_build_object(
        'http_code', 403,
        'message', 'openid_scope_refused'
      )
    );
  end if;

  select mapping.mcp_resource, mapping.agent_id
  into mapped_resource, mapped_agent
  from ari_probe.mcp_client as mapping
  where mapping.client_id = v_client_id
    and mapping.probe_label = 'ari-test-synthetic';

  if mapped_resource is null or mapped_agent is null then
    return jsonb_build_object(
      'error', jsonb_build_object(
        'http_code', 403,
        'message', 'unmapped_client_id'
      )
    );
  end if;

  original_session := coalesce(claims ->> 'session_id', '');
  if coalesce(event ->> 'user_id', '') !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    or original_session !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  then
    return jsonb_build_object(
      'error', jsonb_build_object(
        'http_code', 401,
        'message', 'source_session_not_live'
      )
    );
  end if;
  uid := (event ->> 'user_id')::uuid;
  original_uuid := original_session::uuid;

  if original_uuid is null
    or original_uuid = '00000000-0000-0000-0000-000000000000'::uuid
    or not exists (
      select 1
      from auth.sessions as session
      where session.id = original_uuid
        and session.user_id = uid
        and (session.not_after is null or session.not_after > pg_catalog.now())
    )
  then
    return jsonb_build_object(
      'error', jsonb_build_object(
        'http_code', 401,
        'message', 'source_session_not_live'
      )
    );
  end if;

  fresh := pg_catalog.gen_random_uuid();
  if fresh is null
    or fresh = '00000000-0000-0000-0000-000000000000'::uuid
    or exists (select 1 from auth.sessions as session where session.id = fresh)
  then
    raise exception 'fresh session_id is nil or already in auth.sessions';
  end if;

  claims := jsonb_set(claims, '{role}', to_jsonb('mcp_ingress'::text), true);
  claims := jsonb_set(claims, '{aud}', to_jsonb(mapped_resource), true);
  claims := jsonb_set(claims, '{session_id}', to_jsonb(fresh::text), true);
  claims := jsonb_set(claims, '{source_session_id}', to_jsonb(original_session), true);
  claims := jsonb_set(claims, '{agent_id}', to_jsonb(mapped_agent), true);
  return jsonb_build_object('claims', claims);
end;
$hook$;

revoke all on function ari_probe.custom_access_token_hook(jsonb)
  from public, anon, authenticated;
grant usage on schema ari_probe to supabase_auth_admin;
grant execute on function ari_probe.custom_access_token_hook(jsonb)
  to supabase_auth_admin;

do $guard$
begin
  if exists (select 1 from pg_roles where rolname = 'mcp_ingress') then
    execute 'revoke all on function ari_probe.custom_access_token_hook(jsonb) from mcp_ingress';
    execute 'revoke all on schema ari_probe from mcp_ingress';
    execute 'revoke all on table ari_probe.mcp_client from mcp_ingress';
  end if;

  if has_function_privilege(
    'public',
    'ari_probe.custom_access_token_hook(jsonb)',
    'execute'
  )
    or has_function_privilege(
      'anon',
      'ari_probe.custom_access_token_hook(jsonb)',
      'execute'
    )
    or has_function_privilege(
      'authenticated',
      'ari_probe.custom_access_token_hook(jsonb)',
      'execute'
    )
  then
    raise exception 'hook is executable by a client role';
  end if;

  if not has_function_privilege(
    'supabase_auth_admin',
    'ari_probe.custom_access_token_hook(jsonb)',
    'execute'
  ) then
    raise exception 'hook is not executable by supabase_auth_admin';
  end if;

  if has_table_privilege('anon', 'ari_probe.mcp_client', 'select')
    or has_table_privilege('authenticated', 'ari_probe.mcp_client', 'select')
    or has_table_privilege('public', 'ari_probe.mcp_client', 'select')
  then
    raise exception 'mcp_client is client-readable';
  end if;
end;
$guard$;

commit;

-- Dashboard step stays off. Primary Users leave Authentication → Hooks
-- disabled until Warden reviews this exact head. Do not enable it from this
-- packet. This agent does not install the hook and does not contact hosted TEST.
--   Authentication → Hooks → Custom Access Token
--   Postgres function: ari_probe.custom_access_token_hook
-- Do not point that hook at any other project.
