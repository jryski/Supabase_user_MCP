-- Additive B mapping and external A mapping for Ari TEST only.
-- This file is not a supabase/migration. This agent does not apply it,
-- does not install the Auth hook, and does not contact hosted TEST.
--
-- sql/03 is unchanged. sql/04 remains the accepted baseline packet. Applying
-- this file replaces ari_probe.custom_access_token_hook. It does not drop
-- ari_probe.mcp_client and it does not delete the baseline A row
-- (probe_label ari-test-synthetic).
--
-- Confirm the dashboard ref is odbcejsuuqdzhabjmozi. Forbidden:
-- lygftpbjgqgvuunkwnxf and any HOUSE, VAULT, or production project.
--
-- N8: one SQL-editor batch. Paste these at the top of the same batch:
--   select set_config('ari.project_ref', 'odbcejsuuqdzhabjmozi', false);
--   select set_config('ari.oauth_client_id', '<baseline A client id>', false);
--   select set_config('ari.external_a_client_id', '<external A client id>', false);
--   select set_config('ari.downstream_client_id', '<B client id>', false);
--   select set_config('ari.mcp_resource', 'https://odbcejsuuqdzhabjmozi.supabase.co/mcp', false);
--   select set_config('ari.agent_id', '<same trusted agent id as A>', false);
-- Prerequisite: sql/01 and sql/04 already applied. Do not recreate the user.
-- Do not apply sql/02.
--
-- ari.mcp_resource is the baseline A row only. External A does not read it.
-- sql/07 inserts external A mcp_resource as the fixed constant
-- http://127.0.0.1:8788/mcp. That value is not a set_config parameter.
--
-- Hook order:
--   1. no client_id -> ordinary login, claims unchanged
--   2. openid -> structured 403 openid_scope_refused
--   3. exact A (baseline or external) -> mcp_ingress, that row's mcp_resource
--      as aud, fresh decoy session_id, source_session_id, trusted agent_id
--   4. exact B -> role authenticated, aud authenticated, REAL session_id,
--      trusted agent_id. No source_session_id. No fresh decoy.
--   5. anything else -> structured 403 unmapped_client_id
-- B is TEST-only public PKCE. This file does not store tokens.
--
-- Rollback, controller only, after the hook is disabled, on this TEST ref:
--   delete from ari_probe.mcp_client where probe_label = 'ari-test-external-a';
--   drop table if exists ari_probe.downstream_client;
--   re-apply the function body from sql/04-hook-v2-for-ariadne.sql
-- Do not delete probe_label ari-test-synthetic.
-- Do not drop the synthetic user, the marker, or mcp_ingress.

begin;

do $target$
declare
  project_ref text := current_setting('ari.project_ref', true);
  allowed_ref constant text := 'odbcejsuuqdzhabjmozi';
  forbidden_ref constant text := 'lygftpbjgqgvuunkwnxf';
  v_baseline text := current_setting('ari.oauth_client_id', true);
  v_external text := current_setting('ari.external_a_client_id', true);
  v_downstream text := current_setting('ari.downstream_client_id', true);
  v_mcp_resource text := current_setting('ari.mcp_resource', true);
  v_agent_id text := current_setting('ari.agent_id', true);
  expected_resource text;
  client_pattern constant text := '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$';
  synthetic_email constant text := 'ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid';
  user_count integer;
begin
  if project_ref is not distinct from forbidden_ref
    or coalesce(project_ref, '') = ''
    or project_ref is distinct from allowed_ref
  then
    raise exception
      'refusing downstream mapping SQL for project ref %; production, HOUSE, and VAULT are forbidden',
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
  if v_mcp_resource is distinct from expected_resource then
    raise exception 'ari.mcp_resource is not the TEST MCP resource';
  end if;
  if coalesce(v_agent_id, '') = '' or v_agent_id ~ '\s' then
    raise exception 'ari.agent_id is required';
  end if;
  if v_baseline is null or v_external is null or v_downstream is null
    or v_baseline !~ client_pattern
    or v_external !~ client_pattern
    or v_downstream !~ client_pattern
    or v_baseline = v_external
    or v_baseline = v_downstream
    or v_external = v_downstream
  then
    raise exception 'baseline A, external A, and B client ids must be distinct';
  end if;

  if not exists (
    select 1
    from ari_probe.mcp_client as mapping
    where mapping.client_id = v_baseline
      and mapping.mcp_resource = v_mcp_resource
      and mapping.agent_id = v_agent_id
      and mapping.probe_label = 'ari-test-synthetic'
  ) then
    raise exception 'baseline A mapping is missing; refusing to continue';
  end if;

  alter table ari_probe.mcp_client drop constraint if exists mcp_client_label_check;
  alter table ari_probe.mcp_client
    add constraint mcp_client_label_check
    check (probe_label in ('ari-test-synthetic', 'ari-test-external-a'));

  insert into ari_probe.mcp_client (client_id, mcp_resource, agent_id, probe_label)
  values (v_external, 'http://127.0.0.1:8788/mcp', v_agent_id, 'ari-test-external-a')
  on conflict (client_id) do update
    set mcp_resource = excluded.mcp_resource,
        agent_id = excluded.agent_id,
        probe_label = excluded.probe_label
    where ari_probe.mcp_client.probe_label = 'ari-test-external-a';

  if not exists (
    select 1
    from ari_probe.mcp_client as mapping
    where mapping.client_id = v_baseline
      and mapping.probe_label = 'ari-test-synthetic'
      and mapping.mcp_resource = v_mcp_resource
  ) then
    raise exception 'baseline A mapping was not left intact';
  end if;

  if not exists (
    select 1
    from ari_probe.mcp_client as mapping
    where mapping.client_id = v_external
      and mapping.probe_label = 'ari-test-external-a'
      and mapping.agent_id = v_agent_id
      and mapping.mcp_resource = 'http://127.0.0.1:8788/mcp'
  ) then
    raise exception 'external A mapping was not inserted';
  end if;

  if exists (
    select 1
    from ari_probe.mcp_client as baseline
    join ari_probe.mcp_client as external
      on baseline.mcp_resource = external.mcp_resource
    where baseline.client_id = v_baseline
      and baseline.probe_label = 'ari-test-synthetic'
      and external.client_id = v_external
      and external.probe_label = 'ari-test-external-a'
  ) then
    raise exception 'external A resource must differ from baseline A';
  end if;

  create table if not exists ari_probe.downstream_client (
    client_id text primary key,
    agent_id text not null,
    probe_label text not null,
    constraint downstream_client_label_check
      check (probe_label = 'ari-test-downstream-b')
  );

  alter table ari_probe.downstream_client enable row level security;
  alter table ari_probe.downstream_client force row level security;
  revoke all on table ari_probe.downstream_client from public, anon, authenticated;
  grant select on table ari_probe.downstream_client to supabase_auth_admin;

  drop policy if exists downstream_client_hook_read on ari_probe.downstream_client;
  create policy downstream_client_hook_read
    on ari_probe.downstream_client
    for select
    to supabase_auth_admin
    using (true);

  if exists (select 1 from pg_catalog.pg_roles where rolname = 'mcp_ingress') then
    execute 'revoke all on schema ari_probe from mcp_ingress';
    execute 'revoke all on table ari_probe.mcp_client from mcp_ingress';
    execute 'revoke all on table ari_probe.downstream_client from mcp_ingress';
  end if;

  insert into ari_probe.downstream_client (client_id, agent_id, probe_label)
  values (v_downstream, v_agent_id, 'ari-test-downstream-b')
  on conflict (client_id) do update
    set agent_id = excluded.agent_id,
        probe_label = excluded.probe_label;

  if exists (
    select 1
    from ari_probe.downstream_client as downstream
    join ari_probe.mcp_client as ingress on ingress.client_id = downstream.client_id
  ) then
    raise exception 'a client id is both an A mapping and a B mapping';
  end if;
end;
$target$;

create or replace function ari_probe.custom_access_token_hook(event jsonb)
returns jsonb
language plpgsql
volatile
security invoker
set search_path = ''
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
  downstream_agent text;
begin
  if claims is null or pg_catalog.jsonb_typeof(claims) <> 'object' then
    raise exception 'hook event is unreadable';
  end if;

  if v_client_id = '' then
    return pg_catalog.jsonb_build_object('claims', claims);
  end if;

  if pg_catalog.jsonb_typeof(claims -> 'scope') = 'string' then
    scope_text := claims ->> 'scope';
  elsif pg_catalog.jsonb_typeof(claims -> 'scope') = 'array' then
    select pg_catalog.string_agg(value, ' ') into scope_text
    from pg_catalog.jsonb_array_elements_text(claims -> 'scope') as value;
  elsif pg_catalog.jsonb_typeof(event -> 'scope') = 'string' then
    scope_text := event ->> 'scope';
  elsif pg_catalog.jsonb_typeof(event -> 'scope') = 'array' then
    select pg_catalog.string_agg(value, ' ') into scope_text
    from pg_catalog.jsonb_array_elements_text(event -> 'scope') as value;
  end if;

  if exists (
    select 1
    from pg_catalog.regexp_split_to_table(coalesce(scope_text, ''), '\s+') as item
    where pg_catalog.lower(item) = 'openid'
  ) then
    return pg_catalog.jsonb_build_object(
      'error', pg_catalog.jsonb_build_object(
        'http_code', 403,
        'message', 'openid_scope_refused'
      )
    );
  end if;

  select mapping.mcp_resource, mapping.agent_id
  into mapped_resource, mapped_agent
  from ari_probe.mcp_client as mapping
  where mapping.client_id = v_client_id
    and mapping.probe_label in ('ari-test-synthetic', 'ari-test-external-a');

  select downstream.agent_id
  into downstream_agent
  from ari_probe.downstream_client as downstream
  where downstream.client_id = v_client_id
    and downstream.probe_label = 'ari-test-downstream-b';

  if mapped_resource is null and downstream_agent is null then
    return pg_catalog.jsonb_build_object(
      'error', pg_catalog.jsonb_build_object(
        'http_code', 403,
        'message', 'unmapped_client_id'
      )
    );
  end if;

  original_session := coalesce(claims ->> 'session_id', '');
  if coalesce(event ->> 'user_id', '') !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    or original_session !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  then
    return pg_catalog.jsonb_build_object(
      'error', pg_catalog.jsonb_build_object(
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
    return pg_catalog.jsonb_build_object(
      'error', pg_catalog.jsonb_build_object(
        'http_code', 401,
        'message', 'source_session_not_live'
      )
    );
  end if;

  if mapped_resource is not null and mapped_agent is not null then
    fresh := pg_catalog.gen_random_uuid();
    if fresh is null
      or fresh = '00000000-0000-0000-0000-000000000000'::uuid
      or exists (select 1 from auth.sessions as session where session.id = fresh)
    then
      raise exception 'fresh session_id is nil or already in auth.sessions';
    end if;

    claims := pg_catalog.jsonb_set(claims, '{role}', pg_catalog.to_jsonb('mcp_ingress'::text), true);
    claims := pg_catalog.jsonb_set(claims, '{aud}', pg_catalog.to_jsonb(mapped_resource), true);
    claims := pg_catalog.jsonb_set(claims, '{session_id}', pg_catalog.to_jsonb(fresh::text), true);
    claims := pg_catalog.jsonb_set(claims, '{source_session_id}', pg_catalog.to_jsonb(original_session), true);
    claims := pg_catalog.jsonb_set(claims, '{agent_id}', pg_catalog.to_jsonb(mapped_agent), true);
    return pg_catalog.jsonb_build_object('claims', claims);
  end if;

  -- Exact B. Keep the real auth.sessions id. Do not mint a decoy.
  claims := claims - 'source_session_id';
  claims := pg_catalog.jsonb_set(claims, '{role}', pg_catalog.to_jsonb('authenticated'::text), true);
  claims := pg_catalog.jsonb_set(claims, '{aud}', pg_catalog.to_jsonb('authenticated'::text), true);
  claims := pg_catalog.jsonb_set(claims, '{session_id}', pg_catalog.to_jsonb(original_session), true);
  claims := pg_catalog.jsonb_set(claims, '{agent_id}', pg_catalog.to_jsonb(downstream_agent), true);
  return pg_catalog.jsonb_build_object('claims', claims);
end;
$hook$;

revoke all on function ari_probe.custom_access_token_hook(jsonb)
  from public, anon, authenticated;
grant usage on schema ari_probe to supabase_auth_admin;
grant execute on function ari_probe.custom_access_token_hook(jsonb)
  to supabase_auth_admin;

do $guard$
begin
  if exists (select 1 from pg_catalog.pg_roles where rolname = 'mcp_ingress') then
    execute 'revoke all on function ari_probe.custom_access_token_hook(jsonb) from mcp_ingress';
    execute 'revoke all on schema ari_probe from mcp_ingress';
    execute 'revoke all on table ari_probe.mcp_client from mcp_ingress';
    execute 'revoke all on table ari_probe.downstream_client from mcp_ingress';
  end if;

  if pg_catalog.has_function_privilege(
      'public',
      'ari_probe.custom_access_token_hook(jsonb)',
      'execute'
    )
    or pg_catalog.has_function_privilege(
      'anon',
      'ari_probe.custom_access_token_hook(jsonb)',
      'execute'
    )
    or pg_catalog.has_function_privilege(
      'authenticated',
      'ari_probe.custom_access_token_hook(jsonb)',
      'execute'
    )
  then
    raise exception 'hook is executable by a client role';
  end if;

  if not pg_catalog.has_function_privilege(
    'supabase_auth_admin',
    'ari_probe.custom_access_token_hook(jsonb)',
    'execute'
  ) then
    raise exception 'hook is not executable by supabase_auth_admin';
  end if;

  if pg_catalog.has_table_privilege('anon', 'ari_probe.mcp_client', 'select')
    or pg_catalog.has_table_privilege('authenticated', 'ari_probe.mcp_client', 'select')
    or pg_catalog.has_table_privilege('public', 'ari_probe.mcp_client', 'select')
    or pg_catalog.has_table_privilege('anon', 'ari_probe.downstream_client', 'select')
    or pg_catalog.has_table_privilege('authenticated', 'ari_probe.downstream_client', 'select')
    or pg_catalog.has_table_privilege('public', 'ari_probe.downstream_client', 'select')
  then
    raise exception 'client mappings are client-readable';
  end if;
end;
$guard$;

commit;

-- Dashboard step stays off until Warden G5 reviews this exact head.
--   Authentication → Hooks → Custom Access Token
--   Postgres function: ari_probe.custom_access_token_hook
-- This agent does not enable that hook and does not contact hosted TEST.
