-- Source-session liveness RPC for Ari TEST only.
-- This file is not a supabase/migration. This agent does not apply it,
-- does not install the Auth hook, and does not contact hosted TEST.
--
-- The function lives in public so PostgREST can expose
-- /rest/v1/rpc/ari_probe_source_session_live_v1 to role authenticated.
-- It returns a boolean and no session metadata.
--
-- Confirm the dashboard project ref is odbcejsuuqdzhabjmozi before running.
-- Forbidden targets: lygftpbjgqgvuunkwnxf and any HOUSE, VAULT, or production
-- project.
--
-- N8: one SQL-editor batch. Paste this at the top of the same batch:
--   select set_config('ari.project_ref', 'odbcejsuuqdzhabjmozi', false);
--
-- Prerequisites: sql/03 (mcp_ingress) and sql/07 (downstream_client and the
-- A rows in ari_probe.mcp_client). Do not apply this file before those.
-- Do not grant new privileges on schema auth. If the function owner cannot
-- read auth.sessions, this batch stops and reports. It does not repair that.
--
-- Rollback, controller only, on this TEST ref:
--   drop function if exists public.ari_probe_source_session_live_v1(uuid, text);

begin;

do $target$
declare
  project_ref text := current_setting('ari.project_ref', true);
  allowed_ref constant text := 'odbcejsuuqdzhabjmozi';
  forbidden_ref constant text := 'lygftpbjgqgvuunkwnxf';
begin
  if project_ref is not distinct from forbidden_ref
    or coalesce(project_ref, '') = ''
    or project_ref is distinct from allowed_ref
  then
    raise exception
      'refusing source-session liveness SQL for project ref %; production, HOUSE, and VAULT are forbidden',
      coalesce(project_ref, '<unset>');
  end if;

  if to_regclass('ari_probe.mcp_client') is null
    or to_regclass('ari_probe.downstream_client') is null
  then
    raise exception
      'STOP AND REPORT: A or B client mapping is missing. Apply sql/07 before this file.';
  end if;

  if not exists (select 1 from pg_catalog.pg_roles where rolname = 'anon')
    or not exists (select 1 from pg_catalog.pg_roles where rolname = 'authenticated')
    or not exists (select 1 from pg_catalog.pg_roles where rolname = 'service_role')
    or not exists (select 1 from pg_catalog.pg_roles where rolname = 'mcp_ingress')
  then
    raise exception
      'STOP AND REPORT: anon, authenticated, service_role, or mcp_ingress is missing';
  end if;

  -- N25: do not grant new auth-schema access when the owner cannot read it.
  if not pg_catalog.has_table_privilege(current_user, 'auth.sessions', 'SELECT') then
    raise exception
      'STOP AND REPORT: function owner % cannot read auth.sessions. This file does not grant new auth-schema access.',
      current_user;
  end if;

  if not exists (
    select 1
    from pg_catalog.pg_attribute as attribute
    join pg_catalog.pg_class as relation on relation.oid = attribute.attrelid
    join pg_catalog.pg_namespace as namespace on namespace.oid = relation.relnamespace
    where namespace.nspname = 'auth'
      and relation.relname = 'sessions'
      and attribute.attname = 'oauth_client_id'
      and not attribute.attisdropped
  ) then
    raise exception
      'STOP AND REPORT: auth.sessions.oauth_client_id is absent. This file does not alter auth.';
  end if;

  if not pg_catalog.has_table_privilege(current_user, 'ari_probe.mcp_client', 'SELECT')
    or not pg_catalog.has_table_privilege(current_user, 'ari_probe.downstream_client', 'SELECT')
  then
    raise exception
      'STOP AND REPORT: function owner cannot read client mappings. This file does not grant those tables to authenticated.';
  end if;
end;
$target$;

-- Lives in public for PostgREST. Boolean only. NULL claims fail closed.
-- Pair-exact: the caller is B, and the named session is that user's A
-- session for the same agent.
create or replace function public.ari_probe_source_session_live_v1(
  source_session_id uuid,
  a_client_id text
)
returns boolean
language plpgsql
stable
security definer
set search_path = ''
as $function$
declare
  v_uid uuid;
  v_claims jsonb;
  v_role text;
  v_client_id text;
  v_agent_id text;
  v_b_agent text;
begin
  v_uid := auth.uid();
  v_claims := auth.jwt();
  if v_uid is null
    or v_claims is null
    or pg_catalog.jsonb_typeof(v_claims) is distinct from 'object'
    or source_session_id is null
    or a_client_id is null
    or pg_catalog.btrim(a_client_id) = ''
  then
    return false;
  end if;

  v_role := v_claims ->> 'role';
  v_client_id := v_claims ->> 'client_id';
  v_agent_id := v_claims ->> 'agent_id';
  if v_role is null
    or v_client_id is null
    or v_agent_id is null
    or pg_catalog.btrim(v_role) = ''
    or pg_catalog.btrim(v_client_id) = ''
    or pg_catalog.btrim(v_agent_id) = ''
    or v_role is distinct from 'authenticated'
  then
    return false;
  end if;

  select mapping.agent_id
  into v_b_agent
  from ari_probe.downstream_client as mapping
  where mapping.client_id = v_client_id
    and mapping.agent_id = v_agent_id
    and mapping.probe_label = 'ari-test-downstream-b';

  if v_b_agent is null then
    return false;
  end if;

  if not exists (
    select 1
    from ari_probe.mcp_client as ingress
    where ingress.client_id = a_client_id
      and ingress.agent_id = v_b_agent
      and ingress.probe_label in ('ari-test-synthetic', 'ari-test-external-a')
  ) then
    return false;
  end if;

  return exists (
    select 1
    from auth.sessions as session
    where session.id = source_session_id
      and session.user_id = v_uid
      and session.oauth_client_id = a_client_id
      and (session.not_after is null or session.not_after > pg_catalog.now())
  );
end;
$function$;

comment on function public.ari_probe_source_session_live_v1(uuid, text) is
  'Lives in public so PostgREST can expose it. Boolean source-session liveness for the paired A client. No session metadata.';

revoke all on function public.ari_probe_source_session_live_v1(uuid, text)
  from public, anon, service_role, mcp_ingress;
grant execute on function public.ari_probe_source_session_live_v1(uuid, text)
  to authenticated;

do $assert$
begin
  if pg_catalog.has_function_privilege(
      'public',
      'public.ari_probe_source_session_live_v1(uuid, text)',
      'execute'
    )
    or pg_catalog.has_function_privilege(
      'anon',
      'public.ari_probe_source_session_live_v1(uuid, text)',
      'execute'
    )
    or pg_catalog.has_function_privilege(
      'service_role',
      'public.ari_probe_source_session_live_v1(uuid, text)',
      'execute'
    )
    or pg_catalog.has_function_privilege(
      'mcp_ingress',
      'public.ari_probe_source_session_live_v1(uuid, text)',
      'execute'
    )
  then
    raise exception
      'ari_probe_source_session_live_v1 is executable by public, anon, service_role, or mcp_ingress';
  end if;

  if not pg_catalog.has_function_privilege(
    'authenticated',
    'public.ari_probe_source_session_live_v1(uuid, text)',
    'execute'
  ) then
    raise exception
      'ari_probe_source_session_live_v1 is not executable by authenticated';
  end if;
end;
$assert$;

commit;
