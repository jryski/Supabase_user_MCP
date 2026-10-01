-- L3 hook SQL for Ariadne. This file is not a supabase/migration.
-- Do not apply it, and do not enable it in Authentication → Hooks.
-- Superseded for review by sql/04-hook-v2-for-ariadne.sql. Do not install
-- this older function.
-- The adapter now requires role mcp_ingress and rejects role=authenticated
-- (L2). That is not permission to install this hook.
-- Still required before any install:
--   1. Warden has reviewed R3 and R4. They are not in this file.
--   2. R3: the hook keys on the exact registered Token A client id, and a
--      present but unmapped client id raises. This function does not do that.
--   3. R4: the Atlas session_id transform, or the run is labelled
--      "confirm Auth hole".
--   4. sql/03-mcp-ingress-role.sql has been applied by the controller on
--      project ref odbcejsuuqdzhabjmozi only.
--   5. The dashboard project ref is odbcejsuuqdzhabjmozi.
--
-- Forbidden targets: lygftpbjgqgvuunkwnxf and any HOUSE, VAULT, or production
-- project.
--
-- The hook reads only ari_probe.agent_binding. It does not read user_metadata.
-- Password sessions are returned unchanged so the synthetic user's own login
-- stays the Token B positive control. Token B is not an MCP credential.
--
-- GoTrue's published hook schema lists role as anon or authenticated. If the
-- issued OAuth token still has role=authenticated, do not use it as Token A.
-- Report ingress_role_not_issued. Do not fall back to a Data API token.

begin;

create or replace function ari_probe.custom_access_token_hook(event jsonb)
returns jsonb
language plpgsql
stable
security invoker
set search_path = pg_catalog, ari_probe
as $hook$
declare
  claims jsonb := event -> 'claims';
  method text := event ->> 'authentication_method';
  uid uuid := (event ->> 'user_id')::uuid;
  bound boolean;
begin
  if method = 'password' then
    return jsonb_build_object('claims', claims);
  end if;

  select exists (
    select 1
    from ari_probe.agent_binding as binding
    where binding.user_id = uid
      and binding.probe_label = 'ari-test-synthetic'
  ) into bound;

  if not bound or coalesce(claims ->> 'client_id', '') = '' then
    return jsonb_build_object('claims', claims);
  end if;

  claims := jsonb_set(claims, '{role}', to_jsonb('mcp_ingress'::text), true);
  claims := jsonb_set(
    claims,
    '{aud}',
    to_jsonb('https://odbcejsuuqdzhabjmozi.supabase.co/mcp'::text),
    true
  );
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
    execute 'revoke all on table ari_probe.agent_binding from mcp_ingress';
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
end;
$guard$;

commit;

-- Dashboard step, still blocked on R3/R4 review. Do not enable it in this slice:
--   Authentication → Hooks → Custom Access Token
--   Postgres function: ari_probe.custom_access_token_hook
-- Do not point that hook at any other project.
