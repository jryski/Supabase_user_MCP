-- R1 isolated ingress role. Controller SQL for Ari TEST only.
-- This file is not a supabase/migration. This agent does not apply it,
-- does not install the Auth hook, and does not write credentials.
--
-- The controller owns the TEST write. Confirm the dashboard project ref is
-- odbcejsuuqdzhabjmozi (org pvooiyttujynxquxkqcr, us-east-1) before running.
-- Forbidden targets: lygftpbjgqgvuunkwnxf and any HOUSE, VAULT, or production
-- project. Do not point this script at those.
--
-- N8: one SQL-editor batch. Paste this statement at the top of the same
-- batch as the rest of this file, then run that batch once:
--   select set_config('ari.project_ref', 'odbcejsuuqdzhabjmozi', false);
-- A later batch is a new session and will not see the setting. An unset
-- ref, or any other ref, aborts. The allowlist is the TEST ref.
--
-- OAuth client id and MCP resource are not literals in this file. The
-- controller passes the exact registered client id out of band
-- (ARI_TEST_EXPECTED_CLIENT_ID). The MCP resource is the TEST project's
-- /mcp URL. Do not invent a stand-in client id here.
--
-- Apply after sql/00 and sql/01 when those are not already on the project.
-- Do not recreate the synthetic user or fixture. Do not apply
-- sql/02-hook-for-ariadne.sql in this slice. R3 and R4 are still open.
--
-- The role is NOLOGIN NOINHERIT. Membership is granted to authenticator
-- only, so PostgREST can set the role. mcp_ingress is not a member of
-- authenticated, anon, or service_role, and it receives no table grants.

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
      'refusing mcp_ingress role SQL for project ref %; production, HOUSE, and VAULT are forbidden',
      coalesce(project_ref, '<unset>');
  end if;

  if not exists (select 1 from pg_roles where rolname = 'authenticator') then
    raise exception 'authenticator is missing; refusing to create mcp_ingress';
  end if;
end;
$target$;

-- N7: same existence fact as sql/01. Do not create or recreate the user.
do $user$
declare
  synthetic_email constant text := 'ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid';
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
end;
$user$;

-- Isolation attributes are set on CREATE ROLE. A non-superuser CREATEROLE
-- session is denied ALTER ROLE clauses that name SUPERUSER, and is denied
-- CREATEDB, REPLICATION, and BYPASSRLS unless it already holds that
-- attribute. Naming them on ALTER raises 42501 and rolls this batch back.
-- When the role already exists and is already isolated, this block does not
-- ALTER it. LOGIN, INHERIT, and CREATEROLE are the only attributes altered,
-- and only when they are not already the isolated values. SUPERUSER or
-- BYPASSRLS on an existing role fails closed. This block does not clear them.
do $create$
declare
  role_row record;
begin
  if not exists (select 1 from pg_roles where rolname = 'mcp_ingress') then
    create role mcp_ingress
      nologin
      noinherit
      nosuperuser
      nocreatedb
      nocreaterole
      noreplication
      nobypassrls;
    return;
  end if;

  select
    rolcanlogin,
    rolinherit,
    rolsuper,
    rolcreaterole,
    rolcreatedb,
    rolreplication,
    rolbypassrls
  into role_row
  from pg_roles
  where rolname = 'mcp_ingress';

  if role_row.rolsuper then
    raise exception
      'mcp_ingress has SUPERUSER; refusing to alter superuser attributes';
  end if;

  if role_row.rolbypassrls then
    raise exception
      'mcp_ingress has BYPASSRLS; refusing to alter bypassrls attributes';
  end if;

  if role_row.rolcreatedb or role_row.rolreplication then
    raise exception
      'mcp_ingress has CREATEDB or REPLICATION; refusing to alter those attributes';
  end if;

  if role_row.rolcanlogin or role_row.rolinherit or role_row.rolcreaterole then
    alter role mcp_ingress nologin noinherit nocreaterole;
  end if;
end;
$create$;

revoke authenticated, anon, service_role from mcp_ingress;
revoke mcp_ingress from authenticated, anon, service_role;
grant mcp_ingress to authenticator;

do $members$
declare
  member_name text;
begin
  for member_name in
    select member_role.rolname
    from pg_auth_members as membership
    join pg_roles as granted_role on granted_role.oid = membership.roleid
    join pg_roles as member_role on member_role.oid = membership.member
    where granted_role.rolname = 'mcp_ingress'
      and member_role.rolname <> 'authenticator'
  loop
    execute format('revoke mcp_ingress from %I', member_name);
  end loop;
end;
$members$;

do $tables$
declare
  schema_name text;
begin
  for schema_name in
    select namespace.nspname
    from pg_namespace as namespace
    where namespace.nspname <> 'information_schema'
      and namespace.nspname not like 'pg\_%' escape '\'
  loop
    execute format(
      'revoke all privileges on all tables in schema %I from mcp_ingress',
      schema_name
    );
  end loop;
end;
$tables$;

do $assert$
declare
  role_row record;
  table_grant_count integer;
begin
  select
    rolcanlogin,
    rolinherit,
    rolsuper,
    rolcreaterole,
    rolcreatedb,
    rolreplication,
    rolbypassrls
  into role_row
  from pg_roles
  where rolname = 'mcp_ingress';

  if role_row is null
    or role_row.rolcanlogin
    or role_row.rolinherit
    or role_row.rolsuper
    or role_row.rolcreaterole
    or role_row.rolcreatedb
    or role_row.rolreplication
    or role_row.rolbypassrls
  then
    raise exception 'mcp_ingress is not an isolated nologin noinherit role';
  end if;

  if not exists (
    select 1
    from pg_auth_members as membership
    join pg_roles as granted_role on granted_role.oid = membership.roleid
    join pg_roles as member_role on member_role.oid = membership.member
    where granted_role.rolname = 'mcp_ingress'
      and member_role.rolname = 'authenticator'
      and not membership.admin_option
  ) then
    raise exception 'mcp_ingress is not granted to authenticator only';
  end if;

  if exists (
    select 1
    from pg_auth_members as membership
    join pg_roles as granted_role on granted_role.oid = membership.roleid
    join pg_roles as member_role on member_role.oid = membership.member
    where granted_role.rolname = 'mcp_ingress'
      and member_role.rolname <> 'authenticator'
  ) then
    raise exception 'mcp_ingress has a member other than authenticator';
  end if;

  if pg_has_role('mcp_ingress', 'authenticated', 'member')
    or pg_has_role('mcp_ingress', 'anon', 'member')
    or pg_has_role('mcp_ingress', 'service_role', 'member')
  then
    raise exception
      'mcp_ingress is a member of authenticated, anon, or service_role';
  end if;

  select count(*) into table_grant_count
  from information_schema.role_table_grants
  where grantee = 'mcp_ingress';

  if table_grant_count <> 0 then
    raise exception 'mcp_ingress has table grants';
  end if;

  if exists (
    select 1
    from pg_class as relation
    cross join lateral aclexplode(relation.relacl) as acl
    join pg_roles as grantee on grantee.oid = acl.grantee
    where grantee.rolname = 'mcp_ingress'
      and relation.relkind in ('r', 'p', 'v', 'm', 'f')
  ) then
    raise exception 'mcp_ingress has table grants';
  end if;

  if exists (
    select 1
    from pg_attribute as attribute
    cross join lateral aclexplode(attribute.attacl) as acl
    join pg_roles as grantee on grantee.oid = acl.grantee
    where grantee.rolname = 'mcp_ingress'
      and not attribute.attisdropped
  ) then
    raise exception 'mcp_ingress has table grants';
  end if;
end;
$assert$;

commit;
