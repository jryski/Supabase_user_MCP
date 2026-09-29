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
-- The role is NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
-- NOREPLICATION NOBYPASSRLS. Those attributes are named on CREATE ROLE.
-- A non-superuser CREATEROLE session is denied ALTER ROLE clauses that
-- name SUPERUSER (42501). This batch does not alter an existing role.
--
-- If mcp_ingress is absent: CREATE ROLE, then GRANT mcp_ingress TO
-- authenticator. If it already exists: the asserts verify it and fail
-- closed. This batch does not repair attributes, memberships, or grants.
-- It does not revoke authenticated, anon, or service_role, and it does
-- not revoke table privileges. A fresh role has none of those.
--
-- Membership may contain exactly two rows, and nothing else:
--   1. authenticator, with set_option true and admin_option false, so
--      PostgREST can set the role.
--   2. current_user, the creating role, with admin_option true,
--      inherit_option false, and set_option false.
-- The creator row lets it grant membership, not act as mcp_ingress.
-- PostgreSQL 16+ adds that row when a non-superuser CREATEROLE session
-- creates the role and createrole_self_grant is empty. Revoke of the row
-- returns success and the row stays, so this batch does not revoke it.
-- Hosted TEST is PostgreSQL 17.6. The in-repo PGlite check is 18.3.
--
-- mcp_ingress is not a member of authenticated, anon, or service_role,
-- and it receives no table or column grants.

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

-- Create only when the role is absent. An existing role is left untouched.
do $create$
begin
  if exists (select 1 from pg_roles where rolname = 'mcp_ingress') then
    return;
  end if;

  create role mcp_ingress
    nologin
    noinherit
    nosuperuser
    nocreatedb
    nocreaterole
    noreplication
    nobypassrls;

  grant mcp_ingress to authenticator;
end;
$create$;

do $assert$
declare
  role_row record;
  table_grant_count integer;
  member_count integer;
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

  -- The creator row lets it grant membership, not act as mcp_ingress.
  select count(*) into member_count
  from pg_auth_members as membership
  join pg_roles as granted_role on granted_role.oid = membership.roleid
  where granted_role.rolname = 'mcp_ingress';

  if member_count <> 2 then
    raise exception
      'mcp_ingress membership is not exactly authenticator and the creating role';
  end if;

  if not exists (
    select 1
    from pg_auth_members as membership
    join pg_roles as granted_role on granted_role.oid = membership.roleid
    join pg_roles as member_role on member_role.oid = membership.member
    where granted_role.rolname = 'mcp_ingress'
      and member_role.rolname = 'authenticator'
      and membership.set_option
      and not membership.admin_option
  ) then
    raise exception
      'mcp_ingress is not granted to authenticator with set and without admin';
  end if;

  if not exists (
    select 1
    from pg_auth_members as membership
    join pg_roles as granted_role on granted_role.oid = membership.roleid
    join pg_roles as member_role on member_role.oid = membership.member
    where granted_role.rolname = 'mcp_ingress'
      and member_role.rolname = current_user
      and member_role.rolname <> 'authenticator'
      and membership.admin_option
      and not membership.inherit_option
      and not membership.set_option
  ) then
    raise exception
      'mcp_ingress creator row must grant membership and must not act as the role';
  end if;

  if exists (
    select 1
    from pg_auth_members as membership
    join pg_roles as granted_role on granted_role.oid = membership.roleid
    join pg_roles as member_role on member_role.oid = membership.member
    where granted_role.rolname = 'mcp_ingress'
      and not (
        (
          member_role.rolname = 'authenticator'
          and membership.set_option
          and not membership.admin_option
        )
        or (
          member_role.rolname = current_user
          and membership.admin_option
          and not membership.inherit_option
          and not membership.set_option
        )
      )
  ) then
    raise exception
      'mcp_ingress has a membership other than authenticator or the creating role';
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
