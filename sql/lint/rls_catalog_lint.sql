create or replace view pg_temp.rls_catalog_lint as
with
api_roles as (
  select oid
  from pg_roles
  where rolname in ('anon', 'authenticated')
),
api_relations as (
  select distinct c.oid
  from pg_class as c
  cross join lateral aclexplode(c.relacl) as acl
  join api_roles as role on role.oid = acl.grantee
  where acl.privilege_type in ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
),
api_routines as (
  select distinct p.oid
  from pg_proc as p
  cross join lateral aclexplode(p.proacl) as acl
  join api_roles as role on role.oid = acl.grantee
  where acl.privilege_type = 'EXECUTE'
),
dangerous_relation_grants as (
  select
    c.oid,
    string_agg(
      format('%s:%s', role.rolname, acl.privilege_type),
      ', ' order by role.rolname, acl.privilege_type
    ) as grants
  from pg_class as c
  cross join lateral aclexplode(c.relacl) as acl
  join pg_roles as role on role.oid = acl.grantee
  where role.rolname in ('anon', 'authenticated')
    and acl.privilege_type in ('TRUNCATE', 'TRIGGER', 'REFERENCES')
  group by c.oid
),
unprotected_write_grants as (
  select
    c.oid,
    role.oid as role_oid,
    role.rolname,
    acl.privilege_type
  from pg_class as c
  cross join lateral aclexplode(c.relacl) as acl
  join pg_roles as role on role.oid = acl.grantee
  where role.rolname in ('anon', 'authenticated')
    and acl.privilege_type in ('INSERT', 'UPDATE')
    and not exists (
      select 1
      from pg_policy as p
      where p.polrelid = c.oid
        and p.polcmd in (
          '*',
          case acl.privilege_type when 'INSERT' then 'a' when 'UPDATE' then 'w' end
        )
        and (
          p.polroles is null
          or cardinality(p.polroles) = 0
          or 0 = any(p.polroles)
          or role.oid = any(p.polroles)
        )
    )
),
findings(severity_order, sev, id, obj, det) as (
  select 1, 'CRITICAL', 'L01', format('%I.%I', n.nspname, c.relname),
    'API-reachable table has RLS disabled'
  from pg_class as c
  join pg_namespace as n on n.oid = c.relnamespace
  join api_relations as api on api.oid = c.oid
  where c.relkind in ('r', 'p') and not c.relrowsecurity

  union all
  select 4, 'WARN', 'L02', format('%I.%I', n.nspname, c.relname),
    'RLS is enabled but the table has zero policies'
  from pg_class as c
  join pg_namespace as n on n.oid = c.relnamespace
  where c.relkind in ('r', 'p')
    and c.relrowsecurity
    and not exists (select 1 from pg_policy as p where p.polrelid = c.oid)

  union all
  select 2, 'HIGH', 'L03',
    format('%I.%I.%I', n.nspname, c.relname, p.polname),
    'Policy applies to PUBLIC or has no explicit role restriction'
  from pg_policy as p
  join pg_class as c on c.oid = p.polrelid
  join pg_namespace as n on n.oid = c.relnamespace
  where p.polroles is null or cardinality(p.polroles) = 0 or 0 = any(p.polroles)

  union all
  select 4, 'WARN', 'L04',
    format('%I.%I.%I', n.nspname, c.relname, p.polname),
    'Policy references deprecated auth.role()'
  from pg_policy as p
  join pg_class as c on c.oid = p.polrelid
  join pg_namespace as n on n.oid = c.relnamespace
  where concat_ws(' ', pg_get_expr(p.polqual, p.polrelid), pg_get_expr(p.polwithcheck, p.polrelid))
    ~* 'auth[.]role\s*[(]'

  union all
  select 2, 'HIGH', 'L05',
    format('%I.%I.%I', n.nspname, c.relname, p.polname),
    'Policy USING expression is true or null'
  from pg_policy as p
  join pg_class as c on c.oid = p.polrelid
  join pg_namespace as n on n.oid = c.relnamespace
  where p.polcmd in ('r', 'w', 'd', '*')
    and (p.polqual is null or lower(btrim(pg_get_expr(p.polqual, p.polrelid), '() ')) = 'true')

  union all
  select 2, 'HIGH', 'L06',
    format('%I.%I.%I', n.nspname, c.relname, p.polname),
    'UPDATE policy is missing WITH CHECK'
  from pg_policy as p
  join pg_class as c on c.oid = p.polrelid
  join pg_namespace as n on n.oid = c.relnamespace
  where p.polcmd in ('w', '*') and p.polwithcheck is null

  union all
  select 2, 'HIGH', 'L07', format('%I.%I', n.nspname, c.relname),
    'API-reachable view does not set security_invoker=true'
  from pg_class as c
  join pg_namespace as n on n.oid = c.relnamespace
  join api_relations as api on api.oid = c.oid
  where c.relkind = 'v'
    and not coalesce(c.reloptions @> array['security_invoker=true'], false)

  union all
  select 2, 'HIGH', 'L08', p.oid::regprocedure::text,
    'API-executable SECURITY DEFINER routine has no fixed search_path'
  from pg_proc as p
  join api_routines as api on api.oid = p.oid
  where p.prosecdef
    and not exists (
      select 1 from unnest(coalesce(p.proconfig, array[]::text[])) as setting
      where setting like 'search_path=%'
    )

  union all
  select 1, 'CRITICAL', 'L09', p.oid::regprocedure::text,
    'Heuristic: API-executable SECURITY DEFINER routine has no source-text identity marker; review required'
  from pg_proc as p
  join api_routines as api on api.oid = p.oid
  where p.prosecdef
    and p.prosrc !~* '(auth[.](uid|jwt)\s*[(]|request[.]jwt)'

  union all
  select 1, 'CRITICAL', 'L10', format('%I.%I', n.nspname, c.relname),
    format('API role has dangerous table privilege: %s', dangerous.grants)
  from dangerous_relation_grants as dangerous
  join pg_class as c on c.oid = dangerous.oid
  join pg_namespace as n on n.oid = c.relnamespace
  where c.relkind in ('r', 'p')

  union all
  select 2, 'HIGH', 'L11',
    format(
      '%I.%I [%s %s]',
      n.nspname,
      c.relname,
      write_grant.rolname,
      write_grant.privilege_type
    ),
    'API write grant has no applicable RLS policy'
  from unprotected_write_grants as write_grant
  join pg_class as c on c.oid = write_grant.oid
  join pg_namespace as n on n.oid = c.relnamespace
  where c.relkind in ('r', 'p')
)
select severity_order, sev, id, obj, det
from findings;

select sev, id, obj, det
from pg_temp.rls_catalog_lint
order by severity_order, id, obj;
