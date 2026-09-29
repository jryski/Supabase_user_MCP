-- L7 baseline. Read-only. Apply only on project ref odbcejsuuqdzhabjmozi
-- (org pvooiyttujynxquxkqcr, us-east-1). Refuse lygftpbjgqgvuunkwnxf and any
-- HOUSE, VAULT, or production project.
--
-- Run this before the fixture and again after any later hook install.
-- Save the row set in the controller note. Do not commit it if it contains
-- project-specific names you do not want in git; the query itself is safe.
-- Token A must gain nothing over the publishable key alone.

select
  n.nspname as schema_name,
  p.proname as function_name,
  pg_get_function_identity_arguments(p.oid) as identity_args,
  p.prosecdef as security_definer,
  has_function_privilege('public', p.oid, 'execute') as public_execute,
  has_function_privilege('anon', p.oid, 'execute') as anon_execute,
  has_function_privilege('authenticated', p.oid, 'execute') as authenticated_execute
from pg_proc as p
join pg_namespace as n on n.oid = p.pronamespace
where n.nspname in (
  'public',
  'storage',
  'graphql',
  'graphql_public',
  'realtime',
  'ari_probe'
)
  and (
    p.prosecdef
    or has_function_privilege('public', p.oid, 'execute')
  )
order by 1, 2, 3;
