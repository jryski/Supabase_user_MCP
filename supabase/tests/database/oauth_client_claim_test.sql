BEGIN;
CREATE EXTENSION IF NOT EXISTS pgtap WITH SCHEMA extensions;
SELECT extensions.plan(12);

SELECT extensions.ok(
  not (select prosecdef from pg_proc p join pg_namespace n on n.oid = p.pronamespace
       where n.nspname = 'policy_lab' and p.proname = 'verified_client_id'),
  'verified_client_id is SECURITY INVOKER'
);

SELECT extensions.ok(
  not has_function_privilege('anon', 'policy_lab.verified_client_id()', 'EXECUTE')
  and not has_function_privilege('authenticated', 'policy_lab.custom_access_token_hook(jsonb)', 'EXECUTE'),
  'API roles cannot execute the access-token hook; anon cannot read verified_client_id'
);

SET LOCAL ROLE authenticated;
SELECT set_config(
  'request.jwt.claims',
  '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated","aud":"authenticated","app_metadata":{"client_id":"client-active"}}',
  true
);
SELECT extensions.results_eq(
  'SELECT policy_lab.verified_client_id()',
  $$VALUES ('client-active'::text)$$,
  'app_metadata.client_id remains valid for existing M2 tokens'
);

SELECT set_config(
  'request.jwt.claims',
  '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated","aud":["authenticated","https://mcp.loopback.invalid/mcp"],"client_id":"client-active","user_metadata":{"client_id":"client-other","read_only":true}}',
  true
);
SELECT extensions.results_eq(
  'SELECT policy_lab.verified_client_id()',
  $$VALUES ('client-active'::text)$$,
  'top-level client_id wins and user_metadata is ignored'
);
SELECT extensions.results_eq(
  'SELECT memory_id FROM public.policy_lab_memory_read ORDER BY memory_id',
  $$VALUES ('memory-alpha'::text)$$,
  'dual aud plus top-level client_id still reaches the authorized workspace'
);

SELECT set_config(
  'request.jwt.claims',
  '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated","aud":"authenticated","user_metadata":{"client_id":"client-active","read_only":true,"role":"authenticated"}}',
  true
);
SELECT extensions.is_empty(
  'SELECT * FROM public.policy_lab_memory_read',
  'user_metadata client_id and read_only never authorize'
);
SELECT extensions.is(
  (SELECT policy_lab.verified_client_id()),
  NULL,
  'verified_client_id ignores user_metadata entirely'
);

SELECT set_config(
  'request.jwt.claims',
  '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated","aud":"authenticated","client_id":"client-other","app_metadata":{"client_id":"client-active"}}',
  true
);
SELECT extensions.is_empty(
  'SELECT * FROM public.policy_lab_memory_read',
  'same user with a different top-level client is denied'
);

SELECT set_config(
  'request.jwt.claims',
  '{"sub":"00000000-0000-0000-0000-000000000002","role":"authenticated","aud":"authenticated","client_id":"client-active"}',
  true
);
SELECT extensions.is_empty(
  'SELECT * FROM public.policy_lab_memory_read',
  'different user with an otherwise active client is denied'
);

RESET ROLE;
SAVEPOINT permissive_oauth_policy;
ALTER POLICY memory_read_intersection ON policy_lab.memories USING (true);
SET LOCAL ROLE authenticated;
SELECT set_config(
  'request.jwt.claims',
  '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated","client_id":"client-active"}',
  true
);
SELECT (count(*) > 1) AS oauth_weakened_visibility
FROM public.policy_lab_memory_read
\gset
RESET ROLE;
ROLLBACK TO SAVEPOINT permissive_oauth_policy;
SELECT extensions.ok(
  :'oauth_weakened_visibility'::boolean,
  'permissive memory policy is still detectable under top-level client_id'
);

SELECT extensions.ok(
  not exists (
    select 1
    from pg_proc p
    join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'policy_lab'
      and p.proname in ('verified_client_id', 'has_active_capability', 'custom_access_token_hook')
      and pg_get_functiondef(p.oid) ~ 'user_metadata'
  ),
  'client helpers never consult user_metadata'
);

SELECT * FROM extensions.finish();
ROLLBACK;
