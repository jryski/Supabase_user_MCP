BEGIN;
CREATE EXTENSION IF NOT EXISTS pgtap WITH SCHEMA extensions;
SELECT extensions.plan(17);

SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated","app_metadata":{"client_id":"client-active"}}', true);
SELECT extensions.results_eq(
  'SELECT memory_id FROM public.policy_lab_memory_read ORDER BY memory_id',
  $$VALUES ('memory-alpha'::text)$$,
  'eligible context sees only its workspace record'
);
SELECT extensions.is_empty(
  $$SELECT memory_id FROM public.policy_lab_memory_read WHERE memory_id = 'memory-no-grant'$$,
  'authentication without capability reveals nothing'
);
SELECT extensions.is_empty(
  $$SELECT memory_id FROM public.policy_lab_memory_read WHERE memory_id = 'memory-beta'$$,
  'cross-workspace record is hidden'
);

SELECT set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-000000000002","role":"authenticated","app_metadata":{"client_id":"client-other"}}', true);
SELECT extensions.results_eq(
  'SELECT memory_id FROM public.policy_lab_memory_read',
  $$VALUES ('memory-beta'::text)$$,
  'another authorized workspace sees only its own record'
);
SELECT extensions.is_empty(
  $$SELECT memory_id FROM public.policy_lab_memory_read WHERE memory_id = 'memory-alpha'$$,
  'another authorized workspace cannot infer the target record'
);

SELECT set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated","app_metadata":{"client_id":"client-other"}}', true);
SELECT extensions.is_empty('SELECT * FROM public.policy_lab_memory_read', 'cross-client context is denied');

SELECT set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-000000000003","role":"authenticated","app_metadata":{"client_id":"client-active"}}', true);
SELECT extensions.is_empty('SELECT * FROM public.policy_lab_memory_read', 'denied principal is denied');

SELECT set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated","app_metadata":{"client_id":"client-active"}}', true);
SELECT extensions.is_empty($$SELECT * FROM public.policy_lab_memory_read WHERE memory_id = 'memory-membership-expired'$$, 'expired membership is denied');
SELECT extensions.is_empty($$SELECT * FROM public.policy_lab_memory_read WHERE memory_id = 'memory-membership-revoked'$$, 'revoked membership is denied');
SELECT extensions.is_empty($$SELECT * FROM public.policy_lab_memory_read WHERE memory_id = 'memory-grant-expired'$$, 'expired grant is denied');
SELECT extensions.is_empty($$SELECT * FROM public.policy_lab_memory_read WHERE memory_id = 'memory-grant-revoked'$$, 'revoked grant is denied');

SELECT set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated","app_metadata":{"client_id":"client-expired"}}', true);
SELECT extensions.is_empty('SELECT * FROM public.policy_lab_memory_read', 'expired client is denied');
SELECT set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated","app_metadata":{"client_id":"client-revoked"}}', true);
SELECT extensions.is_empty('SELECT * FROM public.policy_lab_memory_read', 'revoked client is denied');

SELECT set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated"}', true);
SELECT extensions.is_empty('SELECT * FROM public.policy_lab_memory_read', 'missing client claim fails closed');
SELECT set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated","app_metadata":{"client_id":42}}', true);
SELECT extensions.is_empty('SELECT * FROM public.policy_lab_memory_read', 'malformed client claim fails closed');

RESET ROLE;
SET LOCAL ROLE anon;
SELECT extensions.throws_ok(
  'SELECT * FROM public.policy_lab_memory_read',
  '42501',
  NULL,
  'unauthenticated caller gets only permission denial'
);

RESET ROLE;
SAVEPOINT weakened_policy;
ALTER POLICY memory_read_intersection ON policy_lab.memories USING (true);
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated","app_metadata":{"client_id":"client-active"}}', true);
SELECT (count(*) > 1) AS weakened_visibility
FROM public.policy_lab_memory_read
\gset
RESET ROLE;
ROLLBACK TO SAVEPOINT weakened_policy;
SELECT extensions.ok(
  :'weakened_visibility'::boolean,
  'guard detects a deliberately weakened memory policy'
);

SELECT * FROM extensions.finish();
ROLLBACK;
