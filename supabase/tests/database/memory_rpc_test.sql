BEGIN;
CREATE EXTENSION IF NOT EXISTS pgtap WITH SCHEMA extensions;
SELECT extensions.plan(23);

SELECT extensions.ok(
  not (select prosecdef from pg_proc p join pg_namespace n on n.oid = p.pronamespace
       where n.nspname = 'memory' and p.proname = 'authorized_memory_get_v1'),
  'memory_get is SECURITY INVOKER'
);
SELECT extensions.ok(
  not (select prosecdef from pg_proc p join pg_namespace n on n.oid = p.pronamespace
       where n.nspname = 'memory' and p.proname = 'authorized_memory_search_v1'),
  'memory_search is SECURITY INVOKER'
);
SELECT extensions.ok(
  not (select prosecdef from pg_proc p join pg_namespace n on n.oid = p.pronamespace
       where n.nspname = 'memory' and p.proname = 'authorized_memory_list_recent_v1'),
  'memory_list_recent is SECURITY INVOKER'
);
SELECT extensions.ok(
  has_function_privilege('authenticated', 'memory.authorized_memory_get_v1(text)', 'EXECUTE')
  and has_function_privilege('authenticated', 'memory.authorized_memory_search_v1(text,text,jsonb,integer,text)', 'EXECUTE')
  and has_function_privilege('authenticated', 'memory.authorized_memory_list_recent_v1(jsonb,integer,text)', 'EXECUTE'),
  'authenticated has execute only on the fixed read RPC surface'
);
SELECT extensions.ok(
  not has_function_privilege('anon', 'memory.authorized_memory_get_v1(text)', 'EXECUTE')
  and not has_function_privilege('anon', 'memory.authorized_memory_search_v1(text,text,jsonb,integer,text)', 'EXECUTE')
  and not has_function_privilege('anon', 'memory.authorized_memory_list_recent_v1(jsonb,integer,text)', 'EXECUTE'),
  'anon has no execute privilege on memory RPCs'
);
SELECT extensions.ok(
  not exists (
    select 1
    from pg_proc p
    join pg_namespace n on n.oid = p.pronamespace,
         lateral unnest(coalesce(p.proargnames, array[]::text[])) arg_name
    where n.nspname = 'memory'
      and p.proname in ('authorized_memory_get_v1','authorized_memory_search_v1','authorized_memory_list_recent_v1')
      and arg_name in ('principal','principal_id','client','client_id','token','schema','relation','path','method','origin')
  ),
  'RPC signatures contain no caller-supplied identity or transport authority'
);

SET LOCAL ROLE authenticated;
SELECT set_config(
  'request.jwt.claims',
  '{"sub":"11111111-1111-4111-9111-111111111111","aud":"authenticated","role":"authenticated","app_metadata":{"client_id":"smp-lab-inspector"}}',
  true
);
SELECT extensions.is(
  memory.authorized_memory_get_v1('mem_01JTESTALPHA000000000001')->'record'->>'id',
  'mem_01JTESTALPHA000000000001',
  'authorized principal can get its record'
);
SELECT extensions.is(
  memory.authorized_memory_get_v1('mem_01JTESTBETA0000000000001')->'record',
  'null'::jsonb,
  'cross-principal get is non-enumerating'
);
SELECT extensions.is(
  memory.authorized_memory_get_v1('mem_01JTESTBETA0000000000001'),
  memory.authorized_memory_get_v1('mem_01JTESTDOESNOTEXIST000000'),
  'cross-principal denial is identical to a not-found response'
);
SELECT extensions.is(
  jsonb_array_length(memory.authorized_memory_list_recent_v1(null, 25, null)->'rows'),
  3,
  'recent list contains only authorized principal rows'
);
SELECT extensions.is(
  memory.authorized_memory_list_recent_v1(null, 25, null)->'rows'->0->>'id',
  'mem_01JTESTALPHA000000000003',
  'recent list ordering is deterministic newest-first'
);
SELECT extensions.is(
  jsonb_array_length(memory.authorized_memory_search_v1('network', 'text', null, 20, null)->'rows'),
  1,
  'lexical search returns only authorized title/content matches'
);
SELECT extensions.is(
  jsonb_array_length(memory.authorized_memory_search_v1('private', 'text', null, 20, null)->'rows'),
  0,
  'search cannot reveal cross-principal matches'
);
SELECT extensions.is(
  memory.authorized_memory_search_v1('hostile', 'text', null, 20, null)->'rows'->0->>'id',
  'mem_01JTESTALPHA000000000002',
  'hostile stored content remains data returned through the same authorization path'
);
SELECT extensions.ok(
  (memory.authorized_memory_search_v1('alpha', 'text', null, 1, null) ? 'nextCursor'),
  'bounded search emits an opaque continuation cursor when more rows exist'
);
SELECT extensions.ok(
  (memory.authorized_memory_search_v1('alpha', 'text', null, 1, null)->>'nextCursor') ~ '^cur_[A-Za-z0-9_-]{16,}$',
  'search cursor matches the closed opaque-cursor shape'
);
SELECT extensions.is(
  jsonb_array_length(
    memory.authorized_memory_search_v1(
      'alpha', 'text', null, 1,
      memory.authorized_memory_search_v1('alpha', 'text', null, 1, null)->>'nextCursor'
    )->'rows'
  ),
  1,
  'search cursor resumes within the authorized result set'
);
SELECT extensions.throws_ok(
  $$select memory.authorized_memory_search_v1('alpha', 'text', null, 1, 'cur_not_a_real_cursor_000000')$$,
  '22023', null, 'unknown search cursor fails closed'
);

SELECT set_config(
  'request.jwt.claims',
  '{"sub":"22222222-2222-4222-9222-222222222222","aud":"authenticated","role":"authenticated","app_metadata":{"client_id":"smp-lab-inspector"}}',
  true
);
SELECT extensions.is(
  memory.authorized_memory_get_v1('mem_01JTESTBETA0000000000001')->'record'->>'id',
  'mem_01JTESTBETA0000000000001',
  'second principal can read its own workspace record'
);
SELECT extensions.is(
  memory.authorized_memory_get_v1('mem_01JTESTALPHA000000000001')->'record',
  'null'::jsonb,
  'second principal cannot read first principal record'
);

SELECT set_config(
  'request.jwt.claims',
  '{"sub":"33333333-3333-4333-9333-333333333333","aud":"authenticated","role":"authenticated","app_metadata":{"client_id":"smp-lab-unapproved"}}',
  true
);
SELECT extensions.is(
  memory.authorized_memory_get_v1('mem_01JTESTREVOKED0000000001')->'record',
  'null'::jsonb,
  'revoked client fails closed'
);

SELECT set_config(
  'request.jwt.claims',
  '{"sub":"44444444-4444-4444-8444-444444444444","aud":"authenticated","role":"authenticated"}',
  true
);
SELECT extensions.is(
  memory.authorized_memory_list_recent_v1(null, 25, null)->'rows',
  '[]'::jsonb,
  'missing client claim returns no records'
);

RESET ROLE;
SET LOCAL ROLE anon;
SELECT extensions.throws_ok(
  $$select memory.authorized_memory_get_v1('mem_01JTESTALPHA000000000001')$$,
  '42501', null, 'unauthenticated caller is denied at function privilege boundary'
);

RESET ROLE;
SELECT * FROM extensions.finish();
ROLLBACK;
