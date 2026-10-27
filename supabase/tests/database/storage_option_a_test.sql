-- Issue #123 S4 Storage RLS. Assumes option A; pending RLS layout decision.
-- Synthetic fixtures only; everything rolls back.
BEGIN;
CREATE EXTENSION IF NOT EXISTS pgtap WITH SCHEMA extensions;
SELECT extensions.plan(93);

-- Fixtures (two users, two delegated agents, one denied user, one service agent).
INSERT INTO policy_lab.principals (principal_id, principal_kind, identity_eligibility) VALUES
  ('aaaaaaaa-0000-4000-8000-000000000001', 'human', 'verified'),
  ('bbbbbbbb-0000-4000-8000-000000000002', 'human', 'verified'),
  ('aaaaaaaa-0000-4000-8000-0000000000a1', 'delegated_agent', 'verified'),
  ('bbbbbbbb-0000-4000-8000-0000000000b1', 'delegated_agent', 'verified'),
  ('dddddddd-0000-4000-8000-000000000004', 'human', 'denied'),
  ('eeeeeeee-0000-4000-8000-000000000005', 'service_agent', 'verified');

INSERT INTO policy_lab.clients (client_id, state, valid_until) VALUES
  ('s4-client-a', 'active', '2099-01-01'),
  ('s4-client-b', 'active', '2099-01-01'),
  ('s4-client-revoked', 'revoked', '2099-01-01'),
  ('s4-client-expired', 'expired', '2020-01-01');

INSERT INTO policy_lab.memberships (principal_id, client_id, workspace_id, state, valid_until) VALUES
  ('aaaaaaaa-0000-4000-8000-000000000001', 's4-client-a', 's4-ws-a', 'active', '2099-01-01'),
  ('aaaaaaaa-0000-4000-8000-000000000001', 's4-client-revoked', 's4-ws-a', 'active', '2099-01-01'),
  ('aaaaaaaa-0000-4000-8000-000000000001', 's4-client-expired', 's4-ws-a', 'active', '2099-01-01'),
  ('bbbbbbbb-0000-4000-8000-000000000002', 's4-client-b', 's4-ws-b', 'active', '2099-01-01'),
  ('aaaaaaaa-0000-4000-8000-0000000000a1', 's4-client-a', 's4-ws-a', 'active', '2099-01-01'),
  ('bbbbbbbb-0000-4000-8000-0000000000b1', 's4-client-b', 's4-ws-b', 'active', '2099-01-01'),
  ('dddddddd-0000-4000-8000-000000000004', 's4-client-a', 's4-ws-a', 'active', '2099-01-01'),
  ('eeeeeeee-0000-4000-8000-000000000005', 's4-client-a', 's4-ws-a', 'active', '2099-01-01');

INSERT INTO policy_lab.capability_grants (principal_id, client_id, workspace_id, capability, state, valid_until)
SELECT p, c, w, cap, 'active', '2099-01-01'
FROM (VALUES
  ('aaaaaaaa-0000-4000-8000-000000000001'::uuid, 's4-client-a', 's4-ws-a'),
  ('aaaaaaaa-0000-4000-8000-000000000001'::uuid, 's4-client-revoked', 's4-ws-a'),
  ('aaaaaaaa-0000-4000-8000-000000000001'::uuid, 's4-client-expired', 's4-ws-a'),
  ('bbbbbbbb-0000-4000-8000-000000000002'::uuid, 's4-client-b', 's4-ws-b'),
  ('aaaaaaaa-0000-4000-8000-0000000000a1'::uuid, 's4-client-a', 's4-ws-a'),
  ('bbbbbbbb-0000-4000-8000-0000000000b1'::uuid, 's4-client-b', 's4-ws-b'),
  ('dddddddd-0000-4000-8000-000000000004'::uuid, 's4-client-a', 's4-ws-a'),
  ('eeeeeeee-0000-4000-8000-000000000005'::uuid, 's4-client-a', 's4-ws-a')
) AS f(p, c, w)
CROSS JOIN (VALUES ('storage:read'), ('storage:write')) AS caps(cap);

INSERT INTO policy_lab.capability_grants (principal_id, client_id, workspace_id, capability, state, valid_until) VALUES
  ('aaaaaaaa-0000-4000-8000-000000000001', 's4-client-a', 's4-ws-a', 'memory:read', 'active', '2099-01-01');

-- agent_a may read and write for user_a; agent_b may only read for user_b.
INSERT INTO policy_lab.storage_delegations
  (agent_principal_id, human_principal_id, client_id, capabilities, state, valid_until) VALUES
  ('aaaaaaaa-0000-4000-8000-0000000000a1', 'aaaaaaaa-0000-4000-8000-000000000001', 's4-client-a',
   array['storage:read', 'storage:write'], 'active', '2099-01-01'),
  ('bbbbbbbb-0000-4000-8000-0000000000b1', 'bbbbbbbb-0000-4000-8000-000000000002', 's4-client-b',
   array['storage:read'], 'active', '2099-01-01');

INSERT INTO storage.buckets (id, name, public) VALUES ('s4-other-bucket', 's4-other-bucket', false)
ON CONFLICT (id) DO NOTHING;

INSERT INTO storage.objects (bucket_id, name) VALUES
  ('mcp-user-storage', 'aaaaaaaa-0000-4000-8000-000000000001/notes/a.txt'),
  ('mcp-user-storage', 'aaaaaaaa-0000-4000-8000-000000000001/delete-me.txt'),
  ('mcp-user-storage', 'aaaaaaaa-0000-4000-8000-000000000001/bad..name.txt'),
  ('mcp-user-storage', 'bbbbbbbb-0000-4000-8000-000000000002/b.txt'),
  ('mcp-user-storage', 'aaaaaaaa-0000-4000-8000-0000000000a1/agent-own.txt'),
  ('s4-other-bucket', 'aaaaaaaa-0000-4000-8000-000000000001/other.txt');

-- Catalog: fail-closed shape of the new functions and policies.
SELECT extensions.is(
  (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'policy_lab' AND p.proname LIKE 'storage%' AND p.prosecdef),
  0::bigint, 'no storage function is SECURITY DEFINER');
SELECT extensions.is(
  (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'policy_lab' AND p.proname LIKE 'storage%'
     AND NOT coalesce(p.proconfig @> array['search_path=""'], false)),
  0::bigint, 'every storage function pins an empty search_path');
SELECT extensions.is(
  (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'policy_lab' AND p.proname LIKE 'storage%'
     AND has_function_privilege('anon', p.oid, 'EXECUTE')),
  0::bigint, 'anon cannot execute any storage function');
SELECT extensions.is(
  (SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
   JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'storage' AND c.relname = 'objects' AND p.polname LIKE 'mcp_user_storage%'
     AND p.polcmd IN ('w', '*')),
  0::bigint, 'no UPDATE or ALL policy on the storage bucket');
SELECT extensions.is(
  (SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
   JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'storage' AND c.relname = 'objects' AND p.polname LIKE 'mcp_user_storage%'
     AND p.polroles <> array[(SELECT oid FROM pg_roles WHERE rolname = 'authenticated')]),
  0::bigint, 'storage bucket policies apply to authenticated only');
SELECT extensions.is(
  (SELECT md5(prosrc) FROM pg_proc WHERE oid = 'policy_lab.has_active_capability(text,text)'::regprocedure),
  '5265c2a74a7507c8caa062690a61ed28', 'grant check has_active_capability is unchanged');
SELECT extensions.ok(
  (SELECT pg_get_expr(polqual, polrelid) !~ 'storage' AND pg_get_expr(polqual, polrelid) ~ 'memory:read'
   FROM pg_policy WHERE polname = 'grant_is_active_context'),
  'memory grant policy grant_is_active_context is unchanged');
SELECT extensions.ok(
  (SELECT NOT public FROM storage.buckets WHERE id = 'mcp-user-storage'), 'bucket is private');

-- Key shape mirrors S1.
SELECT extensions.ok(policy_lab.storage_relative_key_ok('notes/a.txt'), 'key: nested txt accepted');
SELECT extensions.ok(NOT policy_lab.storage_relative_key_ok('../a.txt'), 'key: dot-dot rejected');
SELECT extensions.ok(NOT policy_lab.storage_relative_key_ok('a//b.txt'), 'key: empty segment rejected');
SELECT extensions.ok(NOT policy_lab.storage_relative_key_ok('.hidden.txt'), 'key: leading dot rejected');
SELECT extensions.ok(NOT policy_lab.storage_relative_key_ok('a/b.html'), 'key: disallowed extension rejected');
SELECT extensions.ok(NOT policy_lab.storage_relative_key_ok('a/b.TXT'), 'key: extension is case-sensitive');
SELECT extensions.ok(NOT policy_lab.storage_relative_key_ok('a/b/c/d/e/f/g/h/i.txt'), 'key: nine segments rejected');
SELECT extensions.ok(NOT policy_lab.storage_relative_key_ok(repeat('a', 129) || '.txt'), 'key: 129-byte segment rejected');
SELECT extensions.ok(NOT policy_lab.storage_relative_key_ok(NULL), 'key: null rejected');

-- CHECK constraints.
SELECT extensions.throws_ok(
  $$INSERT INTO policy_lab.capability_grants VALUES
    ('aaaaaaaa-0000-4000-8000-000000000001', 's4-client-a', 's4-ws-a', 'storage:admin', 'active', '2099-01-01')$$,
  '23514', NULL, 'grant CHECK refuses an unknown storage capability');
SELECT extensions.throws_ok(
  $$INSERT INTO policy_lab.storage_delegations VALUES
    ('aaaaaaaa-0000-4000-8000-0000000000a1', 'aaaaaaaa-0000-4000-8000-000000000001', 's4-client-b',
     array['storage:admin'], 'active', '2099-01-01')$$,
  '23514', NULL, 'delegation CHECK refuses capabilities outside storage');
SELECT extensions.throws_ok(
  $$INSERT INTO policy_lab.storage_delegations VALUES
    ('aaaaaaaa-0000-4000-8000-0000000000a1', 'aaaaaaaa-0000-4000-8000-0000000000a1', 's4-client-b',
     array['storage:read'], 'active', '2099-01-01')$$,
  '23514', NULL, 'delegation CHECK refuses self-delegation');
SELECT extensions.throws_ok(
  $$INSERT INTO policy_lab.storage_delegations VALUES
    ('bbbbbbbb-0000-4000-8000-000000000002', 'aaaaaaaa-0000-4000-8000-000000000001', 's4-client-a',
     array['storage:read'], 'active', '2099-01-01')$$,
  '23514', NULL, 'delegation guard refuses a human in the agent slot');

SET LOCAL ROLE authenticated;

-- user_a through client a.
SELECT set_config('request.jwt.claims', '{"sub":"aaaaaaaa-0000-4000-8000-000000000001","role":"authenticated","app_metadata":{"client_id":"s4-client-a"}}', true);
SELECT extensions.is(policy_lab.storage_principal(), 'aaaaaaaa-0000-4000-8000-000000000001'::uuid, 'user_a: principal is self');
SELECT extensions.is(policy_lab.storage_session_capabilities(), '["storage:read", "storage:write"]'::jsonb, 'user_a: read and write');
SELECT extensions.results_eq(
  $$SELECT name FROM storage.objects WHERE bucket_id = 'mcp-user-storage' ORDER BY name$$,
  $$VALUES ('aaaaaaaa-0000-4000-8000-000000000001/delete-me.txt'::text), ('aaaaaaaa-0000-4000-8000-000000000001/notes/a.txt')$$,
  'user_a: lists only own well-formed objects');
SELECT extensions.is_empty(
  $$SELECT 1 FROM storage.objects WHERE name LIKE 'bbbbbbbb-0000-4000-8000-000000000002/%'$$,
  'user_a: cannot see user_b objects');
SELECT extensions.is_empty(
  $$SELECT 1 FROM storage.objects WHERE bucket_id = 's4-other-bucket'$$,
  'user_a: cannot see own prefix in another bucket');
SELECT extensions.results_eq(
  $$SELECT capability FROM policy_lab.capability_grants ORDER BY capability$$,
  $$VALUES ('memory:read'::text), ('storage:read'), ('storage:write')$$,
  'user_a: sees own memory and storage grants only');
SELECT extensions.lives_ok(
  $$INSERT INTO storage.objects (bucket_id, name) VALUES ('mcp-user-storage', 'aaaaaaaa-0000-4000-8000-000000000001/new.txt')$$,
  'user_a: put under own prefix allowed');
SELECT extensions.throws_ok(
  $$INSERT INTO storage.objects (bucket_id, name) VALUES ('mcp-user-storage', 'bbbbbbbb-0000-4000-8000-000000000002/x.txt')$$,
  '42501', NULL, 'user_a: put under user_b prefix denied');
SELECT extensions.throws_ok(
  $$INSERT INTO storage.objects (bucket_id, name) VALUES ('mcp-user-storage', 'aaaaaaaa-0000-4000-8000-000000000001/../x.txt')$$,
  '42501', NULL, 'user_a: path escape denied');
SELECT extensions.throws_ok(
  $$INSERT INTO storage.objects (bucket_id, name) VALUES ('mcp-user-storage', 'aaaaaaaa-0000-4000-8000-000000000001/x.svg')$$,
  '42501', NULL, 'user_a: disallowed type denied');
SELECT extensions.throws_ok(
  $$INSERT INTO storage.objects (bucket_id, name) VALUES ('mcp-user-storage', 'aaaaaaaa-0000-4000-8000-000000000001x/a.txt')$$,
  '42501', NULL, 'user_a: look-alike prefix denied');
SELECT extensions.throws_ok(
  $$INSERT INTO storage.objects (bucket_id, name) VALUES ('s4-other-bucket', 'aaaaaaaa-0000-4000-8000-000000000001/y.txt')$$,
  '42501', NULL, 'user_a: other bucket denied');
-- Hosted Storage refuses direct SQL deletes on storage.objects (protect_delete
-- trigger, ERRCODE 42501) unless storage.allow_delete_query is 'true', which the
-- Storage API sets for its own deletes. Without the flag the delete must fail;
-- with it, RLS alone decides which rows go. Skipped where the trigger is absent.
SELECT CASE WHEN EXISTS (
    SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'storage' AND c.relname = 'objects' AND t.tgname = 'protect_objects_delete')
  THEN extensions.throws_ok(
    $$DELETE FROM storage.objects WHERE name = 'aaaaaaaa-0000-4000-8000-000000000001/delete-me.txt'$$,
    '42501', 'Direct deletion from storage tables is not allowed. Use the Storage API instead.',
    'user_a: direct delete without the Storage API flag is refused')
  ELSE extensions.skip('storage protect_delete trigger not installed', 1) END;
SELECT set_config('storage.allow_delete_query', 'true', true);
WITH d AS (
  DELETE FROM storage.objects WHERE name = 'bbbbbbbb-0000-4000-8000-000000000002/b.txt' RETURNING 1)
SELECT extensions.is(count(*)::int, 0, 'user_a: delete of user_b object removes no rows (RLS)') FROM d;
WITH d AS (
  DELETE FROM storage.objects WHERE name = 'aaaaaaaa-0000-4000-8000-000000000001/delete-me.txt' RETURNING 1)
SELECT extensions.is(count(*)::int, 1, 'user_a: delete of own object removes exactly one row') FROM d;
SELECT set_config('storage.allow_delete_query', 'false', true);
SELECT CASE WHEN EXISTS (
    SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'storage' AND c.relname = 'objects' AND t.tgname = 'protect_objects_delete')
  THEN extensions.throws_ok(
    $$DELETE FROM storage.objects WHERE name = 'aaaaaaaa-0000-4000-8000-000000000001/notes/a.txt'$$,
    '42501', 'Direct deletion from storage tables is not allowed. Use the Storage API instead.',
    'user_a: direct delete is refused again once the flag is cleared')
  ELSE extensions.skip('storage protect_delete trigger not installed', 1) END;
UPDATE storage.objects SET name = 'aaaaaaaa-0000-4000-8000-000000000001/renamed.txt'
  WHERE name = 'aaaaaaaa-0000-4000-8000-000000000001/notes/a.txt';

-- Cross-client: user_a through client b, user_b through client a.
SELECT set_config('request.jwt.claims', '{"sub":"aaaaaaaa-0000-4000-8000-000000000001","role":"authenticated","app_metadata":{"client_id":"s4-client-b"}}', true);
SELECT extensions.ok(policy_lab.storage_principal() IS NULL, 'cross-client user_a: no principal');
SELECT extensions.is(policy_lab.storage_session_capabilities(), '[]'::jsonb, 'cross-client user_a: no capabilities');
SELECT extensions.is_empty($$SELECT 1 FROM storage.objects$$, 'cross-client user_a: sees nothing');
SELECT set_config('request.jwt.claims', '{"sub":"bbbbbbbb-0000-4000-8000-000000000002","role":"authenticated","app_metadata":{"client_id":"s4-client-a"}}', true);
SELECT extensions.is_empty($$SELECT 1 FROM storage.objects$$, 'cross-client user_b: sees nothing');

-- user_b through client b.
SELECT set_config('request.jwt.claims', '{"sub":"bbbbbbbb-0000-4000-8000-000000000002","role":"authenticated","app_metadata":{"client_id":"s4-client-b"}}', true);
SELECT extensions.results_eq(
  $$SELECT name FROM storage.objects ORDER BY name$$,
  $$VALUES ('bbbbbbbb-0000-4000-8000-000000000002/b.txt'::text)$$,
  'user_b: own object survived user_a delete attempt; sees nothing of user_a');
SELECT extensions.is_empty(
  $$SELECT 1 FROM policy_lab.capability_grants WHERE principal_id <> auth.uid()$$,
  'user_b: cannot see other grants');

-- agent_a (delegated by user_a, read+write) through client a.
SELECT set_config('request.jwt.claims', '{"sub":"aaaaaaaa-0000-4000-8000-0000000000a1","role":"authenticated","app_metadata":{"client_id":"s4-client-a"}}', true);
SELECT extensions.is(policy_lab.storage_principal(), 'aaaaaaaa-0000-4000-8000-000000000001'::uuid, 'agent_a: principal is user_a');
SELECT extensions.is(policy_lab.storage_object_prefix(), 'aaaaaaaa-0000-4000-8000-000000000001/', 'agent_a: prefix seam is the human prefix (sub-prefix open)');
SELECT extensions.results_eq(
  $$SELECT name FROM storage.objects ORDER BY name$$,
  $$VALUES ('aaaaaaaa-0000-4000-8000-000000000001/new.txt'::text), ('aaaaaaaa-0000-4000-8000-000000000001/notes/a.txt')$$,
  'agent_a: sees user_a objects (delete and rename by user_a applied as expected)');
SELECT extensions.lives_ok(
  $$INSERT INTO storage.objects (bucket_id, name) VALUES ('mcp-user-storage', 'aaaaaaaa-0000-4000-8000-000000000001/agent-note.txt')$$,
  'agent_a: put under user_a prefix allowed');
SELECT extensions.throws_ok(
  $$INSERT INTO storage.objects (bucket_id, name) VALUES ('mcp-user-storage', 'aaaaaaaa-0000-4000-8000-0000000000a1/x.txt')$$,
  '42501', NULL, 'agent_a: put under its own uid prefix denied');
SELECT extensions.throws_ok(
  $$INSERT INTO storage.objects (bucket_id, name) VALUES ('mcp-user-storage', 'bbbbbbbb-0000-4000-8000-000000000002/x.txt')$$,
  '42501', NULL, 'agent_a: put under user_b prefix denied');
SELECT extensions.is_empty(
  $$SELECT 1 FROM storage.objects WHERE name LIKE 'bbbbbbbb-%'$$, 'agent_a: cannot see user_b objects');
SELECT extensions.results_eq(
  $$SELECT principal_id::text, capability FROM policy_lab.capability_grants WHERE principal_id <> auth.uid() ORDER BY capability$$,
  $$VALUES ('aaaaaaaa-0000-4000-8000-000000000001'::text, 'storage:read'::text),
           ('aaaaaaaa-0000-4000-8000-000000000001', 'storage:write')$$,
  'agent_a: sees only the delegating human storage grants for this client');

-- agent_a through client b (wrong client for its delegation).
SELECT set_config('request.jwt.claims', '{"sub":"aaaaaaaa-0000-4000-8000-0000000000a1","role":"authenticated","app_metadata":{"client_id":"s4-client-b"}}', true);
SELECT extensions.ok(policy_lab.storage_principal() IS NULL, 'agent_a via client b: no principal');

-- agent_b (delegated read only) through client b.
SELECT set_config('request.jwt.claims', '{"sub":"bbbbbbbb-0000-4000-8000-0000000000b1","role":"authenticated","app_metadata":{"client_id":"s4-client-b"}}', true);
SELECT extensions.is(policy_lab.storage_session_capabilities(), '["storage:read"]'::jsonb, 'agent_b: delegation caps write');
SELECT extensions.results_eq(
  $$SELECT name FROM storage.objects ORDER BY name$$,
  $$VALUES ('bbbbbbbb-0000-4000-8000-000000000002/b.txt'::text)$$, 'agent_b: reads user_b objects');
SELECT extensions.throws_ok(
  $$INSERT INTO storage.objects (bucket_id, name) VALUES ('mcp-user-storage', 'bbbbbbbb-0000-4000-8000-000000000002/y.txt')$$,
  '42501', NULL, 'agent_b: put denied without delegated write');
SELECT extensions.results_eq(
  $$SELECT principal_id::text, capability FROM policy_lab.capability_grants WHERE principal_id <> auth.uid()$$,
  $$VALUES ('bbbbbbbb-0000-4000-8000-000000000002'::text, 'storage:read'::text)$$,
  'agent_b: sees only the delegated capability of its human grants');

-- Revoked and expired clients, denied and non-human/agent principals, malformed claims.
SELECT set_config('request.jwt.claims', '{"sub":"aaaaaaaa-0000-4000-8000-000000000001","role":"authenticated","app_metadata":{"client_id":"s4-client-revoked"}}', true);
SELECT extensions.is_empty($$SELECT 1 FROM storage.objects$$, 'revoked client: sees nothing');
SELECT set_config('request.jwt.claims', '{"sub":"aaaaaaaa-0000-4000-8000-000000000001","role":"authenticated","app_metadata":{"client_id":"s4-client-expired"}}', true);
SELECT extensions.is_empty($$SELECT 1 FROM storage.objects$$, 'expired client: sees nothing');
SELECT set_config('request.jwt.claims', '{"sub":"dddddddd-0000-4000-8000-000000000004","role":"authenticated","app_metadata":{"client_id":"s4-client-a"}}', true);
SELECT extensions.ok(policy_lab.storage_principal() IS NULL, 'denied principal: no principal');
SELECT set_config('request.jwt.claims', '{"sub":"eeeeeeee-0000-4000-8000-000000000005","role":"authenticated","app_metadata":{"client_id":"s4-client-a"}}', true);
SELECT extensions.ok(policy_lab.storage_principal() IS NULL, 'service agent: no principal');
SELECT extensions.ok(policy_lab.storage_object_prefix() IS NULL, 'service agent: no prefix');
SELECT extensions.is_empty($$SELECT 1 FROM storage.objects$$, 'service agent: sees nothing');
SELECT set_config('request.jwt.claims', '{"sub":"aaaaaaaa-0000-4000-8000-000000000001","role":"authenticated"}', true);
SELECT extensions.ok(policy_lab.storage_principal() IS NULL, 'missing client claim: no principal');
SELECT set_config('request.jwt.claims', '{"sub":"aaaaaaaa-0000-4000-8000-000000000001","role":"authenticated","client_id":"s4-client-a"}', true);
SELECT extensions.ok(policy_lab.storage_principal() IS NULL, 'top-level client_id alone is not accepted');
SELECT set_config('request.jwt.claims', '{"sub":"aaaaaaaa-0000-4000-8000-000000000001","role":"authenticated","app_metadata":{"client_id":42}}', true);
SELECT extensions.is_empty($$SELECT 1 FROM storage.objects$$, 'malformed client claim: sees nothing');

RESET ROLE;
SELECT extensions.ok(
  NOT EXISTS (SELECT 1 FROM storage.objects WHERE name = 'aaaaaaaa-0000-4000-8000-000000000001/delete-me.txt'),
  'user_a: delete of own object took effect');
SELECT extensions.ok(
  EXISTS (SELECT 1 FROM storage.objects WHERE name = 'aaaaaaaa-0000-4000-8000-000000000001/notes/a.txt'),
  'user_a: no UPDATE policy, so rename had no effect');

-- The delegating human's current authority: agent_a's delegation and user_a's grants stay
-- active while user_a's membership or identity eligibility changes. Each takes effect on the
-- next statement, through the session functions and through direct storage.objects RLS.
SELECT extensions.is(
  (SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
   JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'policy_lab' AND p.polname LIKE 'storage_delegator%'
     AND (p.polcmd <> 'r' OR p.polroles <> array[(SELECT oid FROM pg_roles WHERE rolname = 'authenticated')])),
  0::bigint, 'delegator visibility policies are SELECT-only for authenticated');
UPDATE policy_lab.memberships SET state = 'revoked'
  WHERE principal_id = 'aaaaaaaa-0000-4000-8000-000000000001' AND client_id = 's4-client-a';
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claims', '{"sub":"aaaaaaaa-0000-4000-8000-0000000000a1","role":"authenticated","app_metadata":{"client_id":"s4-client-a"}}', true);
SELECT extensions.is(policy_lab.storage_session_capabilities(), '[]'::jsonb, 'revoked human membership: agent_a has no capabilities');
SELECT extensions.ok(policy_lab.storage_principal() IS NULL, 'revoked human membership: agent_a has no principal');
SELECT extensions.is_empty($$SELECT 1 FROM storage.objects$$, 'revoked human membership: agent_a sees nothing (direct RLS)');
SELECT extensions.throws_ok(
  $$INSERT INTO storage.objects (bucket_id, name) VALUES ('mcp-user-storage', 'aaaaaaaa-0000-4000-8000-000000000001/suspended.txt')$$,
  '42501', NULL, 'revoked human membership: agent_a put denied (direct RLS)');
RESET ROLE;
UPDATE policy_lab.memberships SET state = 'active'
  WHERE principal_id = 'aaaaaaaa-0000-4000-8000-000000000001' AND client_id = 's4-client-a';
UPDATE policy_lab.principals SET identity_eligibility = 'denied' WHERE principal_id = 'aaaaaaaa-0000-4000-8000-000000000001';
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claims', '{"sub":"aaaaaaaa-0000-4000-8000-0000000000a1","role":"authenticated","app_metadata":{"client_id":"s4-client-a"}}', true);
SELECT extensions.is(policy_lab.storage_session_capabilities(), '[]'::jsonb, 'denied human eligibility: agent_a has no capabilities');
SELECT extensions.ok(policy_lab.storage_principal() IS NULL, 'denied human eligibility: agent_a has no principal');
SELECT extensions.is_empty($$SELECT 1 FROM storage.objects$$, 'denied human eligibility: agent_a sees nothing (direct RLS)');
SELECT extensions.throws_ok(
  $$INSERT INTO storage.objects (bucket_id, name) VALUES ('mcp-user-storage', 'aaaaaaaa-0000-4000-8000-000000000001/suspended.txt')$$,
  '42501', NULL, 'denied human eligibility: agent_a put denied (direct RLS)');
RESET ROLE;
UPDATE policy_lab.principals SET identity_eligibility = 'verified' WHERE principal_id = 'aaaaaaaa-0000-4000-8000-000000000001';
UPDATE policy_lab.memberships SET valid_until = '2020-01-01'
  WHERE principal_id = 'aaaaaaaa-0000-4000-8000-000000000001' AND client_id = 's4-client-a';
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claims', '{"sub":"aaaaaaaa-0000-4000-8000-0000000000a1","role":"authenticated","app_metadata":{"client_id":"s4-client-a"}}', true);
SELECT extensions.is(policy_lab.storage_session_capabilities(), '[]'::jsonb, 'expired human membership: agent_a has no capabilities');
SELECT extensions.ok(policy_lab.storage_principal() IS NULL, 'expired human membership: agent_a has no principal');
SELECT extensions.is_empty($$SELECT 1 FROM storage.objects$$, 'expired human membership: agent_a sees nothing (direct RLS)');
RESET ROLE;
UPDATE policy_lab.memberships SET valid_until = '2099-01-01'
  WHERE principal_id = 'aaaaaaaa-0000-4000-8000-000000000001' AND client_id = 's4-client-a';
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claims', '{"sub":"aaaaaaaa-0000-4000-8000-0000000000a1","role":"authenticated","app_metadata":{"client_id":"s4-client-a"}}', true);
SELECT extensions.is(policy_lab.storage_principal(), 'aaaaaaaa-0000-4000-8000-000000000001'::uuid, 'restored human authority: agent_a principal is user_a again');
SELECT extensions.results_eq(
  $$SELECT principal_id::text FROM policy_lab.principals ORDER BY 1$$,
  $$VALUES ('aaaaaaaa-0000-4000-8000-000000000001'::text), ('aaaaaaaa-0000-4000-8000-0000000000a1')$$,
  'agent_a: sees only its own and its delegating human principal rows');
SELECT extensions.results_eq(
  $$SELECT principal_id::text, client_id FROM policy_lab.memberships ORDER BY 1, 2$$,
  $$VALUES ('aaaaaaaa-0000-4000-8000-000000000001'::text, 's4-client-a'::text),
           ('aaaaaaaa-0000-4000-8000-0000000000a1', 's4-client-a')$$,
  'agent_a: sees only the delegating human memberships through this client');
RESET ROLE;

-- Revocation takes effect on the next statement.
UPDATE policy_lab.storage_delegations SET state = 'revoked'
  WHERE agent_principal_id = 'aaaaaaaa-0000-4000-8000-0000000000a1';
UPDATE policy_lab.capability_grants SET state = 'revoked'
  WHERE principal_id = 'aaaaaaaa-0000-4000-8000-000000000001' AND client_id = 's4-client-a'
    AND capability = 'storage:read';
UPDATE policy_lab.capability_grants SET valid_until = '2020-01-01'
  WHERE principal_id = 'bbbbbbbb-0000-4000-8000-000000000002' AND capability LIKE 'storage:%';

SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claims', '{"sub":"aaaaaaaa-0000-4000-8000-0000000000a1","role":"authenticated","app_metadata":{"client_id":"s4-client-a"}}', true);
SELECT extensions.ok(policy_lab.storage_principal() IS NULL, 'revoked delegation: agent_a has no principal');
SELECT extensions.is_empty($$SELECT 1 FROM storage.objects$$, 'revoked delegation: agent_a sees nothing');
SELECT set_config('request.jwt.claims', '{"sub":"aaaaaaaa-0000-4000-8000-000000000001","role":"authenticated","app_metadata":{"client_id":"s4-client-a"}}', true);
SELECT extensions.is(policy_lab.storage_session_capabilities(), '["storage:write"]'::jsonb, 'revoked read grant: user_a keeps only write');
SELECT extensions.is_empty($$SELECT 1 FROM storage.objects$$, 'revoked read grant: user_a lists nothing');
SELECT set_config('request.jwt.claims', '{"sub":"bbbbbbbb-0000-4000-8000-000000000002","role":"authenticated","app_metadata":{"client_id":"s4-client-b"}}', true);
SELECT extensions.is(policy_lab.storage_session_capabilities(), '[]'::jsonb, 'expired grants: user_b has none');
SELECT extensions.is_empty($$SELECT 1 FROM storage.objects$$, 'expired grants: user_b sees nothing');
-- agent_b's delegation is still active, but user_b's own storage grants have expired.
SELECT set_config('request.jwt.claims', '{"sub":"bbbbbbbb-0000-4000-8000-0000000000b1","role":"authenticated","app_metadata":{"client_id":"s4-client-b"}}', true);
SELECT extensions.is(policy_lab.storage_session_capabilities(), '[]'::jsonb, 'expired human grants: agent_b has no capabilities');
SELECT extensions.ok(policy_lab.storage_principal() IS NULL, 'expired human grants: agent_b has no principal');
SELECT extensions.is_empty($$SELECT 1 FROM storage.objects$$, 'expired human grants: agent_b sees nothing');

RESET ROLE;
SET LOCAL ROLE anon;
SELECT extensions.throws_ok('SELECT policy_lab.storage_principal()', '42501', NULL, 'anon cannot call storage_principal');
SELECT extensions.is_empty($$SELECT 1 FROM storage.objects WHERE bucket_id = 'mcp-user-storage'$$, 'anon sees no bucket objects');
RESET ROLE;

SELECT * FROM extensions.finish();
ROLLBACK;
