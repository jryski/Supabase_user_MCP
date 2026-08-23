BEGIN;
CREATE EXTENSION IF NOT EXISTS pgtap WITH SCHEMA extensions;
SELECT extensions.plan(19);

SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated","app_metadata":{"client_id":"client-active"}}', true);
SELECT extensions.results_eq(
  'SELECT event_id FROM policy_lab.audit_events ORDER BY event_id',
  $$VALUES ('audit-active'::text)$$,
  'active principal, client, membership, and grant can read the principal audit event'
);
SELECT extensions.is_empty($$SELECT event_id FROM policy_lab.audit_events WHERE event_id = 'audit-client-revoked'$$, 'revoked client audit event is denied');
SELECT extensions.is_empty($$SELECT event_id FROM policy_lab.audit_events WHERE event_id = 'audit-membership-revoked'$$, 'revoked membership audit event is denied');
SELECT extensions.is_empty($$SELECT event_id FROM policy_lab.audit_events WHERE event_id = 'audit-grant-revoked'$$, 'revoked grant audit event is denied');
SELECT extensions.is_empty($$SELECT event_id FROM policy_lab.audit_events WHERE event_id = 'audit-other-principal'$$, 'another principal audit event is denied');

RESET ROLE;
SET LOCAL ROLE anon;
SELECT extensions.throws_ok('SELECT * FROM policy_lab.audit_events', '42501', NULL, 'anon cannot read audit events');

RESET ROLE;
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated","app_metadata":{"client_id":"client-active"}}', true);
SELECT extensions.throws_ok(
  $$INSERT INTO policy_lab.audit_events (event_id, recorded_at, principal_id, event_type) VALUES ('forbidden-auth-insert', now(), '00000000-0000-0000-0000-000000000001', 'memory.read.denied')$$,
  '42501', NULL, 'authenticated cannot insert audit rows'
);
SELECT extensions.throws_ok($$UPDATE policy_lab.audit_events SET metadata = '{}' WHERE event_id = 'audit-active'$$, '42501', NULL, 'authenticated cannot update audit rows');
SELECT extensions.throws_ok($$DELETE FROM policy_lab.audit_events WHERE event_id = 'audit-active'$$, '42501', NULL, 'authenticated cannot delete audit rows');

RESET ROLE;
SET LOCAL ROLE anon;
SELECT extensions.throws_ok(
  $$INSERT INTO policy_lab.audit_events (event_id, recorded_at, principal_id, event_type) VALUES ('forbidden-anon-insert', now(), '00000000-0000-0000-0000-000000000001', 'memory.read.denied')$$,
  '42501', NULL, 'anon cannot insert audit rows'
);
SELECT extensions.throws_ok($$UPDATE policy_lab.audit_events SET metadata = '{}' WHERE event_id = 'audit-active'$$, '42501', NULL, 'anon cannot update audit rows');
SELECT extensions.throws_ok($$DELETE FROM policy_lab.audit_events WHERE event_id = 'audit-active'$$, '42501', NULL, 'anon cannot delete audit rows');

RESET ROLE;
SAVEPOINT revoke_grant;
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated","app_metadata":{"client_id":"client-active"}}', true);
SELECT extensions.results_eq($$SELECT event_id FROM policy_lab.audit_events WHERE event_id = 'audit-active'$$, $$VALUES ('audit-active'::text)$$, 'active grant allows the audit read before revocation');
RESET ROLE;
UPDATE policy_lab.capability_grants SET state = 'revoked' WHERE principal_id = '00000000-0000-0000-0000-000000000001' AND client_id = 'client-active' AND workspace_id = 'workspace-alpha' AND capability = 'memory:read';
SET LOCAL ROLE authenticated;
SELECT extensions.is_empty($$SELECT event_id FROM policy_lab.audit_events WHERE event_id = 'audit-active'$$, 'the same request context sees zero rows immediately after grant revocation');
RESET ROLE;
ROLLBACK TO SAVEPOINT revoke_grant;

SAVEPOINT revoke_membership;
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated","app_metadata":{"client_id":"client-active"}}', true);
SELECT extensions.results_eq($$SELECT event_id FROM policy_lab.audit_events WHERE event_id = 'audit-active'$$, $$VALUES ('audit-active'::text)$$, 'active membership allows the audit read before revocation');
RESET ROLE;
UPDATE policy_lab.memberships SET state = 'revoked' WHERE principal_id = '00000000-0000-0000-0000-000000000001' AND client_id = 'client-active' AND workspace_id = 'workspace-alpha';
SET LOCAL ROLE authenticated;
SELECT extensions.is_empty($$SELECT event_id FROM policy_lab.audit_events WHERE event_id = 'audit-active'$$, 'the same request context sees zero rows immediately after membership revocation');
RESET ROLE;
ROLLBACK TO SAVEPOINT revoke_membership;

SAVEPOINT broken_audit_grant;
GRANT INSERT ON policy_lab.audit_events TO authenticated;
SELECT extensions.ok(
  has_table_privilege('authenticated', 'policy_lab.audit_events', 'INSERT'),
  'guard detects a deliberately broken authenticated audit grant'
);
ROLLBACK TO SAVEPOINT broken_audit_grant;

SAVEPOINT broken_revocation_predicate;
ALTER POLICY audit_event_current_principal_read ON policy_lab.audit_events USING (true);
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated","app_metadata":{"client_id":"client-active"}}', true);
SELECT (count(*) > 1) AS weakened_visibility FROM policy_lab.audit_events
\gset
RESET ROLE;
ROLLBACK TO SAVEPOINT broken_revocation_predicate;
SELECT extensions.ok(:'weakened_visibility'::boolean, 'guard detects a deliberately broken audit revocation predicate');

SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated","app_metadata":{"client_id":"client-active"}}', true);
SELECT extensions.results_eq($$SELECT event_id FROM policy_lab.audit_events$$, $$VALUES ('audit-active'::text)$$, 'rollback restores the trusted audit policy');
RESET ROLE;

SELECT * FROM extensions.finish();
ROLLBACK;
