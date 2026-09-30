import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  acquireControllerLock,
  assertLocalOnly,
  BASELINE_USER_ID,
  HOSTED_PROJECT_REF,
  installerSql,
  LOCAL_B_CLIENT_ID,
  openLabDatabase,
  rollbackSql,
  runLocalLab,
  SECOND_USER_ID,
} from './ari-memory-read-lab.mjs';
import { runHostedController } from './ari-memory-read-lab-hosted.mjs';

async function apply(db, sql) {
  try {
    await db.exec(sql);
    return { ok: true };
  } catch (error) {
    await db.exec('rollback').catch(() => {});
    return {
      ok: false,
      code: error !== null && typeof error === 'object' ? error.code : undefined,
      message: error instanceof Error ? error.message : String(error),
    };
  }
}

test('installer fails closed and a matching reentry is idempotent', async () => {
  const sql = installerSql();
  assert.equal(/create\s+(schema|table)\s+if\s+not\s+exists/i.test(sql), false);
  assert.equal(/create\s+(or\s+replace\s+)?function\s+if\s+not\s+exists/i.test(sql), false);
  assert.equal(/create\s+view/i.test(sql), false);
  assert.equal(sql.includes('memory:write'), false);
  assert.equal(
    /create\s+(or\s+replace\s+)?function[\s\S]{0,120}custom_access_token_hook/i.test(sql),
    false,
  );
  const db = await openLabDatabase();
  const version = await db.query(`
    select obj_description('policy_lab'::regnamespace, 'pg_namespace') as version
  `);
  assert.equal(version.rows[0].version, 'ari-memory-read-lab-v1');
  const definition = await db.query(`
    select pg_get_functiondef('policy_lab.verified_client_id()'::regprocedure) as body
  `);
  assert.equal(definition.rows[0].body.includes('user_metadata'), false);
  assert.match(definition.rows[0].body, /app_metadata/);
  const again = await apply(db, sql);
  assert.equal(again.ok, true, again.message);
  await db.close();

  const collision = await openBare();
  await collision.exec('create schema policy_lab');
  const refused = await apply(collision, sql);
  assert.equal(refused.ok, false, refused.message);
  assert.match(refused.message, /collision|owned version|partial/);
  await collision.close();

  const extra = await openLabDatabase();
  await extra.exec('create table policy_lab.extra (id int)');
  const drifted = await apply(extra, sql);
  assert.equal(drifted.ok, false, drifted.message);
  assert.match(drifted.message, /allowlist|version|collision/);
  const stillThere = await extra.query(`select to_regclass('policy_lab.memories') as name`);
  assert.equal(stillThere.rows[0].name, 'policy_lab.memories');
  await extra.close();
});

test('reentry stops on weakened policy, user_metadata helper, and extra column', async () => {
  const sql = installerSql();
  const policy = await openLabDatabase();
  await policy.exec('alter policy memory_read_intersection on policy_lab.memories using (true)');
  await policy.exec(`
    insert into policy_lab.principals (principal_id, principal_kind, identity_eligibility)
    values ('1928e465-6ab9-439c-9ab8-d7d0c8bba16d', 'human', 'verified');
    insert into policy_lab.memories (memory_id, workspace_id, title, content)
    values ('mem_foreign_repro_row_00000001', 'ws-foreign', 'foreign', 'visible');
  `);
  const leaked = await policy.transaction(async (tx) => {
    await tx.exec('set local role authenticated');
    await tx.query(`select set_config('request.jwt.claims', $1, true)`, [
      JSON.stringify({
        sub: '6f0c2a44-91d4-4e7b-a13c-5d8e7b0a9c22',
        role: 'authenticated',
        aud: 'authenticated',
      }),
    ]);
    return tx.query(`select memory_id from policy_lab.memories`);
  });
  assert.equal(leaked.rows.length, 1);
  const refused = await apply(policy, sql);
  assert.equal(refused.ok, false, refused.message);
  assert.match(refused.message, /STOP owned manifest drift: policy/);
  const stillWeak = await policy.query(`
    select pg_get_expr(policy.polqual, policy.polrelid) as expr
    from pg_policy as policy
    join pg_class as relation on relation.oid = policy.polrelid
    where policy.polname = 'memory_read_intersection'
  `);
  assert.equal(stillWeak.rows[0].expr, 'true');
  await policy.close();

  const helper = await openLabDatabase();
  await helper.exec(`
    create or replace function policy_lab.verified_client_id()
    returns text language sql stable security invoker set search_path = pg_catalog
    as $fn$
      select nullif(auth.jwt() #>> '{user_metadata,client_id}', '');
    $fn$
  `);
  const helperRefused = await apply(helper, sql);
  assert.equal(helperRefused.ok, false, helperRefused.message);
  assert.match(helperRefused.message, /STOP owned manifest drift: function/);
  const body = await helper.query(`
    select prosrc from pg_proc
    join pg_namespace on pg_namespace.oid = pg_proc.pronamespace
    where nspname = 'policy_lab' and proname = 'verified_client_id'
  `);
  assert.match(body.rows[0].prosrc, /user_metadata/);
  await helper.close();

  const column = await openLabDatabase();
  await column.exec('alter table policy_lab.memories add column extra text');
  const columnRefused = await apply(column, sql);
  assert.equal(columnRefused.ok, false, columnRefused.message);
  assert.match(columnRefused.message, /STOP owned manifest drift: column/);
  const extra = await column.query(`
    select column_name from information_schema.columns
    where table_schema = 'policy_lab' and table_name = 'memories' and column_name = 'extra'
  `);
  assert.equal(extra.rows.length, 1);
  await column.close();
});

test('rollback stops on an unknown internal policy and drops a clean lab', async () => {
  const rollback = rollbackSql();
  assert.equal(
    rollback.split('\n').some((line) => /^\s*drop\b/i.test(line) && /\bcascade\b/i.test(line)),
    false,
  );
  const internal = await openLabDatabase();
  await internal.exec(
    'create policy unrelated_extension on policy_lab.memories for select to authenticated using (true)',
  );
  const internalStopped = await apply(internal, rollback);
  assert.equal(internalStopped.ok, false, internalStopped.message);
  assert.match(internalStopped.message, /STOP owned manifest drift: policy/);
  const policyRemains = await internal.query(`
    select polname from pg_policy
    join pg_class on pg_class.oid = pg_policy.polrelid
    where relname = 'memories' and polname = 'unrelated_extension'
  `);
  assert.equal(policyRemains.rows.length, 1);
  const schemaRemains = await internal.query(`select to_regnamespace('policy_lab') as name`);
  assert.notEqual(schemaRemains.rows[0].name, null);
  await internal.close();

  const blocked = await openLabDatabase();
  await blocked.exec('create view public.lab_leak as select memory_id from policy_lab.memories');
  const stopped = await apply(blocked, rollback);
  assert.equal(stopped.ok, false, stopped.message);
  assert.match(stopped.message, /STOP/);
  const remains = await blocked.query(`select to_regnamespace('policy_lab') as name`);
  assert.notEqual(remains.rows[0].name, null);
  await blocked.close();

  const clean = await openLabDatabase();
  const removed = await apply(clean, rollback);
  assert.equal(removed.ok, true, removed.message);
  const gone = await clean.query(`
    select to_regnamespace('policy_lab') as policy_lab, to_regnamespace('memory') as memory
  `);
  assert.equal(gone.rows[0].policy_lab, null);
  assert.equal(gone.rows[0].memory, null);
  await clean.close();
});

test('local retained lab proves isolation, denials, and exact cleanup', async () => {
  const receipt = await runLocalLab();
  assert.equal(receipt.acceptance, false);
  assert.equal(receipt.hostedContact, false);
  assert.equal(receipt.hostedExecution, 'refused');
  assert.equal(receipt.listenerCount, 0);
  assert.equal(receipt.adminCredentialUsed, false);
  assert.equal(receipt.d1, 'not_executed');
  assert.equal(receipt.d2, 'not_executed');
  assert.equal(receipt.rowsPass, true, JSON.stringify(receipt.rows));
  assert.equal(receipt.cleanupStatus, 'confirmed');
  assert.equal(receipt.ownershipBefore > 0, true);
  assert.equal(receipt.ownershipAfter, 0);
  assert.equal(receipt.baselineRetained, true);
  assert.equal(receipt.positiveMemoryCount, 6);
  assert.equal(receipt.subjectProvenance.baselineUserId, BASELINE_USER_ID);
  assert.equal(receipt.subjectProvenance.secondUserId, SECOND_USER_ID);
  assert.equal(receipt.subjectProvenance.bClientId, LOCAL_B_CLIENT_ID);
  assert.deepEqual(receipt.subjectProvenance.sessionIds, []);
  assert.equal(receipt.issuanceStatus, 'not_required');
  const gap = receipt.rows.find((item) => item.id === 'same_user_different_b_client');
  assert.equal(gap.executed, false);
  assert.equal(gap.label, 'not_executed');
  const text = JSON.stringify(receipt);
  assert.equal(text.includes('eyJ'), false);
  assert.equal(text.includes('access_token'), false);
  assert.equal(text.includes('service_role'), false);
});

test('hosted synthetic controller reads through native token B and the real tools', async () => {
  const secondUserId = '6f0c2a44-91d4-4e7b-a13c-5d8e7b0a9c22';
  const receipt = await runHostedController({
    transport: 'synthetic',
    secondUserId,
    acquireLock: false,
  });
  assert.equal(receipt.acceptance, false);
  assert.equal(receipt.hostedContact, false);
  assert.equal(receipt.hostedExecution, 'synthetic_loopback');
  assert.equal(receipt.listenerCount, 1);
  assert.equal(receipt.listenerClosed, true);
  assert.equal(receipt.adminCredentialUsed, false);
  assert.equal(receipt.rowsPass, true, JSON.stringify(receipt.rows));
  assert.equal(receipt.cleanupStatus, 'confirmed');
  assert.equal(receipt.subjectProvenance.secondUserId, secondUserId);
  assert.notEqual(receipt.subjectProvenance.secondUserId, SECOND_USER_ID);
  assert.equal(receipt.subjectProvenance.baselineUserId, BASELINE_USER_ID);
  const grants = receipt.grantFacts;
  assert.equal(grants.length >= 2, true);
  assert.equal(new Set(grants.map((fact) => fact.sub)).size, 2);
  assert.equal(new Set(grants.map((fact) => fact.sessionId)).size >= 2, true);
  assert.equal(receipt.cleanup.memoryIds.length, 13);
  assert.equal(receipt.cleanup.memberships.length > 0, true);
  assert.equal(receipt.cleanup.grants.length > 0, true);
  assert.deepEqual(receipt.cleanup.transientClientIds.sort(), [
    'c1111111-1111-4111-8111-111111111111',
    'c2222222-2222-4222-8222-222222222222',
  ]);
  assert.equal(receipt.cleanup.deniedPrincipalId, 'd3333333-3333-4333-8333-333333333333');
  assert.equal(receipt.cleanup.schemasRemain, true);
  assert.equal(receipt.baselineRetained, true);
  assert.equal(receipt.ownershipAfter, 0);
  const positive = receipt.rows.find((item) => item.id === 'foreign_only_token_positive');
  assert.equal(positive.pass, true);
  const concurrent = receipt.rows.find((item) => item.id === 'bounded_concurrent_retry');
  assert.equal(concurrent.reason, 'cross_user');
  const text = JSON.stringify(receipt);
  assert.equal(text.includes('eyJ'), false);
  assert.equal(text.includes('access_token'), false);
  assert.equal(text.includes(PASSWORD_SENTINEL), false);
  assert.equal(text.includes('service_role'), false);

  const stalled = await runHostedController({
    transport: 'synthetic',
    secondUserId,
    acquireLock: false,
    stall: 'headers',
  });
  assert.equal(stalled.acceptance, false);
  assert.equal(stalled.rowsPass, false);
  assert.equal(stalled.reason, 'orchestration_timeout');
  assert.equal(stalled.cleanupStatus, 'confirmed');
  assert.equal(stalled.hostedContact, false);
});

test('runner refuses hosted contact, a held lock, and the memory lab shell', async () => {
  assert.throws(
    () => assertLocalOnly({ ARI_MEMORY_LAB_MODE: 'hosted' }),
    /hosted_execution_refused/,
  );
  assert.throws(
    () =>
      assertLocalOnly({
        ARI_MEMORY_LAB_MODE: 'local',
        ARI_TEST_SUPABASE_URL: `https://${HOSTED_PROJECT_REF}.supabase.co`,
      }),
    /hosted_execution_refused/,
  );
  const source = await readFile(new URL('./ari-memory-read-lab.mjs', import.meta.url), 'utf8');
  assert.equal(source.includes('run-m2-memory-lab'), false);
  await assert.rejects(
    () =>
      runHostedController({
        transport: 'retained-test',
        supabaseUrl: `https://${HOSTED_PROJECT_REF}.supabase.co`,
      }),
    /hosted_execution_refused/,
  );
  await assert.rejects(
    () =>
      runHostedController(
        { transport: 'synthetic' },
        { ARI_TEST_SUPABASE_URL: `https://${HOSTED_PROJECT_REF}.supabase.co` },
      ),
    /hosted_execution_refused/,
  );
  const release = acquireControllerLock();
  try {
    const child = spawn(process.execPath, ['scripts/ari-memory-read-lab.mjs', 'run'], {
      env: {
        PATH: process.env.PATH,
        HOME: process.env.HOME ?? '/tmp',
        ARI_MEMORY_LAB_MODE: 'local',
      },
    });
    let stdout = '';
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString('utf8');
    });
    const [code] = await once(child, 'exit');
    assert.equal(code, 2);
    assert.match(stdout, /controller_lock_held/);
  } finally {
    release();
  }
});

const PASSWORD_SENTINEL = 'synthetic-password-sentinel';

async function openBare() {
  const { PGlite } = await import('@electric-sql/pglite');
  const db = new PGlite();
  await db.waitReady;
  await db.exec(`
    create role anon nologin noinherit;
    create role authenticated nologin noinherit;
    create role mcp_ingress nologin noinherit nosuperuser nobypassrls;
    create schema auth;
    grant usage on schema auth to authenticated;
    create function auth.uid() returns uuid language sql stable as $fn$
      select null::uuid;
    $fn$;
    create function auth.jwt() returns jsonb language sql stable as $fn$
      select '{}'::jsonb;
    $fn$;
    select set_config('ari.project_ref', '${HOSTED_PROJECT_REF}', false);
  `);
  return db;
}
