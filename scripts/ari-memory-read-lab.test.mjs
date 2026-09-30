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

test('rollback stops on an unknown dependency and drops a clean lab', async () => {
  const rollback = rollbackSql();
  assert.equal(
    rollback.split('\n').some((line) => /^\s*drop\b/i.test(line) && /\bcascade\b/i.test(line)),
    false,
  );
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
