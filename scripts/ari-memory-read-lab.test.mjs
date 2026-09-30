import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  acquireControllerLock,
  assertLocalOnly,
  BASELINE_USER_ID,
  HOSTED_PROJECT_REF,
  hostedPreflight,
  installerSql,
  LOCAL_B_CLIENT_ID,
  openLabDatabase,
  rollbackSql,
  runLocalLab,
  SECOND_USER_ID,
} from './ari-memory-read-lab.mjs';
import { runHostedController } from './ari-memory-read-lab-hosted.mjs';
import { startRetainedTransportFixture } from './ari-memory-read-lab-retained-fixture.mjs';

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

test('reentry and rollback stop on quoted-key whitespace, volatility, and policy roles', async () => {
  const sql = installerSql();
  const quoted = await openLabDatabase();
  await quoted.exec(`
    create or replace function policy_lab.verified_client_id()
    returns text language sql stable security invoker set search_path = pg_catalog
    as $fn$
      select coalesce(
        nullif(auth.jwt() ->> 'client_ id', ''),
        nullif(auth.jwt() #>> '{app_metadata,client_id}', '')
      );
    $fn$
  `);
  const quotedRefused = await apply(quoted, sql);
  assert.equal(quotedRefused.ok, false, quotedRefused.message);
  assert.match(quotedRefused.message, /STOP owned manifest drift: function/);
  const quotedBody = await quoted.query(`
    select prosrc from pg_proc
    join pg_namespace on pg_namespace.oid = pg_proc.pronamespace
    where nspname = 'policy_lab' and proname = 'verified_client_id'
  `);
  assert.match(quotedBody.rows[0].prosrc, /client_ id/);
  await quoted.close();

  const volatility = await openLabDatabase();
  await volatility.exec('alter function policy_lab.verified_client_id() immutable');
  const volatilityRefused = await apply(volatility, sql);
  assert.equal(volatilityRefused.ok, false, volatilityRefused.message);
  assert.match(volatilityRefused.message, /STOP owned manifest drift: function/);
  const volatileFlag = await volatility.query(`
    select provolatile from pg_proc
    join pg_namespace on pg_namespace.oid = pg_proc.pronamespace
    where nspname = 'policy_lab' and proname = 'verified_client_id'
  `);
  assert.equal(volatileFlag.rows[0].provolatile, 'i');
  await volatility.close();

  const rollback = rollbackSql();
  const roles = await openLabDatabase();
  await roles.exec('alter policy memory_read_intersection on policy_lab.memories to public');
  const rolesStopped = await apply(roles, rollback);
  assert.equal(rolesStopped.ok, false, rolesStopped.message);
  assert.match(rolesStopped.message, /STOP owned manifest drift: policy/);
  const stillPublic = await roles.query(`
    select policy.polroles = array[0]::oid[] as is_public
    from pg_policy as policy
    join pg_class as relation on relation.oid = policy.polrelid
    where policy.polname = 'memory_read_intersection'
  `);
  assert.equal(stillPublic.rows[0].is_public, true);
  const schemaRemains = await roles.query(`select to_regnamespace('policy_lab') as name`);
  assert.notEqual(schemaRemains.rows[0].name, null);
  const memoryRemains = await roles.query(`select to_regclass('policy_lab.memories') as name`);
  assert.equal(memoryRemains.rows[0].name, 'policy_lab.memories');
  await roles.close();
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

function reservePort() {
  return new Promise((resolve) => {
    const server = createServer();
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
  });
}

function gitValue(args) {
  return execFileSync('git', args, { encoding: 'utf8' }).trim();
}

async function runCli(args, env) {
  const child = spawn(process.execPath, ['scripts/ari-memory-read-lab.mjs', ...args], {
    env: { PATH: process.env.PATH, HOME: process.env.HOME ?? '/tmp', ...env },
  });
  let stdout = '';
  child.stdout.on('data', (chunk) => {
    stdout += chunk.toString('utf8');
  });
  const [code] = await once(child, 'exit');
  return { code, stdout };
}

test('retained driver reaches auth and data reads and refuses a bad manifest', async () => {
  const hostedSource = await readFile(
    new URL('./ari-memory-read-lab-hosted.mjs', import.meta.url),
    'utf8',
  );
  const retained = hostedSource.slice(
    hostedSource.indexOf('async function driveRetained'),
    hostedSource.indexOf('async function driveSynthetic'),
  );
  for (const banned of [
    'startIssuer',
    'openLabDatabase',
    'clearSessions',
    'PGlite',
    'synthetic-password-sentinel',
    'LOCAL_B_CLIENT_ID',
  ]) {
    assert.equal(retained.includes(banned), false, banned);
  }
  const cli = await readFile(new URL('./ari-memory-read-lab.mjs', import.meta.url), 'utf8');
  const hostedBranch = cli.slice(
    cli.indexOf("if (command === 'hosted'"),
    cli.indexOf("if (command !== 'run')"),
  );
  assert.ok(hostedBranch.indexOf('hostedPreflight') < hostedBranch.indexOf('assertCleanWorktree'));
  assert.throws(() => hostedPreflight('hosted', {}, {}), /hosted_execution_refused/);
  assert.throws(
    () => hostedPreflight('hosted', {}, { ARI_MEMORY_LAB_EXECUTOR: 'ariadne' }),
    /manifest_required/,
  );
  assert.throws(
    () =>
      hostedPreflight(
        'hosted',
        { manifestPath: 'reviewed.json' },
        { ARI_MEMORY_LAB_EXECUTOR: 'ariadne' },
      ),
    /credentials_required/,
  );
  const refused = await runCli(['hosted']);
  assert.equal(refused.code, 2);
  assert.match(refused.stdout, /hosted_execution_refused/);
  const missing = await runCli(['hosted'], { ARI_MEMORY_LAB_EXECUTOR: 'ariadne' });
  assert.equal(missing.code, 2);
  assert.match(missing.stdout, /manifest_required/);

  const baseline = '1928e465-6ab9-439c-9ab8-d7d0c8bba16d';
  const second = '6f0c2a44-91d4-4e7b-a13c-5d8e7b0a9c22';
  const bClientId = 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d';
  const password = 'retained-fixture-password';
  const publishable = 'sb_publishable_retained_fixture_not_a_secret';
  const fixture = await startRetainedTransportFixture({
    aClientId: 'external-a-client',
    bClientId,
    agentId: 'hook-only-agent',
    users: [
      { sub: baseline, email: 'baseline@loopback.invalid', password },
      { sub: second, email: 'second@loopback.invalid', password },
    ],
    memories: [
      {
        id: 'mem_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        ownerId: baseline,
        title: 'baseline-new',
        content: 'retained-baseline-new',
        createdAt: '2026-09-30T00:00:03+00:00',
      },
      {
        id: 'mem_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab',
        ownerId: baseline,
        title: 'baseline-old',
        content: 'retained-baseline-old',
        createdAt: '2026-09-30T00:00:01+00:00',
      },
      {
        id: 'mem_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        ownerId: second,
        title: 'second-row',
        content: 'retained-second-row',
        createdAt: '2026-09-30T00:00:02+00:00',
      },
    ],
  });
  const dir = mkdtempSync(join(tmpdir(), 'ari-memory-retained-manifest-'));
  const manifestPath = join(dir, 'manifest.json');
  const credentialsPath = join(dir, 'credentials.json');
  const mcpPort = await reservePort();
  const reviewedHead = gitValue(['rev-parse', 'HEAD']);
  const reviewedTree = gitValue(['rev-parse', 'HEAD^{tree}']);
  const manifest = {
    version: 'ari-memory-read-lab-v1',
    projectRef: HOSTED_PROJECT_REF,
    supabaseUrl: fixture.origin,
    reviewedHead,
    reviewedTree,
    resource: `http://127.0.0.1:${mcpPort}/mcp`,
    aClientId: 'external-a-client',
    bClientId,
    agentId: 'hook-only-agent',
    aRedirectUri: `http://127.0.0.1:${mcpPort}/oauth/callback`,
    bRedirectUri: `http://127.0.0.1:${mcpPort}/oauth/downstream/callback`,
    users: [
      { role: 'baseline', id: baseline, email: 'baseline@loopback.invalid' },
      { role: 'second', id: second, email: 'second@loopback.invalid' },
    ],
    fixtures: {
      runId: '11111111-1111-4111-8111-111111111111',
      deniedPrincipalId: 'd3333333-3333-4333-8333-333333333333',
      transientClients: [
        { id: 'c1111111-1111-4111-8111-111111111111', state: 'revoked' },
        { id: 'c2222222-2222-4222-8222-222222222222', state: 'expired' },
      ],
      rows: [
        {
          memoryId: 'mem_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          workspaceId: 'ws-retained-baseline',
          ownerId: baseline,
          title: 'baseline-new',
          content: 'retained-baseline-new',
          createdAt: '2026-09-30T00:00:03+00:00',
        },
        {
          memoryId: 'mem_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab',
          workspaceId: 'ws-retained-baseline',
          ownerId: baseline,
          title: 'baseline-old',
          content: 'retained-baseline-old',
          createdAt: '2026-09-30T00:00:01+00:00',
        },
        {
          memoryId: 'mem_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
          workspaceId: 'ws-retained-second',
          ownerId: second,
          title: 'second-row',
          content: 'retained-second-row',
          createdAt: '2026-09-30T00:00:02+00:00',
        },
      ],
    },
  };
  writeFileSync(manifestPath, JSON.stringify(manifest));
  writeFileSync(
    credentialsPath,
    JSON.stringify({
      publishableKey: publishable,
      jwks: fixture.jwks,
      users: [
        { id: baseline, password },
        { id: second, password },
      ],
    }),
  );
  try {
    const receipt = await runHostedController(
      {
        transport: 'retained-test',
        manifestPath,
        credentialsPath,
        fetchImpl: fixture.fetchImpl,
        acquireLock: false,
      },
      { ARI_MEMORY_LAB_EXECUTOR: 'ariadne' },
    );
    assert.equal(receipt.acceptance, false);
    assert.equal(receipt.hostedContact, false);
    assert.equal(receipt.hostedExecution, 'retained_fixture');
    assert.equal(receipt.rowsPass, true, JSON.stringify(receipt.rows));
    assert.equal(receipt.reason, 'retained_transport_proved');
    assert.equal(receipt.credentialsLoaded, true);
    assert.equal(receipt.listenerCount, 1);
    assert.equal(receipt.listenerClosed, true);
    assert.equal(receipt.d1, 'not_executed');
    assert.equal(receipt.d2, 'not_executed');
    assert.equal(receipt.adminCredentialUsed, false);
    assert.equal(receipt.cleanupStatus, 'statements_only');
    assert.equal(receipt.sameUserDifferentBClient, 'not_executed');
    const gap = receipt.rows.find((item) => item.id === 'same_user_different_b_client');
    assert.equal(gap.executed, false);
    assert.equal(gap.label, 'not_executed');
    assert.equal(receipt.grantFacts.length, 2);
    assert.equal(new Set(receipt.grantFacts.map((fact) => fact.sub)).size, 2);
    assert.equal(receipt.sessionLedger.length >= 4, true);
    for (const phase of [
      'password_grant',
      'oauth_token_a',
      'mcp_initialize',
      'handler_bind',
      'mcp_memory_get',
      'mcp_memory_list_recent',
      'mcp_memory_search',
    ]) {
      assert.equal(receipt.phases.includes(phase), true, phase);
    }
    const hit = (prefix) => fixture.hits.some((item) => item.startsWith(prefix));
    for (const prefix of [
      'POST /auth/v1/token?grant_type=password',
      'GET /auth/v1/oauth/authorize',
      'POST /auth/v1/oauth/token',
      'GET /auth/v1/user',
      'POST /rest/v1/rpc/ari_probe_source_session_live_v1',
      'POST /rest/v1/rpc/authorized_memory_get_v1',
      'POST /rest/v1/rpc/authorized_memory_list_recent_v1',
      'POST /rest/v1/rpc/authorized_memory_search_v1',
    ]) {
      assert.equal(hit(prefix), true, prefix);
    }
    assert.equal(
      fixture.hits.some((item) => item.includes('/consent')),
      true,
    );
    assert.equal(receipt.seedStatements[0].startsWith('insert into policy_lab.principals'), true);
    assert.equal(receipt.seedStatements[1].startsWith('insert into policy_lab.clients'), true);
    assert.equal(receipt.seedStatements[2].startsWith('insert into policy_lab.memberships'), true);
    assert.equal(
      receipt.seedStatements[3].startsWith('insert into policy_lab.capability_grants'),
      true,
    );
    assert.equal(receipt.seedStatements[4].startsWith('insert into policy_lab.memories'), true);
    assert.equal(receipt.cleanupStatements[0].startsWith('delete from policy_lab.memories'), true);
    assert.equal(
      receipt.cleanupStatements[4].startsWith('delete from policy_lab.principals'),
      true,
    );
    const cleanup = receipt.cleanupStatements.join('\n');
    assert.equal(cleanup.includes(baseline), false);
    assert.equal(cleanup.includes(second), false);
    assert.equal(cleanup.includes(bClientId), false);
    assert.equal(cleanup.includes('mem_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'), true);
    assert.equal(cleanup.includes('d3333333-3333-4333-8333-333333333333'), true);
    assert.equal(receipt.seedStatements.join('\n').includes(bClientId), true);
    const text = JSON.stringify(receipt);
    assert.equal(text.includes(password), false);
    assert.equal(text.includes(publishable), false);
    assert.equal(text.includes('eyJ'), false);
    assert.equal(text.includes('access_token'), false);
    assert.equal(text.includes('service_role'), false);

    const calls = [];
    const blockedFetch = async () => {
      calls.push('called');
      throw new Error('fixture_fetch_forbidden');
    };
    for (const supabaseUrl of [
      'https://evil.supabase.co',
      `https://${HOSTED_PROJECT_REF}.supabase.co`,
    ]) {
      writeFileSync(manifestPath, JSON.stringify({ ...manifest, supabaseUrl }));
      await assert.rejects(
        () =>
          runHostedController(
            {
              transport: 'retained-test',
              manifestPath,
              credentialsPath,
              fetchImpl: blockedFetch,
              acquireLock: false,
            },
            { ARI_MEMORY_LAB_EXECUTOR: 'ariadne' },
          ),
        /wrong_target/,
      );
    }
    writeFileSync(manifestPath, JSON.stringify({ version: 'ari-memory-read-lab-v1' }));
    await assert.rejects(
      () =>
        runHostedController(
          {
            transport: 'retained-test',
            manifestPath,
            credentialsPath,
            fetchImpl: blockedFetch,
            acquireLock: false,
          },
          { ARI_MEMORY_LAB_EXECUTOR: 'ariadne' },
        ),
      /manifest_incomplete/,
    );
    writeFileSync(manifestPath, JSON.stringify({ ...manifest, reviewedHead: '0'.repeat(40) }));
    await assert.rejects(
      () =>
        runHostedController(
          {
            transport: 'retained-test',
            manifestPath,
            credentialsPath,
            fetchImpl: blockedFetch,
            acquireLock: false,
          },
          { ARI_MEMORY_LAB_EXECUTOR: 'ariadne' },
        ),
      /manifest_head_mismatch/,
    );
    assert.equal(calls.length, 0);
  } finally {
    await fixture.close();
    rmSync(dir, { recursive: true, force: true });
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
