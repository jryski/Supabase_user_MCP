import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { after, before, describe, test } from 'node:test';
import { PGlite } from '@electric-sql/pglite';

const USER = '11111111-1111-4111-8111-111111111111';
const OTHER = '44444444-4444-4444-8444-444444444444';
const SOURCE = '22222222-2222-4222-8222-222222222222';
const B_SESSION = '33333333-3333-4333-8333-333333333333';
const B_DEAD = '55555555-5555-4555-8555-555555555555';
const DEAD = '66666666-6666-4666-8666-666666666666';
const FUTURE = '77777777-7777-4777-8777-777777777777';
const CLIENT_A = 'registered-client-parameter';
const CLIENT_EXT = 'external-a-client-parameter';
const CLIENT_B = 'downstream-b-client-parameter';
// Distinct synthetic ids. auth.sessions.oauth_client_id is uuid upstream
// (supabase/auth 20250904133000). Claim and argument client ids stay text.
const NATIVE_A = 'a0a0a0a0-a0a0-40a0-80a0-a0a0a0a0a0a0';
const NATIVE_EXT = 'b0b0b0b0-b0b0-40b0-80b0-b0b0b0b0b0b0';
const NATIVE_B = 'c0c0c0c0-c0c0-40c0-80c0-c0c0c0c0c0c0';
const NATIVE_OTHER_AGENT = 'd0d0d0d0-d0d0-40d0-80d0-d0d0d0d0d0d0';
const NATIVE_WRONG = 'e0e0e0e0-e0e0-40e0-80e0-e0e0e0e0e0e0';
const NON_OAUTH = '88888888-8888-4888-8888-888888888888';
const WRONG_SESSION = '12121212-1212-4121-8121-121212121212';
const CROSS_A = '99999999-9999-4999-8999-999999999999';
const CROSS_B = 'abababab-abab-4aba-8aba-abababababab';
const RESOURCE = 'https://odbcejsuuqdzhabjmozi.supabase.co/mcp';
const EXTERNAL_RESOURCE = 'http://127.0.0.1:8788/mcp';
const AGENT = 'hook-only-agent-parameter';
const OTHER_AGENT = 'other-agent-parameter';
const MARKER = 'ari-probe-marker-odbcejsuuqdzhabjmozi';

const sql05 = new URL('./sql/05-source-session-liveness.sql', import.meta.url);
const sql06 = new URL('./sql/06-ingress-client-rls.sql', import.meta.url);
const sql07 = new URL('./sql/07-downstream-and-external-a.sql', import.meta.url);
const sql04 = new URL('./sql/04-hook-v2-for-ariadne.sql', import.meta.url);
const sql03 = new URL('./sql/03-mcp-ingress-role.sql', import.meta.url);

function claims(clientId, agentId, role = 'authenticated', sessionId = B_SESSION) {
  return JSON.stringify({
    role,
    client_id: clientId,
    agent_id: agentId,
    sub: USER,
    session_id: sessionId,
  });
}

describe('lane B SQL packet', { concurrency: false }, () => {
  test('sql/07 pins external A to the loopback resource', async () => {
    const sql = await readFile(sql07, 'utf8');
    assert.match(sql, /values \(v_external, 'http:\/\/127\.0\.0\.1:8788\/mcp', v_agent_id/);
    assert.match(sql, /mapping\.mcp_resource = 'http:\/\/127\.0\.0\.1:8788\/mcp'/);
    assert.match(sql, /external A resource must differ from baseline A/);
    assert.equal(sql.includes('values (v_external, v_mcp_resource'), false);
  });

  test('sql/03 and sql/04 stay free of the B mapping', async () => {
    const roleSql = await readFile(sql03, 'utf8');
    const hookSql = await readFile(sql04, 'utf8');
    assert.equal(roleSql.includes('downstream_client'), false);
    assert.equal(roleSql.includes('ari_probe_source_session_live_v1'), false);
    assert.equal(hookSql.includes('downstream_client'), false);
    assert.equal(hookSql.includes('ari-test-external-a'), false);
  });

  test('sql/05 is guarded, pair-exact, and does not grant auth', async () => {
    const sql = await readFile(sql05, 'utf8');
    assert.match(sql, /set search_path = ''/);
    assert.match(
      sql,
      /public\.ari_probe_source_session_live_v1\(\s*source_session_id uuid,\s*a_client_id text\s*\)/,
    );
    assert.match(sql, /auth\.uid\(\)/);
    assert.match(sql, /auth\.jwt\(\)/);
    assert.match(sql, /auth\.sessions/);
    assert.match(sql, /ari_probe\.downstream_client/);
    assert.match(sql, /ari_probe\.mcp_client/);
    assert.match(sql, /session\.oauth_client_id::text = a_client_id/);
    assert.doesNotMatch(sql, /session\.oauth_client_id = a_client_id/);
    assert.match(sql, /v_claims ->> 'session_id'/);
    assert.match(sql, /b_session\.user_id = v_uid/);
    assert.match(sql, /b_session\.oauth_client_id::text = v_client_id/);
    assert.doesNotMatch(sql, /b_session\.oauth_client_id = v_client_id/);
    assert.match(sql, /b_session\.not_after is null or b_session\.not_after > pg_catalog\.now\(\)/);
    assert.match(sql, /ingress\.agent_id = v_b_agent/);
    assert.match(
      sql,
      /revoke all on function public\.ari_probe_source_session_live_v1\(uuid, text\)\s*from public, anon, service_role, mcp_ingress/i,
    );
    assert.match(
      sql,
      /grant execute on function public\.ari_probe_source_session_live_v1\(uuid, text\)\s*to authenticated/i,
    );
    assert.match(sql, /has_function_privilege/);
    assert.match(sql, /Lives in public so PostgREST/);
    assert.match(sql, /STOP AND REPORT: function owner % cannot read auth\.sessions/);
    assert.doesNotMatch(sql, /grant\s+(select|usage|execute|all)\s+on\s+(schema\s+)?auth/i);
    assert.match(sql, /returns boolean/);
  });

  test('sql/06 parameterizes A clients and limits F1 to the marker', async () => {
    const sql = await readFile(sql06, 'utf8');
    assert.match(sql, /N21: F1 here covers public\.ari_probe_marker only/);
    assert.match(sql, /Production F1 is every\s+-- protected surface/);
    assert.match(sql, /as restrictive/);
    assert.match(sql, /format\(/);
    assert.match(sql, /%L/);
    assert.doesNotMatch(sql, /create policy[\s\S]*storage\.objects/);
    assert.equal(sql.includes(CLIENT_A), false);
  });
});

describe('sql/05 liveness in PGlite', { concurrency: false }, () => {
  /** @type {import('@electric-sql/pglite').PGlite} */
  let db;

  before(async () => {
    db = new PGlite();
    await db.waitReady;
    await db.exec(`
      create role anon nologin;
      create role authenticated nologin;
      create role service_role nologin;
      create role mcp_ingress nologin;
      create schema auth;
      create table auth.sessions (
        id uuid primary key,
        user_id uuid not null,
        oauth_client_id uuid,
        not_after timestamptz
      );
      create schema ari_probe;
      create table ari_probe.mcp_client (
        client_id text primary key,
        mcp_resource text not null,
        agent_id text not null,
        probe_label text not null
      );
      create table ari_probe.downstream_client (
        client_id text primary key,
        agent_id text not null,
        probe_label text not null
      );
      insert into ari_probe.mcp_client (client_id, mcp_resource, agent_id, probe_label) values
        ('${NATIVE_A}', '${RESOURCE}', '${AGENT}', 'ari-test-synthetic'),
        ('${NATIVE_EXT}', '${RESOURCE}', '${AGENT}', 'ari-test-external-a'),
        ('${NATIVE_OTHER_AGENT}', '${RESOURCE}', '${OTHER_AGENT}', 'ari-test-synthetic'),
        ('not-a-uuid', '${RESOURCE}', '${AGENT}', 'ari-test-synthetic');
      insert into ari_probe.downstream_client (client_id, agent_id, probe_label) values
        ('${NATIVE_B}', '${AGENT}', 'ari-test-downstream-b'),
        ('not-a-client', '${AGENT}', 'ari-test-downstream-b');
      insert into auth.sessions (id, user_id, oauth_client_id, not_after) values
        ('${SOURCE}', '${USER}', '${NATIVE_A}', null),
        ('${FUTURE}', '${USER}', '${NATIVE_EXT}', '2999-01-01T00:00:00Z'),
        ('${DEAD}', '${USER}', '${NATIVE_A}', '2000-01-01T00:00:00Z'),
        ('${B_SESSION}', '${USER}', '${NATIVE_B}', null),
        ('${B_DEAD}', '${USER}', '${NATIVE_B}', '2000-01-01T00:00:00Z'),
        ('${NON_OAUTH}', '${USER}', null, null),
        ('${WRONG_SESSION}', '${USER}', '${NATIVE_WRONG}', null),
        ('${CROSS_A}', '${OTHER}', '${NATIVE_A}', null),
        ('${CROSS_B}', '${OTHER}', '${NATIVE_B}', null);
      create function auth.uid() returns uuid language sql stable as $$
        select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid
      $$;
      create function auth.jwt() returns jsonb language sql stable as $$
        select nullif(current_setting('request.jwt.claims', true), '')::jsonb
      $$;
    `);
    await db.query(`select set_config('ari.project_ref', 'odbcejsuuqdzhabjmozi', false)`);
    await db.exec(await readFile(sql05, 'utf8'));
  });

  after(async () => {
    await db?.close();
  });

  async function live(sessionId, aClientId, jwt, sub = USER) {
    await db.query(`select set_config('request.jwt.claim.sub', $1, false)`, [sub ?? '']);
    await db.query(`select set_config('request.jwt.claims', $1, false)`, [jwt ?? '']);
    const result = await db.query(
      `select public.ari_probe_source_session_live_v1($1::uuid, $2::text) as live`,
      [sessionId, aClientId],
    );
    return result.rows[0]?.live;
  }

  test('synthetic oauth_client_id is the upstream uuid type', async () => {
    const result = await db.query(`
      select pg_catalog.format_type(attribute.atttypid, attribute.atttypmod) as typname
      from pg_catalog.pg_attribute as attribute
      join pg_catalog.pg_class as relation on relation.oid = attribute.attrelid
      join pg_catalog.pg_namespace as namespace on namespace.oid = relation.relnamespace
      where namespace.nspname = 'auth'
        and relation.relname = 'sessions'
        and attribute.attname = 'oauth_client_id'
        and not attribute.attisdropped
    `);
    assert.equal(result.rows[0]?.typname, 'uuid');
  });

  test('uncast uuid oauth_client_id equality with text is undefined', async () => {
    await assert.rejects(
      db.query(`select 1 from auth.sessions as session where session.oauth_client_id = $1::text`, [
        NATIVE_A,
      ]),
      (error) => {
        assert.equal(error.code, '42883');
        return true;
      },
    );
  });

  test('true only for the exact A session of the same agent', async () => {
    assert.equal(await live(SOURCE, NATIVE_A, claims(NATIVE_B, AGENT)), true);
    assert.equal(await live(FUTURE, NATIVE_EXT, claims(NATIVE_B, AGENT)), true);
  });

  test('null claims, wrong pair, dead session, and other agent fail closed', async () => {
    assert.equal(await live(null, NATIVE_A, claims(NATIVE_B, AGENT)), false);
    assert.equal(await live(SOURCE, null, claims(NATIVE_B, AGENT)), false);
    assert.equal(await live(SOURCE, NATIVE_A, null), false);
    assert.equal(await live(SOURCE, NATIVE_A, claims(NATIVE_B, AGENT), null), false);
    assert.equal(await live(SOURCE, NATIVE_A, claims(NATIVE_B, AGENT, 'mcp_ingress')), false);
    assert.equal(await live(SOURCE, NATIVE_A, claims(NATIVE_A, AGENT)), false);
    assert.equal(await live(SOURCE, NATIVE_B, claims(NATIVE_B, AGENT)), false);
    assert.equal(await live(SOURCE, NATIVE_EXT, claims(NATIVE_B, AGENT)), false);
    assert.equal(await live(DEAD, NATIVE_A, claims(NATIVE_B, AGENT)), false);
    assert.equal(
      await live(SOURCE, NATIVE_A, claims(NATIVE_B, AGENT, 'authenticated', B_DEAD)),
      false,
    );
    assert.equal(
      await live(
        SOURCE,
        NATIVE_A,
        claims(NATIVE_B, AGENT, 'authenticated', '00000000-0000-0000-0000-000000000000'),
      ),
      false,
    );
    assert.equal(
      await live(
        SOURCE,
        NATIVE_A,
        JSON.stringify({
          role: 'authenticated',
          client_id: NATIVE_B,
          agent_id: AGENT,
          sub: USER,
        }),
      ),
      false,
    );
    assert.equal(
      await live(SOURCE, NATIVE_A, claims(NATIVE_B, AGENT, 'authenticated', 'not-a-uuid')),
      false,
    );
    assert.equal(await live(SOURCE, NATIVE_OTHER_AGENT, claims(NATIVE_B, AGENT)), false);
    assert.equal(await live(SOURCE, NATIVE_A, claims(NATIVE_B, OTHER_AGENT)), false);
    assert.equal(await live(SOURCE, NATIVE_A, JSON.stringify({ role: 'authenticated' })), false);
    assert.equal(await live(NON_OAUTH, NATIVE_A, claims(NATIVE_B, AGENT)), false);
    assert.equal(
      await live(SOURCE, NATIVE_A, claims(NATIVE_B, AGENT, 'authenticated', NON_OAUTH)),
      false,
    );
    assert.equal(await live(WRONG_SESSION, NATIVE_A, claims(NATIVE_B, AGENT)), false);
    assert.equal(await live(CROSS_A, NATIVE_A, claims(NATIVE_B, AGENT)), false);
    assert.equal(
      await live(SOURCE, NATIVE_A, claims(NATIVE_B, AGENT, 'authenticated', CROSS_B), OTHER),
      false,
    );
    assert.equal(await live(SOURCE, 'not-a-uuid', claims(NATIVE_B, AGENT)), false);
    assert.equal(await live(SOURCE, NATIVE_A, claims('not-a-client', AGENT)), false);
    assert.equal(await live(SOURCE, '   ', claims(NATIVE_B, AGENT)), false);
  });

  test('B session present is true; deleting only B or only A is false', async () => {
    await db.exec('begin');
    try {
      assert.equal(await live(SOURCE, NATIVE_A, claims(NATIVE_B, AGENT)), true);
      await db.query(`delete from auth.sessions where id = $1`, [B_SESSION]);
      const aRemains = await db.query(
        `select count(*)::int as n from auth.sessions where id = $1`,
        [SOURCE],
      );
      assert.equal(aRemains.rows[0]?.n, 1);
      assert.equal(await live(SOURCE, NATIVE_A, claims(NATIVE_B, AGENT)), false);
      await db.query(
        `insert into auth.sessions (id, user_id, oauth_client_id, not_after) values ($1, $2, $3::uuid, null)`,
        [B_SESSION, USER, NATIVE_B],
      );
      await db.query(`delete from auth.sessions where id = $1`, [SOURCE]);
      const bRemains = await db.query(
        `select count(*)::int as n from auth.sessions where id = $1`,
        [B_SESSION],
      );
      assert.equal(bRemains.rows[0]?.n, 1);
      assert.equal(await live(SOURCE, NATIVE_A, claims(NATIVE_B, AGENT)), false);
    } finally {
      await db.exec('rollback');
    }
    assert.equal(await live(SOURCE, NATIVE_A, claims(NATIVE_B, AGENT)), true);
  });

  test('execute is authenticated only', async () => {
    const privileges = await db.query(`
      select
        has_function_privilege('public', 'public.ari_probe_source_session_live_v1(uuid, text)', 'execute') as public,
        has_function_privilege('anon', 'public.ari_probe_source_session_live_v1(uuid, text)', 'execute') as anon,
        has_function_privilege('service_role', 'public.ari_probe_source_session_live_v1(uuid, text)', 'execute') as service_role,
        has_function_privilege('mcp_ingress', 'public.ari_probe_source_session_live_v1(uuid, text)', 'execute') as mcp_ingress,
        has_function_privilege('authenticated', 'public.ari_probe_source_session_live_v1(uuid, text)', 'execute') as authenticated
    `);
    assert.deepEqual(privileges.rows[0], {
      public: false,
      anon: false,
      service_role: false,
      mcp_ingress: false,
      authenticated: true,
    });
  });
});

describe('sql/06 marker F1 in PGlite', { concurrency: false }, () => {
  /** @type {import('@electric-sql/pglite').PGlite} */
  let db;

  before(async () => {
    db = new PGlite();
    await db.waitReady;
    await db.exec(`
      create role anon nologin;
      create role authenticated nologin;
      grant authenticated to current_user;
      create schema auth;
      create table auth.users (id uuid primary key, email text unique);
      insert into auth.users (id, email) values
        ('${USER}', 'ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid');
      create function auth.uid() returns uuid language sql stable as $$
        select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid
      $$;
      create function auth.jwt() returns jsonb language sql stable as $$
        select nullif(current_setting('request.jwt.claims', true), '')::jsonb
      $$;
      create table public.ari_probe_marker (
        marker text primary key,
        owner_id uuid not null
      );
      alter table public.ari_probe_marker enable row level security;
      alter table public.ari_probe_marker force row level security;
      grant select on public.ari_probe_marker to authenticated;
      create policy ari_probe_marker_owner_read
        on public.ari_probe_marker
        for select
        to authenticated
        using ((select auth.uid()) = owner_id);
      insert into public.ari_probe_marker (marker, owner_id) values ('${MARKER}', '${USER}');
    `);
    await db.query(`select set_config('ari.project_ref', 'odbcejsuuqdzhabjmozi', false)`);
    await db.query(`select set_config('ari.oauth_client_id', $1, false)`, [CLIENT_A]);
    await db.query(`select set_config('ari.external_a_client_id', $1, false)`, [CLIENT_EXT]);
    await db.exec(await readFile(sql06, 'utf8'));
  });

  after(async () => {
    await db?.close();
  });

  async function visible(clientId, sub = USER) {
    await db.exec('reset role');
    await db.query(`select set_config('request.jwt.claim.sub', $1, false)`, [sub]);
    await db.query(`select set_config('request.jwt.claims', $1, false)`, [
      JSON.stringify({ role: 'authenticated', client_id: clientId, sub }),
    ]);
    await db.exec('set role authenticated');
    try {
      const result = await db.query(`select marker from public.ari_probe_marker`);
      return result.rows.map((row) => row.marker);
    } finally {
      await db.exec('reset role');
    }
  }

  test('B can read the owned marker and both A clients cannot', async () => {
    assert.deepEqual(await visible(CLIENT_B), [MARKER]);
    assert.deepEqual(await visible(CLIENT_A), []);
    assert.deepEqual(await visible(CLIENT_EXT), []);
    assert.deepEqual(await visible(CLIENT_B, OTHER), []);
  });
});

describe('sql/07 keeps baseline A and maps B', { concurrency: false }, () => {
  /** @type {import('@electric-sql/pglite').PGlite} */
  let db;

  before(async () => {
    db = new PGlite();
    await db.waitReady;
    await db.exec(`
      create role anon nologin;
      create role authenticated nologin;
      create role supabase_auth_admin nologin;
      create schema auth;
      create table auth.users (id uuid primary key, email text not null unique);
      create table auth.sessions (
        id uuid primary key,
        user_id uuid not null,
        not_after timestamptz
      );
      insert into auth.users (id, email) values
        ('${USER}', 'ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid'),
        ('${OTHER}', 'ari-probe-other@odbcejsuuqdzhabjmozi.invalid');
      insert into auth.sessions (id, user_id, not_after) values
        ('${SOURCE}', '${USER}', null),
        ('${DEAD}', '${USER}', '2000-01-01T00:00:00Z');
    `);
    await db.query(`select set_config('ari.project_ref', 'odbcejsuuqdzhabjmozi', false)`);
    await db.query(`select set_config('ari.oauth_client_id', $1, false)`, [CLIENT_A]);
    await db.query(`select set_config('ari.mcp_resource', $1, false)`, [RESOURCE]);
    await db.query(`select set_config('ari.agent_id', $1, false)`, [AGENT]);
    await db.exec(await readFile(sql04, 'utf8'));
    await db.query(`select set_config('ari.external_a_client_id', $1, false)`, [CLIENT_EXT]);
    await db.query(`select set_config('ari.downstream_client_id', $1, false)`, [CLIENT_B]);
    await db.exec(await readFile(sql07, 'utf8'));
  });

  after(async () => {
    await db?.close();
  });

  async function hook(event) {
    const result = await db.query(
      `select ari_probe.custom_access_token_hook($1::jsonb) as result`,
      [JSON.stringify(event)],
    );
    const value = result.rows[0]?.result;
    return typeof value === 'string' ? JSON.parse(value) : value;
  }

  function oauthEvent(clientId, extra = {}) {
    return {
      user_id: USER,
      authentication_method: 'oauth',
      claims: {
        sub: USER,
        client_id: clientId,
        role: 'authenticated',
        aud: 'authenticated',
        session_id: SOURCE,
        scope: 'email',
      },
      ...extra,
    };
  }

  test('baseline A and external A carry different resources', async () => {
    const rows = await db.query(
      `select client_id, probe_label, mcp_resource from ari_probe.mcp_client order by probe_label`,
    );
    assert.deepEqual(rows.rows, [
      {
        client_id: CLIENT_EXT,
        probe_label: 'ari-test-external-a',
        mcp_resource: EXTERNAL_RESOURCE,
      },
      {
        client_id: CLIENT_A,
        probe_label: 'ari-test-synthetic',
        mcp_resource: RESOURCE,
      },
    ]);
    assert.notEqual(rows.rows[0].mcp_resource, rows.rows[1].mcp_resource);
    const result = await hook(oauthEvent(CLIENT_A));
    assert.equal(result.claims.role, 'mcp_ingress');
    assert.equal(result.claims.aud, RESOURCE);
    assert.equal(result.claims.source_session_id, SOURCE);
    assert.equal(result.claims.agent_id, AGENT);
    assert.notEqual(result.claims.session_id, SOURCE);
    const external = await hook(oauthEvent(CLIENT_EXT));
    assert.equal(external.claims.role, 'mcp_ingress');
    assert.equal(external.claims.aud, EXTERNAL_RESOURCE);
    assert.equal(external.claims.agent_id, AGENT);
    assert.equal(external.claims.source_session_id, SOURCE);
    assert.notEqual(external.claims.session_id, SOURCE);
  });

  test('B keeps the real session and drops openid and unmapped clients', async () => {
    const result = await hook(oauthEvent(CLIENT_B));
    assert.equal(result.claims.role, 'authenticated');
    assert.equal(result.claims.aud, 'authenticated');
    assert.equal(result.claims.session_id, SOURCE);
    assert.equal(result.claims.agent_id, AGENT);
    assert.equal(result.claims.source_session_id, undefined);
    const absent = await hook({
      user_id: USER,
      authentication_method: 'password',
      claims: { sub: USER, role: 'authenticated', aud: 'authenticated', session_id: SOURCE },
    });
    assert.equal(absent.claims.role, 'authenticated');
    assert.equal(absent.claims.agent_id, undefined);
    const openid = await hook(
      oauthEvent(CLIENT_B, { claims: { ...oauthEvent(CLIENT_B).claims, scope: 'email openid' } }),
    );
    assert.deepEqual(openid.error, { http_code: 403, message: 'openid_scope_refused' });
    const unmapped = await hook(oauthEvent('some-other-client'));
    assert.deepEqual(unmapped.error, { http_code: 403, message: 'unmapped_client_id' });
    const dead = await hook({
      ...oauthEvent(CLIENT_B),
      claims: { ...oauthEvent(CLIENT_B).claims, session_id: DEAD },
    });
    assert.deepEqual(dead.error, { http_code: 401, message: 'source_session_not_live' });
  });
});
