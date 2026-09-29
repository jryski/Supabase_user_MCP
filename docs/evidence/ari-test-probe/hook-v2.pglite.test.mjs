import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { after, before, describe, test } from 'node:test';
import { PGlite } from '@electric-sql/pglite';
import { decideHookV2, isNonNilUuid } from './hook-v2.mjs';

const USER = '11111111-1111-4111-8111-111111111111';
const OTHER_USER = '44444444-4444-4444-8444-444444444444';
const SOURCE = '22222222-2222-4222-8222-222222222222';
const OTHER_SESSION = '55555555-5555-4555-8555-555555555555';
const DEAD = '66666666-6666-4666-8666-666666666666';
const FRESH = '33333333-3333-4333-8333-333333333333';
const CLIENT_A = 'registered-client-parameter';
const RESOURCE = 'https://odbcejsuuqdzhabjmozi.supabase.co/mcp';
const AGENT = 'hook-only-agent-parameter';
const NOW = Date.parse('2026-09-29T00:00:00Z');

const SQL_TEXT = {
  openid_scope_refused: 'openid scope is refused for every oauth client',
  unmapped_client_id: 'unmapped oauth client_id',
  source_session_not_live: 'source session is not live',
  fresh_session_id_rejected: 'fresh session_id is nil or already in auth.sessions',
  hook_event_unreadable: 'hook event is unreadable',
};

function mappedEvent(claims = {}, event = {}) {
  return {
    user_id: USER,
    authentication_method: 'oauth',
    ...event,
    claims: {
      sub: USER,
      client_id: CLIENT_A,
      role: 'authenticated',
      aud: 'authenticated',
      session_id: SOURCE,
      scope: 'email',
      ...claims,
    },
  };
}

function oracleInput(event, extra = {}) {
  return {
    clients: [{ clientId: CLIENT_A, mcpResource: RESOURCE, agentId: AGENT }],
    sessions: [{ id: SOURCE, userId: USER, notAfter: null }],
    randomUuid: () => FRESH,
    now: NOW,
    event,
    ...extra,
  };
}

describe('sql/04 verbatim in PGlite', { concurrency: false }, () => {
  /** @type {import('@electric-sql/pglite').PGlite} */
  let db;
  /** @type {string} */
  let sql;

  before(async () => {
    sql = await readFile(new URL('./sql/04-hook-v2-for-ariadne.sql', import.meta.url), 'utf8');
    db = new PGlite();
    await db.waitReady;
    await db.exec(`
      create role anon nologin;
      create role authenticated nologin;
      create role supabase_auth_admin nologin;
      create schema auth;
      create table auth.users (
        id uuid primary key,
        email text not null unique
      );
      create table auth.sessions (
        id uuid primary key,
        user_id uuid not null,
        not_after timestamptz
      );
      insert into auth.users (id, email) values
        ('${USER}', 'ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid'),
        ('${OTHER_USER}', 'ari-probe-other@odbcejsuuqdzhabjmozi.invalid');
    `);
    await db.query(`select set_config('ari.project_ref', 'odbcejsuuqdzhabjmozi', false)`);
    await db.query(`select set_config('ari.oauth_client_id', $1, false)`, [CLIENT_A]);
    await db.query(`select set_config('ari.mcp_resource', $1, false)`, [RESOURCE]);
    await db.query(`select set_config('ari.agent_id', $1, false)`, [AGENT]);
    await db.exec(sql);
    await db.query(
      `insert into auth.sessions (id, user_id, not_after) values
        ($1::uuid, $2::uuid, null),
        ($3::uuid, $4::uuid, null),
        ($5::uuid, $2::uuid, '2000-01-01T00:00:00Z')`,
      [SOURCE, USER, OTHER_SESSION, OTHER_USER, DEAD],
    );
  });

  after(async () => {
    await db?.close();
  });

  async function callHook(event) {
    try {
      const result = await db.query(
        `select ari_probe.custom_access_token_hook($1::jsonb) as result`,
        [JSON.stringify(event)],
      );
      const value = result.rows[0]?.result;
      const parsed = typeof value === 'string' ? JSON.parse(value) : value;
      return { ok: true, claims: parsed.claims };
    } catch (error) {
      await db.exec('rollback').catch(() => {});
      return { ok: false, message: error instanceof Error ? error.message : String(error) };
    }
  }

  function assertAgrees(sqlResult, jsResult) {
    assert.equal(jsResult.revocationClaimed, false);
    if (jsResult.action === 'raise') {
      assert.equal(sqlResult.ok, false);
      assert.match(sqlResult.message, new RegExp(SQL_TEXT[jsResult.reason]));
      return;
    }
    assert.equal(sqlResult.ok, true);
    if (jsResult.action === 'unchanged') {
      assert.deepEqual(sqlResult.claims, jsResult.claims);
      return;
    }
    assert.equal(jsResult.action, 'map');
    const { session_id: sqlSession, ...sqlRest } = sqlResult.claims;
    const { session_id: jsSession, ...jsRest } = jsResult.claims;
    assert.deepEqual(sqlRest, jsRest);
    assert.equal(isNonNilUuid(sqlSession), true);
    assert.equal(isNonNilUuid(jsSession), true);
    assert.notEqual(sqlSession, sqlResult.claims.source_session_id);
  }

  test('setup commits and creates the hook', async () => {
    assert.match(sql, /^begin;/m);
    assert.match(sql, /^commit;/m);
    const hook = await db.query(`
      select p.proname
      from pg_proc as p
      join pg_namespace as n on n.oid = p.pronamespace
      where n.nspname = 'ari_probe' and p.proname = 'custom_access_token_hook'
    `);
    assert.equal(hook.rows.length, 1);
    const mapped = await db.query(`select count(*)::int as n from ari_probe.mcp_client`);
    assert.equal(Number(mapped.rows[0].n), 1);
  });

  test('mapped client A agrees with the oracle except the fresh session id', async () => {
    const event = mappedEvent();
    const sqlResult = await callHook(event);
    const jsResult = decideHookV2(oracleInput(event));
    assertAgrees(sqlResult, jsResult);
    assert.equal(sqlResult.claims.aud, RESOURCE);
    assert.equal(sqlResult.claims.role, 'mcp_ingress');
    assert.equal(sqlResult.claims.source_session_id, SOURCE);
    assert.equal(sqlResult.claims.agent_id, AGENT);
    const found = await db.query(
      `select count(*)::int as n from auth.sessions where id = $1::uuid`,
      [sqlResult.claims.session_id],
    );
    assert.equal(Number(found.rows[0].n), 0);
    assert.equal(event.claims.role, 'authenticated');
    assert.equal(event.claims.session_id, SOURCE);
  });

  test('absent client_id is unchanged on the SQL path and the oracle', async () => {
    const claims = { sub: USER, role: 'authenticated', aud: 'authenticated', session_id: SOURCE };
    const event = { user_id: USER, authentication_method: 'password', claims };
    const sqlResult = await callHook(event);
    assertAgrees(sqlResult, decideHookV2(oracleInput(event)));
    assert.equal(sqlResult.claims.client_id, undefined);
    assert.equal(sqlResult.claims.role, 'authenticated');
  });

  test('unmapped, dead, other-user, and nil sessions raise on both paths', async () => {
    const cases = [
      {
        event: mappedEvent({ client_id: 'registered-but-unmapped' }),
        extra: {},
      },
      {
        event: mappedEvent({ session_id: DEAD }),
        extra: {
          sessions: [{ id: DEAD, userId: USER, notAfter: '2000-01-01T00:00:00Z' }],
        },
      },
      {
        event: mappedEvent({ session_id: OTHER_SESSION }),
        extra: {
          sessions: [{ id: OTHER_SESSION, userId: OTHER_USER, notAfter: null }],
        },
      },
      {
        event: mappedEvent({ session_id: '00000000-0000-0000-0000-000000000000' }),
        extra: { sessions: [] },
      },
    ];
    for (const item of cases) {
      const sqlResult = await callHook(item.event);
      const jsResult = decideHookV2(oracleInput(item.event, item.extra));
      assertAgrees(sqlResult, jsResult);
      assert.equal(jsResult.action, 'raise');
    }
  });

  test('openid string and array raise on both paths', async () => {
    const stringEvent = mappedEvent({ scope: 'email openid' });
    const arrayEvent = {
      user_id: USER,
      scope: ['OpenID'],
      claims: { client_id: 'some-other-registered-client', session_id: SOURCE },
    };
    for (const event of [stringEvent, arrayEvent]) {
      const sqlResult = await callHook(event);
      const jsResult = decideHookV2(oracleInput(event));
      assertAgrees(sqlResult, jsResult);
      assert.equal(jsResult.reason, 'openid_scope_refused');
    }
  });
});
