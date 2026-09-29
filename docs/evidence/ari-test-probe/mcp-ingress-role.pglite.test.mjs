import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { PGlite } from '@electric-sql/pglite';

const EMAIL = 'ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid';
const USER = '11111111-1111-4111-8111-111111111111';
const ALLOWED = 'odbcejsuuqdzhabjmozi';
const FORBIDDEN = 'lygftpbjgqgvuunkwnxf';

const OLD_SUPERUSER_ALTER = `
begin;
create role mcp_ingress
  nologin
  noinherit
  nosuperuser
  nocreatedb
  nocreaterole
  noreplication;
alter role mcp_ingress
  nologin
  noinherit
  nosuperuser
  nocreatedb
  nocreaterole
  noreplication;
commit;
`;

async function freshDb() {
  const db = new PGlite();
  await db.waitReady;
  await db.exec(`
    create role anon nologin noinherit;
    create role authenticated nologin noinherit;
    create role service_role nologin noinherit;
    create role authenticator nologin noinherit;
    create schema auth;
    create table auth.users (
      id uuid primary key,
      email text not null unique
    );
    insert into auth.users (id, email)
    values ('${USER}', '${EMAIL}');
    create role applier
      nologin
      nosuperuser
      createrole
      nocreatedb
      noreplication
      nobypassrls;
    grant anon, authenticated, service_role, authenticator
      to applier
      with admin option;
    grant usage on schema auth to applier;
    grant select on table auth.users to applier;
  `);
  return db;
}

async function applySql(db, sql, { asApplier = false } = {}) {
  try {
    if (asApplier) await db.exec('set role applier');
    await db.exec(sql);
    if (asApplier) await db.exec('reset role');
    return { ok: true };
  } catch (error) {
    await db.exec('rollback').catch(() => {});
    if (asApplier) await db.exec('reset role').catch(() => {});
    return {
      ok: false,
      code: error !== null && typeof error === 'object' ? error.code : undefined,
      message: error instanceof Error ? error.message : String(error),
    };
  }
}

async function roleRow(db) {
  const result = await db.query(`
    select
      rolcanlogin,
      rolinherit,
      rolsuper,
      rolcreaterole,
      rolcreatedb,
      rolreplication,
      rolbypassrls
    from pg_roles
    where rolname = 'mcp_ingress'
  `);
  return result.rows[0] ?? null;
}

function assertIsolated(row) {
  assert.ok(row);
  assert.equal(row.rolcanlogin, false);
  assert.equal(row.rolinherit, false);
  assert.equal(row.rolsuper, false);
  assert.equal(row.rolcreaterole, false);
  assert.equal(row.rolcreatedb, false);
  assert.equal(row.rolreplication, false);
  assert.equal(row.rolbypassrls, false);
}

test('old ALTER ROLE NOSUPERUSER is denied to a non-superuser CREATEROLE session', async () => {
  const db = await freshDb();
  try {
    const result = await applySql(db, OLD_SUPERUSER_ALTER, { asApplier: true });
    assert.equal(result.ok, false);
    assert.equal(result.code, '42501');
    assert.match(result.message, /permission denied to alter role/);
    assert.equal(await roleRow(db), null);
  } finally {
    await db.close();
  }
});

test('sql/03 creates mcp_ingress as a non-superuser CREATEROLE session', async () => {
  const sql = await readFile(new URL('./sql/03-mcp-ingress-role.sql', import.meta.url), 'utf8');
  assert.equal(/\balter\s+role\s+mcp_ingress\b[^;]*\bnosuperuser\b/iu.test(sql), false);
  assert.equal(/\balter\s+role\s+mcp_ingress\b[^;]*\bnobypassrls\b/iu.test(sql), false);
  assert.equal(/\balter\s+role\s+mcp_ingress\b[^;]*\bnocreatedb\b/iu.test(sql), false);
  assert.equal(/\balter\s+role\s+mcp_ingress\b[^;]*\bnoreplication\b/iu.test(sql), false);
  assert.match(sql, /create role mcp_ingress/);
  assert.match(sql, /nobypassrls/);
  assert.match(sql, /refusing to alter superuser attributes/);

  const db = await freshDb();
  try {
    const createSql = sql.match(/create role mcp_ingress[\s\S]*?nobypassrls\s*;/iu);
    assert.ok(createSql);
    const createdAsApplier = await applySql(db, createSql[0], { asApplier: true });
    assert.equal(createdAsApplier.ok, true, createdAsApplier.message);
    assertIsolated(await roleRow(db));
    const alterDenied = await applySql(db, 'alter role mcp_ingress nosuperuser', {
      asApplier: true,
    });
    assert.equal(alterDenied.ok, false);
    assert.equal(alterDenied.code, '42501');
    assertIsolated(await roleRow(db));
    await db.exec('drop role mcp_ingress');

    await db.query(`select set_config('ari.project_ref', $1, false)`, [ALLOWED]);
    // SET ROLE keeps the bootstrap user as the grantor of the creator admin
    // membership, so this session cannot revoke it. The batch must still not
    // fail with the SUPERUSER-attribute denial.
    const underApplier = await applySql(db, sql, { asApplier: true });
    assert.notEqual(underApplier.code, '42501');
    assert.doesNotMatch(underApplier.message ?? '', /permission denied to alter role/);

    const created = await applySql(db, sql);
    assert.equal(created.ok, true, created.message);
    assertIsolated(await roleRow(db));

    const members = await db.query(`
      select member_role.rolname, membership.admin_option
      from pg_auth_members as membership
      join pg_roles as granted_role on granted_role.oid = membership.roleid
      join pg_roles as member_role on member_role.oid = membership.member
      where granted_role.rolname = 'mcp_ingress'
    `);
    assert.deepEqual(members.rows, [{ rolname: 'authenticator', admin_option: false }]);
    const inherited = await db.query(`
      select
        pg_has_role('mcp_ingress', 'authenticated', 'member') as authenticated,
        pg_has_role('mcp_ingress', 'anon', 'member') as anon,
        pg_has_role('mcp_ingress', 'service_role', 'member') as service_role
    `);
    assert.deepEqual(inherited.rows[0], {
      authenticated: false,
      anon: false,
      service_role: false,
    });
    const grants = await db.query(`
      select count(*)::int as grants
      from information_schema.role_table_grants
      where grantee = 'mcp_ingress'
    `);
    assert.equal(grants.rows[0].grants, 0);

    const again = await applySql(db, sql);
    assert.equal(again.ok, true, again.message);
    assertIsolated(await roleRow(db));
  } finally {
    await db.close();
  }
});

test('sql/03 clears LOGIN without altering SUPERUSER attributes', async () => {
  const sql = await readFile(new URL('./sql/03-mcp-ingress-role.sql', import.meta.url), 'utf8');
  const db = await freshDb();
  try {
    await db.exec(`
      set role applier;
      create role mcp_ingress
        login
        inherit
        nosuperuser
        nocreatedb
        nocreaterole
        noreplication
        nobypassrls;
      reset role;
    `);
    await db.query(`select set_config('ari.project_ref', $1, false)`, [ALLOWED]);
    const result = await applySql(db, sql);
    assert.equal(result.ok, true, result.message);
    assertIsolated(await roleRow(db));
  } finally {
    await db.close();
  }
});

test('sql/03 fails closed when mcp_ingress already has SUPERUSER or BYPASSRLS', async () => {
  const sql = await readFile(new URL('./sql/03-mcp-ingress-role.sql', import.meta.url), 'utf8');
  const superDb = await freshDb();
  try {
    await superDb.exec('create role mcp_ingress nologin superuser nobypassrls');
    await superDb.query(`select set_config('ari.project_ref', $1, false)`, [ALLOWED]);
    const superResult = await applySql(superDb, sql, { asApplier: true });
    assert.equal(superResult.ok, false);
    assert.match(superResult.message, /refusing to alter superuser attributes/);
    assert.equal((await roleRow(superDb)).rolsuper, true);
  } finally {
    await superDb.close();
  }

  const bypassDb = await freshDb();
  try {
    await bypassDb.exec('create role mcp_ingress nologin nosuperuser bypassrls');
    await bypassDb.query(`select set_config('ari.project_ref', $1, false)`, [ALLOWED]);
    const bypassResult = await applySql(bypassDb, sql, { asApplier: true });
    assert.equal(bypassResult.ok, false);
    assert.match(bypassResult.message, /refusing to alter bypassrls attributes/);
    assert.equal((await roleRow(bypassDb)).rolbypassrls, true);
    assert.equal((await roleRow(bypassDb)).rolsuper, false);
  } finally {
    await bypassDb.close();
  }
});

test('sql/03 still refuses a forbidden project ref', async () => {
  const sql = await readFile(new URL('./sql/03-mcp-ingress-role.sql', import.meta.url), 'utf8');
  const db = await freshDb();
  try {
    await db.query(`select set_config('ari.project_ref', $1, false)`, [FORBIDDEN]);
    const result = await applySql(db, sql, { asApplier: true });
    assert.equal(result.ok, false);
    assert.match(result.message, /production, HOUSE, and VAULT are forbidden/);
    assert.equal(await roleRow(db), null);
  } finally {
    await db.close();
  }
});
