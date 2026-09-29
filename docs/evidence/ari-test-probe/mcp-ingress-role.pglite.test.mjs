import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { PGlite } from '@electric-sql/pglite';

const EMAIL = 'ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid';
const USER = '11111111-1111-4111-8111-111111111111';
const ALLOWED = 'odbcejsuuqdzhabjmozi';
const FORBIDDEN = 'lygftpbjgqgvuunkwnxf';

// Hosted ari-test is PostgreSQL 17.6 (Ariadne MC1515): applier current_user
// is postgres, non-superuser, CREATEROLE, with ADMIN on anon, authenticated,
// authenticator, and service_role. createrole_self_grant is empty.
// In-repo PGlite is PostgreSQL 18.3. SET ROLE keeps the bootstrap superuser
// as session_user, so that superuser is the grantor of the creator admin
// row. On the host the applier is current_user, so the grantor is that role.
// The SQL assert keys off current_user and the option flags, not the grantor.
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

async function freshDb({ admin }) {
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
      login
      nosuperuser
      createrole
      createdb
      noreplication
      bypassrls;
    grant usage on schema auth to applier;
    grant select on table auth.users to applier;
  `);
  if (admin) {
    await db.exec(`
      grant anon, authenticated, authenticator, service_role
        to applier
        with admin true, inherit true, set true;
    `);
  }
  await db.exec(`select set_config('createrole_self_grant', '', false)`);
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

async function members(db) {
  const result = await db.query(`
    select
      member_role.rolname,
      membership.admin_option,
      membership.inherit_option,
      membership.set_option,
      grantor_role.rolname as grantor
    from pg_auth_members as membership
    join pg_roles as granted_role on granted_role.oid = membership.roleid
    join pg_roles as member_role on member_role.oid = membership.member
    join pg_roles as grantor_role on grantor_role.oid = membership.grantor
    where granted_role.rolname = 'mcp_ingress'
    order by member_role.rolname
  `);
  return result.rows;
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

function assertSqlContract(sql) {
  assert.equal(/^\s*alter\s+role\b/imu.test(sql), false);
  assert.equal(/^\s*revoke\b/imu.test(sql), false);
  assert.match(sql, /create role mcp_ingress/);
  assert.match(sql, /nologin/);
  assert.match(sql, /noinherit/);
  assert.match(sql, /nosuperuser/);
  assert.match(sql, /nocreatedb/);
  assert.match(sql, /nocreaterole/);
  assert.match(sql, /noreplication/);
  assert.match(sql, /nobypassrls/);
  assert.match(sql, /grant mcp_ingress to authenticator/);
  assert.match(sql, /creator row lets it grant membership, not act as mcp_ingress/);
  assert.match(sql, /set_option/);
  assert.match(sql, /admin_option/);
  assert.match(sql, /inherit_option/);
  assert.match(sql, /current_user/);
}

async function assertEngine(db) {
  const version = await db.query(`select version() as version`);
  assert.match(version.rows[0].version, /PostgreSQL 18\.3/);
  const guc = await db.query(`select current_setting('createrole_self_grant') as guc`);
  assert.equal(guc.rows[0].guc, '');
}

async function assertCommitted(db) {
  assertIsolated(await roleRow(db));
  assert.deepEqual(await members(db), [
    {
      rolname: 'applier',
      admin_option: true,
      inherit_option: false,
      set_option: false,
      grantor: 'postgres',
    },
    {
      rolname: 'authenticator',
      admin_option: false,
      inherit_option: false,
      set_option: true,
      grantor: 'applier',
    },
  ]);
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
  const columns = await db.query(`
    select count(*)::int as grants
    from pg_attribute as attribute
    cross join lateral aclexplode(attribute.attacl) as acl
    join pg_roles as grantee on grantee.oid = acl.grantee
    where grantee.rolname = 'mcp_ingress'
      and not attribute.attisdropped
  `);
  assert.equal(columns.rows[0].grants, 0);
}

test('old ALTER ROLE NOSUPERUSER is denied to a non-superuser CREATEROLE session', async () => {
  const db = await freshDb({ admin: true });
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

test('sql/03 commits the whole file for an ADMIN-granted CREATEROLE applier', async () => {
  const sql = await readFile(new URL('./sql/03-mcp-ingress-role.sql', import.meta.url), 'utf8');
  assertSqlContract(sql);
  const db = await freshDb({ admin: true });
  try {
    await assertEngine(db);
    const applier = await db.query(`
      select rolsuper, rolcreaterole, rolcreatedb, rolbypassrls
      from pg_roles
      where rolname = 'applier'
    `);
    assert.deepEqual(applier.rows[0], {
      rolsuper: false,
      rolcreaterole: true,
      rolcreatedb: true,
      rolbypassrls: true,
    });
    const adminGrants = await db.query(`
      select granted_role.rolname
      from pg_auth_members as membership
      join pg_roles as granted_role on granted_role.oid = membership.roleid
      join pg_roles as member_role on member_role.oid = membership.member
      where member_role.rolname = 'applier'
        and membership.admin_option
        and membership.inherit_option
        and membership.set_option
      order by granted_role.rolname
    `);
    assert.deepEqual(
      adminGrants.rows.map((row) => row.rolname),
      ['anon', 'authenticated', 'authenticator', 'service_role'],
    );

    await db.query(`select set_config('ari.project_ref', $1, false)`, [ALLOWED]);
    const created = await applySql(db, sql, { asApplier: true });
    assert.equal(created.ok, true, created.message);
    await assertCommitted(db);

    const revoked = await applySql(db, 'revoke mcp_ingress from applier', { asApplier: true });
    assert.equal(revoked.ok, true, revoked.message);
    await assertCommitted(db);

    const again = await applySql(db, sql, { asApplier: true });
    assert.equal(again.ok, true, again.message);
    await assertCommitted(db);
  } finally {
    await db.close();
  }
});

test('sql/03 commits the whole file for a CREATEROLE applier with no ADMIN', async () => {
  const sql = await readFile(new URL('./sql/03-mcp-ingress-role.sql', import.meta.url), 'utf8');
  const db = await freshDb({ admin: false });
  try {
    await assertEngine(db);
    const adminGrants = await db.query(`
      select count(*)::int as memberships
      from pg_auth_members as membership
      join pg_roles as member_role on member_role.oid = membership.member
      where member_role.rolname = 'applier'
    `);
    assert.equal(adminGrants.rows[0].memberships, 0);

    await db.query(`select set_config('ari.project_ref', $1, false)`, [ALLOWED]);
    const created = await applySql(db, sql, { asApplier: true });
    assert.equal(created.ok, true, created.message);
    await assertCommitted(db);

    const again = await applySql(db, sql, { asApplier: true });
    assert.equal(again.ok, true, again.message);
    await assertCommitted(db);
  } finally {
    await db.close();
  }
});

test('sql/03 fails closed when an existing mcp_ingress is not already isolated', async () => {
  const sql = await readFile(new URL('./sql/03-mcp-ingress-role.sql', import.meta.url), 'utf8');

  const superDb = await freshDb({ admin: true });
  try {
    await superDb.exec('create role mcp_ingress nologin superuser nobypassrls');
    await superDb.query(`select set_config('ari.project_ref', $1, false)`, [ALLOWED]);
    const superResult = await applySql(superDb, sql, { asApplier: true });
    assert.equal(superResult.ok, false);
    assert.match(superResult.message, /mcp_ingress is not an isolated nologin noinherit role/);
    assert.equal((await roleRow(superDb)).rolsuper, true);
  } finally {
    await superDb.close();
  }

  const bypassDb = await freshDb({ admin: true });
  try {
    await bypassDb.exec('create role mcp_ingress nologin nosuperuser bypassrls');
    await bypassDb.query(`select set_config('ari.project_ref', $1, false)`, [ALLOWED]);
    const bypassResult = await applySql(bypassDb, sql, { asApplier: true });
    assert.equal(bypassResult.ok, false);
    assert.match(bypassResult.message, /mcp_ingress is not an isolated nologin noinherit role/);
    assert.equal((await roleRow(bypassDb)).rolbypassrls, true);
    assert.equal((await roleRow(bypassDb)).rolsuper, false);
  } finally {
    await bypassDb.close();
  }

  const loginDb = await freshDb({ admin: false });
  try {
    await loginDb.exec(`
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
    await loginDb.query(`select set_config('ari.project_ref', $1, false)`, [ALLOWED]);
    const loginResult = await applySql(loginDb, sql, { asApplier: true });
    assert.equal(loginResult.ok, false);
    assert.match(loginResult.message, /mcp_ingress is not an isolated nologin noinherit role/);
    assert.equal((await roleRow(loginDb)).rolcanlogin, true);
    assert.equal((await roleRow(loginDb)).rolinherit, true);
  } finally {
    await loginDb.close();
  }
});

test('sql/03 does not repair an extra member or a table grant', async () => {
  const sql = await readFile(new URL('./sql/03-mcp-ingress-role.sql', import.meta.url), 'utf8');
  const memberDb = await freshDb({ admin: true });
  try {
    await memberDb.query(`select set_config('ari.project_ref', $1, false)`, [ALLOWED]);
    const created = await applySql(memberDb, sql, { asApplier: true });
    assert.equal(created.ok, true, created.message);
    await memberDb.exec('grant mcp_ingress to anon');
    const repaired = await applySql(memberDb, sql, { asApplier: true });
    assert.equal(repaired.ok, false);
    assert.match(
      repaired.message,
      /mcp_ingress membership is not exactly authenticator and the creating role/,
    );
    const names = (await members(memberDb)).map((row) => row.rolname);
    assert.deepEqual(names, ['anon', 'applier', 'authenticator']);
  } finally {
    await memberDb.close();
  }

  const grantDb = await freshDb({ admin: false });
  try {
    await grantDb.query(`select set_config('ari.project_ref', $1, false)`, [ALLOWED]);
    const created = await applySql(grantDb, sql, { asApplier: true });
    assert.equal(created.ok, true, created.message);
    await grantDb.exec('grant select on table auth.users to mcp_ingress');
    const repaired = await applySql(grantDb, sql, { asApplier: true });
    assert.equal(repaired.ok, false);
    assert.match(repaired.message, /mcp_ingress has table grants/);
    const still = await grantDb.query(`
      select privilege_type
      from information_schema.role_table_grants
      where grantee = 'mcp_ingress'
        and table_schema = 'auth'
        and table_name = 'users'
    `);
    assert.deepEqual(still.rows, [{ privilege_type: 'SELECT' }]);
  } finally {
    await grantDb.close();
  }
});

test('sql/03 still refuses a forbidden project ref', async () => {
  const sql = await readFile(new URL('./sql/03-mcp-ingress-role.sql', import.meta.url), 'utf8');
  const db = await freshDb({ admin: true });
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
