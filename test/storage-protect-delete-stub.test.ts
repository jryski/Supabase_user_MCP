import { PGlite } from '@electric-sql/pglite';
import { pgcrypto } from '@electric-sql/pglite/contrib/pgcrypto';
import { uuid_ossp } from '@electric-sql/pglite/contrib/uuid_ossp';
import { describe, expect, it } from 'vitest';

import { applyRepoMigrations, applySupabaseStub } from './support/pglite-supabase-stub.js';

/**
 * The local storage stub carries the hosted Storage `protect_delete` guard, so
 * repo SQL tests cannot pass locally with a bare `DELETE FROM storage.objects`
 * that hosted Storage would refuse. Synthetic data only.
 */

const REPO_ROOT = new URL('..', import.meta.url).pathname;
const USER = 'aaaaaaaa-0000-4000-8000-000000000001';
const OTHER = 'bbbbbbbb-0000-4000-8000-000000000002';
const CLAIMS = JSON.stringify({
  sub: USER,
  role: 'authenticated',
  app_metadata: { client_id: 'stub-client' },
});
const MESSAGE = 'Direct deletion from storage tables is not allowed. Use the Storage API instead.';

async function database(protectDelete: boolean): Promise<PGlite> {
  const db = new PGlite({ extensions: { pgcrypto, uuid_ossp } });
  await applySupabaseStub(db, { protectDelete });
  await applyRepoMigrations(db, REPO_ROOT);
  await db.exec(`
    insert into policy_lab.principals (principal_id, principal_kind, identity_eligibility)
      values ('${USER}', 'human', 'verified'), ('${OTHER}', 'human', 'verified');
    insert into policy_lab.clients (client_id, state, valid_until)
      values ('stub-client', 'active', '2099-01-01');
    insert into policy_lab.memberships (principal_id, client_id, workspace_id, state, valid_until)
      values ('${USER}', 'stub-client', 'ws', 'active', '2099-01-01');
    insert into policy_lab.capability_grants (principal_id, client_id, workspace_id, capability, state, valid_until)
      values ('${USER}', 'stub-client', 'ws', 'storage:read', 'active', '2099-01-01'),
             ('${USER}', 'stub-client', 'ws', 'storage:write', 'active', '2099-01-01');
    insert into storage.objects (bucket_id, name) values
      ('mcp-user-storage', '${USER}/own.txt'), ('mcp-user-storage', '${OTHER}/theirs.txt');
  `);
  return db;
}

async function deleteAsUser(db: PGlite, name: string, allowFlag: boolean): Promise<number> {
  return db.transaction(async (tx) => {
    await tx.query(`select set_config('request.jwt.claims', $1, true)`, [CLAIMS]);
    if (allowFlag) await tx.exec(`select set_config('storage.allow_delete_query', 'true', true)`);
    await tx.exec('set local role authenticated');
    const result = await tx.query('delete from storage.objects where name = $1 returning 1', [
      name,
    ]);
    return result.rows.length;
  });
}

async function count(db: PGlite): Promise<number> {
  const result = await db.query<{ n: number }>('select count(*)::int as n from storage.objects');
  return result.rows[0]?.n ?? -1;
}

describe('PGlite storage stub: protect_delete guard', () => {
  it('RED: a bare direct delete is refused with the hosted error, even for the owner', async () => {
    const db = await database(true);
    await expect(deleteAsUser(db, `${USER}/own.txt`, false)).rejects.toMatchObject({
      code: '42501',
      message: MESSAGE,
    });
    await expect(db.exec(`delete from storage.objects`)).rejects.toMatchObject({ code: '42501' });
    await expect(db.exec(`delete from storage.buckets where id = 'none'`)).rejects.toMatchObject({
      code: '42501',
    });
    expect(await count(db)).toBe(2);
    await db.close();
  });

  it('GREEN: with storage.allow_delete_query set, RLS alone decides what is deleted', async () => {
    const db = await database(true);
    expect(await deleteAsUser(db, `${OTHER}/theirs.txt`, true)).toBe(0);
    expect(await deleteAsUser(db, `${USER}/own.txt`, true)).toBe(1);
    expect(await count(db)).toBe(1);
    // The flag is transaction-local: the next transaction is guarded again.
    await expect(deleteAsUser(db, `${OTHER}/theirs.txt`, false)).rejects.toMatchObject({
      code: '42501',
    });
    await db.close();
  });

  it('without the guard the same bare delete would silently pass (why the stub needs it)', async () => {
    const db = await database(false);
    expect(await deleteAsUser(db, `${USER}/own.txt`, false)).toBe(1);
    await db.close();
  });
});
