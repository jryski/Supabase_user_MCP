import { readFile } from 'node:fs/promises';

import { PGlite } from '@electric-sql/pglite';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { SOURCE_SESSION_LIVENESS_RPC } from '../../packages/server/src/source-session-liveness.js';

/**
 * Runs sql/liveness/source_session_live_v1.sql against an in-process Postgres
 * with a minimal synthetic auth schema. No Supabase project is involved.
 */

const SQL_PATH = new URL('../../sql/liveness/source_session_live_v1.sql', import.meta.url);

const USER = '11111111-1111-4111-8111-111111111111';
const OTHER_USER = '55555555-5555-4555-8555-555555555555';
const SOURCE = '22222222-2222-4222-8222-222222222222';
const CALLER = '33333333-3333-4333-8333-333333333333';
const OTHER_SOURCE = '44444444-4444-4444-8444-444444444444';
const EXPIRED_SOURCE = '66666666-6666-4666-8666-666666666666';
const CLIENT_A = '77777777-7777-4777-8777-777777777777';
const CLIENT_OTHER = '88888888-8888-4888-8888-888888888888';

const STUB_AUTH = `
create role anon nologin;
create role authenticated nologin;
create schema auth;
grant usage on schema auth to anon, authenticated;
create function auth.jwt() returns jsonb language sql stable as $$
  select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb
$$;
create function auth.uid() returns uuid language sql stable as $$
  select nullif(auth.jwt() ->> 'sub', '')::uuid
$$;
create table auth.sessions (
  id uuid primary key,
  user_id uuid not null,
  not_after timestamptz,
  oauth_client_id uuid
);
revoke all on auth.sessions from public;
`;

let db: PGlite;

async function asCaller(
  claims: Record<string, unknown> | null,
  sourceSessionId: string,
  aClientId: string | null,
): Promise<unknown> {
  return db.transaction(async (tx) => {
    await tx.query(`select set_config('request.jwt.claims', $1, true)`, [
      claims === null ? '' : JSON.stringify(claims),
    ]);
    await tx.exec('set local role authenticated');
    const result = await tx.query<{ live: unknown }>(
      `select public.${SOURCE_SESSION_LIVENESS_RPC}($1::uuid, $2::text) as live`,
      [sourceSessionId, aClientId],
    );
    return result.rows[0]?.live;
  });
}

const callerClaims = { sub: USER, session_id: CALLER, role: 'authenticated' };

describe('source_session_live_v1 SQL fixture', () => {
  beforeAll(async () => {
    db = new PGlite();
    await db.exec(STUB_AUTH);
    await db.exec(await readFile(SQL_PATH, 'utf8'));
    await db.query(
      `insert into auth.sessions (id, user_id, not_after, oauth_client_id) values
        ($1, $5, null, $7),
        ($2, $5, null, $8),
        ($3, $6, null, $7),
        ($4, $5, now() - interval '1 minute', $7)`,
      [SOURCE, CALLER, OTHER_SOURCE, EXPIRED_SOURCE, USER, OTHER_USER, CLIENT_A, CLIENT_OTHER],
    );
  });

  afterAll(async () => {
    await db.close();
  });

  it('names the function the server calls', async () => {
    const sql = await readFile(SQL_PATH, 'utf8');
    expect(sql).toContain(`function public.${SOURCE_SESSION_LIVENESS_RPC}(`);
    expect(sql).toMatch(/security definer\s+set search_path = ''/u);
  });

  it('is true for a live source session of the same user and client', async () => {
    expect(await asCaller(callerClaims, SOURCE, CLIENT_A)).toBe(true);
  });

  it('is false once the source session is gone or expired', async () => {
    expect(await asCaller(callerClaims, EXPIRED_SOURCE, CLIENT_A)).toBe(false);
    await db.query('delete from auth.sessions where id = $1', [SOURCE]);
    expect(await asCaller(callerClaims, SOURCE, CLIENT_A)).toBe(false);
    await db.query(
      'insert into auth.sessions (id, user_id, not_after, oauth_client_id) values ($1, $2, null, $3)',
      [SOURCE, USER, CLIENT_A],
    );
  });

  it('is false for another user, another client, or the caller session itself', async () => {
    expect(await asCaller(callerClaims, OTHER_SOURCE, CLIENT_A)).toBe(false);
    expect(await asCaller(callerClaims, SOURCE, CLIENT_OTHER)).toBe(false);
    expect(await asCaller(callerClaims, SOURCE, '')).toBe(false);
    expect(await asCaller(callerClaims, SOURCE, null)).toBe(false);
    expect(await asCaller(callerClaims, CALLER, CLIENT_OTHER)).toBe(false);
  });

  it('is false when the caller session is revoked or missing', async () => {
    expect(await asCaller({ sub: USER, role: 'authenticated' }, SOURCE, CLIENT_A)).toBe(false);
    expect(await asCaller({ ...callerClaims, session_id: OTHER_SOURCE }, SOURCE, CLIENT_A)).toBe(
      false,
    );
    expect(await asCaller(null, SOURCE, CLIENT_A)).toBe(false);
  });

  it('fails closed when the client column is absent', async () => {
    await db.exec('alter table auth.sessions rename column oauth_client_id to legacy_client_id');
    try {
      expect(await asCaller(callerClaims, SOURCE, CLIENT_A)).toBe(false);
    } finally {
      await db.exec('alter table auth.sessions rename column legacy_client_id to oauth_client_id');
    }
  });

  it('is callable by authenticated only', async () => {
    const grants = await db.query<{ anon: boolean; authenticated: boolean; public_role: boolean }>(
      `select
         has_function_privilege('anon', 'public.${SOURCE_SESSION_LIVENESS_RPC}(uuid, text)', 'EXECUTE') as anon,
         has_function_privilege('authenticated', 'public.${SOURCE_SESSION_LIVENESS_RPC}(uuid, text)', 'EXECUTE') as authenticated,
         exists (
           select 1 from pg_proc as p, aclexplode(p.proacl) as acl
           where p.proname = '${SOURCE_SESSION_LIVENESS_RPC}' and acl.grantee = 0
         ) as public_role`,
    );
    expect(grants.rows[0]).toEqual({ anon: false, authenticated: true, public_role: false });
  });

  it('does not let authenticated read auth.sessions directly', async () => {
    await expect(
      db.transaction(async (tx) => {
        await tx.exec('set local role authenticated');
        await tx.query('select id from auth.sessions');
      }),
    ).rejects.toThrow(/permission denied/u);
  });
});
