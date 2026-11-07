import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { PGlite } from '@electric-sql/pglite';
import { pgcrypto } from '@electric-sql/pglite/contrib/pgcrypto';
import { uuid_ossp } from '@electric-sql/pglite/contrib/uuid_ossp';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  STORAGE_RPC,
  STORAGE_RPC_SCHEMA,
} from '../../packages/server/src/user-scoped-storage-client.js';
import { applyRepoMigrations, applySupabaseStub } from '../support/pglite-supabase-stub.js';

/**
 * The storage client's session RPCs go through narrow wrappers in an exposed schema, so
 * policy_lab is never added to the Data API. Synthetic identifiers only.
 */

const root = resolve(import.meta.dirname, '../..');
const SEAM = 'supabase/migrations/20261027000300_storage_session_rpc_seam.sql';
const HUMAN = 'e5e5e5e5-0000-4000-8000-000000000005';
const CLIENT = 'seam-client';

const exposedSchemas = (): string[] =>
  JSON.parse(
    /^\[api\][\s\S]*?^schemas = (\[[^\]]*\])$/m.exec(
      readFileSync(resolve(root, 'supabase/config.toml'), 'utf8'),
    )?.[1] ?? '[]',
  );

describe('storage session RPC seam', () => {
  let db: PGlite;

  beforeAll(async () => {
    db = await PGlite.create({ extensions: { pgcrypto, uuid_ossp } });
    await applySupabaseStub(db);
    await applyRepoMigrations(db, root);
    await db.exec(`
      insert into policy_lab.principals (principal_id, principal_kind, identity_eligibility)
        values ('${HUMAN}', 'human', 'verified');
      insert into policy_lab.clients (client_id, state, valid_until)
        values ('${CLIENT}', 'active', now() + interval '1 day');
      insert into policy_lab.memberships (principal_id, client_id, workspace_id, state, valid_until)
        values ('${HUMAN}', '${CLIENT}', 'seam-ws', 'active', now() + interval '1 day');
      insert into policy_lab.capability_grants
        (principal_id, client_id, workspace_id, capability, state, valid_until)
        values ('${HUMAN}', '${CLIENT}', 'seam-ws', 'storage:read', 'active', now() + interval '1 day');
    `);
  }, 60_000);

  afterAll(async () => {
    await db?.close();
  });

  it('keeps policy_lab out of the Data API and targets an exposed schema', () => {
    const schemas = exposedSchemas();
    expect(schemas).toEqual(['public', 'memory', 'storage', 'extensions']);
    expect(schemas).not.toContain('policy_lab');
    expect(schemas).toContain(STORAGE_RPC_SCHEMA);
  });

  it('defines exactly two SECURITY INVOKER wrappers with an empty search_path', async () => {
    const result = await db.query<{
      name: string;
      definer: boolean;
      config: string[] | null;
      result: string;
      body: string;
    }>(`
      select p.proname as name, p.prosecdef as definer, p.proconfig as config,
             pg_get_function_result(p.oid) as result, p.prosrc as body
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
      where n.nspname = 'public' and p.proname like 'mcp\\_storage\\_%'
      order by 1`);
    expect(result.rows.map((row) => row.name)).toEqual(
      [STORAGE_RPC.principal, STORAGE_RPC.sessionCapabilities].sort(),
    );
    for (const row of result.rows) {
      expect(row.definer).toBe(false);
      expect(row.config).toEqual(['search_path=""']);
    }
    const byName = Object.fromEntries(result.rows.map((row) => [row.name, row]));
    expect(byName[STORAGE_RPC.principal]?.result).toBe('uuid');
    expect(byName[STORAGE_RPC.principal]?.body.trim()).toBe(
      'select policy_lab.storage_principal();',
    );
    expect(byName[STORAGE_RPC.sessionCapabilities]?.result).toBe('jsonb');
    expect(byName[STORAGE_RPC.sessionCapabilities]?.body.trim()).toBe(
      'select policy_lab.storage_session_capabilities();',
    );
  });

  it('grants EXECUTE to authenticated only', async () => {
    for (const name of Object.values(STORAGE_RPC)) {
      const result = await db.query<{ role: string; allowed: boolean }>(
        `select r.rolname as role,
                has_function_privilege(r.oid, 'public.${name}()', 'EXECUTE') as allowed
         from pg_roles r where r.rolname in ('anon', 'authenticated', 'service_role')
         order by 1`,
      );
      expect(result.rows).toEqual([
        { role: 'anon', allowed: false },
        { role: 'authenticated', allowed: true },
        { role: 'service_role', allowed: false },
      ]);
      const acl = await db.query<{ acl: string[] }>(
        `select proacl::text[] as acl from pg_proc where oid = 'public.${name}()'::regprocedure`,
      );
      expect(acl.rows[0]?.acl.filter((entry) => !entry.startsWith('postgres='))).toEqual([
        'authenticated=X/postgres',
      ]);
    }
  });

  it('returns what the policy_lab functions return, as the caller', async () => {
    const asCaller = async (claims: Record<string, unknown>) =>
      db.transaction(async (tx) => {
        await tx.query(`select set_config('request.jwt.claims', $1, true)`, [
          JSON.stringify(claims),
        ]);
        await tx.exec('set local role authenticated');
        const result = await tx.query<{
          principal: string | null;
          caps: unknown;
          inner_principal: string | null;
          inner_caps: unknown;
        }>(`select public.${STORAGE_RPC.principal}() as principal,
                   public.${STORAGE_RPC.sessionCapabilities}() as caps,
                   policy_lab.storage_principal() as inner_principal,
                   policy_lab.storage_session_capabilities() as inner_caps`);
        return result.rows[0];
      });
    const own = await asCaller({
      sub: HUMAN,
      role: 'authenticated',
      app_metadata: { client_id: CLIENT },
    });
    expect(own).toEqual({
      principal: HUMAN,
      caps: ['storage:read'],
      inner_principal: HUMAN,
      inner_caps: ['storage:read'],
    });
    const otherClient = await asCaller({
      sub: HUMAN,
      role: 'authenticated',
      app_metadata: { client_id: 'seam-other' },
    });
    expect(otherClient).toEqual({
      principal: null,
      caps: [],
      inner_principal: null,
      inner_caps: [],
    });
  });

  it('refuses anon', async () => {
    await expect(
      db.transaction(async (tx) => {
        await tx.exec('set local role anon');
        await tx.query(`select public.${STORAGE_RPC.principal}()`);
      }),
    ).rejects.toThrow(/permission denied/);
  });

  it('is additive: only creates the wrappers and sets their privileges', () => {
    const sql = readFileSync(resolve(root, SEAM), 'utf8').replace(/--[^\n]*/g, '');
    expect(sql).not.toMatch(
      /security\s+definer|bypassrls|\balter\b|\bdrop\b|create\s+policy|to\s+anon\b/i,
    );
    expect(sql.match(/create function [a-z0-9_.]+/g)).toEqual([
      `create function public.${STORAGE_RPC.principal}`,
      `create function public.${STORAGE_RPC.sessionCapabilities}`,
    ]);
  });
});
