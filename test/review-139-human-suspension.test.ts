import { PGlite } from '@electric-sql/pglite';
import { pgcrypto } from '@electric-sql/pglite/contrib/pgcrypto';
import { uuid_ossp } from '@electric-sql/pglite/contrib/uuid_ossp';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { applyRepoMigrations, applySupabaseStub } from './support/pglite-supabase-stub.js';

/**
 * Review probe for #139: a delegated agent's storage access must follow the delegating
 * human's current authority, not only the human's grant row. One verified human, one
 * verified delegated agent, one client, one active delegation and one object under the
 * human's prefix. Suspending the human (revoked or expired membership, denied identity
 * eligibility) must take the agent from 1 to 0 on the next statement, both through the
 * session functions the server calls and through direct Storage RLS. Synthetic only.
 */

const REPO_ROOT = new URL('..', import.meta.url).pathname;
const HUMAN = 'c3c3c3c3-0000-4000-8000-000000000003';
const AGENT = 'c3c3c3c3-0000-4000-8000-0000000000c3';
const OTHER_HUMAN = 'd4d4d4d4-0000-4000-8000-000000000004';
const CLIENT = 'review-139-client';
const OTHER_CLIENT = 'review-139-other-client';
const OBJECT = `${HUMAN}/notes/probe.txt`;
const AGENT_CLAIMS = JSON.stringify({
  sub: AGENT,
  role: 'authenticated',
  app_metadata: { client_id: CLIENT },
});

interface Probe {
  /** policy_lab.storage_has_capability('storage:read') as 0/1 (existing session path). */
  readonly session: number;
  /** 1 when policy_lab.storage_principal() resolves to the human, else 0. */
  readonly principal: number;
  /** Rows of the human's object the agent can see through storage.objects RLS. */
  readonly rls: number;
  /** 1 when an insert under the human's prefix passes storage.objects RLS, else 0. */
  readonly put: number;
}

let db: PGlite;

async function probe(): Promise<Probe> {
  const read = await db.transaction(async (tx) => {
    await tx.query(`select set_config('request.jwt.claims', $1, true)`, [AGENT_CLAIMS]);
    await tx.exec('set local role authenticated');
    const result = await tx.query<{ session: number; principal: number; rls: number }>(
      `select policy_lab.storage_has_capability('storage:read')::int as session,
              (coalesce(policy_lab.storage_principal() = $1::uuid, false))::int as principal,
              (select count(*)::int from storage.objects
                where bucket_id = 'mcp-user-storage' and name = $2) as rls`,
      [HUMAN, OBJECT],
    );
    const row = result.rows[0];
    if (row === undefined) throw new Error('probe returned no row');
    return row;
  });
  let put = 0;
  try {
    await db.transaction(async (tx) => {
      await tx.query(`select set_config('request.jwt.claims', $1, true)`, [AGENT_CLAIMS]);
      await tx.exec('set local role authenticated');
      await tx.query(
        `insert into storage.objects (bucket_id, name) values ('mcp-user-storage', $1)`,
        [`${HUMAN}/notes/put-probe.txt`],
      );
      put = 1;
      await tx.rollback();
    });
  } catch (error) {
    if ((error as { code?: string }).code !== '42501') throw error;
  }
  return { ...read, put };
}

async function asOwner(sql: string): Promise<void> {
  await db.exec(sql);
}

const ALLOWED: Probe = { session: 1, principal: 1, rls: 1, put: 1 };
const DENIED: Probe = { session: 0, principal: 0, rls: 0, put: 0 };

beforeAll(async () => {
  db = new PGlite({ extensions: { pgcrypto, uuid_ossp } });
  await applySupabaseStub(db);
  await applyRepoMigrations(db, REPO_ROOT);
  await asOwner(`
    insert into policy_lab.principals (principal_id, principal_kind, identity_eligibility) values
      ('${HUMAN}', 'human', 'verified'),
      ('${AGENT}', 'delegated_agent', 'verified'),
      ('${OTHER_HUMAN}', 'human', 'verified');
    insert into policy_lab.clients (client_id, state, valid_until) values
      ('${CLIENT}', 'active', '2099-01-01'),
      ('${OTHER_CLIENT}', 'active', '2099-01-01');
    insert into policy_lab.memberships (principal_id, client_id, workspace_id, state, valid_until) values
      ('${HUMAN}', '${CLIENT}', 'review-ws', 'active', '2099-01-01'),
      ('${HUMAN}', '${OTHER_CLIENT}', 'review-ws', 'active', '2099-01-01'),
      ('${AGENT}', '${CLIENT}', 'review-ws', 'active', '2099-01-01'),
      ('${OTHER_HUMAN}', '${CLIENT}', 'review-ws', 'active', '2099-01-01');
    insert into policy_lab.capability_grants
      (principal_id, client_id, workspace_id, capability, state, valid_until)
    select p, '${CLIENT}', 'review-ws', cap, 'active', '2099-01-01'
    from (values ('${HUMAN}'::uuid), ('${AGENT}'::uuid)) as f(p)
    cross join (values ('storage:read'), ('storage:write')) as c(cap);
    insert into policy_lab.storage_delegations
      (agent_principal_id, human_principal_id, client_id, capabilities, state, valid_until)
      values ('${AGENT}', '${HUMAN}', '${CLIENT}', array['storage:read', 'storage:write'],
              'active', '2099-01-01');
    insert into storage.objects (bucket_id, name) values ('mcp-user-storage', '${OBJECT}');
  `);
});

afterAll(async () => {
  await db?.close();
});

describe('review #139: delegated storage follows the human current authority', () => {
  it('positive control: verified human, active membership, grant and delegation give 1', async () => {
    expect(await probe()).toEqual(ALLOWED);
  });

  it('revoked human membership gives 0 on the next statement', async () => {
    await asOwner(`update policy_lab.memberships set state = 'revoked'
      where principal_id = '${HUMAN}' and client_id = '${CLIENT}'`);
    expect(await probe()).toEqual(DENIED);
    await asOwner(`update policy_lab.memberships set state = 'active'
      where principal_id = '${HUMAN}' and client_id = '${CLIENT}'`);
    expect(await probe()).toEqual(ALLOWED);
  });

  it('expired human membership gives 0', async () => {
    await asOwner(`update policy_lab.memberships set valid_until = now() - interval '1 second'
      where principal_id = '${HUMAN}' and client_id = '${CLIENT}'`);
    expect(await probe()).toEqual(DENIED);
    await asOwner(`update policy_lab.memberships set valid_until = '2099-01-01'
      where principal_id = '${HUMAN}' and client_id = '${CLIENT}'`);
    expect(await probe()).toEqual(ALLOWED);
  });

  it('a human membership through another client does not stand in for this client', async () => {
    await asOwner(`delete from policy_lab.memberships
      where principal_id = '${HUMAN}' and client_id = '${CLIENT}'`);
    expect(await probe()).toEqual(DENIED);
    await asOwner(`insert into policy_lab.memberships
      (principal_id, client_id, workspace_id, state, valid_until)
      values ('${HUMAN}', '${CLIENT}', 'review-ws', 'active', '2099-01-01')`);
    expect(await probe()).toEqual(ALLOWED);
  });

  it('a human membership in another workspace does not cover the grant workspace', async () => {
    await asOwner(`update policy_lab.memberships set workspace_id = 'review-ws-other'
      where principal_id = '${HUMAN}' and client_id = '${CLIENT}'`);
    expect(await probe()).toEqual(DENIED);
    await asOwner(`update policy_lab.memberships set workspace_id = 'review-ws'
      where principal_id = '${HUMAN}' and client_id = '${CLIENT}'`);
    expect(await probe()).toEqual(ALLOWED);
  });

  it('denied human identity eligibility gives 0 on the next statement', async () => {
    await asOwner(`update policy_lab.principals set identity_eligibility = 'denied'
      where principal_id = '${HUMAN}'`);
    expect(await probe()).toEqual(DENIED);
    await asOwner(`update policy_lab.principals set identity_eligibility = 'verified'
      where principal_id = '${HUMAN}'`);
    expect(await probe()).toEqual(ALLOWED);
  });

  it('the agent sees only its own and its delegating human principal and memberships', async () => {
    const seen = await db.transaction(async (tx) => {
      await tx.query(`select set_config('request.jwt.claims', $1, true)`, [AGENT_CLAIMS]);
      await tx.exec('set local role authenticated');
      const principals = await tx.query<{ id: string }>(
        'select principal_id::text as id from policy_lab.principals order by 1',
      );
      const memberships = await tx.query<{ id: string; client: string }>(
        'select principal_id::text as id, client_id as client from policy_lab.memberships order by 1, 2',
      );
      return { principals: principals.rows, memberships: memberships.rows };
    });
    expect(seen.principals).toEqual([{ id: HUMAN }, { id: AGENT }]);
    expect(seen.memberships).toEqual([
      { id: HUMAN, client: CLIENT },
      { id: AGENT, client: CLIENT },
    ]);
  });
});
