// Independent review probe, not a candidate implementation change.
// Synthetic PGlite only; loads the exact candidate migration files.
import { PGlite } from '@electric-sql/pglite';
import { pgcrypto } from '@electric-sql/pglite/contrib/pgcrypto';
import { uuid_ossp } from '@electric-sql/pglite/contrib/uuid_ossp';
import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import { applyRepoMigrations, applySupabaseStub } from './support/pglite-supabase-stub.js';

const HUMAN = '11111111-1111-4111-8111-111111111111';
const AGENT = '22222222-2222-4222-8222-222222222222';
const CLIENT = 'review-client';
let db: PGlite;

beforeAll(async () => {
  db = new PGlite({ extensions: { pgcrypto, uuid_ossp } });
  await applySupabaseStub(db, { protectDelete: true });
  await applyRepoMigrations(db, new URL('..', import.meta.url).pathname);
  await db.exec(`
    insert into policy_lab.principals(principal_id, principal_kind, identity_eligibility) values
      ('${HUMAN}', 'human', 'verified'), ('${AGENT}', 'delegated_agent', 'verified');
    insert into policy_lab.clients(client_id, state, valid_until)
      values ('${CLIENT}', 'active', '2099-01-01');
    insert into policy_lab.memberships(principal_id, client_id, workspace_id, state, valid_until)
      values ('${HUMAN}', '${CLIENT}', 'review-ws', 'active', '2099-01-01'),
             ('${AGENT}', '${CLIENT}', 'review-ws', 'active', '2099-01-01');
    insert into policy_lab.capability_grants(principal_id, client_id, workspace_id, capability, state, valid_until)
      values ('${HUMAN}', '${CLIENT}', 'review-ws', 'storage:read', 'active', '2099-01-01'),
             ('${AGENT}', '${CLIENT}', 'review-ws', 'storage:read', 'active', '2099-01-01');
    insert into policy_lab.storage_delegations(agent_principal_id,human_principal_id,client_id,capabilities,state,valid_until)
      values ('${AGENT}', '${HUMAN}', '${CLIENT}', array['storage:read'], 'active', '2099-01-01');
    insert into storage.objects(bucket_id,name)
      values ('mcp-user-storage','${HUMAN}/notes/existing.md');
  `);
});
afterAll(async () => { await db?.close(); });

async function visibleRows(): Promise<number> {
  return db.transaction(async tx => {
    await tx.query("select set_config('request.jwt.claims', $1, true)", [JSON.stringify({
      sub: AGENT, role: 'authenticated', app_metadata: { client_id: CLIENT },
    })]);
    await tx.exec('set local role authenticated');
    const rows = await tx.query<{ n: number }>(
      "select count(*)::int as n from storage.objects where bucket_id='mcp-user-storage'",
    );
    return (rows.rows[0] as { n: number }).n;
  });
}

describe('independent #139 delegated access review', () => {
  it('positive control: live human and agent can see the delegated object', async () => {
    expect(await visibleRows()).toBe(1);
  });
  it('must deny agent after the human membership is revoked', async () => {
    await db.exec(`update policy_lab.memberships set state='revoked' where principal_id='${HUMAN}'`);
    try { expect(await visibleRows()).toBe(0); }
    finally { await db.exec(`update policy_lab.memberships set state='active' where principal_id='${HUMAN}'`); }
  });
  it('must deny agent after the human identity eligibility is denied', async () => {
    await db.exec(`update policy_lab.principals set identity_eligibility='denied' where principal_id='${HUMAN}'`);
    try { expect(await visibleRows()).toBe(0); }
    finally { await db.exec(`update policy_lab.principals set identity_eligibility='verified' where principal_id='${HUMAN}'`); }
  });
});

