import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { PGlite } from '@electric-sql/pglite';

export const LAB_VERSION = 'ari-memory-read-lab-v1';
export const BASELINE_USER_ID = '1928e465-6ab9-439c-9ab8-d7d0c8bba16d';
export const SECOND_USER_ID = '6f0c2a44-91d4-4e7b-a13c-5d8e7b0a9c21';
export const SECOND_USER_IDENTITY = 'ari-memory-lab-second@loopback.invalid';
export const LOCAL_B_CLIENT_ID = 'b7c1d2e3-4f50-4a6b-8c7d-9e0f1a2b3c4d';
export const REVOKED_CLIENT_ID = 'c1111111-1111-4111-8111-111111111111';
export const EXPIRED_CLIENT_ID = 'c2222222-2222-4222-8222-222222222222';
export const DENIED_PRINCIPAL_ID = 'd3333333-3333-4333-8333-333333333333';
export const SHARED_TOKEN = 'shared-lab-token';
export const BASELINE_ONLY_TOKEN = 'only-baseline-token';
export const SECOND_ONLY_TOKEN = 'only-second-token';
export const HOSTILE_SENTINEL = 'inert-hostile-content-sentinel';
export const FAR_EXPIRY = '2099-01-01T00:00:00.000Z';
export const PAST_EXPIRY = '2020-01-01T00:00:00.000Z';
export const HOSTED_PROJECT_REF = 'odbcejsuuqdzhabjmozi';

const INSTALLER = new URL(
  '../docs/evidence/ari-test-probe/sql/08-memory-read-lab.sql',
  import.meta.url,
);
const ROLLBACK = new URL(
  '../docs/evidence/ari-test-probe/sql/08-memory-read-lab-rollback.sql',
  import.meta.url,
);
const LOCK_DIR = join(tmpdir(), 'ari-memory-read-lab.lock');

function coded(code) {
  return Object.assign(new Error(code), { code });
}

function git(args) {
  return execFileSync('git', args, { encoding: 'utf8', cwd: process.cwd() }).trim();
}

export function installerSql() {
  return readFileSync(INSTALLER, 'utf8');
}

export function rollbackSql() {
  return readFileSync(ROLLBACK, 'utf8');
}

export function sqlSha256(text) {
  return createHash('sha256').update(text).digest('hex');
}

export function assertLocalOnly(env) {
  if (env.ARI_MEMORY_LAB_MODE !== 'local') throw coded('hosted_execution_refused');
  const url = `${env.ARI_TEST_SUPABASE_URL ?? ''}${env.SUPABASE_URL ?? ''}`;
  if (url.toLowerCase().includes(HOSTED_PROJECT_REF)) throw coded('hosted_execution_refused');
}

export function assertCleanWorktree() {
  const dirty = git(['status', '--porcelain=v1', '--untracked-files=no']);
  if (dirty.length > 0) throw coded('worktree_dirty');
}

export function acquireControllerLock() {
  try {
    mkdirSync(LOCK_DIR);
  } catch (error) {
    if (error !== null && typeof error === 'object' && error.code === 'EEXIST') {
      throw coded('controller_lock_held');
    }
    throw error;
  }
  return () => rmSync(LOCK_DIR, { recursive: true, force: true });
}

export function plan() {
  return {
    packet: 'ari-memory-read-lab',
    version: LAB_VERSION,
    acceptance: false,
    hostedContact: false,
    executedByWriter: false,
    listenerCount: 0,
    mode: 'local-synthetic',
    hostedProjectPinned: HOSTED_PROJECT_REF,
    hostedExecution: 'refused',
    provenance: 'mc1681:jesse_via_warden',
    d1: 'not_executed',
    d2: 'not_executed',
    baselineUserId: BASELINE_USER_ID,
    secondUserIdentity: SECOND_USER_IDENTITY,
    bClientBinding: 'local_synthetic_stand_in',
    sameUserDifferentBClient: 'not_executed',
    hookBypass: 'excluded_from_first_hosted_batch',
    directTokenA: 'excluded_from_first_hosted_batch',
    exposedSchemaDelta: 'add memory only when absent; never add policy_lab',
    adminCredentialUsed: false,
  };
}

export async function openLabDatabase() {
  const db = new PGlite();
  await db.waitReady;
  await db.exec(`
    create role anon nologin noinherit;
    create role authenticated nologin noinherit;
    create role mcp_ingress nologin noinherit nosuperuser nobypassrls;
    create schema auth;
    grant usage on schema auth to authenticated;
    create function auth.uid()
    returns uuid
    language sql
    stable
    as $fn$
      select (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')::uuid;
    $fn$;
    create function auth.jwt()
    returns jsonb
    language sql
    stable
    as $fn$
      select nullif(current_setting('request.jwt.claims', true), '')::jsonb;
    $fn$;
    select set_config('ari.project_ref', '${HOSTED_PROJECT_REF}', false);
    set timezone to 'UTC';
    set datestyle to iso;
  `);
  await db.exec(installerSql());
  return db;
}

function claims(sub, clientId, { metadata = 'top' } = {}) {
  if (metadata === 'user') {
    return {
      sub,
      role: 'authenticated',
      aud: 'authenticated',
      user_metadata: { client_id: clientId },
    };
  }
  if (metadata === 'app') {
    return {
      sub,
      role: 'authenticated',
      aud: 'authenticated',
      app_metadata: { client_id: clientId },
    };
  }
  return { sub, role: 'authenticated', aud: 'authenticated', client_id: clientId };
}

function jsonValue(value) {
  if (typeof value === 'string') return JSON.parse(value);
  return value;
}

async function asUser(db, claim, statement, params) {
  return db.transaction(async (tx) => {
    await tx.exec('set local role authenticated');
    await tx.query(`select set_config('request.jwt.claims', $1, true)`, [JSON.stringify(claim)]);
    const result = await tx.query(statement, params);
    return result.rows[0];
  });
}

async function readRpc(db, claim, statement, params) {
  const row = await asUser(db, claim, statement, params);
  return jsonValue(row.result);
}

function memoryId(runId, slot) {
  return `mem_${runId.replaceAll('-', '')}_${slot}`;
}

function workspaceId(runId, name) {
  return `ws-${runId}-${name}`;
}

function buildManifest(runId) {
  const positiveTag = `run:${runId}`;
  const denialTag = `denial:${runId}`;
  const slots = {
    a1: {
      user: 'baseline',
      kind: 'positive',
      title: 'baseline one',
      content: SHARED_TOKEN,
      createdAt: '2026-09-30T00:00:01.000Z',
    },
    a2: {
      user: 'baseline',
      kind: 'positive',
      title: 'baseline two',
      content: BASELINE_ONLY_TOKEN,
      createdAt: '2026-09-30T00:00:02.000Z',
    },
    a3: {
      user: 'baseline',
      kind: 'positive',
      title: 'baseline three',
      content: HOSTILE_SENTINEL,
      createdAt: '2026-09-30T00:00:03.000Z',
    },
    b1: {
      user: 'second',
      kind: 'positive',
      title: 'second one',
      content: SHARED_TOKEN,
      createdAt: '2026-09-30T00:00:01.000Z',
    },
    b2: {
      user: 'second',
      kind: 'positive',
      title: 'second two',
      content: SECOND_ONLY_TOKEN,
      createdAt: '2026-09-30T00:00:02.000Z',
    },
    b3: {
      user: 'second',
      kind: 'positive',
      title: 'second three',
      content: HOSTILE_SENTINEL,
      createdAt: '2026-09-30T00:00:03.000Z',
    },
    denied: {
      user: 'denied',
      kind: 'denial',
      title: 'denied identity',
      content: 'denied-identity-token',
    },
    membershipRevoked: {
      user: 'baseline',
      kind: 'denial',
      title: 'revoked membership',
      content: 'revoked-membership-token',
    },
    membershipExpired: {
      user: 'baseline',
      kind: 'denial',
      title: 'expired membership',
      content: 'expired-membership-token',
    },
    clientRevoked: {
      user: 'baseline',
      kind: 'denial',
      title: 'revoked client',
      content: 'revoked-client-token',
    },
    clientExpired: {
      user: 'baseline',
      kind: 'denial',
      title: 'expired client',
      content: 'expired-client-token',
    },
    readRevoked: {
      user: 'baseline',
      kind: 'denial',
      title: 'revoked read',
      content: 'revoked-read-token',
    },
    searchExpired: {
      user: 'baseline',
      kind: 'denial',
      title: 'expired search',
      content: 'expired-search-token',
    },
  };
  const memories = Object.entries(slots).map(([slot, row]) => ({
    slot,
    id: memoryId(runId, slot),
    workspaceId: workspaceId(
      runId,
      slot === 'a1' || slot === 'a2' || slot === 'a3'
        ? 'baseline'
        : slot === 'b1' || slot === 'b2' || slot === 'b3'
          ? 'second'
          : slot,
    ),
    tag: row.kind === 'positive' ? positiveTag : denialTag,
    createdAt: row.createdAt ?? '2026-09-29T00:00:00.000Z',
    ...row,
  }));
  return {
    runId,
    positiveTag,
    denialTag,
    memories,
    memoryIds: memories.map((row) => row.id),
    workspaceIds: [...new Set(memories.map((row) => row.workspaceId))],
    expiresAt: FAR_EXPIRY,
  };
}

function memory(manifest, slot) {
  const found = manifest.memories.find((row) => row.slot === slot);
  if (found === undefined) throw coded('fixture_missing');
  return found;
}

async function seed(db, manifest) {
  await db.query(
    `insert into policy_lab.principals (principal_id, principal_kind, identity_eligibility)
     values ($1, 'human', 'verified'), ($2, 'human', 'verified'), ($3, 'human', 'denied')`,
    [BASELINE_USER_ID, SECOND_USER_ID, DENIED_PRINCIPAL_ID],
  );
  await db.query(
    `insert into policy_lab.clients (client_id, state, valid_until) values
      ($1, 'active', $4),
      ($2, 'revoked', $4),
      ($3, 'expired', $5)`,
    [LOCAL_B_CLIENT_ID, REVOKED_CLIENT_ID, EXPIRED_CLIENT_ID, FAR_EXPIRY, PAST_EXPIRY],
  );
  const positive = ['baseline', 'second'];
  for (const name of positive) {
    const principal = name === 'baseline' ? BASELINE_USER_ID : SECOND_USER_ID;
    const workspace = workspaceId(manifest.runId, name);
    await db.query(
      `insert into policy_lab.memberships
        (principal_id, client_id, workspace_id, state, valid_until)
       values ($1, $2, $3, 'active', $4)`,
      [principal, LOCAL_B_CLIENT_ID, workspace, FAR_EXPIRY],
    );
    for (const capability of ['memory:read', 'memory:search']) {
      await db.query(
        `insert into policy_lab.capability_grants
          (principal_id, client_id, workspace_id, capability, state, valid_until)
         values ($1, $2, $3, $4, 'active', $5)`,
        [principal, LOCAL_B_CLIENT_ID, workspace, capability, FAR_EXPIRY],
      );
    }
  }
  const denial = [
    [
      'membershipRevoked',
      BASELINE_USER_ID,
      LOCAL_B_CLIENT_ID,
      'revoked',
      FAR_EXPIRY,
      'active',
      FAR_EXPIRY,
      'active',
      FAR_EXPIRY,
    ],
    [
      'membershipExpired',
      BASELINE_USER_ID,
      LOCAL_B_CLIENT_ID,
      'expired',
      PAST_EXPIRY,
      'active',
      FAR_EXPIRY,
      'active',
      FAR_EXPIRY,
    ],
    [
      'clientRevoked',
      BASELINE_USER_ID,
      REVOKED_CLIENT_ID,
      'active',
      FAR_EXPIRY,
      'active',
      FAR_EXPIRY,
      'active',
      FAR_EXPIRY,
    ],
    [
      'clientExpired',
      BASELINE_USER_ID,
      EXPIRED_CLIENT_ID,
      'active',
      FAR_EXPIRY,
      'active',
      FAR_EXPIRY,
      'active',
      FAR_EXPIRY,
    ],
    [
      'readRevoked',
      BASELINE_USER_ID,
      LOCAL_B_CLIENT_ID,
      'active',
      FAR_EXPIRY,
      'revoked',
      FAR_EXPIRY,
      'active',
      FAR_EXPIRY,
    ],
    [
      'searchExpired',
      BASELINE_USER_ID,
      LOCAL_B_CLIENT_ID,
      'active',
      FAR_EXPIRY,
      'active',
      FAR_EXPIRY,
      'expired',
      PAST_EXPIRY,
    ],
    [
      'denied',
      DENIED_PRINCIPAL_ID,
      LOCAL_B_CLIENT_ID,
      'active',
      FAR_EXPIRY,
      'active',
      FAR_EXPIRY,
      'active',
      FAR_EXPIRY,
    ],
  ];
  for (const [
    slot,
    principal,
    clientId,
    membershipState,
    membershipUntil,
    readState,
    readUntil,
    searchState,
    searchUntil,
  ] of denial) {
    const workspace = memory(manifest, slot).workspaceId;
    await db.query(
      `insert into policy_lab.memberships
        (principal_id, client_id, workspace_id, state, valid_until)
       values ($1, $2, $3, $4, $5)`,
      [principal, clientId, workspace, membershipState, membershipUntil],
    );
    await db.query(
      `insert into policy_lab.capability_grants
        (principal_id, client_id, workspace_id, capability, state, valid_until)
       values ($1, $2, $3, 'memory:read', $4, $5),
              ($1, $2, $3, 'memory:search', $6, $7)`,
      [principal, clientId, workspace, readState, readUntil, searchState, searchUntil],
    );
  }
  for (const row of manifest.memories) {
    await db.query(
      `insert into policy_lab.memories
        (memory_id, workspace_id, title, content, created_at, provenance_summary, tags)
       values ($1, $2, $3, $4, $5, 'synthetic retained-lab fixture', $6)`,
      [row.id, row.workspaceId, row.title, row.content, row.createdAt, [row.tag]],
    );
  }
}

async function countIds(db, ids) {
  const result = await db.query(
    `select count(*)::int as count from policy_lab.memories where memory_id = any($1::text[])`,
    [ids],
  );
  return result.rows[0].count;
}

async function cleanup(db, manifest) {
  await db.query(`delete from policy_lab.memories where memory_id = any($1::text[])`, [
    manifest.memoryIds,
  ]);
  await db.query(`delete from policy_lab.capability_grants where workspace_id = any($1::text[])`, [
    manifest.workspaceIds,
  ]);
  await db.query(`delete from policy_lab.memberships where workspace_id = any($1::text[])`, [
    manifest.workspaceIds,
  ]);
  await db.query(`delete from policy_lab.clients where client_id = any($1::text[])`, [
    [REVOKED_CLIENT_ID, EXPIRED_CLIENT_ID],
  ]);
  await db.query(`delete from policy_lab.principals where principal_id = $1`, [
    DENIED_PRINCIPAL_ID,
  ]);
}

async function retainedBaseline(db) {
  const principals = await db.query(
    `select count(*)::int as count from policy_lab.principals
     where principal_id = any($1::uuid[])`,
    [[BASELINE_USER_ID, SECOND_USER_ID]],
  );
  const client = await db.query(
    `select count(*)::int as count from policy_lab.clients where client_id = $1`,
    [LOCAL_B_CLIENT_ID],
  );
  return principals.rows[0].count === 2 && client.rows[0].count === 1;
}

function idsOf(payload) {
  if (payload === null || typeof payload !== 'object' || !Array.isArray(payload.rows)) {
    throw coded('malformed_read');
  }
  return payload.rows.map((row) => row.id);
}

async function getRecord(db, claim, id) {
  const payload = await readRpc(
    db,
    claim,
    `select memory.authorized_memory_get_v1($1::text) as result`,
    [id],
  );
  if (payload === null || typeof payload !== 'object' || !Object.hasOwn(payload, 'record')) {
    throw coded('malformed_read');
  }
  return payload.record;
}

async function listRecent(db, claim, tag, limit, cursor) {
  return readRpc(
    db,
    claim,
    `select memory.authorized_memory_list_recent_v1($1::jsonb, $2::int, $3::text) as result`,
    [JSON.stringify({ tags: [tag] }), limit, cursor],
  );
}

async function search(db, claim, tag, query) {
  return readRpc(
    db,
    claim,
    `select memory.authorized_memory_search_v1($1::text, 'text', $2::jsonb, 20, null) as result`,
    [query, JSON.stringify({ tags: [tag] })],
  );
}

function row(id, pass, reason, extra = {}) {
  return { id, executed: true, pass, reason, ...extra };
}

async function prove(db, manifest, rows) {
  const expiryRoom = Date.parse(FAR_EXPIRY) - Date.now();
  if (expiryRoom < 24 * 60 * 60 * 1000) throw coded('fixture_expiry_window');
  const coexist = await db.query(
    `select principal_id from policy_lab.capability_grants
     where client_id = $1 and capability = 'memory:read' and state = 'active'
       and principal_id = any($2::uuid[])
     group by principal_id`,
    [LOCAL_B_CLIENT_ID, [BASELINE_USER_ID, SECOND_USER_ID]],
  );
  if (coexist.rows.length !== 2) throw coded('grants_not_coexistent');

  const baseline = claims(BASELINE_USER_ID, LOCAL_B_CLIENT_ID);
  const second = claims(SECOND_USER_ID, LOCAL_B_CLIENT_ID);
  const own = [
    ['baseline_get', baseline, 'a1', 'a2', 'a3'],
    ['second_get', second, 'b1', 'b2', 'b3'],
  ];
  for (const [prefix, claim, first, secondSlot, third] of own) {
    const record = await getRecord(db, claim, memory(manifest, third).id);
    const pass = record?.id === memory(manifest, third).id && record.content === HOSTILE_SENTINEL;
    rows.push(row(`${prefix}`, pass, pass ? 'own_record' : 'own_record_missed'));
    if (!pass) throw coded('own_record_missed');
    const listed = idsOf(await listRecent(db, claim, manifest.positiveTag, 25, null));
    const expected = [third, secondSlot, first].map((slot) => memory(manifest, slot).id);
    const listPass = listed.join() === expected.join();
    rows.push(
      row(`${prefix.replace('_get', '_list')}`, listPass, listPass ? 'own_only' : 'list_mismatch'),
    );
    if (!listPass) throw coded('list_mismatch');
    const found = idsOf(await search(db, claim, manifest.positiveTag, SHARED_TOKEN));
    const searchPass = found.length === 1 && found[0] === memory(manifest, first).id;
    rows.push(
      row(
        `${prefix.replace('_get', '_search')}`,
        searchPass,
        searchPass ? 'own_match' : 'search_mismatch',
      ),
    );
    if (!searchPass) throw coded('search_mismatch');
  }

  const pages = [];
  let cursor = null;
  for (let index = 0; index < 3; index += 1) {
    const payload = await listRecent(db, baseline, manifest.positiveTag, 1, cursor);
    const pageIds = idsOf(payload);
    if (pageIds.length !== 1) throw coded('pagination_incomplete');
    pages.push(pageIds[0]);
    cursor = payload.nextCursor ?? null;
    if (index < 2 && typeof cursor !== 'string') throw coded('pagination_incomplete');
  }
  const pagePass =
    cursor === null &&
    pages.join() === ['a3', 'a2', 'a1'].map((slot) => memory(manifest, slot).id).join();
  rows.push(row('pagination_complete', pagePass, pagePass ? 'complete' : 'pagination_incomplete'));
  if (!pagePass) throw coded('pagination_incomplete');

  const foreign = await getRecord(db, baseline, memory(manifest, 'b1').id);
  const missing = await getRecord(
    db,
    baseline,
    memory(manifest, 'a1').id.replace('_a1', '_missing'),
  );
  const foreignPass = foreign === null && missing === null;
  rows.push(row('foreign_get_null', foreignPass, foreignPass ? 'record_null' : 'foreign_visible'));
  if (!foreignPass) throw coded('foreign_visible');

  const foreignSearch = idsOf(await search(db, baseline, manifest.positiveTag, SECOND_ONLY_TOKEN));
  const reverseSearch = idsOf(await search(db, second, manifest.positiveTag, BASELINE_ONLY_TOKEN));
  const emptyPass = foreignSearch.length === 0 && reverseSearch.length === 0;
  rows.push(row('foreign_only_search_empty', emptyPass, emptyPass ? 'empty' : 'foreign_match'));
  if (!emptyPass) throw coded('foreign_match');

  const firstPage = await listRecent(db, baseline, manifest.positiveTag, 1, null);
  let cursorRefused = false;
  try {
    await listRecent(db, second, manifest.positiveTag, 1, firstPage.nextCursor);
  } catch (error) {
    cursorRefused = error?.code === '22023';
  }
  rows.push(
    row(
      'cross_user_cursor_refused',
      cursorRefused,
      cursorRefused ? 'invalid_cursor' : 'cursor_accepted',
    ),
  );
  if (!cursorRefused) throw coded('cursor_accepted');

  const target = memory(manifest, 'a1').id;
  const [left, right] = await Promise.all([
    getRecord(db, baseline, target),
    getRecord(db, baseline, target),
  ]);
  const again = await getRecord(db, baseline, target);
  const concurrentPass = left?.id === target && right?.id === target && again?.id === target;
  rows.push(
    row('bounded_concurrent_retry', concurrentPass, concurrentPass ? 'same_id' : 'retry_mismatch'),
  );
  if (!concurrentPass) throw coded('retry_mismatch');

  const denied = await getRecord(
    db,
    claims(DENIED_PRINCIPAL_ID, LOCAL_B_CLIENT_ID),
    memory(manifest, 'denied').id,
  );
  rows.push(row('denied_identity', denied === null, denied === null ? 'denied' : 'denied_visible'));
  if (denied !== null) throw coded('denied_visible');

  const oneVariable = [
    ['revoked_membership', 'membershipRevoked', claims(BASELINE_USER_ID, LOCAL_B_CLIENT_ID)],
    ['expired_membership', 'membershipExpired', claims(BASELINE_USER_ID, LOCAL_B_CLIENT_ID)],
    ['revoked_client', 'clientRevoked', claims(BASELINE_USER_ID, REVOKED_CLIENT_ID)],
    ['expired_client', 'clientExpired', claims(BASELINE_USER_ID, EXPIRED_CLIENT_ID)],
    ['revoked_read_grant', 'readRevoked', claims(BASELINE_USER_ID, LOCAL_B_CLIENT_ID)],
  ];
  for (const [id, slot, claim] of oneVariable) {
    const record = await getRecord(db, claim, memory(manifest, slot).id);
    const pass = record === null;
    rows.push(row(id, pass, pass ? 'denied' : 'denial_visible'));
    if (!pass) throw coded('denial_visible');
  }

  const searchStill = memory(manifest, 'searchExpired');
  const readable = await getRecord(db, baseline, searchStill.id);
  const hidden = idsOf(await search(db, baseline, manifest.denialTag, 'expired-search-token'));
  const splitPass = readable?.id === searchStill.id && hidden.length === 0;
  rows.push(
    row(
      'expired_search_leaves_get',
      splitPass,
      splitPass ? 'read_active_search_expired' : 'grant_split_failed',
    ),
  );
  if (!splitPass) throw coded('grant_split_failed');

  const ignored = await getRecord(
    db,
    claims(BASELINE_USER_ID, LOCAL_B_CLIENT_ID, { metadata: 'user' }),
    memory(manifest, 'a1').id,
  );
  rows.push(
    row(
      'user_metadata_ignored',
      ignored === null,
      ignored === null ? 'ignored' : 'user_metadata_accepted',
    ),
  );
  if (ignored !== null) throw coded('user_metadata_accepted');

  const fallback = await getRecord(
    db,
    claims(BASELINE_USER_ID, LOCAL_B_CLIENT_ID, { metadata: 'app' }),
    memory(manifest, 'a1').id,
  );
  const fallbackPass = fallback?.id === memory(manifest, 'a1').id;
  rows.push(
    row(
      'app_metadata_client_fallback',
      fallbackPass,
      fallbackPass ? 'app_metadata' : 'fallback_missed',
    ),
  );
  if (!fallbackPass) throw coded('fallback_missed');

  let anonDenied = false;
  try {
    await db.transaction(async (tx) => {
      await tx.exec('set local role anon');
      await tx.query('select memory_id from policy_lab.memories');
    });
  } catch (error) {
    anonDenied = error?.code === '42501';
  }
  rows.push(row('anon_select_denied', anonDenied, anonDenied ? '42501' : 'anon_read'));
  if (!anonDenied) throw coded('anon_read');

  let insertDenied = false;
  try {
    await asUser(
      db,
      baseline,
      `insert into policy_lab.memories (memory_id, workspace_id, title)
       values ('mem_should_not_insert', 'ws-no', 'no')`,
      [],
    );
  } catch (error) {
    insertDenied = error?.code === '42501';
  }
  rows.push(
    row('authenticated_insert_denied', insertDenied, insertDenied ? '42501' : 'insert_allowed'),
  );
  if (!insertDenied) throw coded('insert_allowed');

  rows.push({
    id: 'same_user_different_b_client',
    executed: false,
    pass: false,
    label: 'not_executed',
    reason: 'not_executed',
  });
}

function receiptShell(manifest, fields) {
  return {
    type: 'receipt',
    packet: 'ari-memory-read-lab',
    version: LAB_VERSION,
    acceptance: false,
    hostedContact: false,
    executedByWriter: true,
    listenerCount: 0,
    mode: 'local-synthetic',
    hostedProjectPinned: HOSTED_PROJECT_REF,
    hostedExecution: 'refused',
    provenanceLabel: 'mc1681:jesse_via_warden',
    d1: 'not_executed',
    d2: 'not_executed',
    hookBypass: 'excluded_from_first_hosted_batch',
    directTokenA: 'excluded_from_first_hosted_batch',
    adminCredentialUsed: false,
    issuanceStatus: 'not_required',
    runId: manifest.runId,
    head: git(['rev-parse', 'HEAD']),
    tree: git(['rev-parse', 'HEAD^{tree}']),
    installerSha256: sqlSha256(installerSql()),
    expiresAt: manifest.expiresAt,
    subjectProvenance: {
      baselineUserId: BASELINE_USER_ID,
      secondUserId: SECOND_USER_ID,
      secondUserIdentity: SECOND_USER_IDENTITY,
      bClientId: LOCAL_B_CLIENT_ID,
      bClientBinding: 'local_synthetic_stand_in',
      sessionIds: [],
    },
    ...fields,
  };
}

export async function runLocalLab() {
  const runId = randomUUID();
  const manifest = buildManifest(runId);
  const db = await openLabDatabase();
  const rows = [];
  let proofCode;
  let ownershipBefore = 0;
  try {
    await seed(db, manifest);
    ownershipBefore = await countIds(db, manifest.memoryIds);
    if (ownershipBefore !== manifest.memoryIds.length) throw coded('ownership_before_mismatch');
    await prove(db, manifest, rows);
  } catch (error) {
    proofCode = typeof error?.code === 'string' ? error.code : 'child_failed';
  }
  let cleanupStatus = 'unresolved';
  let ownershipAfter = null;
  let baselineRetained = false;
  try {
    await cleanup(db, manifest);
    ownershipAfter = await countIds(db, manifest.memoryIds);
    baselineRetained = await retainedBaseline(db);
    cleanupStatus = ownershipAfter === 0 && baselineRetained ? 'confirmed' : 'unresolved';
  } catch {
    cleanupStatus = 'unresolved';
  }
  await db.close();
  const executed = rows.filter((item) => item.executed === true);
  const rowsPass =
    proofCode === undefined &&
    executed.length > 0 &&
    executed.every((item) => item.pass === true) &&
    cleanupStatus === 'confirmed';
  return receiptShell(manifest, {
    rowsPass,
    reason: rowsPass ? 'local_synthetic_proved' : (proofCode ?? 'cleanup_unconfirmed'),
    cleanupStatus,
    ownershipBefore,
    ownershipAfter,
    baselineRetained,
    positiveMemoryCount: manifest.memories.filter((item) => item.kind === 'positive').length,
    rows,
  });
}

async function main() {
  const command = process.argv[2] ?? 'plan';
  if (command === 'plan') {
    process.stdout.write(`${JSON.stringify(plan(), null, 2)}\n`);
    return;
  }
  if (command !== 'run') {
    process.stderr.write('usage: node scripts/ari-memory-read-lab.mjs [plan|run]\n');
    process.exitCode = 2;
    return;
  }
  let release;
  try {
    assertLocalOnly(process.env);
    assertCleanWorktree();
    release = acquireControllerLock();
    const receipt = await runLocalLab();
    process.stdout.write(`${JSON.stringify(receipt)}\n`);
    if (receipt.rowsPass !== true || receipt.acceptance !== false) process.exitCode = 2;
  } catch (error) {
    const failure = {
      type: 'receipt',
      packet: 'ari-memory-read-lab',
      acceptance: false,
      hostedContact: false,
      rowsPass: false,
      reason: typeof error?.code === 'string' ? error.code : 'child_failed',
      listenerCount: 0,
    };
    process.stdout.write(`${JSON.stringify(failure)}\n`);
    process.exitCode = 2;
  } finally {
    release?.();
  }
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(invokedPath).href) {
  await main();
}
