import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { PGlite, type Transaction } from '@electric-sql/pglite';
import { pgcrypto } from '@electric-sql/pglite/contrib/pgcrypto';
import { uuid_ossp } from '@electric-sql/pglite/contrib/uuid_ossp';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { STORAGE_SIGNED_URL_TTL_SECONDS } from '../packages/contracts/src/storage-bounds.js';
import { createPathPrefixStoragePrincipalResolver } from '../packages/server/src/storage-principal.js';
import {
  createStorageReadTools,
  prepareStorageMcpRegistration,
} from '../packages/server/src/storage-read-tools.js';
import {
  createUserScopedStorageClient,
  STORAGE_RPC,
  type UserScopedStorageClient,
} from '../packages/server/src/user-scoped-storage-client.js';
import { applyRepoMigrations, applySupabaseStub } from './support/pglite-supabase-stub.js';

/**
 * Issue #123 S4 end to end, option A (assumes option A; pending RLS layout decision).
 *
 * Real storage tools -> real user-scoped HTTP client -> a small in-process stand-in for the
 * Storage API and the Data API -> PGlite with every repository migration, the synthetic
 * Supabase stub and the hosted protect_delete trigger. Every request runs as `authenticated`
 * with the caller's own claims, so RLS decides. Two humans x two clients, plus one delegated
 * agent. Synthetic identifiers only; no Supabase project is involved.
 */

const REPO_ROOT = new URL('..', import.meta.url).pathname;
const ORIGIN = 'https://storage-e2e.invalid';
const BUCKET = 'mcp-user-storage';
const PUBLISHABLE_KEY = 'sb_publishable_synthetic';
/** The Data API schemas supabase/config.toml exposes, read from the file itself. */
const EXPOSED_SCHEMAS: readonly string[] = JSON.parse(
  /^\[api\][\s\S]*?^schemas = (\[[^\]]*\])$/m.exec(
    readFileSync(new URL('../supabase/config.toml', import.meta.url), 'utf8'),
  )?.[1] ?? '[]',
);
const NOW = Date.parse('2026-10-27T16:00:00.000Z');

const HUMAN_A = 'a1a1a1a1-0000-4000-8000-000000000001';
const HUMAN_B = 'b2b2b2b2-0000-4000-8000-000000000002';
const AGENT_A = 'a1a1a1a1-0000-4000-8000-0000000000a1';
const CLIENT_1 = 'e2e-client-1';
const CLIENT_2 = 'e2e-client-2';

const b64url = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const userToken = (sub: string, clientId: string) =>
  `${b64url({ alg: 'none', typ: 'JWT' })}.${b64url({
    sub,
    role: 'authenticated',
    app_metadata: { client_id: clientId },
  })}.c3ludGhldGlj`;
const text = (value: string) => Buffer.from(value).toString('base64');

interface Claims {
  readonly sub: string;
  readonly role: string;
}

function json(status: number, value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const denied = () => json(400, { statusCode: '403', error: 'Unauthorized' });
const notFound = () => json(400, { statusCode: '404', error: 'not_found' });

/**
 * Minimal stand-in for the two upstream HTTP surfaces the client uses. It does no
 * authorization of its own: each request becomes SQL run as `authenticated` with the
 * caller's JWT claims, as the real services do, so the repository's RLS decides.
 */
class PgliteStorageApi {
  readonly blobs = new Map<string, Uint8Array>();
  readonly signed = new Map<string, { name: string; expiresAt: number }>();
  clock = NOW;

  constructor(private readonly db: PGlite) {}

  private async asCaller<T>(claims: Claims, run: (tx: Transaction) => Promise<T>): Promise<T> {
    return this.db.transaction(async (tx) => {
      await tx.query(`select set_config('request.jwt.claims', $1, true)`, [JSON.stringify(claims)]);
      await tx.exec('set local role authenticated');
      return run(tx);
    });
  }

  readonly fetch: typeof globalThis.fetch = async (input, init) => {
    const url = new URL(String(input));
    const method = init?.method ?? 'GET';
    const headers = new Headers(init?.headers);
    if (url.origin !== ORIGIN) return json(404, {});

    // Signed URLs carry no user token, exactly like the real service.
    const signedPath = url.pathname.match(/^\/storage\/v1\/object\/sign\/([^/]+)\/(.+)$/);
    if (method === 'GET' && signedPath !== null) {
      const entry = this.signed.get(url.searchParams.get('token') ?? '');
      const name = signedPath[2]?.split('/').map(decodeURIComponent).join('/');
      if (entry === undefined || entry.name !== name || this.clock >= entry.expiresAt) {
        return json(400, { statusCode: '400', error: 'InvalidJWT' });
      }
      const bytes = this.blobs.get(entry.name);
      return bytes === undefined ? notFound() : new Response(bytes, { status: 200 });
    }

    if (headers.get('apikey') !== PUBLISHABLE_KEY) return json(401, {});
    const bearer = headers.get('authorization')?.replace(/^Bearer /, '') ?? '';
    const claims = JSON.parse(Buffer.from(bearer.split('.')[1] ?? '', 'base64url').toString());
    if (claims.role !== 'authenticated') return json(401, {});
    const body = init?.body;

    // PostgREST resolves /rpc/<name> in the Content-Profile schema, which must be exposed.
    const rpc = url.pathname.match(/^\/rest\/v1\/rpc\/([a-z0-9_]+)$/);
    if (rpc !== null) {
      const profile = headers.get('content-profile') ?? 'public';
      if (!EXPOSED_SCHEMAS.includes(profile)) return json(406, {});
      if (profile !== 'public' || !Object.values(STORAGE_RPC).includes(rpc[1] as never)) {
        return json(404, {});
      }
      const value = await this.asCaller(claims, async (tx) => {
        const result = await tx.query<{ v: unknown }>(`select public.${rpc[1]}() as v`);
        return result.rows[0]?.v ?? null;
      });
      return json(200, value);
    }

    if (method === 'POST' && url.pathname === `/storage/v1/object/list/${BUCKET}`) {
      const request = JSON.parse(String(body));
      const prefix = `${request.prefix}/`;
      const rows = await this.asCaller(claims, async (tx) => {
        const result = await tx.query<{
          name: string;
          id: string;
          metadata: unknown;
          created_at: Date;
        }>(
          `select name, id::text, metadata, created_at from storage.objects
           where bucket_id = $1 and starts_with(name, $2) order by name`,
          [BUCKET, prefix],
        );
        return result.rows;
      });
      const children = new Map<string, unknown>();
      for (const row of rows) {
        const rest = row.name.slice(prefix.length);
        const [head = ''] = rest.split('/');
        if (children.has(head)) continue;
        children.set(
          head,
          rest.includes('/')
            ? { name: head, id: null, metadata: null, updated_at: null }
            : {
                name: head,
                id: row.id,
                metadata: row.metadata,
                updated_at: row.created_at.toISOString(),
              },
        );
      }
      const entries = [...children.entries()]
        .toSorted(([a], [b]) => (a < b ? -1 : 1))
        .map(([, entry]) => entry);
      return json(200, entries.slice(request.offset, request.offset + request.limit));
    }

    const objectPath = url.pathname.match(
      /^\/storage\/v1\/object(?:\/(authenticated|sign))?\/([^/]+)(?:\/(.+))?$/,
    );
    if (objectPath === null || objectPath[2] !== BUCKET) return notFound();
    const [, mode, , encodedName] = objectPath;
    const name = encodedName?.split('/').map(decodeURIComponent).join('/');

    if (mode === 'authenticated' || mode === 'sign') {
      const row = await this.asCaller(claims, async (tx) => {
        const result = await tx.query<{
          metadata: { size: number; mimetype: string };
          created_at: Date;
        }>('select metadata, created_at from storage.objects where bucket_id = $1 and name = $2', [
          BUCKET,
          name,
        ]);
        return result.rows[0];
      });
      if (row === undefined || name === undefined) return notFound();
      if (mode === 'sign') {
        const token = randomBytes(16).toString('hex');
        const expiresIn = Number(JSON.parse(String(body)).expiresIn);
        this.signed.set(token, { name, expiresAt: this.clock + expiresIn * 1000 });
        return json(200, { signedURL: `/object/sign/${BUCKET}/${encodedName}?token=${token}` });
      }
      const responseHeaders = {
        'content-length': String(row.metadata.size),
        'content-type': row.metadata.mimetype,
        'last-modified': row.created_at.toUTCString(),
      };
      if (method === 'HEAD') return new Response(null, { status: 200, headers: responseHeaders });
      return new Response(this.blobs.get(name) ?? new Uint8Array(), {
        status: 200,
        headers: responseHeaders,
      });
    }

    if (method === 'POST' && name !== undefined) {
      if (headers.get('x-upsert') !== 'false') return json(400, {});
      const bytes = new Uint8Array(body as Uint8Array);
      const mimeType = headers.get('content-type') ?? '';
      const bucket = await this.db.query<{ allowed: string[]; limit: number }>(
        'select allowed_mime_types as allowed, file_size_limit::int as limit from storage.buckets where id = $1',
        [BUCKET],
      );
      const rule = bucket.rows[0];
      if (rule === undefined || !rule.allowed.includes(mimeType) || bytes.byteLength > rule.limit) {
        return json(400, { statusCode: '415', error: 'invalid_mime_type' });
      }
      try {
        const id = await this.asCaller(claims, async (tx) => {
          const result = await tx.query<{ id: string }>(
            `insert into storage.objects (bucket_id, name, owner_id, metadata)
             values ($1, $2, $3, jsonb_build_object('size', $4::int, 'mimetype', $5::text))
             returning id::text`,
            [BUCKET, name, claims.sub, bytes.byteLength, mimeType],
          );
          return result.rows[0]?.id;
        });
        this.blobs.set(name, bytes);
        return json(200, { Key: `${BUCKET}/${name}`, Id: id });
      } catch (error) {
        const code = (error as { code?: string }).code;
        if (code === '42501') return denied();
        if (code === '23505') return json(409, { statusCode: '409', error: 'Duplicate' });
        throw error;
      }
    }

    if (method === 'DELETE' && name === undefined) {
      const prefixes: string[] = JSON.parse(String(body)).prefixes;
      // The Storage API sets the delete flag for its own deletes; RLS still decides.
      const removed = await this.asCaller(claims, async (tx) => {
        await tx.query(`select set_config('storage.allow_delete_query', 'true', true)`);
        const result = await tx.query<{ name: string; id: string }>(
          `delete from storage.objects where bucket_id = $1 and name = any($2::text[])
           returning name, id::text`,
          [BUCKET, prefixes],
        );
        return result.rows;
      });
      for (const row of removed) this.blobs.delete(row.name);
      return json(
        200,
        removed.map((row) => ({ ...row, bucket_id: BUCKET })),
      );
    }
    return notFound();
  };
}

let db: PGlite;
let api: PgliteStorageApi;
let callSequence = 0;

function rawClient(sub: string, clientId: string): UserScopedStorageClient {
  return createUserScopedStorageClient({
    origin: ORIGIN,
    bucket: BUCKET,
    credentials: {
      projectPublishableKey: PUBLISHABLE_KEY,
      userAccessToken: userToken(sub, clientId),
    },
    fetch: api.fetch,
  });
}

/** One MCP session: registration exactly as the server does it, then the registered tools. */
async function session(sub: string, clientId: string) {
  const client = rawClient(sub, clientId);
  const prepared = await prepareStorageMcpRegistration(
    { client, now: () => NOW },
    { principalId: sub },
  );
  if (prepared.status !== 'registered') {
    return { status: prepared.status, capabilities: prepared.capabilities, toolNames: [] } as const;
  }
  const scope = await createPathPrefixStoragePrincipalResolver(
    client.fetchStoragePrincipal,
    client.tokenSubject,
  ).resolve({ principalId: sub }, new AbortController().signal);
  const tools = createStorageReadTools({
    client,
    scope,
    capabilities: prepared.capabilities,
    toolNames: prepared.toolNames,
    now: () => NOW,
  });
  // A distinct governor key per call keeps the process-wide rate limiter out of this test.
  const context = () => {
    callSequence += 1;
    return { principalId: `e2e-call-${callSequence}`, now: () => NOW };
  };
  return {
    status: prepared.status,
    capabilities: prepared.capabilities,
    toolNames: prepared.toolNames,
    put: (key: string, content: string, mimeType = 'text/plain') =>
      tools.put({ key, mimeType, contentBase64: text(content) }, context()),
    get: (key: string, delivery: 'auto' | 'inline' | 'signed_url' = 'inline') =>
      tools.get({ key, delivery }, context()),
    list: (prefix = '') => tools.list({ prefix }, context()),
    remove: (key: string) => tools.delete({ key }, context()),
  } as const;
}

type Session = Extract<Awaited<ReturnType<typeof session>>, { put: unknown }>;

async function open(sub: string, clientId: string): Promise<Session> {
  const opened = await session(sub, clientId);
  if (opened.status !== 'registered') throw new Error(`session not registered: ${opened.status}`);
  return opened;
}

function errorCode(output: unknown): string | undefined {
  const value = output as { ok: boolean; error?: { code: string } };
  return value.ok ? undefined : value.error?.code;
}

function content(output: unknown): string | undefined {
  const value = output as { ok: boolean; record?: { contentBase64?: string } };
  return value.ok && value.record?.contentBase64 !== undefined
    ? Buffer.from(value.record.contentBase64, 'base64').toString()
    : undefined;
}

function keys(output: unknown): string[] {
  const value = output as { ok: boolean; items?: Array<{ key: string }> };
  return value.ok ? (value.items ?? []).map((item) => item.key) : [];
}

async function objectNames(): Promise<string[]> {
  const result = await db.query<{ name: string }>('select name from storage.objects order by name');
  return result.rows.map((row) => row.name);
}

beforeAll(async () => {
  db = new PGlite({ extensions: { pgcrypto, uuid_ossp } });
  await applySupabaseStub(db, { protectDelete: true });
  await applyRepoMigrations(db, REPO_ROOT);
  await db.exec(`
    insert into policy_lab.principals (principal_id, principal_kind, identity_eligibility) values
      ('${HUMAN_A}', 'human', 'verified'), ('${HUMAN_B}', 'human', 'verified'),
      ('${AGENT_A}', 'delegated_agent', 'verified');
    insert into policy_lab.clients (client_id, state, valid_until) values
      ('${CLIENT_1}', 'active', '2099-01-01'), ('${CLIENT_2}', 'active', '2099-01-01');
    insert into policy_lab.memberships (principal_id, client_id, workspace_id, state, valid_until)
    select p, c, 'e2e-ws', 'active', '2099-01-01'
    from unnest(array['${HUMAN_A}', '${HUMAN_B}', '${AGENT_A}']::uuid[]) as p
    cross join unnest(array['${CLIENT_1}', '${CLIENT_2}']) as c;
    insert into policy_lab.capability_grants (principal_id, client_id, workspace_id, capability, state, valid_until)
    select p, c, 'e2e-ws', cap, 'active', '2099-01-01'
    from unnest(array['${HUMAN_A}', '${HUMAN_B}', '${AGENT_A}']::uuid[]) as p
    cross join unnest(array['${CLIENT_1}', '${CLIENT_2}']) as c
    cross join unnest(array['storage:read', 'storage:write']) as cap;
    insert into policy_lab.storage_delegations
      (agent_principal_id, human_principal_id, client_id, capabilities, state, valid_until)
    values ('${AGENT_A}', '${HUMAN_A}', '${CLIENT_1}', array['storage:read', 'storage:write'],
            'active', now() + interval '1 hour');
  `);
  api = new PgliteStorageApi(db);
});

afterAll(async () => {
  await db?.close();
});

describe('storage option A end to end in PGlite: 2 humans x 2 clients + 1 delegated agent', () => {
  it('allow: every human session registers read and write tools and writes under its own prefix', async () => {
    for (const [sub, clientId] of [
      [HUMAN_A, CLIENT_1],
      [HUMAN_A, CLIENT_2],
      [HUMAN_B, CLIENT_1],
      [HUMAN_B, CLIENT_2],
    ] as const) {
      const s = await open(sub, clientId);
      expect(s.capabilities).toEqual(['storage:read', 'storage:write']);
      expect([...s.toolNames].sort()).toEqual([
        'storage_capabilities',
        'storage_delete',
        'storage_get',
        'storage_list',
        'storage_put',
      ]);
      const label = `${sub === HUMAN_A ? 'a' : 'b'}-${clientId.slice(-1)}`;
      expect(await s.put(`notes/${label}.md`, `# ${label}`, 'text/markdown')).toMatchObject({
        ok: true,
        record: { key: `notes/${label}.md` },
      });
    }
    expect(await objectNames()).toEqual([
      `${HUMAN_A}/notes/a-1.md`,
      `${HUMAN_A}/notes/a-2.md`,
      `${HUMAN_B}/notes/b-1.md`,
      `${HUMAN_B}/notes/b-2.md`,
    ]);
    // Same human through the other client sees the same prefix; the other human sees none of it.
    const a2 = await open(HUMAN_A, CLIENT_2);
    expect(content(await a2.get('notes/a-1.md'))).toBe('# a-1');
    expect(keys(await a2.list('notes'))).toEqual(['notes/a-1.md', 'notes/a-2.md']);
    const b1 = await open(HUMAN_B, CLIENT_1);
    expect(keys(await b1.list('notes'))).toEqual(['notes/b-1.md', 'notes/b-2.md']);
  });

  it("allow: the delegated agent works inside its human's prefix, through the delegation's client only", async () => {
    const agent = await open(AGENT_A, CLIENT_1);
    expect(agent.capabilities).toEqual(['storage:read', 'storage:write']);
    expect(await agent.put('agent/report.txt', 'agent report')).toMatchObject({ ok: true });
    expect(await objectNames()).toContain(`${HUMAN_A}/agent/report.txt`);
    expect((await objectNames()).some((name) => name.startsWith(`${AGENT_A}/`))).toBe(false);
    expect(content(await agent.get('notes/a-1.md'))).toBe('# a-1');
    // No delegation through client 2, even though the agent holds its own grants there.
    const elsewhere = await session(AGENT_A, CLIENT_2);
    expect(elsewhere.status).toBe('not_granted');
    expect(elsewhere.toolNames).toEqual([]);
  });

  it('denials: cross-principal, overwrite, wrong prefix and bounds, at the tool and the RLS layer', async () => {
    const b1 = await open(HUMAN_B, CLIENT_1);
    // Tool layer: a foreign id inside the key stays under the caller's own prefix.
    expect(errorCode(await b1.get(`${HUMAN_A}/notes/a-1.md`))).toBe('RESOURCE_UNAVAILABLE');
    expect(errorCode(await b1.remove(`${HUMAN_A}/notes/a-1.md`))).toBe('RESOURCE_UNAVAILABLE');
    // RLS layer: the raw client asking for the other human's real object key gets nothing.
    const rawB = rawClient(HUMAN_B, CLIENT_1);
    const signal = new AbortController().signal;
    expect(await rawB.downloadObject(`${HUMAN_A}/notes/a-1.md`, 1024, signal)).toBeNull();
    expect(await rawB.getObjectInfo(`${HUMAN_A}/notes/a-1.md`, signal)).toBeNull();
    expect(await rawB.deleteObject(`${HUMAN_A}/notes/a-1.md`, signal)).toBe(false);
    expect(
      await rawB.uploadObject(`${HUMAN_A}/planted.txt`, Buffer.from('x'), 'text/plain', signal),
    ).toBe(false);
    const rawAgent = rawClient(AGENT_A, CLIENT_1);
    expect(
      await rawAgent.uploadObject(`${AGENT_A}/own.txt`, Buffer.from('x'), 'text/plain', signal),
    ).toBe(false);
    expect(
      await rawAgent.uploadObject(`${HUMAN_B}/x.txt`, Buffer.from('x'), 'text/plain', signal),
    ).toBe(false);
    // No overwrite: the second put is refused and the first content stays.
    const a1 = await open(HUMAN_A, CLIENT_1);
    expect(errorCode(await a1.put('notes/a-1.md', 'replaced', 'text/markdown'))).toBe(
      'RESOURCE_UNAVAILABLE',
    );
    expect(content(await a1.get('notes/a-1.md'))).toBe('# a-1');
    // Bounds are refused before any upstream call.
    expect(errorCode(await a1.put('../escape.txt', 'x'))).toBe('INVALID_REQUEST');
    expect(errorCode(await a1.put('page.html', '<p>', 'text/html'))).toBe('INVALID_REQUEST');
    expect(await objectNames()).toEqual([
      `${HUMAN_A}/agent/report.txt`,
      `${HUMAN_A}/notes/a-1.md`,
      `${HUMAN_A}/notes/a-2.md`,
      `${HUMAN_B}/notes/b-1.md`,
      `${HUMAN_B}/notes/b-2.md`,
    ]);
  });

  it("the agent never exceeds its human's own grant", async () => {
    await db.exec(`update policy_lab.capability_grants set state = 'revoked'
      where principal_id = '${HUMAN_A}' and client_id = '${CLIENT_1}' and capability = 'storage:write'`);
    const agent = await session(AGENT_A, CLIENT_1);
    expect(agent.capabilities).toEqual(['storage:read']);
    expect(agent.toolNames).not.toContain('storage_put');
    await db.exec(`update policy_lab.capability_grants set state = 'active'
      where principal_id = '${HUMAN_A}' and client_id = '${CLIENT_1}' and capability = 'storage:write'`);
    expect((await session(AGENT_A, CLIENT_1)).capabilities).toEqual([
      'storage:read',
      'storage:write',
    ]);
  });

  it('revocation: the next call is denied, but an already-issued signed URL works until it expires', async () => {
    const agent = await open(AGENT_A, CLIENT_1);
    const issued = (await agent.get('agent/report.txt', 'signed_url')) as {
      ok: boolean;
      record: { signedUrl: string; expiresAt: string };
    };
    expect(issued.ok).toBe(true);
    expect(Date.parse(issued.record.expiresAt) - NOW).toBe(STORAGE_SIGNED_URL_TTL_SECONDS * 1000);
    expect(await (await api.fetch(issued.record.signedUrl)).text()).toBe('agent report');

    await db.exec(`update policy_lab.storage_delegations set state = 'revoked'
      where agent_principal_id = '${AGENT_A}'`);
    // The open session is denied on its next call, by the database.
    expect(errorCode(await agent.get('agent/report.txt'))).toBe('RESOURCE_UNAVAILABLE');
    expect(errorCode(await agent.put('agent/late.txt', 'late'))).toBe('RESOURCE_UNAVAILABLE');
    expect(errorCode(await agent.remove('agent/report.txt'))).toBe('RESOURCE_UNAVAILABLE');
    expect(keys(await agent.list('notes'))).toEqual([]);
    expect((await session(AGENT_A, CLIENT_1)).status).toBe('not_granted');

    // Revocation does NOT cancel the URL issued before it; only expiry does.
    api.clock = NOW + (STORAGE_SIGNED_URL_TTL_SECONDS - 1) * 1000;
    const stillValid = await api.fetch(issued.record.signedUrl);
    expect(stillValid.status).toBe(200);
    expect(await stillValid.text()).toBe('agent report');
    api.clock = NOW + STORAGE_SIGNED_URL_TTL_SECONDS * 1000;
    expect((await api.fetch(issued.record.signedUrl)).status).toBe(400);
    api.clock = NOW;
    expect(await objectNames()).toContain(`${HUMAN_A}/agent/report.txt`);
  });

  it('expiry: an expired delegation or an expired human grant denies on the next call', async () => {
    await db.exec(`update policy_lab.storage_delegations
      set state = 'active', valid_until = now() - interval '1 second'
      where agent_principal_id = '${AGENT_A}'`);
    expect((await session(AGENT_A, CLIENT_1)).status).toBe('not_granted');

    const b2 = await open(HUMAN_B, CLIENT_2);
    expect(content(await b2.get('notes/b-2.md'))).toBe('# b-2');
    await db.exec(`update policy_lab.capability_grants set valid_until = now() - interval '1 second'
      where principal_id = '${HUMAN_B}' and client_id = '${CLIENT_2}'`);
    expect(errorCode(await b2.get('notes/b-2.md'))).toBe('RESOURCE_UNAVAILABLE');
    expect(errorCode(await b2.put('notes/after.md', 'x', 'text/markdown'))).toBe(
      'RESOURCE_UNAVAILABLE',
    );
    expect(errorCode(await b2.remove('notes/b-2.md'))).toBe('RESOURCE_UNAVAILABLE');
    expect((await session(HUMAN_B, CLIENT_2)).status).toBe('not_granted');
    // The same human through the other client is unaffected.
    const b1 = await open(HUMAN_B, CLIENT_1);
    expect(content(await b1.get('notes/b-2.md'))).toBe('# b-2');
  });

  it('cleanup: owners delete through the tools; a bare SQL delete is refused by the hosted guard', async () => {
    const a1 = await open(HUMAN_A, CLIENT_1);
    for (const key of ['agent/report.txt', 'notes/a-1.md', 'notes/a-2.md']) {
      expect(await a1.remove(key)).toEqual({ ok: true, deleted: { key } });
    }
    expect(errorCode(await a1.remove('notes/a-1.md'))).toBe('RESOURCE_UNAVAILABLE');
    const b1 = await open(HUMAN_B, CLIENT_1);
    for (const key of ['notes/b-1.md', 'notes/b-2.md']) {
      expect(await b1.remove(key)).toEqual({ ok: true, deleted: { key } });
    }
    expect(await objectNames()).toEqual([]);
    expect(api.blobs.size).toBe(0);

    await db.exec(
      `insert into storage.objects (bucket_id, name) values ('${BUCKET}', '${HUMAN_A}/stray.txt')`,
    );
    await expect(db.exec('delete from storage.objects')).rejects.toMatchObject({
      code: '42501',
      message: 'Direct deletion from storage tables is not allowed. Use the Storage API instead.',
    });
    const removed = await db.transaction(async (tx) => {
      await tx.query(`select set_config('storage.allow_delete_query', 'true', true)`);
      return (await tx.query('delete from storage.objects returning name')).rows.length;
    });
    expect(removed).toBe(1);
    expect(await objectNames()).toEqual([]);
  });
});
