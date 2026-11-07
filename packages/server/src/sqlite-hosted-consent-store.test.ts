import { execFile } from 'node:child_process';
import {
  chmodSync,
  linkSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createHostedOAuthConsentHandler } from './hosted-oauth-consent.js';
import type { OAuthConsentApi } from './oauth-consent.js';
import {
  createSqliteHostedConsentChallengeStore,
  SQLITE_CONSENT_DATABASE_NAME,
  SQLITE_CONSENT_STORE_ERROR,
  type SqliteHostedConsentChallengeStore,
} from './sqlite-hosted-consent-store.js';

const USER = '11111111-1111-4111-8111-111111111111';
const CLIENT = '22222222-2222-4222-8222-222222222222';
const ROUTE = 'https://host.example.test/oauth/consent';
const CALLBACK = 'https://client.example.test/callback';
const AUTHORIZATION = 'synthetic-authorization';
const run = promisify(execFile);
const directories: string[] = [];
const connections: SqliteHostedConsentChallengeStore[] = [];
const nonce = (value: number) => Buffer.alloc(32, value).toString('base64url');
const challenge = (expiresAt = Date.now() + 60_000) => ({
  userId: USER,
  sessionId: 'opaque-host-session',
  authorizationId: AUTHORIZATION,
  viewSha256: 'a'.repeat(64),
  expiresAt,
});

function directory(): string {
  const path = realpathSync(mkdtempSync(join(tmpdir(), 'mcp-consent-')));
  directories.push(path);
  return path;
}

async function open(path: string, maxEntries = 2, now?: () => number) {
  const store = await createSqliteHostedConsentChallengeStore({
    directory: path,
    maxEntries,
    ...(now === undefined ? {} : { now }),
  });
  connections.push(store);
  return store;
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const store of connections.splice(0)) store.close();
  for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe.skipIf(process.platform === 'win32' || process.getuid === undefined)(
  'persistent SQLite consent challenges',
  () => {
    it('preserves pending metadata across connections/restart and never overwrites a live nonce', async () => {
      const path = directory();
      const first = await open(path);
      const second = await open(path);
      const original = challenge();
      expect(await first.putIfAbsent(nonce(1), original)).toBe(true);
      expect(await second.putIfAbsent(nonce(1), { ...original, sessionId: 'changed' })).toBe(false);
      first.close();
      second.close();
      const restarted = await open(path);
      expect(await restarted.take(nonce(1))).toEqual(original);
      expect(await restarted.take(nonce(1))).toBeUndefined();
    });

    it('verifies DELETE + EXTRA on every connection and retains consumed state after reopening', async () => {
      const { DatabaseSync } = await import('node:sqlite');
      const exec = DatabaseSync.prototype.exec;
      const profiles: { journal: unknown; synchronous: unknown }[] = [];
      vi.spyOn(DatabaseSync.prototype, 'exec').mockImplementation(function (
        this: InstanceType<typeof DatabaseSync>,
        sql: string,
      ) {
        exec.call(this, sql);
        if (sql.includes('PRAGMA main.synchronous = EXTRA;'))
          profiles.push({
            journal: this.prepare('PRAGMA main.journal_mode').get()?.journal_mode,
            synchronous: this.prepare('PRAGMA main.synchronous').get()?.synchronous,
          });
      });
      const path = directory();
      const first = await open(path);
      const second = await open(path);
      const value = challenge();
      expect(await first.putIfAbsent(nonce(1), value)).toBe(true);
      expect(await second.take(nonce(1))).toEqual(value);
      first.close();
      second.close();
      const reopened = await open(path);
      expect(await reopened.take(nonce(1))).toBeUndefined();
      expect(profiles).toEqual(
        Array.from({ length: 3 }, () => ({
          journal: 'delete',
          synchronous: 3,
        })),
      );
    });

    it.each([
      ['synchronous FULL', 'PRAGMA main.synchronous = FULL;'],
      ['journal MEMORY', 'PRAGMA main.journal_mode = MEMORY; PRAGMA main.synchronous = EXTRA;'],
    ] as const)(
      'fails closed before initialization if configuration yields %s',
      async (_, replacement) => {
        const { DatabaseSync } = await import('node:sqlite');
        const exec = DatabaseSync.prototype.exec;
        vi.spyOn(DatabaseSync.prototype, 'exec').mockImplementation(function (
          this: InstanceType<typeof DatabaseSync>,
          sql: string,
        ) {
          exec.call(this, sql.replace('PRAGMA main.synchronous = EXTRA;', replacement));
        });
        const path = directory();
        await expect(open(path)).rejects.toThrow(SQLITE_CONSENT_STORE_ERROR);
        const unchanged = new DatabaseSync(join(path, SQLITE_CONSENT_DATABASE_NAME));
        try {
          expect(
            unchanged
              .prepare(
                "SELECT count(*) AS count FROM sqlite_schema WHERE name LIKE 'mcp_consent_%'",
              )
              .get()?.count,
          ).toBe(0);
        } finally {
          unchanged.close();
        }
      },
    );

    it.each([
      ['synchronous FULL', 'PRAGMA main.synchronous = FULL;'],
      ['journal MEMORY', 'PRAGMA main.journal_mode = MEMORY;'],
    ] as const)('refuses consumption after a connection changes to %s', async (_, downgrade) => {
      const { DatabaseSync } = await import('node:sqlite');
      const exec = DatabaseSync.prototype.exec;
      let active: InstanceType<typeof DatabaseSync> | undefined;
      vi.spyOn(DatabaseSync.prototype, 'exec').mockImplementation(function (
        this: InstanceType<typeof DatabaseSync>,
        sql: string,
      ) {
        active = this;
        exec.call(this, sql);
      });
      const store = await open(directory());
      const value = challenge();
      await store.putIfAbsent(nonce(1), value);
      if (!active) throw new Error('Synthetic adapter connection was not observed.');
      active.exec(downgrade);
      await expect(store.take(nonce(1))).rejects.toThrow(SQLITE_CONSENT_STORE_ERROR);
      active.exec('PRAGMA main.journal_mode = DELETE; PRAGMA main.synchronous = EXTRA;');
      expect(await store.take(nonce(1))).toEqual(value);
      expect(await store.take(nonce(1))).toBeUndefined();
    });

    it('refuses an existing WAL database without converting it or consuming pending metadata', async () => {
      const { DatabaseSync } = await import('node:sqlite');
      const path = directory();
      const store = await open(path);
      await store.putIfAbsent(nonce(1), challenge());
      store.close();
      const filename = join(path, SQLITE_CONSENT_DATABASE_NAME);
      const setup = new DatabaseSync(filename);
      try {
        expect(setup.prepare('PRAGMA main.journal_mode = WAL').get()?.journal_mode).toBe('wal');
      } finally {
        setup.close();
      }
      await expect(open(path)).rejects.toThrow(SQLITE_CONSENT_STORE_ERROR);
      const unchanged = new DatabaseSync(filename);
      try {
        expect(unchanged.prepare('PRAGMA main.journal_mode').get()?.journal_mode).toBe('wal');
        expect(
          unchanged.prepare('SELECT count(*) AS count FROM mcp_consent_challenges').get()?.count,
        ).toBe(1);
      } finally {
        unchanged.close();
      }
    });

    it('enforces shared capacity, expires entries and makes space without evicting live forms', async () => {
      let time = 1000;
      const path = directory();
      const first = await open(path, 2, () => time);
      const second = await open(path, 2, () => time);
      expect(await first.putIfAbsent(nonce(1), challenge(2000))).toBe(true);
      expect(await second.putIfAbsent(nonce(2), challenge(3000))).toBe(true);
      expect(await first.putIfAbsent(nonce(3), challenge(3000))).toBe(false);
      time = 2000;
      expect(await second.take(nonce(1))).toBeUndefined();
      expect(await first.putIfAbsent(nonce(3), challenge(3000))).toBe(true);
      expect(await second.take(nonce(2))).toEqual(challenge(3000));
      expect(await first.take(nonce(3))).toEqual(challenge(3000));
    });

    it('does not silently change an existing database capacity', async () => {
      const path = directory();
      const first = await open(path);
      const value = challenge();
      await first.putIfAbsent(nonce(1), value);
      await expect(open(path, 3)).rejects.toThrow(SQLITE_CONSENT_STORE_ERROR);
      expect(await first.take(nonce(1))).toEqual(value);
    });

    it('stores hashed nonce keys and only the strict metadata fields', async () => {
      const path = directory();
      const store = await open(path);
      const value = challenge();
      const key = nonce(1);
      expect(await store.putIfAbsent(key, value)).toBe(true);
      expect(
        readFileSync(join(path, SQLITE_CONSENT_DATABASE_NAME)).includes(Buffer.from(key)),
      ).toBe(false);
      const invalid = { ...value, accessToken: 'synthetic-material-must-not-be-stored' };
      await expect(store.putIfAbsent(nonce(2), invalid)).rejects.toThrow(
        SQLITE_CONSENT_STORE_ERROR,
      );
      expect(
        readFileSync(join(path, SQLITE_CONSENT_DATABASE_NAME)).includes(
          Buffer.from(invalid.accessToken),
        ),
      ).toBe(false);
    });

    it('refuses malformed nonce/metadata, distant expiry and invalid time without native details', async () => {
      const store = await open(directory(), 2, () => 1000);
      for (const key of ['', '../outside', 'x'.repeat(44)]) {
        await expect(store.putIfAbsent(key, challenge(2000))).rejects.toThrow(
          SQLITE_CONSENT_STORE_ERROR,
        );
        await expect(store.take(key)).rejects.toThrow(SQLITE_CONSENT_STORE_ERROR);
      }
      for (const value of [
        { ...challenge(2000), userId: 'not-a-user' },
        { ...challenge(2000), viewSha256: 'not-a-digest' },
        { ...challenge(2000), sessionId: '' },
        { ...challenge(2000), authorizationId: '../outside' },
        challenge(301001),
      ]) {
        await expect(store.putIfAbsent(nonce(1), value)).rejects.toThrow(
          SQLITE_CONSENT_STORE_ERROR,
        );
      }
      expect(await store.putIfAbsent(nonce(1), challenge(1000))).toBe(false);
      const brokenClock = await open(directory(), 2, () => Number.NaN);
      await expect(brokenClock.take(nonce(1))).rejects.toThrow(SQLITE_CONSENT_STORE_ERROR);
    });

    it('refuses unsafe directory permissions and symlinked directory paths', async () => {
      const path = directory();
      chmodSync(path, 0o755);
      await expect(open(path)).rejects.toThrow(SQLITE_CONSENT_STORE_ERROR);
      chmodSync(path, 0o700);
      const parent = directory();
      const alias = join(parent, 'alias');
      symlinkSync(path, alias);
      await expect(open(alias)).rejects.toThrow(SQLITE_CONSENT_STORE_ERROR);
    });

    it.each(['symlink', 'hardlink'] as const)('refuses a %s database file', async (kind) => {
      const path = directory();
      (await open(path)).close();
      const filename = join(path, SQLITE_CONSENT_DATABASE_NAME);
      const retained = join(path, 'retained.sqlite');
      renameSync(filename, retained);
      if (kind === 'symlink') symlinkSync(retained, filename);
      else linkSync(retained, filename);
      await expect(open(path)).rejects.toThrow(SQLITE_CONSENT_STORE_ERROR);
    });

    it('refuses replaced or newly insecure storage before consuming a nonce', async () => {
      const path = directory();
      const store = await open(path);
      const value = challenge();
      await store.putIfAbsent(nonce(1), value);
      const filename = join(path, SQLITE_CONSENT_DATABASE_NAME);
      chmodSync(filename, 0o644);
      await expect(store.take(nonce(1))).rejects.toThrow(SQLITE_CONSENT_STORE_ERROR);
      chmodSync(filename, 0o600);
      expect(await store.take(nonce(1))).toEqual(value);
      renameSync(filename, join(path, 'retained.sqlite'));
      writeFileSync(filename, '', { mode: 0o600 });
      await expect(store.take(nonce(2))).rejects.toThrow(SQLITE_CONSENT_STORE_ERROR);
    });

    it('leaves an unrelated private SQLite database unchanged', async () => {
      const { DatabaseSync } = await import('node:sqlite');
      const path = directory();
      const filename = join(path, SQLITE_CONSENT_DATABASE_NAME);
      writeFileSync(filename, '', { mode: 0o600 });
      const other = new DatabaseSync(filename);
      other.exec("CREATE TABLE unrelated(value TEXT); INSERT INTO unrelated VALUES ('synthetic');");
      other.close();
      await expect(open(path)).rejects.toThrow(SQLITE_CONSENT_STORE_ERROR);
      const unchanged = new DatabaseSync(filename);
      try {
        expect(unchanged.prepare('SELECT value FROM unrelated').get()?.value).toBe('synthetic');
        expect(
          unchanged
            .prepare("SELECT count(*) AS count FROM sqlite_schema WHERE name LIKE 'mcp_consent_%'")
            .get()?.count,
        ).toBe(0);
      } finally {
        unchanged.close();
      }
    });

    it('fails closed on a busy database and retains the unconsumed form', async () => {
      const { DatabaseSync } = await import('node:sqlite');
      const path = directory();
      const store = await open(path);
      const value = challenge();
      await store.putIfAbsent(nonce(1), value);
      const blocker = new DatabaseSync(join(path, SQLITE_CONSENT_DATABASE_NAME));
      try {
        blocker.exec('BEGIN IMMEDIATE');
        await expect(store.take(nonce(1))).rejects.toThrow(SQLITE_CONSENT_STORE_ERROR);
        blocker.exec('ROLLBACK');
        expect(await store.take(nonce(1))).toEqual(value);
      } finally {
        blocker.close();
      }
    });

    it('allows exactly one consumer across three real Node processes', async () => {
      const path = directory();
      const store = await open(path);
      await store.putIfAbsent(nonce(1), challenge());
      const module = new URL('../dist/sqlite-hosted-consent-store.js', import.meta.url).href;
      const script = `
        const {createSqliteHostedConsentChallengeStore}=await import(${JSON.stringify(module)});
        const store=await createSqliteHostedConsentChallengeStore({directory:process.argv[1],maxEntries:2});
        try { console.log(JSON.stringify({consumed:(await store.take(process.argv[2]))!==undefined})); }
        finally { store.close(); }
      `;
      const results = await Promise.all(
        [1, 2, 3].map(async () => {
          const result = await run(
            process.execPath,
            ['--input-type=module', '-e', script, path, nonce(1)],
            {
              timeout: 5000,
              maxBuffer: 4096,
              env: { NODE_NO_WARNINGS: '1' },
            },
          );
          return JSON.parse(result.stdout.toString()) as { consumed: boolean };
        }),
      );
      expect(results.filter((result) => result.consumed)).toHaveLength(1);
      expect(await store.take(nonce(1))).toBeUndefined();
    });

    it.each([false, true])(
      'mounts the real consent route across connections; lost reply=%s',
      async (lostReply) => {
        const path = directory();
        const first = await open(path);
        const second = await open(path);
        let approvals = 0;
        const oauth = {
          getAuthorizationDetails: async () => ({
            data: {
              authorization_id: AUTHORIZATION,
              client: { id: CLIENT, name: 'Synthetic client' },
              user: { id: USER },
              redirect_uri: CALLBACK,
              scope: 'openid email',
            },
            error: null,
          }),
          approveAuthorization: async () => {
            approvals += 1;
            if (lostReply) throw new Error('Synthetic lost reply');
            return {
              data: { redirect_url: `${CALLBACK}?code=synthetic&state=original` },
              error: null,
            };
          },
          denyAuthorization: async () => ({
            data: { redirect_url: `${CALLBACK}?error=access_denied` },
            error: null,
          }),
        } as unknown as OAuthConsentApi;
        const handler = (challenges: SqliteHostedConsentChallengeStore) =>
          createHostedOAuthConsentHandler({
            routeUrl: ROUTE,
            binding: {
              expectedClientId: CLIENT,
              redirectUris: [CALLBACK],
              allowedScopes: ['openid', 'email'],
            },
            getVerifiedSession: async () => ({
              userId: USER,
              sessionId: 'opaque-host-session',
              oauth,
            }),
            challenges,
          });
        const a = handler(first);
        const b = handler(second);
        const form = await a(new Request(`${ROUTE}?authorization_id=${AUTHORIZATION}`));
        expect(form.status).toBe(200);
        const key = /name="nonce" value="([A-Za-z0-9_-]+)"/u.exec(await form.text())?.[1] ?? '';
        const submit = () =>
          new Request(ROUTE, {
            method: 'POST',
            headers: {
              origin: new URL(ROUTE).origin,
              'content-type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({ nonce: key, decision: 'approve' }),
          });
        const decision = await b(submit());
        expect(decision.status).toBe(lostReply ? 409 : 303);
        if (lostReply) {
          expect(await decision.text()).toBe(
            'Consent outcome unavailable. Restart authorization to check its status.',
          );
        }
        first.close();
        const restarted = handler(await open(path));
        expect((await restarted(submit())).status).toBe(409);
        expect(approvals).toBe(1);
      },
    );
  },
);
