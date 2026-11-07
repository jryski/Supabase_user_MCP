import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, type BigIntStats } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import type { DatabaseSync as SqliteDatabase } from 'node:sqlite';
import { RemotePrincipalIdSchema } from '@supabase-user-mcp/contracts';
import type {
  HostedConsentChallenge,
  HostedConsentChallengeStore,
} from './hosted-oauth-consent.js';

export const SQLITE_CONSENT_DATABASE_NAME = 'hosted-consent.sqlite';
export const SQLITE_CONSENT_STORE_ERROR = 'SQLITE_CONSENT_STORE_UNAVAILABLE';
const APPLICATION_ID = 0x4d435043;
const MAX_DATABASE_BYTES = 16n * 1024n * 1024n;
const MAX_ENTRIES = 4096;
const MAX_TTL_MS = 5 * 60_000;
const NONCE = /^[A-Za-z0-9_-]{43}$/u;
const AUTHORIZATION_ID = /^[A-Za-z0-9_-]{1,128}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;

export interface SqliteHostedConsentChallengeStoreOptions {
  /** Existing absolute private directory on a local POSIX filesystem. Never a tool argument. */
  readonly directory: string;
  /** Persisted per database; every process must use the same value. Default 1024, maximum 4096. */
  readonly maxEntries?: number;
  readonly now?: () => number;
}

export interface SqliteHostedConsentChallengeStore extends HostedConsentChallengeStore {
  /** Close only this process's connection when its host stops accepting requests. */
  readonly close: () => void;
}

function unavailable(): never {
  throw new Error(SQLITE_CONSENT_STORE_ERROR);
}

function sameIdentity(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function privateDirectory(directory: string, uid: bigint): BigIntStats {
  let entry = directory;
  let leaf: BigIntStats | undefined;
  while (true) {
    const stat = lstatSync(entry, { bigint: true });
    if (stat.isSymbolicLink() || !stat.isDirectory()) unavailable();
    if (entry === directory) {
      if (stat.uid !== uid || (stat.mode & 0o7777n) !== 0o700n) unavailable();
      leaf = stat;
    } else {
      if (stat.uid !== 0n && stat.uid !== uid) unavailable();
      const rootSticky = stat.uid === 0n && (stat.mode & 0o1000n) !== 0n;
      if ((stat.mode & 0o022n) !== 0n && !rootSticky) unavailable();
    }
    const parent = dirname(entry);
    if (parent === entry) break;
    entry = parent;
  }
  if (leaf === undefined) unavailable();
  return leaf;
}

function privateFile(stat: BigIntStats, uid: bigint): void {
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.nlink !== 1n ||
    stat.uid !== uid ||
    (stat.mode & 0o7777n) !== 0o600n ||
    stat.size > MAX_DATABASE_BYTES
  )
    unavailable();
}

function nonceHash(value: string): string {
  if (typeof value !== 'string' || !NONCE.test(value)) unavailable();
  return createHash('sha256').update(value).digest('hex');
}

function challengeMetadata(value: unknown): HostedConsentChallenge {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) unavailable();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) unavailable();
  const expected = ['authorizationId', 'expiresAt', 'sessionId', 'userId', 'viewSha256'];
  const keys = Reflect.ownKeys(value);
  if (keys.length !== expected.length || keys.some((key) => !expected.includes(String(key))))
    unavailable();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    Object.values(descriptors).some(
      (descriptor) => !('value' in descriptor) || !descriptor.enumerable,
    )
  )
    unavailable();
  const record = value as Record<string, unknown>;
  if (
    typeof record.userId !== 'string' ||
    !RemotePrincipalIdSchema.safeParse(record.userId).success ||
    record.userId === '00000000-0000-0000-0000-000000000000' ||
    typeof record.sessionId !== 'string' ||
    record.sessionId.length === 0 ||
    record.sessionId.length > 256 ||
    record.sessionId.trim() !== record.sessionId ||
    typeof record.authorizationId !== 'string' ||
    !AUTHORIZATION_ID.test(record.authorizationId) ||
    typeof record.viewSha256 !== 'string' ||
    !SHA256.test(record.viewSha256) ||
    typeof record.expiresAt !== 'number' ||
    !Number.isSafeInteger(record.expiresAt) ||
    record.expiresAt < 0
  )
    unavailable();
  return Object.freeze({
    userId: record.userId,
    sessionId: record.sessionId,
    authorizationId: record.authorizationId,
    viewSha256: record.viewSha256,
    expiresAt: record.expiresAt,
  });
}

/**
 * Explicit opt-in metadata store for consent forms, not Token B custody.
 * All participating processes must use the same latest local database.
 * SQLite commits deletion before take returns; no decision or failed call is replayed.
 */
export async function createSqliteHostedConsentChallengeStore(
  options: SqliteHostedConsentChallengeStoreOptions,
): Promise<SqliteHostedConsentChallengeStore> {
  let opened: SqliteDatabase | undefined;
  try {
    if (
      process.platform === 'win32' ||
      process.getuid === undefined ||
      typeof options.directory !== 'string' ||
      !isAbsolute(options.directory) ||
      options.directory !== resolve(options.directory) ||
      options.directory.includes('\0') ||
      options.directory === dirname(options.directory) ||
      (options.now !== undefined && typeof options.now !== 'function')
    )
      unavailable();
    const directory = options.directory;
    const limit = options.maxEntries ?? 1024;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_ENTRIES) unavailable();
    const now = options.now ?? Date.now;
    const uid = BigInt(process.getuid());
    const directoryIdentity = privateDirectory(directory, uid);
    const filename = join(directory, SQLITE_CONSENT_DATABASE_NAME);
    // Lazy import keeps the experimental SQLite module out of all default entrypoints.
    const { DatabaseSync } = await import('node:sqlite');
    if (!sameIdentity(directoryIdentity, privateDirectory(directory, uid))) unavailable();
    let fd: number;
    try {
      fd = openSync(
        filename,
        constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600,
      );
    } catch (error) {
      if (
        typeof error !== 'object' ||
        error === null ||
        !('code' in error) ||
        error.code !== 'EEXIST'
      )
        unavailable();
      fd = openSync(filename, constants.O_RDWR | constants.O_NOFOLLOW);
    }
    let fileIdentity: BigIntStats;
    try {
      fileIdentity = fstatSync(fd, { bigint: true });
      privateFile(fileIdentity, uid);
    } finally {
      closeSync(fd);
    }
    let closed = false;
    const guard = () => {
      if (closed || !sameIdentity(directoryIdentity, privateDirectory(directory, uid)))
        unavailable();
      const current = lstatSync(filename, { bigint: true });
      privateFile(current, uid);
      if (!sameIdentity(fileIdentity, current)) unavailable();
    };
    guard();
    const db = new DatabaseSync(filename, { allowExtension: false, timeout: 250 });
    opened = db;
    const transact = <T>(operation: () => T): T => {
      let active = false;
      try {
        guard();
        db.exec('BEGIN IMMEDIATE');
        active = true;
        const result = operation();
        db.exec('COMMIT');
        active = false;
        guard();
        return result;
      } catch {
        if (active) {
          try {
            db.exec('ROLLBACK');
          } catch {
            /* A lost commit outcome stays unavailable. */
          }
        }
        return unavailable();
      }
    };
    db.exec('PRAGMA trusted_schema = OFF; PRAGMA synchronous = FULL; PRAGMA secure_delete = ON;');
    transact(() => {
      const id = db.prepare('PRAGMA application_id').get()?.application_id;
      const version = db.prepare('PRAGMA user_version').get()?.user_version;
      if (id === 0 && version === 0) {
        if (
          db
            .prepare("SELECT count(*) AS count FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'")
            .get()?.count !== 0
        )
          unavailable();
        db.exec(`
          CREATE TABLE mcp_consent_settings (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            max_entries INTEGER NOT NULL CHECK(max_entries BETWEEN 1 AND 4096)
          ) STRICT;
          CREATE TABLE mcp_consent_challenges (
            nonce_sha TEXT PRIMARY KEY CHECK(length(nonce_sha) = 64),
            user_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            authorization_id TEXT NOT NULL,
            view_sha256 TEXT NOT NULL,
            expires_at INTEGER NOT NULL
          ) STRICT;
          CREATE INDEX mcp_consent_expiry ON mcp_consent_challenges(expires_at);
          PRAGMA application_id = 0x4d435043;
          PRAGMA user_version = 1;
        `);
        db.prepare('INSERT INTO mcp_consent_settings VALUES (1, ?)').run(limit);
      } else if (id !== APPLICATION_ID || version !== 1) unavailable();
      if (
        db.prepare('SELECT max_entries FROM mcp_consent_settings WHERE singleton = 1').get()
          ?.max_entries !== limit
      )
        unavailable();
      // Missing or incompatible state is refused, never silently reset.
      db.prepare(
        'SELECT nonce_sha, user_id, session_id, authorization_id, view_sha256, expires_at FROM mcp_consent_challenges LIMIT 0',
      ).all();
    });
    const expire = db.prepare('DELETE FROM mcp_consent_challenges WHERE expires_at <= ?');
    const insert = db.prepare(`
      INSERT INTO mcp_consent_challenges
        (nonce_sha, user_id, session_id, authorization_id, view_sha256, expires_at)
      SELECT ?, ?, ?, ?, ?, ? WHERE (SELECT count(*) FROM mcp_consent_challenges) < ?
      ON CONFLICT(nonce_sha) DO NOTHING
    `);
    const take = db.prepare(`
      DELETE FROM mcp_consent_challenges WHERE nonce_sha = ?
      RETURNING user_id AS userId, session_id AS sessionId,
        authorization_id AS authorizationId, view_sha256 AS viewSha256, expires_at AS expiresAt
    `);
    const clock = () => {
      const value = now();
      if (!Number.isSafeInteger(value) || value < 0) unavailable();
      return value;
    };
    return Object.freeze({
      async putIfAbsent(nonce: string, value: HostedConsentChallenge): Promise<boolean> {
        try {
          const key = nonceHash(nonce);
          const challenge = challengeMetadata(value);
          const time = clock();
          if (challenge.expiresAt <= time) return false;
          if (challenge.expiresAt - time > MAX_TTL_MS) unavailable();
          return transact(() => {
            expire.run(time);
            return (
              insert.run(
                key,
                challenge.userId,
                challenge.sessionId,
                challenge.authorizationId,
                challenge.viewSha256,
                challenge.expiresAt,
                limit,
              ).changes === 1
            );
          });
        } catch {
          return unavailable();
        }
      },
      async take(nonce: string): Promise<HostedConsentChallenge | undefined> {
        try {
          const key = nonceHash(nonce);
          const time = clock();
          const value = transact(() => take.get(key));
          if (value === undefined) return undefined;
          const challenge = challengeMetadata(value);
          if (challenge.expiresAt <= time) return undefined;
          if (challenge.expiresAt - time > MAX_TTL_MS) unavailable();
          return challenge;
        } catch {
          return unavailable();
        }
      },
      close(): void {
        try {
          if (!closed) {
            closed = true;
            db.close();
          }
        } catch {
          unavailable();
        }
      },
    });
  } catch {
    try {
      opened?.close();
    } catch {
      /* Do not leak native SQLite or filesystem errors. */
    }
    return unavailable();
  }
}
