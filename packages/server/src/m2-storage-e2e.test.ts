import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { loadLocalCredentials } from './local-credential-loader.js';
import {
  createUserScopedStorageClient,
  STORAGE_RPC,
  STORAGE_RPC_SCHEMA,
  type UserScopedStorageClient,
} from './user-scoped-storage-client.js';

/**
 * Issue #123 S4 real-stack probe (assumes option A; pending RLS layout decision).
 *
 * The real user-scoped storage client, with a real local Auth session, against the local
 * Supabase PostgREST and Storage API started by supabase/tests/run-m2-memory-lab.sh. Runs only
 * when that script exports its environment; skipped otherwise. Synthetic fixtures only
 * (supabase/seed-storage-m2.sql): alice holds storage read and write, bob holds none.
 */

const requiredEnvironment = [
  'M2_SUPABASE_URL',
  'M2_PUBLISHABLE_KEY',
  'M2_ALICE_TOKEN',
  'M2_BOB_TOKEN',
] as const;
const enabled = requiredEnvironment.every((key) => (process.env[key] ?? '').length > 0);
const localDescribe = enabled ? describe : describe.skip;

const VIRTUAL_ORIGIN = 'https://m2-storage-loopback.invalid';
const BUCKET = 'mcp-user-storage';
const ALICE = '11111111-1111-4111-9111-111111111111';
const BOB = '22222222-2222-4222-9222-222222222222';

let credentialDirectory = '';

beforeAll(async () => {
  if (enabled) credentialDirectory = await mkdtemp(join(tmpdir(), 'supabase-user-mcp-m2s-'));
});

afterAll(async () => {
  if (credentialDirectory) await rm(credentialDirectory, { recursive: true, force: true });
});

function env(name: (typeof requiredEnvironment)[number]): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}

/** Sends the client's requests to the local stack; the client itself requires https. */
function loopbackFetch(actualOrigin: string): typeof globalThis.fetch {
  return async (input, init) => {
    const requested = new URL(
      typeof input === 'string' || input instanceof URL ? input : input.url,
    );
    return globalThis.fetch(
      new URL(`${requested.pathname}${requested.search}`, actualOrigin),
      init,
    );
  };
}

async function storageClientFor(label: string, token: string): Promise<UserScopedStorageClient> {
  const path = join(credentialDirectory, `${label}.json`);
  await writeFile(
    path,
    JSON.stringify({ projectPublishableKey: env('M2_PUBLISHABLE_KEY'), userAccessToken: token }),
    { mode: 0o600 },
  );
  return createUserScopedStorageClient({
    origin: VIRTUAL_ORIGIN,
    bucket: BUCKET,
    credentials: await loadLocalCredentials(path),
    fetch: loopbackFetch(env('M2_SUPABASE_URL')),
  });
}

async function rpcStatus(
  name: string,
  profile: string,
  bearer: string | undefined,
): Promise<number> {
  const headers: Record<string, string> = {
    apikey: env('M2_PUBLISHABLE_KEY'),
    'Content-Type': 'application/json',
    'Content-Profile': profile,
    'Accept-Profile': profile,
  };
  if (bearer !== undefined) headers.Authorization = `Bearer ${bearer}`;
  const response = await fetch(new URL(`/rest/v1/rpc/${name}`, env('M2_SUPABASE_URL')), {
    method: 'POST',
    redirect: 'error',
    headers,
    body: '{}',
  });
  await response.body?.cancel();
  return response.status;
}

localDescribe('M2 storage: user-scoped client -> PostgREST seam + Storage API -> RLS', () => {
  const signal = AbortSignal.timeout(30_000);

  it('resolves the session through the exposed wrappers, never the policy_lab profile', async () => {
    expect(STORAGE_RPC_SCHEMA).toBe('public');
    const alice = await storageClientFor('alice', env('M2_ALICE_TOKEN'));
    expect(alice.tokenSubject).toBe(ALICE);
    expect(await alice.fetchStoragePrincipal(signal)).toBe(ALICE);
    expect(await alice.fetchStorageGrants(signal)).toEqual(['storage:read', 'storage:write']);
    // policy_lab is not an exposed schema, so PostgREST refuses the profile outright.
    expect(await rpcStatus('storage_principal', 'policy_lab', env('M2_ALICE_TOKEN'))).toBe(406);
    // The wrappers are not executable without a user session.
    const anon = await rpcStatus(STORAGE_RPC.principal, 'public', undefined);
    expect(anon >= 400 && anon < 500).toBe(true);
  });

  it('uploads, lists, downloads and deletes under the caller prefix only', async () => {
    const alice = await storageClientFor('alice', env('M2_ALICE_TOKEN'));
    const bob = await storageClientFor('bob', env('M2_BOB_TOKEN'));
    const key = `${ALICE}/m2-probe/${Date.now()}.txt`;
    const body = new TextEncoder().encode('synthetic m2 storage probe');
    expect(await alice.uploadObject(key, body, 'text/plain', signal)).toBe(true);
    try {
      const page = await alice.listObjects(
        { folder: `${ALICE}/m2-probe`, limit: 10, offset: 0 },
        signal,
      );
      expect(page.entries.some((entry) => entry.kind === 'object' && entry.objectKey === key)).toBe(
        true,
      );
      expect(await alice.downloadObject(key, 1024, signal)).toEqual(body);

      // bob has no storage grant: no principal, no capabilities, no access to alice's objects.
      await expect(bob.fetchStoragePrincipal(signal)).rejects.toThrow();
      expect(await bob.fetchStorageGrants(signal)).toEqual([]);
      expect(await bob.downloadObject(key, 1024, signal)).toBeNull();
      const bobPage = await bob.listObjects(
        { folder: `${ALICE}/m2-probe`, limit: 10, offset: 0 },
        signal,
      );
      expect(bobPage.entries).toEqual([]);
      expect(await bob.uploadObject(`${ALICE}/m2-probe/bob.txt`, body, 'text/plain', signal)).toBe(
        false,
      );
      expect(await bob.uploadObject(`${BOB}/m2-probe/bob.txt`, body, 'text/plain', signal)).toBe(
        false,
      );
      expect(await bob.deleteObject(key, signal)).toBe(false);
    } finally {
      expect(await alice.deleteObject(key, signal)).toBe(true);
    }
    expect(await alice.downloadObject(key, 1024, signal)).toBeNull();
  });
});
