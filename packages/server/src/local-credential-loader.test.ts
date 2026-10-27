import { mkdtemp, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  LocalCredentialError,
  loadLocalCredentials,
  type PermissionInspector,
} from './local-credential-loader.js';

const futureToken = `header.${Buffer.from(
  JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600 }),
).toString('base64url')}.signature`;
const validBody = JSON.stringify({
  projectPublishableKey: 'sb_publishable_synthetic',
  userAccessToken: futureToken,
});
const securePermissions: PermissionInspector = () => 'secure';

async function fixture(body = validBody): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'fixed-credentials-'));
  const path = join(directory, 'credentials.json');
  await writeFile(path, body, { mode: 0o600 });
  return path;
}

function expectSecretFree(error: unknown): void {
  expect(error).toBeInstanceOf(LocalCredentialError);
  const value = error as LocalCredentialError;
  expect(value.message).toBe(value.code);
  expect(JSON.stringify(value)).not.toContain('synthetic');
  expect(JSON.stringify(value)).not.toContain('credentials.json');
  expect(JSON.stringify(value)).not.toContain('signature');
}

describe('loadLocalCredentials', () => {
  it('loads a strict, separated credential document from the supplied path', async () => {
    const result = await loadLocalCredentials(await fixture(), {
      permissionInspector: securePermissions,
    });
    expect(result).toEqual({
      projectPublishableKey: 'sb_publishable_synthetic',
      userAccessToken: futureToken,
    });
    expect(result.projectPublishableKey).not.toBe(result.userAccessToken);
  });

  it.each([
    ['blank', JSON.stringify({ projectPublishableKey: ' ', userAccessToken: futureToken })],
    [
      'unknown key',
      JSON.stringify({ projectPublishableKey: 'key', userAccessToken: futureToken, extra: 'no' }),
    ],
    [
      'conflated',
      JSON.stringify({ projectPublishableKey: futureToken, userAccessToken: futureToken }),
    ],
    ['malformed', '{'],
    [
      'expired',
      // Synthetic expired token, assembled so secret scanners do not see a literal.
      JSON.stringify({
        projectPublishableKey: 'key',
        userAccessToken: ['e30', 'eyJleHAiOjF9', 'sig'].join('.'),
      }),
    ],
  ])('rejects %s input without disclosure', async (_name, body) => {
    await expect(
      loadLocalCredentials(await fixture(body), { permissionInspector: securePermissions }),
    ).rejects.toSatisfy((error: unknown) => {
      expectSecretFree(error);
      return true;
    });
  });

  it.each([
    ['lower-case secret key', 'sb_secret_synthetic'],
    ['upper-case secret key', 'SB_SECRET_synthetic'],
    ['mixed-case secret key', 'Sb_Secret_synthetic'],
    ['space-padded secret key', '  sb_secret_synthetic  '],
    ['tab- and newline-padded secret key', '\tSB_SECRET_synthetic\n'],
    ['bare secret prefix', 'sb_secret_'],
  ])('refuses a %s with a stable code and no disclosure', async (_name, key) => {
    const body = JSON.stringify({ projectPublishableKey: key, userAccessToken: futureToken });
    const error = await loadLocalCredentials(await fixture(body), {
      permissionInspector: securePermissions,
    }).catch((caught: unknown) => caught);
    expectSecretFree(error);
    expect((error as LocalCredentialError).code).toBe('CREDENTIAL_SECRET_KEY');
    expect(JSON.stringify(error)).not.toContain('secret_');
  });

  it.each([
    ['publishable key', 'sb_publishable_synthetic', 'sb_publishable_synthetic'],
    ['padded publishable key', '  sb_publishable_synthetic\t', 'sb_publishable_synthetic'],
    ['other key shape', 'key', 'key'],
    [
      'key that only contains the secret marker',
      'sb_publishable_sb_secret_x',
      'sb_publishable_sb_secret_x',
    ],
  ])('still accepts a %s', async (_name, key, expected) => {
    const body = JSON.stringify({ projectPublishableKey: key, userAccessToken: futureToken });
    const result = await loadLocalCredentials(await fixture(body), {
      permissionInspector: securePermissions,
    });
    expect(result).toEqual({ projectPublishableKey: expected, userAccessToken: futureToken });
  });

  it('rejects missing, non-file, symlinked, oversized, and insecure files with stable codes', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'fixed-credentials-negative-'));
    const target = await fixture();
    const link = join(directory, 'link.json');
    await symlink(target, link);
    await expect(
      loadLocalCredentials(join(directory, 'missing'), { permissionInspector: securePermissions }),
    ).rejects.toMatchObject({ code: 'CREDENTIAL_FILE_MISSING' });
    await expect(
      loadLocalCredentials(directory, { permissionInspector: securePermissions }),
    ).rejects.toMatchObject({ code: 'CREDENTIAL_NOT_FILE' });
    await expect(
      loadLocalCredentials(link, { permissionInspector: securePermissions }),
    ).rejects.toMatchObject({ code: 'CREDENTIAL_SYMLINK' });
    await expect(
      loadLocalCredentials(await fixture('x'.repeat(16_385)), {
        permissionInspector: securePermissions,
      }),
    ).rejects.toMatchObject({ code: 'CREDENTIAL_FILE_TOO_LARGE' });
    await expect(
      loadLocalCredentials(target, { permissionInspector: () => 'insecure' }),
    ).rejects.toMatchObject({ code: 'CREDENTIAL_INSECURE_PERMISSIONS' });
  });

  it('fails closed when Windows ACLs cannot be proven secure', async () => {
    await expect(
      loadLocalCredentials(await fixture(), { permissionInspector: () => 'unsupported' }),
    ).rejects.toMatchObject({ code: 'CREDENTIAL_PERMISSION_CHECK_UNSUPPORTED' });
  });

  it('provides the opened file owner and mode to the permission inspector', async () => {
    const inspected: Array<{ mode: number; ownerUid: number }> = [];
    await loadLocalCredentials(await fixture(), {
      permissionInspector: (_path, mode, ownerUid) => {
        inspected.push({ mode, ownerUid });
        return 'secure';
      },
    });
    expect(inspected).toHaveLength(1);
    expect(inspected[0]?.mode).toBeTypeOf('number');
    expect(inspected[0]?.ownerUid).toBeTypeOf('number');
  });
});
