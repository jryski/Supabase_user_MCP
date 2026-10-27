import { mkdtemp, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  LocalCredentialError,
  loadLocalCredentials,
  type PermissionInspector,
} from './local-credential-loader.js';

const SUBJECT = 'abcdef01-2345-4678-9abc-def012345678';
const FUTURE_EXP = Math.floor(Date.now() / 1000) + 3600;

/** Synthetic, unsigned token shape assembled at runtime; never a real credential. */
function syntheticToken(payload: unknown, raw?: string): string {
  const body = raw ?? Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `header.${body}.signature`;
}

const futureToken = syntheticToken({ exp: FUTURE_EXP, role: 'authenticated', sub: SUBJECT });
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
    [
      'blank',
      JSON.stringify({ projectPublishableKey: ' ', userAccessToken: futureToken }),
      'CREDENTIAL_BLANK',
    ],
    [
      'unknown key',
      JSON.stringify({
        projectPublishableKey: 'sb_publishable_synthetic',
        userAccessToken: futureToken,
        extra: 'no',
      }),
      'CREDENTIAL_SCHEMA_INVALID',
    ],
    [
      'conflated',
      JSON.stringify({ projectPublishableKey: futureToken, userAccessToken: futureToken }),
      'CREDENTIAL_CONFLATED',
    ],
    ['malformed', '{', 'CREDENTIAL_MALFORMED'],
    [
      'expired',
      JSON.stringify({
        projectPublishableKey: 'sb_publishable_synthetic',
        userAccessToken: syntheticToken({ exp: 1, role: 'authenticated', sub: SUBJECT }),
      }),
      'CREDENTIAL_TOKEN_EXPIRED',
    ],
  ])('rejects %s input without disclosure', async (_name, body, code) => {
    await expect(
      loadLocalCredentials(await fixture(body), { permissionInspector: securePermissions }),
    ).rejects.toSatisfy((error: unknown) => {
      expectSecretFree(error);
      expect((error as LocalCredentialError).code).toBe(code);
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
    ['no-break-space padded secret key', '\u00a0sb_secret_synthetic\u00a0'],
    ['byte-order-mark prefixed secret key', '\ufeffsb_secret_synthetic'],
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

  async function keyRefusal(key: string): Promise<LocalCredentialError> {
    const body = JSON.stringify({ projectPublishableKey: key, userAccessToken: futureToken });
    const error = await loadLocalCredentials(await fixture(body), {
      permissionInspector: securePermissions,
    }).catch((caught: unknown) => caught);
    expectSecretFree(error);
    expect(JSON.stringify(error)).not.toContain(key.trim());
    return error as LocalCredentialError;
  }

  // Every key that is not exactly `sb_publishable_<token chars>` after trimming
  // is refused, including obfuscated secret keys that a prefix denylist misses.
  it.each([
    ['zero-width space before the secret prefix', '\u200bsb_secret_synthetic'],
    ['zero-width non-joiner before the secret prefix', '\u200csb_secret_synthetic'],
    ['zero-width joiner before the secret prefix', '\u200dsb_secret_synthetic'],
    ['word joiner before the secret prefix', '\u2060sb_secret_synthetic'],
    ['zero-width space inside the secret prefix', 'sb_\u200bsecret_synthetic'],
    ['soft hyphen inside the secret prefix', 'sb_se\u00adcret_synthetic'],
    [
      'fullwidth secret prefix',
      '\uff53\uff42\uff3f\uff53\uff45\uff43\uff52\uff45\uff54\uff3fsynthetic',
    ],
    ['Cyrillic look-alike secret prefix', '\u0455b_secret_synthetic'],
    ['hyphenated secret prefix', 'sb-secret-synthetic'],
    ['secret prefix without its separator', 'sb_secretXsynthetic'],
    ['access-token prefix', 'sbp_synthetic'],
    ['arbitrary string', 'hunter2'],
    ['generic key', 'key'],
    ['unprefixed publishable-looking key', 'synthetic-publishable-key'],
    ['bare word publishable', 'publishable'],
    ['upper-case publishable prefix', 'SB_PUBLISHABLE_synthetic'],
    ['bare publishable prefix', 'sb_publishable_'],
    ['zero-width space before the publishable prefix', '\u200bsb_publishable_synthetic'],
    ['zero-width space inside a publishable key', 'sb_publishable_syn\u200bthetic'],
    ['trailing zero-width space after a publishable key', 'sb_publishable_synthetic\u200b'],
    ['fullwidth publishable prefix', '\uff53\uff42\uff3fpublishable_synthetic'],
    ['Cyrillic look-alike publishable prefix', 'sb_publi\u0455hable_synthetic'],
    ['inner whitespace', 'sb_publishable_syn thetic'],
    ['dotted publishable key', 'sb_publishable_synthetic.extra'],
  ])('refuses a %s as not publishable', async (_name, key) => {
    expect((await keyRefusal(key)).code).toBe('CREDENTIAL_KEY_NOT_PUBLISHABLE');
  });

  it('keeps the conflated code for a JWT-shaped publishable-prefixed key', async () => {
    expect((await keyRefusal('sb_publishable_a.b.c')).code).toBe('CREDENTIAL_CONFLATED');
  });

  // The token slot must decode (unverified) to a signed-in user's token.
  it.each([
    ['service_role token', syntheticToken({ exp: FUTURE_EXP, role: 'service_role', sub: SUBJECT })],
    ['anon token', syntheticToken({ exp: FUTURE_EXP, role: 'anon' })],
    ['anon token with a subject', syntheticToken({ exp: FUTURE_EXP, role: 'anon', sub: SUBJECT })],
    ['upper-case role', syntheticToken({ exp: FUTURE_EXP, role: 'AUTHENTICATED', sub: SUBJECT })],
    ['padded role', syntheticToken({ exp: FUTURE_EXP, role: ' authenticated', sub: SUBJECT })],
    ['missing role', syntheticToken({ exp: FUTURE_EXP, sub: SUBJECT })],
    ['non-string role', syntheticToken({ exp: FUTURE_EXP, role: ['authenticated'], sub: SUBJECT })],
    ['missing subject', syntheticToken({ exp: FUTURE_EXP, role: 'authenticated' })],
    [
      'non-uuid subject',
      syntheticToken({ exp: FUTURE_EXP, role: 'authenticated', sub: 'synthetic-user' }),
    ],
    [
      'upper-case subject',
      syntheticToken({ exp: FUTURE_EXP, role: 'authenticated', sub: SUBJECT.toUpperCase() }),
    ],
    ['missing expiry', syntheticToken({ role: 'authenticated', sub: SUBJECT })],
    ['array payload', syntheticToken([FUTURE_EXP, 'authenticated', SUBJECT])],
    ['null payload', syntheticToken(null)],
    ['non-JSON payload', syntheticToken(undefined, Buffer.from('not json').toString('base64url'))],
    [
      'invalid UTF-8 payload',
      syntheticToken(undefined, Buffer.from([0xff, 0xfe]).toString('base64url')),
    ],
    ['empty payload segment', 'header..signature'],
    ['non-base64url payload segment', 'header.pay+load.signature'],
    ['two segments', 'header.signature'],
    ['four segments', `${futureToken}.extra`],
    ['secret key as token', 'sb_secret_synthetic'],
  ])('refuses a %s in the token slot', async (_name, token) => {
    const body = JSON.stringify({
      projectPublishableKey: 'sb_publishable_synthetic',
      userAccessToken: token,
    });
    const error = await loadLocalCredentials(await fixture(body), {
      permissionInspector: securePermissions,
    }).catch((caught: unknown) => caught);
    expectSecretFree(error);
    expect((error as LocalCredentialError).code).toBe('CREDENTIAL_TOKEN_INVALID');
  });

  it('accepts a padded authenticated token and returns it trimmed', async () => {
    const body = JSON.stringify({
      projectPublishableKey: 'sb_publishable_synthetic',
      userAccessToken: ` ${futureToken}\n`,
    });
    const result = await loadLocalCredentials(await fixture(body), {
      permissionInspector: securePermissions,
    });
    expect(result.userAccessToken).toBe(futureToken);
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
