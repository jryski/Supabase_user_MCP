import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import {
  missingDistFiles,
  offenders,
  runtimeFiles,
  scanText,
} from './support/runtime-boundary-scan.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const PACKAGES = join(ROOT, 'packages');

describe('runtime admin-client boundary', () => {
  it('keeps the Auth admin client registration helper out of runtime source', async () => {
    const files = await runtimeFiles(PACKAGES, 'src');
    expect(files.length).toBeGreaterThan(0);
    expect(await offenders(ROOT, files)).toEqual([]);
  });

  it('keeps the Auth admin client registration helper out of the built package', async () => {
    // `npm test` builds before vitest runs, so dist is present in the gate.
    // A missing, empty or partial dist fails here instead of scanning nothing.
    expect(await missingDistFiles(PACKAGES)).toEqual([]);
    const files = await runtimeFiles(PACKAGES, 'dist');
    expect(files.length).toBeGreaterThan(0);
    expect(await offenders(ROOT, files)).toEqual([]);
  });

  it('does not export an Auth admin client registration helper from the PKCE client', async () => {
    const client = await readFile(join(PACKAGES, 'server/src/local-oauth-pkce-client.ts'), 'utf8');
    expect(client).not.toContain('registerLocalPublicOAuthClient');
  });
});

describe('runtime boundary scanner fixtures', () => {
  const caught: ReadonlyArray<readonly [string, string]> = [
    ['admin endpoint', "await fetch(origin + '/auth/v1/admin/oauth/clients');"],
    ['service role option', 'const client = create({ serviceRoleKey });'],
    ['property read', 'const key = process.env.SUPABASE_SERVICE_ROLE_KEY;'],
    ['bracket read', "const key = process.env['SUPABASE_SERVICE_ROLE_KEY'];"],
    ['bare single-quoted role', "const claims = { role: 'service_role' };"],
    ['bare double-quoted role', 'if (claims.role === "service_role") allow();'],
    ['bare template role', 'const role = `service_role`;'],
    ['destructured role key', 'const { SUPABASE_SERVICE_ROLE_KEY } = process.env;'],
    ['destructured renamed role key', 'const { SUPABASE_SERVICE_ROLE_KEY: k, A } = env;'],
    ['destructured parameter', 'export const f = ({ SUPABASE_SERVICE_ROLE_KEY }) => 1;'],
    ['secret key property', 'const key = process.env.SUPABASE_SECRET_KEY;'],
    ['secret keys property', 'const keys = process.env.SUPABASE_SECRET_KEYS;'],
    ['destructured secret key', 'const { SUPABASE_SECRET_KEY: key } = process.env;'],
    ['bracket secret key', 'const key = env["SUPABASE_SECRET_KEY"];'],
    ['getter secret key', "const key = Deno.env.get('SUPABASE_SECRET_KEY');"],
    ['lab helper import', "import { x } from '../../test/support/local-oauth-admin-lab.js';"],
  ];

  it.each(caught)('flags %s', (_name, line) => {
    expect(scanText(`export const a = 1;\n${line}\n`)).not.toEqual([]);
  });

  const allowed: ReadonlyArray<readonly [string, string]> = [
    [
      'refusal list entry',
      "export const FORBIDDEN = ['A',\n  'SUPABASE_SERVICE_ROLE_KEY',\n  'SUPABASE_SECRET_KEY',\n];",
    ],
    ['prose inside a string', "const policy = 'prohibited, including service_role';"],
    ['line comment', '// keeps the library from reading SUPABASE_SECRET_KEY(S).'],
    ['doc comment', ' * not a user key (for example `service_role` or `anon`).'],
    ['secret key error code', "fail('CREDENTIAL_SECRET_KEY');"],
  ];

  it.each(allowed)('allows %s', (_name, text) => {
    expect(scanText(text)).toEqual([]);
  });

  let fixtureRoot: string | undefined;
  afterEach(async () => {
    if (fixtureRoot) await rm(fixtureRoot, { recursive: true, force: true });
    fixtureRoot = undefined;
  });

  async function fixture(files: Record<string, string>): Promise<string> {
    fixtureRoot = await mkdtemp(join(tmpdir(), 'boundary-scan-'));
    for (const [path, text] of Object.entries(files)) {
      const full = join(fixtureRoot, path);
      await mkdir(dirname(full), { recursive: true });
      await writeFile(full, text);
    }
    return fixtureRoot;
  }

  it('fails a package whose dist is missing', async () => {
    const root = await fixture({ 'pkg/src/index.ts': 'export const a = 1;\n' });
    expect(await missingDistFiles(root)).toEqual(['pkg/dist/index.js']);
    expect(await runtimeFiles(root, 'dist')).toEqual([]);
  });

  it('fails a package whose dist is empty', async () => {
    const root = await fixture({
      'pkg/src/index.ts': 'export const a = 1;\n',
      'pkg/dist/.keep': '',
    });
    expect(await missingDistFiles(root)).toEqual(['pkg/dist/index.js']);
  });

  it('fails a partial dist and a zero-byte build output', async () => {
    const root = await fixture({
      'pkg/src/index.ts': 'export const a = 1;\n',
      'pkg/src/nested/b.ts': 'export const b = 1;\n',
      'pkg/src/c.ts': 'export const c = 1;\n',
      'pkg/src/c.test.ts': 'test();\n',
      'pkg/dist/index.js': 'export const a = 1;\n',
      'pkg/dist/c.js': '',
    });
    expect((await missingDistFiles(root)).sort()).toEqual([
      'pkg/dist/c.js',
      'pkg/dist/nested/b.js',
    ]);
  });

  it('finds an offender in a built fixture and ignores built tests', async () => {
    const root = await fixture({
      'pkg/src/index.ts': 'export const a = 1;\n',
      'pkg/dist/index.js': 'const { SUPABASE_SERVICE_ROLE_KEY } = process.env;\n',
      'pkg/dist/index.test.js': "const role = 'service_role';\n",
    });
    expect(await missingDistFiles(root)).toEqual([]);
    const files = await runtimeFiles(root, 'dist');
    expect(files.map((file) => file.slice(root.length + 1))).toEqual(['pkg/dist/index.js']);
    expect(await offenders(root, files)).toHaveLength(1);
  });
});
