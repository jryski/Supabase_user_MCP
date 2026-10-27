import { readdir, readFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const PACKAGES = join(ROOT, 'packages');

/** Admin Auth endpoints and the privileged key belong to local lab support only. */
const FORBIDDEN_RUNTIME_PATTERNS: readonly RegExp[] = [
  /\/auth\/v1\/admin/u,
  /serviceRoleKey/u,
  /\.SUPABASE_SERVICE_ROLE_KEY\b|\[['"]SUPABASE_SERVICE_ROLE_KEY['"]\]/u,
  /local-oauth-admin-lab/u,
  /test\/support/u,
];

function isTestFile(path: string): boolean {
  return /\.test\./u.test(path);
}

async function walk(dir: string): Promise<string[]> {
  let entries: import('node:fs').Dirent[];
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const files: string[] = [];
  for (const entry of entries) {
    if (entry.name === 'node_modules') continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) files.push(...(await walk(full)));
    else files.push(full);
  }
  return files;
}

async function runtimeFiles(sub: 'src' | 'dist'): Promise<string[]> {
  const packages = await readdir(PACKAGES, { withFileTypes: true });
  const files: string[] = [];
  for (const pkg of packages) {
    if (!pkg.isDirectory()) continue;
    const all = await walk(join(PACKAGES, pkg.name, sub));
    files.push(
      ...all.filter((file) =>
        sub === 'src'
          ? file.endsWith('.ts') && !isTestFile(file)
          : /\.(?:js|d\.ts)$/u.test(file) && !isTestFile(file),
      ),
    );
  }
  return files;
}

async function offenders(files: readonly string[]): Promise<string[]> {
  const found: string[] = [];
  for (const file of files) {
    const text = await readFile(file, 'utf8');
    for (const pattern of FORBIDDEN_RUNTIME_PATTERNS) {
      if (pattern.test(text)) found.push(`${relative(ROOT, file)} ${pattern.source}`);
    }
  }
  return found;
}

describe('runtime admin-client boundary', () => {
  it('keeps the Auth admin client registration helper out of runtime source', async () => {
    const files = await runtimeFiles('src');
    expect(files.length).toBeGreaterThan(0);
    expect(await offenders(files)).toEqual([]);
  });

  it('keeps the Auth admin client registration helper out of the built package', async () => {
    // `npm test` builds before vitest runs, so dist is present in the gate.
    const files = await runtimeFiles('dist');
    expect(await offenders(files)).toEqual([]);
  });

  it('does not export an Auth admin client registration helper from the PKCE client', async () => {
    const client = await readFile(join(PACKAGES, 'server/src/local-oauth-pkce-client.ts'), 'utf8');
    expect(client).not.toContain('registerLocalPublicOAuthClient');
  });
});
