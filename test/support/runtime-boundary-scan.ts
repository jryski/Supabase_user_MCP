import type { Dirent } from 'node:fs';
import { readdir, readFile, stat } from 'node:fs/promises';
import { join, relative } from 'node:path';

/**
 * Admin Auth endpoints and privileged keys belong to local lab support only.
 *
 * Quoted names inside a refusal list (for example the remote startup's
 * forbidden environment names) are allowed; reading, destructuring or
 * bracket-indexing a privileged key is not, and neither is a bare
 * `service_role` string literal.
 */
export const FORBIDDEN_RUNTIME_PATTERNS: readonly RegExp[] = [
  /\/auth\/v1\/admin/u,
  /serviceRoleKey/u,
  /local-oauth-admin-lab/u,
  /test\/support/u,
  // A role name used as a value: `role: 'service_role'`, `=== "service_role"`.
  /(['"`])service_role\1/u,
  // Any unquoted use of a privileged key name: property access, destructuring,
  // shorthand properties, plain identifiers.
  /(?<![\w'"`])SUPABASE_(?:SERVICE_ROLE_KEY|SECRET_KEYS?)(?![\w'"`])/u,
  // Bracket access or getter calls with a quoted privileged key name.
  /\[\s*(['"`])SUPABASE_(?:SERVICE_ROLE_KEY|SECRET_KEYS?)\1\s*\]/u,
  /\.get\(\s*(['"`])SUPABASE_(?:SERVICE_ROLE_KEY|SECRET_KEYS?)\1\s*\)/u,
];

/** Drop whole-line comments so prose about a refused key is not a finding. */
export function stripLineComments(text: string): string {
  return text
    .split('\n')
    .filter((line) => !/^\s*(?:\/\/|\/\*|\*)/u.test(line))
    .join('\n');
}

export function scanText(text: string): string[] {
  const code = stripLineComments(text);
  return FORBIDDEN_RUNTIME_PATTERNS.filter((pattern) => pattern.test(code)).map(
    (pattern) => pattern.source,
  );
}

function isTestFile(path: string): boolean {
  return /\.test\./u.test(path);
}

async function walk(dir: string): Promise<string[]> {
  let entries: Dirent[];
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

async function packageDirs(packagesDir: string): Promise<string[]> {
  const entries = await readdir(packagesDir, { withFileTypes: true });
  return entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => join(packagesDir, entry.name));
}

function isRuntime(file: string, sub: 'src' | 'dist'): boolean {
  if (isTestFile(file)) return false;
  return sub === 'src' ? file.endsWith('.ts') : /\.(?:js|d\.ts)$/u.test(file);
}

export async function runtimeFiles(packagesDir: string, sub: 'src' | 'dist'): Promise<string[]> {
  const files: string[] = [];
  for (const pkg of await packageDirs(packagesDir)) {
    const all = await walk(join(pkg, sub));
    files.push(...all.filter((file) => isRuntime(file, sub)));
  }
  return files;
}

/**
 * Every runtime source file must have its built `.js` next to it in dist.
 * An empty, missing or partial dist is a finding, so the dist scan can never
 * pass by scanning nothing.
 */
export async function missingDistFiles(packagesDir: string): Promise<string[]> {
  const missing: string[] = [];
  for (const pkg of await packageDirs(packagesDir)) {
    const sources = (await walk(join(pkg, 'src'))).filter((file) => isRuntime(file, 'src'));
    for (const source of sources) {
      const built = join(pkg, 'dist', relative(join(pkg, 'src'), source)).replace(/\.ts$/u, '.js');
      const found = await stat(built).then(
        (info) => info.isFile() && info.size > 0,
        () => false,
      );
      if (!found) missing.push(relative(packagesDir, built));
    }
  }
  return missing;
}

export async function offenders(root: string, files: readonly string[]): Promise<string[]> {
  const found: string[] = [];
  for (const file of files) {
    for (const source of scanText(await readFile(file, 'utf8'))) {
      found.push(`${relative(root, file)} ${source}`);
    }
  }
  return found;
}
