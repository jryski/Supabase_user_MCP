import { spawnSync } from 'node:child_process';
import { copyFileSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const source = resolve(root, 'sql/lint/rls_catalog_lint.sql');
const staged = resolve(root, 'supabase/tests/.rls_catalog_lint.generated.sql');

let exitCode = 1;
try {
  copyFileSync(source, staged);
  const command = process.platform === 'win32' ? 'supabase.cmd' : 'supabase';
  const result = spawnSync(
    command,
    ['test', 'db', 'supabase/tests/rls_catalog_lint.test.sql', '--local'],
    { cwd: root, stdio: 'inherit', shell: process.platform === 'win32' },
  );
  exitCode = result.status ?? 1;
} finally {
  rmSync(staged, { force: true });
}

process.exitCode = exitCode;
