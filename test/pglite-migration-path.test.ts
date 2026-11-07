import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import { applyRepoMigrations } from './support/pglite-supabase-stub.js';

describe('PGlite migration fixture path handling', () => {
  it('loads the same sorted files from a native path and an encoded file URL', async () => {
    const root = await mkdtemp(join(tmpdir(), 'pglite-path-'));
    // Resolve and verify the exact recursive-cleanup target before use.
    if (dirname(resolve(root)) !== resolve(tmpdir()) || !basename(root).startsWith('pglite-path-'))
      throw Error('Unexpected fixture root');
    const fixture = join(root, 'space and # fragment');
    try {
      const directory = join(fixture, 'supabase', 'migrations');
      await mkdir(directory, { recursive: true });
      await writeFile(join(directory, '002_second.sql'), 'select 2;');
      await writeFile(join(directory, '001_first.sql'), 'select 1;');
      await writeFile(join(directory, 'ignored.txt'), 'not SQL');
      for (const input of [fixture, pathToFileURL(fixture)]) {
        const statements: string[] = [];
        const files = await applyRepoMigrations(
          {
            exec: async (sql) => {
              statements.push(sql);
            },
          },
          input,
        );
        expect(files).toEqual(['001_first.sql', '002_second.sql']);
        expect(statements).toEqual(['select 1;', 'select 2;']);
      }
    } finally {
      // Delete only the explicitly verified, owned temporary child above.
      await rm(root, { recursive: true, force: true });
    }
  });
});
