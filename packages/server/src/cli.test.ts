import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

const CLI_SOURCE = new URL('./cli.ts', import.meta.url);
const PUBLIC_INDEX_SOURCE = new URL('./index.ts', import.meta.url);

describe('production CLI contract', () => {
  it('launches the verified read-only startup runner instead of the M0 compatibility server', async () => {
    const source = await readFile(CLI_SOURCE, 'utf8');

    expect(source).toContain('runReadOnlyStdioCli');
    expect(source).not.toContain('createServer');
    expect(source).not.toContain('compatibility probe listening');
  });

  it('does not re-export the M0 probe factory from the public server barrel', async () => {
    const source = await readFile(PUBLIC_INDEX_SOURCE, 'utf8');

    expect(source).not.toMatch(/\bcreateServer,/u);
  });
});
