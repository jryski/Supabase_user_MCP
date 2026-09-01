import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

const M2_HARNESS = new URL('../supabase/tests/run-m2-memory-lab.sh', import.meta.url);

describe('M2 official-upstream harness contract', () => {
  it('uses official Auth sign-in and a non-model-facing PostgREST surface census', async () => {
    const script = await readFile(M2_HARNESS, 'utf8');

    expect(script).not.toContain('/auth/v1/token?grant_type=password');
    expect(script).toContain('test/support/mint-m2-token.ts');
    expect(script).toContain('test/support/check-m2-postgrest-surface.ts');
    expect(script).toContain('official-auth-js-sign-in');
    expect(script).toContain('postgrest-openapi-surface-census');
  });
});
