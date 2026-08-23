import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (path: string): string => readFileSync(path, 'utf8');

describe('RLS catalog lint contract', () => {
  it('ships the deterministic catalog-only lint and its database fixture', () => {
    const lint = read('sql/lint/rls_catalog_lint.sql');
    const fixture = read('supabase/tests/rls_catalog_lint.test.sql');
    const runner = read('scripts/run-policy-lab-catalog-test.mjs');
    const packageJson = JSON.parse(read('package.json')) as {
      scripts: Record<string, string>;
    };

    expect(packageJson.scripts['policy-lab:test:catalog']).toBe(
      'node scripts/run-policy-lab-catalog-test.mjs',
    );
    expect(runner).toContain('copyFileSync(source, staged)');
    expect(runner).toContain('rmSync(staged, { force: true })');
    expect(fixture).toContain('\\ir .rls_catalog_lint.generated.sql');
    expect(lint).toMatch(/select\s+sev,\s*id,\s*obj,\s*det/i);
    expect(lint).toMatch(/order by\s+severity_order,\s*id,\s*obj/i);
    expect(lint).toMatch(/aclexplode/i);
    expect(lint).toMatch(/pg_(?:class|policy|proc)/i);
    expect(lint).not.toMatch(/execute\s+format|service_role|bypassrls/i);

    for (const id of ['L01', 'L02', 'L03', 'L04', 'L05', 'L06', 'L07', 'L08', 'L09']) {
      expect(lint).toContain(`'${id}'`);
      expect(fixture).toContain(id);
    }
  });
});
