import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = resolve(import.meta.dirname, '../..');
const read = (path: string) => readFileSync(resolve(root, path), 'utf8');

describe('local Supabase policy lab contract', () => {
  it('pins deterministic lifecycle scripts and the Supabase CLI', () => {
    const packageJson = JSON.parse(read('package.json')) as {
      scripts: Record<string, string>;
      devDependencies: Record<string, string>;
    };

    expect(packageJson.devDependencies.supabase).toBe('2.115.0');
    expect(packageJson.scripts['policy-lab:reset']).toBe('supabase db reset --local');
    expect(packageJson.scripts['policy-lab:test']).toBe('supabase test db --local');
  });

  it('pins the local project and required SQL files', () => {
    expect(read('supabase/config.toml')).toContain('project_id = "supabase-user-mcp-policy-lab"');
    expect(read('supabase/seed.sql')).toContain('policy_lab.memories');
    expect(read('supabase/tests/policy_lab.test.sql')).toContain(
      'CREATE EXTENSION IF NOT EXISTS pgtap',
    );
  });

  it('contains fail-closed identity, lifecycle, capability, and RLS markers', () => {
    const migration = read('supabase/migrations/20260823000100_policy_lab.sql');

    for (const marker of [
      'auth.uid()',
      "auth.jwt() -> 'app_metadata' ->> 'client_id'",
      "capability = 'memory:read'",
      "identity_eligibility = 'verified'",
      "state = 'active'",
      'valid_until > now()',
      'ENABLE ROW LEVEL SECURITY',
      'FORCE ROW LEVEL SECURITY',
      'security_invoker = true',
      'REVOKE ALL',
    ]) {
      expect(migration).toContain(marker);
    }

    expect(migration).not.toMatch(/SECURITY\s+DEFINER/i);
    expect(migration).not.toMatch(/service_role|BYPASSRLS/i);
  });
});
