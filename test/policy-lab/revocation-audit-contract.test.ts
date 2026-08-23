import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (path: string): string => readFileSync(path, 'utf8');

describe('revocation audit contract', () => {
  it('ships a focused, append-only, principal-scoped audit fixture', () => {
    const packageJson = JSON.parse(read('package.json')) as {
      scripts: Record<string, string>;
    };
    const migration = read('supabase/migrations/20260823000200_revocation_audit.sql');
    const seed = read('supabase/seed.sql');
    const fixture = read('supabase/tests/revocation_audit.test.sql');
    const evidence = read('docs/evidence/ISSUE_12_REVOCATION_AUDIT.md');

    expect(packageJson.scripts['policy-lab:test:revocation-audit']).toBe(
      'supabase test db supabase/tests/revocation_audit.test.sql --local',
    );
    expect(migration).toMatch(/create table policy_lab\.audit_events/i);
    expect(migration).toMatch(/event_id text primary key/i);
    expect(migration).toMatch(/recorded_at timestamptz/i);
    expect(migration).toMatch(/enable row level security/i);
    expect(migration).toMatch(/force row level security/i);
    expect(migration).toMatch(/revoke all[\s\S]*anon, authenticated/i);
    expect(migration).toMatch(/grant select[\s\S]*authenticated/i);
    expect(migration).not.toMatch(/security definer|service_role|bypassrls/i);
    expect(migration).not.toMatch(/create\s+(?:or\s+replace\s+)?function|create\s+procedure/i);

    for (const value of [
      'audit-active',
      'audit-client-revoked',
      'audit-membership-revoked',
      'audit-grant-revoked',
    ]) {
      expect(seed).toContain(value);
      expect(fixture).toContain(value);
    }

    expect(fixture).toMatch(/set local role authenticated/i);
    expect(fixture).toMatch(/set local role anon/i);
    expect(fixture).toMatch(/throws_ok[\s\S]*(?:insert|update|delete)/i);
    expect(fixture).toMatch(/savepoint[\s\S]*rollback to savepoint/i);
    expect(fixture).toMatch(/alter policy[\s\S]*guard detects/i);
    expect(fixture).toMatch(/update policy_lab\.capability_grants[\s\S]*state = 'revoked'/i);
    expect(evidence).toContain('# Issue 12: revocation and trusted audit');
    expect(evidence).toMatch(/transaction bound/i);
    expect(evidence).toMatch(/synthetic non-secret metadata/i);
  });
});
