import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

const migrationPath = 'sql/repair_post_model_message_identity_allocation.sql';
const migration = readFileSync(migrationPath, 'utf8');
const normalized = migration.replace(/\s+/g, ' ').trim().toLowerCase();

describe('post_model_message identity-allocation repair', () => {
  it('preserves the bounded security-definer function boundary', () => {
    expect(normalized).toContain('create or replace function public.post_model_message(');
    expect(normalized).toContain('returns jsonb language plpgsql security definer');
    expect(normalized).toContain('set search_path = pg_catalog, public');
    expect(normalized).toContain("raise exception 'from_agent is required'");
    expect(normalized).toContain("raise exception 'to_agent is required'");
    expect(normalized).toContain("raise exception 'body is required'");
    expect(normalized).toContain("raise exception 're_seq does not exist: %', p_re_seq");
  });

  it('lets the generated identity allocate seq and returns the stored value', () => {
    const insertColumns = normalized.match(
      /insert into public\.model_channel\s*\(([^)]*)\)\s*values/,
    );

    expect(insertColumns?.[1]?.split(',').map((column) => column.trim())).toEqual([
      'from_agent',
      'to_agent',
      're_seq',
      'subject',
      'body',
    ]);
    expect(normalized).toContain('returning id, seq into v_id, v_seq');
    expect(normalized).not.toMatch(/max\s*\(\s*seq\s*\)/);
    expect(normalized).not.toContain('pg_advisory_xact_lock');
  });

  it('restates the service-role-only execute ACL', () => {
    const signature = 'public.post_model_message(text, text, text, text, bigint)';

    expect(normalized).toContain(`revoke all on function ${signature} from public`);
    expect(normalized).toContain(`revoke all on function ${signature} from anon`);
    expect(normalized).toContain(`revoke all on function ${signature} from authenticated`);
    expect(normalized).toContain(`grant execute on function ${signature} to postgres`);
    expect(normalized).toContain(`grant execute on function ${signature} to service_role`);
  });
});
