import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

import {
  STORAGE_ALLOWED_MIME_TYPES,
  STORAGE_MAX_OBJECT_BYTES,
  STORAGE_MIME_BY_EXTENSION,
} from '../../packages/contracts/src/storage-bounds.js';
import { STORAGE_CAPABILITIES } from '../../packages/contracts/src/storage-tools.js';
import { STORAGE_RPC_SCHEMA } from '../../packages/server/src/user-scoped-storage-client.js';

// Issue #123 S4. Assumes option A; pending RLS layout decision.
const root = resolve(import.meta.dirname, '../..');
const read = (path: string) => readFileSync(resolve(root, path), 'utf8');
const sha256 = (path: string) =>
  createHash('sha256')
    .update(readFileSync(resolve(root, path)))
    .digest('hex');

const MIGRATION = 'supabase/migrations/20261027000100_storage_option_a.sql';
const FOLLOW_UP = 'supabase/migrations/20261027000200_storage_delegation_human_grant.sql';
const PGTAP = 'supabase/tests/database/storage_option_a_test.sql';
const CAVEAT = 'assumes option A; pending RLS layout decision';

// Byte pins for the grant-check invariant files. S4 must not edit them.
const INVARIANT_FILES: Readonly<Record<string, string>> = {
  'supabase/migrations/20260823000100_policy_lab.sql':
    '3b602ef598f1289c78ad0315c6dbad17932010339a1fb971be7e9f769dbbd600',
  'supabase/migrations/20260830000100_memory_read_rpc.sql':
    '49ab45ea0414e7cb14b37467b483d87542417251f9d1cfbf386fadd966fac7ea',
  'supabase/migrations/20260826000200_storage_object_policy.sql':
    '0c029be9324e86932ffe37d8aba29f69d840ef8240b7cace4178a42c4fab35dc',
};

describe('issue #123 S4 storage RLS (option A)', () => {
  const sql = read(MIGRATION);
  const code = sql.replace(/--[^\n]*/g, '');

  it('leaves the grant-check invariant files byte-identical', () => {
    for (const [path, digest] of Object.entries(INVARIANT_FILES)) {
      expect(sha256(path), path).toBe(digest);
    }
    expect(code).not.toMatch(/function\s+policy_lab\.has_active_capability/i);
    expect(code).not.toMatch(/(?:drop|alter)\s+policy\s+grant_is_active_context/i);
  });

  it('is fail-closed: invoker rights, fixed search_path, no service role, no UPDATE policy', () => {
    expect(code).not.toMatch(/service_role|bypassrls|security\s+definer/i);
    const functions = code.match(/create function[\s\S]*?\$\$;/gi) ?? [];
    expect(functions.length).toBe(7);
    for (const fn of functions) {
      expect(fn).toMatch(/security invoker/);
      expect(fn).toMatch(/set search_path = ''/);
    }
    const policies = code.match(/create policy[\s\S]*?;/gi) ?? [];
    const objectPolicies = policies.filter((p) => p.includes('on storage.objects'));
    expect(objectPolicies.map((p) => /for (\w+)/.exec(p)?.[1]).sort()).toEqual([
      'delete',
      'insert',
      'select',
    ]);
    for (const policy of policies) expect(policy).toMatch(/to authenticated\b/);
    for (const policy of objectPolicies) expect(policy).toContain("bucket_id = 'mcp-user-storage'");
    expect(code).not.toMatch(/grant[^;]*to[^;]*\banon\b/i);
  });

  it('keeps the agent sub-prefix choice behind one seam', () => {
    expect(code.match(/storage_principal\(\)::text/g)).toHaveLength(1);
    expect(code).toMatch(
      /create function policy_lab\.storage_object_prefix\(\)[\s\S]*?storage_principal\(\)::text \|\| '\/'/,
    );
    for (const policy of code.match(/create policy[^;]*on storage\.objects[^;]*;/gi) ?? []) {
      expect(policy).toContain('policy_lab.storage_object_allowed(name,');
    }
  });

  it('only widens the grant vocabulary by the two storage capabilities', () => {
    const check =
      /add constraint capability_grants_capability_check\s+check \(capability in \(([^)]*)\)\)/.exec(
        code,
      );
    expect(check?.[1]?.match(/'[^']+'/g)).toEqual([
      "'memory:search'",
      "'memory:read'",
      ...STORAGE_CAPABILITIES.map((c) => `'${c}'`),
    ]);
  });

  it('mirrors the S1 bounds in the bucket and key-shape check', () => {
    const bucket = /insert into storage\.buckets[\s\S]*?on conflict/.exec(code)?.[0] ?? '';
    expect(bucket).toContain(String(STORAGE_MAX_OBJECT_BYTES));
    expect(bucket).toMatch(/\n\s+false,/);
    expect(bucket.match(/'[a-z]+\/[a-z]+'/g)?.map((m) => m.slice(1, -1))).toEqual([
      ...STORAGE_ALLOWED_MIME_TYPES,
    ]);
    const extensions = /\[\.\]\(([a-z|]+)\)\$/.exec(code)?.[1]?.split('|');
    expect(extensions).toEqual(Object.keys(STORAGE_MIME_BY_EXTENSION));
    expect(code).toContain('{0,7}');
    expect(code).toContain('octet_length(relative_key) <= 512');
    expect(code).toContain('octet_length(s.segment) > 128');
  });

  it('provides the session RPCs the S2 client calls, in its schema', () => {
    expect(STORAGE_RPC_SCHEMA).toBe('policy_lab');
    expect(code).toContain('create function policy_lab.storage_principal()\nreturns uuid');
    expect(code).toContain(
      'create function policy_lab.storage_session_capabilities()\nreturns jsonb',
    );
  });

  it('ships a psql-free pgTAP suite covering the denial matrix', () => {
    const pgtap = read(PGTAP);
    expect(pgtap).not.toMatch(/^\\/m);
    expect(pgtap).toMatch(/^ROLLBACK;$/m);
    for (const marker of [
      'cross-client',
      'revoked delegation',
      'expired grants',
      'denied principal',
      'service agent',
      'missing client claim',
      'malformed client claim',
      'anon cannot call',
      'no UPDATE policy',
      'has_active_capability is unchanged',
      'expired human grants',
      'direct delete without the Storage API flag is refused',
    ]) {
      expect(pgtap).toContain(marker);
    }
  });

  it('labels every S4 doc with the option A caveat', () => {
    for (const path of [
      MIGRATION,
      FOLLOW_UP,
      PGTAP,
      'docs/decisions/0009-storage-rls-option-a.md',
      'docs/evidence/ISSUE_123_STORAGE_S4_RLS.md',
    ]) {
      expect(read(path).toLowerCase(), path).toContain(CAVEAT.toLowerCase());
    }
  });

  it('adds the human-grant check for agents without touching earlier grant checks', () => {
    const followUp = read(FOLLOW_UP).replace(/--[^\n]*/g, '');
    expect(followUp).not.toMatch(/service_role|bypassrls|security\s+definer/i);
    expect(followUp).not.toMatch(/has_active_capability\s*\(\s*required_capability text/i);
    expect(followUp).not.toMatch(/(?:drop|alter)\s+(?:policy|table)/i);
    expect(followUp).not.toMatch(/for (?:update|all)\b/i);
    expect(followUp).not.toMatch(/on storage\./i);
    const policies = followUp.match(/create policy[\s\S]*?;/gi) ?? [];
    expect(policies).toHaveLength(1);
    expect(policies[0]).toMatch(/on policy_lab\.capability_grants\s+for select to authenticated/);
    const functions = followUp.match(/create or replace function[\s\S]*?\$\$;/gi) ?? [];
    expect(functions).toHaveLength(1);
    expect(functions[0]).toMatch(
      /^create or replace function policy_lab\.storage_has_capability\(/,
    );
    expect(functions[0]).toMatch(/security invoker/);
    expect(functions[0]).toMatch(/set search_path = ''/);
    expect(functions[0]).toMatch(/g\.principal_id = d\.human_principal_id/);
    // The replaced body keeps every check of the original and only adds the human grant.
    const original = /create function policy_lab\.storage_has_capability[\s\S]*?\$\$;/.exec(
      code,
    )?.[0];
    const humanGrant =
      /\n\s+and exists \(\n\s+select 1\n\s+from policy_lab\.capability_grants g[\s\S]*?g\.valid_until > now\(\)\n\s+\)/;
    expect(
      functions[0]
        ?.replace(humanGrant, '')
        .replace('create or replace function', 'create function'),
    ).toBe(original);
    expect(followUp).not.toMatch(/to\s+anon\b/i);
  });
});
