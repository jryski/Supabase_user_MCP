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
    expect(functions.length).toBe(6);
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
    ]) {
      expect(pgtap).toContain(marker);
    }
  });

  it('labels every S4 doc with the option A caveat', () => {
    for (const path of [
      MIGRATION,
      PGTAP,
      'docs/decisions/0009-storage-rls-option-a.md',
      'docs/evidence/ISSUE_123_STORAGE_S4_RLS.md',
    ]) {
      expect(read(path).toLowerCase(), path).toContain(CAVEAT.toLowerCase());
    }
  });
});
