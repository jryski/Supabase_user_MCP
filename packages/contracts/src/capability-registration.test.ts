import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { describe, expect, it, vi } from 'vitest';

import {
  CAPABILITY_APPROVAL_ALLOWLIST_VERSION,
  CAPABILITY_DESCRIPTOR_VERSION,
  CAPABILITY_REGISTRY_VERSION,
  type CapabilityComposition,
  type CapabilityDescriptorBody,
  type CapabilityServerPolicy,
  capabilityBodySha256,
  FORBIDDEN_ARGUMENT_TOKENS,
  isForbiddenArgumentName,
  MAX_REGISTERED_CAPABILITIES,
  parseCapabilityApprovalAllowlist,
  RESERVED_TOOL_NAMES,
  validateCapabilityArguments,
  validateCapabilityRegistry,
} from './capability-registration.js';

// Synthetic descriptors only: no real project, schema or function names.
const SCHEMA = 'app_synthetic';

function body(overrides: Partial<CapabilityDescriptorBody> = {}): CapabilityDescriptorBody {
  return {
    descriptorVersion: CAPABILITY_DESCRIPTOR_VERSION,
    name: 'app_example_lookup',
    title: 'Example lookup',
    description: 'Synthetic read capability for contract tests.',
    kind: 'read',
    rpc: { schema: SCHEMA, function: 'example_lookup' },
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['label'],
      properties: {
        label: { type: 'string', maxLength: 64 },
        limit: { type: 'integer', minimum: 1, maximum: 10 },
      },
    },
    limits: { maxResponseBytes: 4_096, timeoutMs: 1_000 },
    ...overrides,
  };
}

function linked(b: CapabilityDescriptorBody, adr = 'ADR-0005') {
  return { body: b, approval: { adr, bodySha256: capabilityBodySha256(b) } };
}

/** Server-owned policy whose release allowlist approves exactly the given bodies. */
function policy(
  composition: CapabilityComposition,
  approvedBodies: CapabilityDescriptorBody[],
  adopterSchemas: string[] = [SCHEMA],
): CapabilityServerPolicy {
  return {
    composition,
    adopterSchemas,
    approvals: {
      allowlistVersion: CAPABILITY_APPROVAL_ALLOWLIST_VERSION,
      approvals: approvedBodies.map((b) => ({
        adr: 'ADR-0005',
        bodySha256: capabilityBodySha256(b),
      })),
    },
  };
}

function file(descriptors: unknown[]) {
  return { registryVersion: CAPABILITY_REGISTRY_VERSION, descriptors };
}

function register(composition: CapabilityComposition, bodies: CapabilityDescriptorBody[]) {
  return validateCapabilityRegistry(
    file(bodies.map((b) => linked(b))),
    policy(composition, bodies),
  );
}

describe('capability registration contract (proposed, issue #122)', () => {
  it('accepts an empty registry, so the default server is unchanged', () => {
    const result = validateCapabilityRegistry(file([]), policy('read-only', []));
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.registry.names).toEqual([]);
  });

  it('accepts an approved read descriptor and returns a frozen finite registry', () => {
    const result = register('read-only', [body()]);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.registry.names).toEqual(['app_example_lookup']);
    expect(Object.isFrozen(result.registry)).toBe(true);
    expect(Object.isFrozen(result.registry.names)).toBe(true);
    const entry = result.registry.resolve('app_example_lookup');
    expect(entry?.rpc).toEqual({ schema: SCHEMA, function: 'example_lookup' });
    expect(Object.isFrozen(entry?.rpc)).toBe(true);
  });

  it('resolves nothing that is not listed (deny by default)', () => {
    const result = register('application', [body()]);
    if (!result.ok) throw new Error('expected ok');
    for (const name of ['memory_search', 'app_other', '__proto__', 'constructor', 'toString', '']) {
      expect(result.registry.resolve(name)).toBeUndefined();
    }
  });

  it('enforces the finite bound', () => {
    const many = Array.from({ length: MAX_REGISTERED_CAPABILITIES + 1 }, (_, i) =>
      body({ name: `app_cap_${i}`, rpc: { schema: SCHEMA, function: `cap_${i}` } }),
    );
    const allowed = many.slice(0, MAX_REGISTERED_CAPABILITIES);
    expect(
      validateCapabilityRegistry(file(many.map((b) => linked(b))), policy('application', allowed)),
    ).toEqual({
      ok: false,
      code: 'registry_too_large',
    });
    expect(register('application', allowed).ok).toBe(true);
  });

  it('rejects reserved and non-prefixed names', () => {
    for (const name of [...RESERVED_TOOL_NAMES, 'lookup', 'App_x', 'app_', 'app_admin x']) {
      const b = body({ name });
      expect(
        validateCapabilityRegistry(file([linked(b)]), policy('application', [b])),
      ).toMatchObject({
        ok: false,
        code: 'descriptor_invalid',
      });
    }
  });

  it('rejects name and RPC collisions', () => {
    const second = body({ name: 'app_second' });
    expect(
      validateCapabilityRegistry(
        file([linked(body()), linked(body())]),
        policy('application', [body()]),
      ),
    ).toEqual({
      ok: false,
      code: 'name_collision',
      index: 1,
    });
    expect(register('application', [body(), second])).toEqual({
      ok: false,
      code: 'rpc_collision',
      index: 1,
    });
  });

  it('has no approval, admin or write kind', () => {
    for (const kind of ['approval', 'admin', 'write', 'execute']) {
      const b = { ...body(), kind } as unknown as CapabilityDescriptorBody;
      expect(
        validateCapabilityRegistry(file([linked(b)]), policy('application', [b])),
      ).toMatchObject({
        ok: false,
        code: 'descriptor_invalid',
      });
    }
  });
});

describe('M1: approval lives outside the descriptor file', () => {
  it('rejects a self-consistent descriptor that the release allowlist does not approve', () => {
    const edited = body({ limits: { maxResponseBytes: 65_536, timeoutMs: 2_000 } });
    // Body edited and digest recomputed in config: integrity passes, approval does not.
    expect(
      validateCapabilityRegistry(file([linked(edited)]), policy('read-only', [body()])),
    ).toEqual({
      ok: false,
      code: 'descriptor_not_approved',
      index: 0,
    });
  });

  it('rejects an unlisted ADR reference even when the digest is approved under another ADR', () => {
    expect(
      validateCapabilityRegistry(file([linked(body(), 'ADR-9999')]), policy('read-only', [body()])),
    ).toEqual({
      ok: false,
      code: 'descriptor_not_approved',
      index: 0,
    });
  });

  it('reports a body that does not match its own link as a digest mismatch', () => {
    const tampered = {
      ...linked(body()),
      body: body({ rpc: { schema: SCHEMA, function: 'other' } }),
    };
    expect(validateCapabilityRegistry(file([tampered]), policy('read-only', [body()]))).toEqual({
      ok: false,
      code: 'descriptor_digest_mismatch',
      index: 0,
    });
  });

  it('parses the release allowlist strictly and freezes it', () => {
    const ok = parseCapabilityApprovalAllowlist({
      allowlistVersion: CAPABILITY_APPROVAL_ALLOWLIST_VERSION,
      approvals: [{ adr: 'ADR-0005', bodySha256: capabilityBodySha256(body()) }],
    });
    expect(ok.ok).toBe(true);
    if (ok.ok) expect(Object.isFrozen(ok.allowlist.approvals)).toBe(true);
    for (const bad of [
      { allowlistVersion: 'v0', approvals: [] },
      {
        allowlistVersion: CAPABILITY_APPROVAL_ALLOWLIST_VERSION,
        approvals: [{ adr: 'ADR-5', bodySha256: 'x' }],
      },
      { allowlistVersion: CAPABILITY_APPROVAL_ALLOWLIST_VERSION, approvals: [], extra: true },
      JSON.parse(
        `{"allowlistVersion":"${CAPABILITY_APPROVAL_ALLOWLIST_VERSION}","approvals":[],"__proto__":{}}`,
      ),
    ]) {
      expect(parseCapabilityApprovalAllowlist(bad)).toEqual({ ok: false });
    }
  });
});

describe('M2: composition is a server parameter', () => {
  it('denies proposal in a read-only server and allows it only when the server selects application', () => {
    const proposal = body({ kind: 'proposal' });
    expect(register('read-only', [proposal])).toEqual({
      ok: false,
      code: 'kind_denied_in_composition',
      index: 0,
    });
    expect(register('application', [proposal]).ok).toBe(true);
  });

  it('rejects a registry file that tries to declare its own composition', () => {
    const proposal = body({ kind: 'proposal' });
    const declared = { ...file([linked(proposal)]), composition: 'application' };
    expect(validateCapabilityRegistry(declared, policy('read-only', [proposal]))).toEqual({
      ok: false,
      code: 'registry_invalid',
    });
  });

  it('rejects an invalid server policy', () => {
    const bad = {
      ...policy('read-only', []),
      composition: 'admin',
    } as unknown as CapabilityServerPolicy;
    expect(validateCapabilityRegistry(file([]), bad)).toEqual({
      ok: false,
      code: 'policy_invalid',
    });
  });
});

describe('M3: adopter schema allowlist', () => {
  it('rejects a schema the server did not list', () => {
    const b = body({ rpc: { schema: 'app_other', function: 'f' } });
    expect(validateCapabilityRegistry(file([linked(b)]), policy('read-only', [b]))).toEqual({
      ok: false,
      code: 'schema_not_allowed',
      index: 0,
    });
  });

  it('refuses public and platform schemas in descriptors and in server policy', () => {
    for (const schema of [
      'public',
      'auth',
      'storage',
      'vault',
      'realtime',
      'graphql',
      'graphql_public',
      'graphql_x',
      'pg_catalog',
      'pgsodium',
      'pgsodium_masks',
      'pgmq',
      'pgmq_public',
      'pgtle',
      'supabase_functions',
      '_realtime',
      '_analytics',
      '_supavisor',
      'information_schema',
      'Public',
      'a.b',
    ]) {
      const b = body({ rpc: { schema, function: 'f' } });
      expect(
        validateCapabilityRegistry(file([linked(b)]), policy('application', [b])),
      ).toMatchObject({
        ok: false,
        code: 'descriptor_invalid',
      });
      expect(validateCapabilityRegistry(file([]), policy('application', [], [schema]))).toEqual({
        ok: false,
        code: 'policy_invalid',
      });
    }
  });
});

describe('M4 and minors: descriptor bounds', () => {
  const withLabel = (label: unknown): CapabilityDescriptorBody => {
    const b = body();
    return {
      ...b,
      inputSchema: { ...b.inputSchema, properties: { ...b.inputSchema.properties, label } },
    } as CapabilityDescriptorBody;
  };
  const rejects = (b: CapabilityDescriptorBody) =>
    expect(validateCapabilityRegistry(file([linked(b)]), policy('application', [b]))).toMatchObject(
      {
        ok: false,
        code: 'descriptor_invalid',
      },
    );

  it('M4: has no regex pattern field', () => {
    rejects(withLabel({ type: 'string', maxLength: 64, pattern: '^(a+)+$' }));
  });

  it('m1: rejects routing, identity and approval argument names by token', () => {
    for (const token of FORBIDDEN_ARGUMENT_TOKENS)
      expect(isForbiddenArgumentName(token)).toBe(true);
    for (const name of [
      'userid',
      'user_uuid',
      'auth_uid',
      'service_role',
      'role_name',
      'jwt_claims',
      'is_approved',
      'approved_by',
      'approval_state',
      'tenant',
      'owner_uuid',
      'password',
      'secret',
      'api_key',
    ]) {
      const b = body();
      rejects({
        ...b,
        inputSchema: {
          ...b.inputSchema,
          properties: { ...b.inputSchema.properties, [name]: { type: 'boolean' } },
        },
      });
    }
    expect(isForbiddenArgumentName('label')).toBe(false);
    expect(isForbiddenArgumentName('limit')).toBe(false);
  });

  it('m2: rejects internally inconsistent string arguments', () => {
    rejects(withLabel({ type: 'string', minLength: 10, maxLength: 5 }));
    rejects(withLabel({ type: 'string', maxLength: 3, enum: ['abcd'] }));
    rejects(withLabel({ type: 'string', minLength: 2, maxLength: 8, enum: ['a'] }));
    rejects(withLabel({ type: 'string', maxLength: 8, enum: ['a\u0000b'] }));
    rejects(withLabel({ type: 'string', maxLength: 8, enum: ['a', 'a'] }));
  });

  it('m4: rejects own __proto__ keys at registry, body and argument level', () => {
    const b = body();
    const sha = capabilityBodySha256(b);
    const allow = policy('application', [b]);
    const encoded = JSON.stringify(b);
    for (const text of [
      `{"registryVersion":"${CAPABILITY_REGISTRY_VERSION}","descriptors":[],"__proto__":{"x":1}}`,
      `{"registryVersion":"${CAPABILITY_REGISTRY_VERSION}","descriptors":[{"body":${encoded.replace('{', '{"__proto__":{},')},"approval":{"adr":"ADR-0005","bodySha256":"${sha}"}}]}`,
      `{"registryVersion":"${CAPABILITY_REGISTRY_VERSION}","descriptors":[{"body":${encoded.replace('"properties":{', '"properties":{"__proto__":{"type":"boolean"},')},"approval":{"adr":"ADR-0005","bodySha256":"${sha}"}}]}`,
    ]) {
      expect(validateCapabilityRegistry(JSON.parse(text), allow)).toEqual({
        ok: false,
        code: 'registry_invalid',
      });
    }
  });

  it('m5: rejects format, bidi, zero-width and line-separator characters in model-facing text', () => {
    for (const ch of ['\u0085', '\u202e', '\u200b', '\u2028', '\u2029', '\u0007']) {
      rejects(body({ description: `Synthetic ${ch} text` }));
      rejects(body({ title: `Title${ch}` }));
    }
  });

  it('m7/n1: checks length before scanning characters (scan never sees oversized text)', () => {
    const scanned: number[] = [];
    const original = RegExp.prototype.test;
    const spy = vi.spyOn(RegExp.prototype, 'test').mockImplementation(function (
      this: RegExp,
      value: string,
    ) {
      scanned.push(String(value).length);
      return original.call(this, value);
    });
    try {
      rejects(body({ description: 'x'.repeat(100_000) }));
      rejects(body({ title: 'x'.repeat(10_000) }));
    } finally {
      spy.mockRestore();
    }
    // Total characters seen by every regex test across both rejections. A guard-free scan,
    // whole-string or per-character, sees at least 110,000 characters; the guarded path sees
    // only the short fixture fields.
    expect(scanned.length).toBeGreaterThan(0);
    const total = scanned.reduce((sum, length) => sum + length, 0);
    expect(total).toBeLessThan(5_000);
  });

  it('m8: reads untrusted input once and refuses non-cloneable values', () => {
    let reads = 0;
    const input = {
      registryVersion: CAPABILITY_REGISTRY_VERSION,
      get descriptors() {
        reads += 1;
        return [];
      },
    };
    expect(validateCapabilityRegistry(input, policy('read-only', [])).ok).toBe(true);
    expect(reads).toBe(1);
    expect(
      validateCapabilityRegistry({ ...file([]), fn: () => 1 }, policy('read-only', [])),
    ).toEqual({
      ok: false,
      code: 'registry_invalid',
    });
  });

  it('rejects unknown descriptor fields, open envelopes, nested arguments and over-limit bounds', () => {
    const b = body();
    const variants: unknown[] = [
      { ...b, url: 'https://example.invalid' },
      { ...b, inputSchema: { ...b.inputSchema, additionalProperties: true } },
      { ...b, inputSchema: { ...b.inputSchema, properties: { label: { type: 'object' } } } },
      { ...b, inputSchema: { ...b.inputSchema, required: ['missing'] } },
      { ...b, limits: { maxResponseBytes: 10_000_000, timeoutMs: 1_000 } },
      { ...b, limits: { maxResponseBytes: 1_000, timeoutMs: 60_000 } },
      { ...b, description: 'x'.repeat(513) },
      { ...b, descriptorVersion: 'supabase-user-mcp.capability-descriptor.v2' },
    ];
    for (const v of variants) {
      const raw = { body: v, approval: { adr: 'ADR-0005', bodySha256: '0'.repeat(64) } };
      expect(validateCapabilityRegistry(file([raw]), policy('application', []))).toMatchObject({
        ok: false,
        code: 'descriptor_invalid',
      });
    }
  });

  it('call-time arguments are closed: extra or forged fields are rejected, not stripped', () => {
    const b = body();
    expect(validateCapabilityArguments(b, { label: 'a', limit: 3 })).toEqual({
      ok: true,
      value: { label: 'a', limit: 3 },
    });
    for (const args of [
      { label: 'a', user_id: 'x' },
      { label: 'a', schema: 'auth' },
      { label: 'a', limit: 11 },
      { label: 'a'.repeat(65) },
      { limit: 1 },
      { label: 1 },
      [],
      null,
    ]) {
      expect(validateCapabilityArguments(b, args)).toEqual({ ok: false });
    }
  });
});

describe('r3 hardening', () => {
  it('n3: snapshots the policy once, so a getter cannot switch composition mid-validation', () => {
    const proposal = body({ kind: 'proposal' });
    const base = policy('read-only', [proposal]);
    let reads = 0;
    const tricky = {
      adopterSchemas: base.adopterSchemas,
      approvals: base.approvals,
      get composition() {
        reads += 1;
        return reads === 1 ? 'read-only' : 'application';
      },
    } as unknown as CapabilityServerPolicy;
    expect(validateCapabilityRegistry(file([linked(proposal)]), tricky)).toEqual({
      ok: false,
      code: 'kind_denied_in_composition',
      index: 0,
    });
    expect(reads).toBe(1);
  });

  it('n3: mutating the policy after validation does not change the registry', () => {
    const p = policy('read-only', [body()]) as { composition: CapabilityComposition };
    const result = validateCapabilityRegistry(file([linked(body())]), p as CapabilityServerPolicy);
    p.composition = 'application';
    expect(result.ok && result.registry.composition).toBe('read-only');
  });

  it('n4: rejects concatenated and synonym identity, credential and routing names', () => {
    for (const name of [
      'tenantid',
      'ownerid',
      'actorid',
      'roleid',
      'accesstoken',
      'apitoken',
      'authtoken',
      'sessionid',
      'passwd',
      'pwd',
      'email',
      'impersonate',
      'on_behalf_of',
      'grant',
      'scope',
      'permission',
      'privilege',
      'claims',
      'identity',
      'host',
      'path',
      'webhook',
      'redirect',
      'username',
    ]) {
      expect(isForbiddenArgumentName(name), name).toBe(true);
    }
    for (const name of ['label', 'limit', 'category', 'start_date', 'page']) {
      expect(isForbiddenArgumentName(name), name).toBe(false);
    }
  });

  it('n5: refuses further platform schema names in descriptors and policy', () => {
    for (const schema of [
      'supabase',
      'auth_x',
      'storage_api',
      'vault_x',
      'realtime_x',
      'net_x',
      'cron_x',
      'tiger',
      'tiger_data',
      'topology',
    ]) {
      const b = body({ rpc: { schema, function: 'f' } });
      expect(
        validateCapabilityRegistry(file([linked(b)]), policy('application', [b])),
      ).toMatchObject({
        ok: false,
        code: 'descriptor_invalid',
      });
      expect(validateCapabilityRegistry(file([]), policy('application', [], [schema]))).toEqual({
        ok: false,
        code: 'policy_invalid',
      });
    }
  });

  it('n7: rejects an oversized descriptors array before copying it', () => {
    const spy = vi.spyOn(globalThis, 'structuredClone');
    try {
      const huge = {
        registryVersion: CAPABILITY_REGISTRY_VERSION,
        descriptors: new Array(1_000_000).fill(0),
      };
      expect(validateCapabilityRegistry(huge, policy('read-only', []))).toEqual({
        ok: false,
        code: 'registry_too_large',
      });
      const cloned = spy.mock.calls.some(([value]) => value === huge);
      expect(cloned).toBe(false);
    } finally {
      spy.mockRestore();
    }
  });
});

describe('capability registration is not wired into runtime', () => {
  const root = resolve(import.meta.dirname, '../../..');
  const pattern = /capability-registration|validateCapabilityRegistry|CapabilityServerPolicy/;

  it('is not exported from the contracts package index or exports map', () => {
    expect(readFileSync(join(root, 'packages/contracts/src/index.ts'), 'utf8')).not.toMatch(
      pattern,
    );
    const pkg = JSON.parse(readFileSync(join(root, 'packages/contracts/package.json'), 'utf8'));
    expect(Object.keys(pkg.exports)).toEqual(['.']);
  });

  it('is not imported by any server source file (recursive)', () => {
    const dir = join(root, 'packages/server/src');
    const files = readdirSync(dir, { recursive: true, encoding: 'utf8' }).filter((f) =>
      f.endsWith('.ts'),
    );
    expect(files.length).toBeGreaterThan(0);
    for (const f of files) expect(readFileSync(join(dir, f), 'utf8')).not.toMatch(pattern);
  });
});
