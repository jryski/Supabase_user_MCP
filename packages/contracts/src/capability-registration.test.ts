import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

import {
  CAPABILITY_DESCRIPTOR_VERSION,
  CAPABILITY_REGISTRY_VERSION,
  type CapabilityDescriptorBody,
  capabilityBodySha256,
  FORBIDDEN_ARGUMENT_NAMES,
  MAX_REGISTERED_CAPABILITIES,
  RESERVED_TOOL_NAMES,
  validateCapabilityArguments,
  validateCapabilityRegistry,
} from './capability-registration.js';

// Synthetic descriptors only: no real project, schema or function names.
function body(overrides: Partial<CapabilityDescriptorBody> = {}): CapabilityDescriptorBody {
  return {
    descriptorVersion: CAPABILITY_DESCRIPTOR_VERSION,
    name: 'app_example_lookup',
    title: 'Example lookup',
    description: 'Synthetic read capability for contract tests.',
    kind: 'read',
    rpc: { schema: 'app_synthetic', function: 'example_lookup' },
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

function reviewed(b: CapabilityDescriptorBody) {
  return { body: b, review: { adr: 'ADR-0005', approvedBodySha256: capabilityBodySha256(b) } };
}

function registry(composition: 'read-only' | 'application', descriptors: unknown[]) {
  return validateCapabilityRegistry({
    registryVersion: CAPABILITY_REGISTRY_VERSION,
    composition,
    descriptors,
  });
}

describe('capability registration contract (proposed, issue #122)', () => {
  it('accepts an empty registry, so the default server is unchanged', () => {
    const result = registry('read-only', []);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.registry.names).toEqual([]);
  });

  it('accepts a reviewed read descriptor and returns a frozen finite registry', () => {
    const result = registry('read-only', [reviewed(body())]);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.registry.names).toEqual(['app_example_lookup']);
    expect(Object.isFrozen(result.registry)).toBe(true);
    expect(Object.isFrozen(result.registry.names)).toBe(true);
    const entry = result.registry.resolve('app_example_lookup');
    expect(entry?.rpc).toEqual({ schema: 'app_synthetic', function: 'example_lookup' });
    expect(Object.isFrozen(entry?.rpc)).toBe(true);
  });

  it('resolves nothing that is not listed (deny by default)', () => {
    const result = registry('application', [reviewed(body())]);
    if (!result.ok) throw new Error('expected ok');
    for (const name of ['memory_search', 'app_other', '__proto__', 'constructor', 'toString', '']) {
      expect(result.registry.resolve(name)).toBeUndefined();
    }
  });

  it('enforces the finite bound', () => {
    const many = Array.from({ length: MAX_REGISTERED_CAPABILITIES + 1 }, (_, i) =>
      reviewed(
        body({ name: `app_cap_${i}`, rpc: { schema: 'app_synthetic', function: `cap_${i}` } }),
      ),
    );
    expect(registry('application', many)).toEqual({ ok: false, code: 'registry_too_large' });
    expect(registry('application', many.slice(0, MAX_REGISTERED_CAPABILITIES)).ok).toBe(true);
  });

  it('rejects reserved and non-prefixed names', () => {
    for (const name of [...RESERVED_TOOL_NAMES, 'lookup', 'App_x', 'app_', 'app_admin x']) {
      expect(registry('application', [reviewed(body({ name }))])).toMatchObject({
        ok: false,
        code: 'descriptor_invalid',
      });
    }
  });

  it('rejects name and RPC collisions', () => {
    expect(registry('application', [reviewed(body()), reviewed(body())])).toEqual({
      ok: false,
      code: 'name_collision',
      index: 1,
    });
    expect(
      registry('application', [reviewed(body()), reviewed(body({ name: 'app_second' }))]),
    ).toEqual({
      ok: false,
      code: 'rpc_collision',
      index: 1,
    });
  });

  it('denies proposal capabilities in the read-only composition only', () => {
    const proposal = reviewed(body({ kind: 'proposal' }));
    expect(registry('read-only', [proposal])).toEqual({
      ok: false,
      code: 'kind_denied_in_composition',
      index: 0,
    });
    expect(registry('application', [proposal]).ok).toBe(true);
  });

  it('has no approval, admin or write kind', () => {
    for (const kind of ['approval', 'admin', 'write', 'execute']) {
      const b = { ...body(), kind } as unknown as CapabilityDescriptorBody;
      expect(registry('application', [reviewed(b)])).toMatchObject({
        ok: false,
        code: 'descriptor_invalid',
      });
    }
  });

  it('rejects a descriptor whose body differs from the reviewed digest', () => {
    const approved = reviewed(body());
    const tampered = {
      ...approved,
      body: body({ rpc: { schema: 'app_synthetic', function: 'other' } }),
    };
    expect(registry('application', [tampered])).toEqual({
      ok: false,
      code: 'descriptor_not_reviewed',
      index: 0,
    });
  });

  it('rejects forbidden schemas', () => {
    for (const schema of [
      'auth',
      'storage',
      'vault',
      'pg_catalog',
      'pg_anything',
      'supabase_functions',
      'Public',
      'a.b',
    ]) {
      expect(
        registry('application', [reviewed(body({ rpc: { schema, function: 'f' } }))]),
      ).toMatchObject({
        ok: false,
        code: 'descriptor_invalid',
      });
    }
  });

  it('rejects routing and identity fields declared as arguments', () => {
    for (const name of FORBIDDEN_ARGUMENT_NAMES) {
      const b = body();
      const forged = {
        ...b,
        inputSchema: {
          ...b.inputSchema,
          properties: { ...b.inputSchema.properties, [name]: { type: 'string', maxLength: 8 } },
        },
      } as CapabilityDescriptorBody;
      expect(registry('application', [reviewed(forged)])).toMatchObject({
        ok: false,
        code: 'descriptor_invalid',
      });
    }
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
      const raw = { body: v, review: { adr: 'ADR-0005', approvedBodySha256: '0'.repeat(64) } };
      expect(registry('application', [raw])).toMatchObject({
        ok: false,
        code: 'descriptor_invalid',
      });
    }
    expect(
      validateCapabilityRegistry({
        registryVersion: CAPABILITY_REGISTRY_VERSION,
        composition: 'admin',
        descriptors: [],
      }),
    ).toEqual({ ok: false, code: 'registry_invalid' });
    expect(
      validateCapabilityRegistry({
        registryVersion: CAPABILITY_REGISTRY_VERSION,
        composition: 'read-only',
        descriptors: [],
        discover: true,
      }),
    ).toEqual({ ok: false, code: 'registry_invalid' });
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

describe('capability registration is not wired into runtime', () => {
  const root = resolve(import.meta.dirname, '../../..');
  it('is not exported from the contracts package index', () => {
    expect(readFileSync(join(root, 'packages/contracts/src/index.ts'), 'utf8')).not.toMatch(
      /capability-registration/,
    );
  });
  it('is not imported by any server source file', () => {
    const dir = join(root, 'packages/server/src');
    for (const file of readdirSync(dir).filter((f) => f.endsWith('.ts'))) {
      expect(readFileSync(join(dir, file), 'utf8')).not.toMatch(
        /capability-registration|validateCapabilityRegistry/,
      );
    }
  });
});
