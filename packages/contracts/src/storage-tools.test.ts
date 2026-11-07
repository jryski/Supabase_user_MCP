import { describe, expect, it } from 'vitest';

import { CAPABILITIES } from './authorization.js';
import { MAX_RESPONSE_BYTES, readToolWireResponseByteLength } from './read-tools.js';
import { STORAGE_MAX_INLINE_BYTES, STORAGE_SIGNED_URL_TTL_SECONDS } from './storage-bounds.js';
import {
  STORAGE_CAPABILITIES,
  STORAGE_CAPABILITIES_TOOL,
  STORAGE_GET_TOOL,
  STORAGE_LIST_TOOL,
  STORAGE_READ_TOOL_NAMES,
  STORAGE_READ_TOOLS,
  StorageCapabilitiesInputSchema,
  StorageGetInputSchema,
  StorageGetOutputSchema,
  StorageListInputSchema,
  StorageListOutputSchema,
} from './storage-tools.js';

const KEY = 'notes/today.md';
const UPDATED = '2026-10-01T00:00:00.000Z';

function inlineRecord(bytes: number) {
  return {
    ok: true,
    record: {
      key: 'blob/max.txt',
      size: bytes,
      mimeType: 'text/plain',
      updatedAt: UPDATED,
      delivery: 'inline',
      contentTrust: 'untrusted',
      contentBase64: Buffer.alloc(bytes, 0xff).toString('base64'),
    },
  };
}

describe('storage capabilities', () => {
  it('are separate from the memory capability set', () => {
    expect([...STORAGE_CAPABILITIES]).toEqual(['storage:read', 'storage:write']);
    for (const capability of STORAGE_CAPABILITIES) {
      expect((CAPABILITIES as readonly string[]).includes(capability)).toBe(false);
    }
  });

  it('read tools all require storage:read and are named consistently', () => {
    expect(STORAGE_READ_TOOLS.map((tool) => tool.name)).toEqual([...STORAGE_READ_TOOL_NAMES]);
    for (const tool of STORAGE_READ_TOOLS) {
      expect(tool.capability).toBe('storage:read');
      expect(Object.isFrozen(tool)).toBe(true);
      expect(tool.limits.maxResponseBytes).toBe(MAX_RESPONSE_BYTES);
    }
    expect(STORAGE_LIST_TOOL.limits.maxRows).toBe(100);
    expect(STORAGE_GET_TOOL.limits.maxRows).toBe(1);
    expect(STORAGE_CAPABILITIES_TOOL.limits.maxRows).toBe(0);
  });
});

describe('storage tool input schemas', () => {
  it('accept only relative keys and no authority fields', () => {
    expect(StorageGetInputSchema.parse({ key: KEY })).toEqual({ key: KEY, delivery: 'auto' });
    expect(StorageListInputSchema.parse({})).toEqual({ prefix: '', limit: 100 });
    expect(StorageCapabilitiesInputSchema.safeParse({}).success).toBe(true);
    for (const extra of ['bucket', 'principal', 'principalId', 'token', 'url', 'owner']) {
      expect(StorageGetInputSchema.safeParse({ key: KEY, [extra]: 'x' }).success).toBe(false);
      expect(StorageListInputSchema.safeParse({ [extra]: 'x' }).success).toBe(false);
      expect(StorageCapabilitiesInputSchema.safeParse({ [extra]: 'x' }).success).toBe(false);
    }
  });

  it('reject path escapes, absolute keys and disallowed types', () => {
    for (const key of [
      '../other/file.txt',
      'a/../../file.txt',
      '/abs/file.txt',
      'a\\b.txt',
      './file.txt',
      'a//b.txt',
      '%2e%2e/file.txt',
      '11111111-1111-4111-9111-111111111111/../x.txt',
      'run.exe',
      'page.html',
      'noext',
    ]) {
      expect(StorageGetInputSchema.safeParse({ key }).success, key).toBe(false);
    }
    expect(StorageListInputSchema.safeParse({ prefix: '../' }).success).toBe(false);
    expect(StorageListInputSchema.safeParse({ prefix: 'docs/' }).success).toBe(false);
  });

  it('bound limit and cursor shape', () => {
    expect(StorageListInputSchema.safeParse({ limit: 0 }).success).toBe(false);
    expect(StorageListInputSchema.safeParse({ limit: 101 }).success).toBe(false);
    expect(StorageListInputSchema.safeParse({ cursor: 'not-a-cursor' }).success).toBe(false);
    expect(StorageListInputSchema.safeParse({ delivery: 'inline' }).success).toBe(false);
    expect(StorageGetInputSchema.safeParse({ key: KEY, delivery: 'stream' }).success).toBe(false);
  });
});

describe('storage tool output schemas', () => {
  it('the largest inline object fits the doubled wire envelope', () => {
    const output = inlineRecord(STORAGE_MAX_INLINE_BYTES);
    expect(StorageGetOutputSchema.safeParse(output).success).toBe(true);
    expect(readToolWireResponseByteLength('r'.repeat(1000), output)).toBeLessThanOrEqual(
      MAX_RESPONSE_BYTES,
    );
    expect(
      StorageGetOutputSchema.safeParse(inlineRecord(STORAGE_MAX_INLINE_BYTES + 3)).success,
    ).toBe(false);
  });

  it('signed URLs must be https and carry untrusted content markers', () => {
    const signed = {
      ok: true,
      record: {
        key: 'big/report.pdf',
        size: 1_000_000,
        mimeType: 'application/pdf',
        updatedAt: UPDATED,
        delivery: 'signed_url',
        contentTrust: 'untrusted',
        signedUrl: 'https://storage.example.test/storage/v1/object/sign/b/k?token=t',
        expiresAt: new Date(
          Date.parse(UPDATED) + STORAGE_SIGNED_URL_TTL_SECONDS * 1000,
        ).toISOString(),
      },
    };
    expect(StorageGetOutputSchema.safeParse(signed).success).toBe(true);
    expect(
      StorageGetOutputSchema.safeParse({
        ...signed,
        record: { ...signed.record, signedUrl: 'http://storage.example.test/x?token=t' },
      }).success,
    ).toBe(false);
    expect(
      StorageGetOutputSchema.safeParse({
        ...signed,
        record: { ...signed.record, contentTrust: 'trusted' },
      }).success,
    ).toBe(false);
    expect(
      StorageGetOutputSchema.safeParse({ ...signed, record: { ...signed.record, owner: 'x' } })
        .success,
    ).toBe(false);
  });

  it('list output rejects absolute or escaping keys and disallowed types', () => {
    const item = {
      kind: 'object',
      key: KEY,
      size: 1,
      mimeType: 'text/markdown',
      updatedAt: UPDATED,
    };
    expect(StorageListOutputSchema.safeParse({ ok: true, items: [item] }).success).toBe(true);
    for (const bad of [
      { ...item, key: '/abs.md' },
      { ...item, key: '../x.md' },
      { ...item, mimeType: 'text/html' },
      { kind: 'folder', key: '' },
    ]) {
      expect(StorageListOutputSchema.safeParse({ ok: true, items: [bad] }).success).toBe(false);
    }
  });
});
