import { describe, expect, it } from 'vitest';

import { MAX_RESPONSE_BYTES } from './read-tools.js';
import {
  checkStorageBucketId,
  checkStorageInlineBase64,
  checkStorageMimeType,
  checkStorageSize,
  parseStorageListPrefix,
  parseStorageRelativeKey,
  STORAGE_ALLOWED_MIME_TYPES,
  STORAGE_INLINE_ENVELOPE_HEADROOM_BYTES,
  STORAGE_MAX_INLINE_BYTES,
  STORAGE_MAX_KEY_SEGMENTS,
  STORAGE_MAX_OBJECT_BYTES,
  STORAGE_MAX_RELATIVE_KEY_BYTES,
  STORAGE_MAX_SEGMENT_BYTES,
  STORAGE_MIME_BY_EXTENSION,
  StorageListPrefixSchema,
  StorageMimeTypeSchema,
  StorageRelativeKeySchema,
} from './storage-bounds.js';

function reason(result: { ok: boolean; reason?: string }): string | undefined {
  return result.ok ? undefined : result.reason;
}

describe('storage relative key bounds', () => {
  it('accepts a bounded relative key and derives its type from the extension', () => {
    const result = parseStorageRelativeKey('notes/2026/synthetic-note.md');
    expect(result).toEqual({
      ok: true,
      value: {
        key: 'notes/2026/synthetic-note.md',
        segments: ['notes', '2026', 'synthetic-note.md'],
        extension: 'md',
        mimeType: 'text/markdown',
      },
    });
    expect(Object.isFrozen(result)).toBe(true);
    expect(result.ok && Object.isFrozen(result.value.segments)).toBe(true);
  });

  it.each([
    ['../other-principal/secret.txt', 'dot_segment'],
    ['a/../../b.txt', 'dot_segment'],
    ['./a.txt', 'dot_segment'],
    ['a/./b.txt', 'dot_segment'],
    ['/abs/path.txt', 'absolute_path'],
    ['//double.txt', 'absolute_path'],
    ['a//b.txt', 'empty_segment'],
    ['a/', 'empty_segment'],
    ['a\\..\\b.txt', 'backslash'],
    ['C:\\x.txt', 'backslash'],
    ['a/..b.txt', 'disallowed_character'],
    ['a/b..txt', 'disallowed_character'],
    ['%2e%2e/b.txt', 'disallowed_character'],
    ['a/%2F/b.txt', 'disallowed_character'],
    ['bucket:other/b.txt', 'disallowed_character'],
    ['a b.txt', 'disallowed_character'],
    ['a/\u0000.txt', 'disallowed_character'],
    ['a\n.txt', 'disallowed_character'],
    ['\u2025/b.txt', 'disallowed_character'],
    ['caf\u00e9.txt', 'disallowed_character'],
    ['\uff0e\uff0e/b.txt', 'disallowed_character'],
    ['.hidden.txt', 'disallowed_character'],
    ['-flag.txt', 'disallowed_character'],
    ['', 'empty'],
  ])('rejects path escape or unsafe key %j', (key, expected) => {
    expect(reason(parseStorageRelativeKey(key))).toBe(expected);
  });

  it.each([
    ['README', 'missing_extension'],
    ['dir/file.', 'missing_extension'],
    ['index.html', 'disallowed_extension'],
    ['image.svg', 'disallowed_extension'],
    ['script.js', 'disallowed_extension'],
    ['data.xml', 'disallowed_extension'],
    ['upper.PNG', 'disallowed_extension'],
    ['double.txt.exe', 'disallowed_extension'],
    ['proto.constructor', 'disallowed_extension'],
    ['proto.__proto__', 'disallowed_extension'],
    ['proto.hasOwnProperty', 'disallowed_extension'],
  ])('rejects key %j without an allowlisted extension', (key, expected) => {
    expect(reason(parseStorageRelativeKey(key))).toBe(expected);
  });

  it('rejects non-string input', () => {
    for (const value of [undefined, null, 1, ['a.txt'], { key: 'a.txt' }]) {
      expect(reason(parseStorageRelativeKey(value))).toBe('not_a_string');
    }
  });

  it('enforces exact segment, depth and total byte limits', () => {
    const segment = 'a'.repeat(STORAGE_MAX_SEGMENT_BYTES);
    expect(parseStorageRelativeKey(`${segment.slice(4)}.txt`).ok).toBe(true);
    expect(reason(parseStorageRelativeKey(`${segment}.txt`))).toBe('segment_too_long');

    const atDepth = [...Array(STORAGE_MAX_KEY_SEGMENTS - 1).fill('d'), 'f.txt'].join('/');
    expect(parseStorageRelativeKey(atDepth).ok).toBe(true);
    expect(reason(parseStorageRelativeKey(`d/${atDepth}`))).toBe('too_many_segments');

    const longKey = `${'b'.repeat(STORAGE_MAX_RELATIVE_KEY_BYTES - 4)}.txt`;
    expect(reason(parseStorageRelativeKey(longKey))).not.toBe('too_long');
    expect(reason(parseStorageRelativeKey(`b${longKey}`))).toBe('too_long');
  });

  it('accepts a multi-segment key of exactly the total byte limit and rejects one byte more', () => {
    const directory = 'a'.repeat(STORAGE_MAX_SEGMENT_BYTES - 1);
    const leaf = `${'b'.repeat(STORAGE_MAX_SEGMENT_BYTES - 4)}.txt`;
    const exact = [directory, directory, directory, leaf].join('/');
    expect(new TextEncoder().encode(exact).byteLength).toBe(STORAGE_MAX_RELATIVE_KEY_BYTES);
    const parsed = parseStorageRelativeKey(exact);
    expect(parsed.ok).toBe(true);
    expect(parsed.ok && parsed.value.segments).toHaveLength(4);
    expect(StorageRelativeKeySchema.safeParse(exact).success).toBe(true);

    const over = [`${directory}a`, directory, directory, leaf].join('/');
    expect(new TextEncoder().encode(over).byteLength).toBe(STORAGE_MAX_RELATIVE_KEY_BYTES + 1);
    expect(reason(parseStorageRelativeKey(over))).toBe('too_long');
  });

  it('exposes the same rules as a zod schema', () => {
    expect(StorageRelativeKeySchema.safeParse('ok/file.json').success).toBe(true);
    expect(StorageRelativeKeySchema.safeParse('../file.json').success).toBe(false);
  });
});

describe('storage list prefix bounds', () => {
  it('accepts the root and bounded prefixes', () => {
    expect(parseStorageListPrefix('')).toEqual({ ok: true, value: '' });
    expect(parseStorageListPrefix('notes/2026')).toEqual({ ok: true, value: 'notes/2026' });
    expect(StorageListPrefixSchema.safeParse('notes').success).toBe(true);
  });

  it.each([
    ['..', 'dot_segment'],
    ['notes/..', 'dot_segment'],
    ['/notes', 'absolute_path'],
    ['notes/', 'empty_segment'],
    ['notes\\x', 'backslash'],
    ['no*tes', 'disallowed_character'],
    ['%', 'disallowed_character'],
  ])('rejects unsafe prefix %j', (prefix, expected) => {
    expect(reason(parseStorageListPrefix(prefix))).toBe(expected);
  });

  it('rejects non-string and overlong prefixes', () => {
    expect(reason(parseStorageListPrefix(7))).toBe('not_a_string');
    expect(reason(parseStorageListPrefix('p'.repeat(STORAGE_MAX_RELATIVE_KEY_BYTES + 1)))).toBe(
      'too_long',
    );
  });
});

describe('storage MIME allowlist', () => {
  it('keeps active content types out of the allowlist', () => {
    for (const type of ['text/html', 'image/svg+xml', 'application/javascript', 'text/xml']) {
      expect(STORAGE_ALLOWED_MIME_TYPES).not.toContain(type);
      expect(StorageMimeTypeSchema.safeParse(type).success).toBe(false);
    }
    expect(Object.isFrozen(STORAGE_MIME_BY_EXTENSION)).toBe(true);
    expect(Object.isFrozen(STORAGE_ALLOWED_MIME_TYPES)).toBe(true);
  });

  it('requires the declared type to match the extension exactly', () => {
    const png = parseStorageRelativeKey('img/a.png');
    if (!png.ok) throw new Error('fixture key rejected');
    expect(checkStorageMimeType(png.value, 'image/png')).toEqual({ ok: true, value: 'image/png' });
    expect(reason(checkStorageMimeType(png.value, 'image/jpeg'))).toBe('mime_extension_mismatch');
    expect(reason(checkStorageMimeType(png.value, 'IMAGE/PNG'))).toBe('disallowed_mime');
    expect(reason(checkStorageMimeType(png.value, 'image/png; charset=utf-8'))).toBe(
      'disallowed_mime',
    );
    expect(reason(checkStorageMimeType(png.value, 'text/html'))).toBe('disallowed_mime');
    expect(reason(checkStorageMimeType(png.value, undefined))).toBe('not_a_string');
  });
});

describe('storage size bounds', () => {
  it('accepts exact limits and rejects one over', () => {
    expect(checkStorageSize(0, 'inline').ok).toBe(true);
    expect(checkStorageSize(STORAGE_MAX_INLINE_BYTES, 'inline').ok).toBe(true);
    expect(reason(checkStorageSize(STORAGE_MAX_INLINE_BYTES + 1, 'inline'))).toBe('size_exceeded');
    expect(checkStorageSize(STORAGE_MAX_OBJECT_BYTES, 'signed').ok).toBe(true);
    expect(reason(checkStorageSize(STORAGE_MAX_OBJECT_BYTES + 1, 'signed'))).toBe('size_exceeded');
  });

  it('fails closed on an unknown or missing mode', () => {
    for (const mode of [undefined, null, '', 'Inline', 'signed_url', 'auto', 0, {}]) {
      expect(reason(checkStorageSize(0, mode as never))).toBe('invalid_mode');
      expect(reason(checkStorageSize(1, mode as never))).toBe('invalid_mode');
    }
  });

  it('fails closed on non-finite, fractional, negative and unsafe sizes', () => {
    for (const value of [
      Number.NaN,
      Number.POSITIVE_INFINITY,
      Number.NEGATIVE_INFINITY,
      -1,
      -0.5,
      1.5,
      Number.MAX_SAFE_INTEGER + 1,
      '10',
      10n,
      null,
      undefined,
    ]) {
      expect(reason(checkStorageSize(value, 'inline'))).toBe('invalid_size');
      expect(reason(checkStorageSize(value, 'signed'))).toBe('invalid_size');
    }
  });

  it('keeps inline objects inside the shared response budget', () => {
    expect(STORAGE_INLINE_ENVELOPE_HEADROOM_BYTES).toBeGreaterThanOrEqual(16 * 1024);
    expect(2 * Math.ceil(STORAGE_MAX_INLINE_BYTES / 3) * 4).toBeLessThan(MAX_RESPONSE_BYTES);
  });
});

describe('storage inline cap at exactly 16 KiB', () => {
  const SIXTEEN_KIB = 16_384;

  it('pins the inline cap to 16 KiB', () => {
    expect(STORAGE_MAX_INLINE_BYTES).toBe(SIXTEEN_KIB);
  });

  it('accepts exactly 16384 bytes and rejects 16385 by size', () => {
    expect(checkStorageSize(SIXTEEN_KIB, 'inline')).toEqual({ ok: true, value: SIXTEEN_KIB });
    expect(reason(checkStorageSize(SIXTEEN_KIB + 1, 'inline'))).toBe('size_exceeded');
  });

  it('accepts base64 decoding to exactly 16384 bytes and rejects 16385', () => {
    const exact = Buffer.alloc(SIXTEEN_KIB, 0xa5).toString('base64');
    expect(Buffer.from(exact, 'base64').byteLength).toBe(SIXTEEN_KIB);
    expect(checkStorageInlineBase64(exact)).toEqual({ ok: true, value: SIXTEEN_KIB });

    const over = Buffer.alloc(SIXTEEN_KIB + 1, 0xa5).toString('base64');
    expect(Buffer.from(over, 'base64').byteLength).toBe(SIXTEEN_KIB + 1);
    expect(reason(checkStorageInlineBase64(over))).toBe('size_exceeded');
  });

  it('fits the doubled 16 KiB payload under the 64 KiB wire cap', () => {
    expect(MAX_RESPONSE_BYTES).toBe(64 * 1024);
    const encoded = Buffer.alloc(SIXTEEN_KIB, 0xa5).toString('base64').length;
    expect(2 * encoded + STORAGE_INLINE_ENVELOPE_HEADROOM_BYTES).toBeLessThanOrEqual(
      MAX_RESPONSE_BYTES,
    );
  });
});

describe('storage inline base64 bounds', () => {
  it('returns the decoded length of canonical base64', () => {
    expect(checkStorageInlineBase64('')).toEqual({ ok: true, value: 0 });
    expect(checkStorageInlineBase64('YQ==')).toEqual({ ok: true, value: 1 });
    expect(checkStorageInlineBase64('YWI=')).toEqual({ ok: true, value: 2 });
    expect(checkStorageInlineBase64('YWJj')).toEqual({ ok: true, value: 3 });
    const max = Buffer.alloc(STORAGE_MAX_INLINE_BYTES, 7).toString('base64');
    expect(checkStorageInlineBase64(max)).toEqual({ ok: true, value: STORAGE_MAX_INLINE_BYTES });
  });

  it('rejects one byte over the inline limit', () => {
    const over = Buffer.alloc(STORAGE_MAX_INLINE_BYTES + 1, 7).toString('base64');
    expect(reason(checkStorageInlineBase64(over))).toBe('size_exceeded');
  });

  it.each(['YQ', 'YQ=', 'Y===', 'YQ==YQ==', 'YR==', 'YWJ=', 'YW-j', 'YW_j', 'YW j', ' YWJj'])(
    'rejects non-canonical base64 %j',
    (value) => {
      expect(reason(checkStorageInlineBase64(value))).toBe('invalid_base64');
    },
  );

  it('rejects non-string content', () => {
    expect(reason(checkStorageInlineBase64(Buffer.from('a')))).toBe('not_a_string');
  });
});

describe('storage bucket id bounds', () => {
  it('accepts a fixed lowercase bucket id', () => {
    expect(checkStorageBucketId('user-files')).toEqual({ ok: true, value: 'user-files' });
  });

  it.each(['', 'ab', 'User-Files', 'user_files', '-files', 'files-', 'a--b', 'a/b', '..', 7])(
    'rejects bucket id %j',
    (bucket) => {
      expect(reason(checkStorageBucketId(bucket))).toBe('invalid_bucket');
    },
  );
});
