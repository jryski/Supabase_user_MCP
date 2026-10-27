import * as z from 'zod/v4';

import { MAX_RESPONSE_BYTES } from './read-tools.js';

/**
 * Issue #123 S1: pure, dependency-free bounds for the future storage tools.
 *
 * Nothing here talks to Supabase, registers a tool, or decides authorization.
 * Authorization stays in database RLS on `storage.objects`. These validators
 * only reject input that must never reach the Storage API: path escapes,
 * oversized payloads, and content types outside a fixed allowlist.
 *
 * The caller never selects a bucket or a principal prefix. A tool accepts only
 * a relative object key; the server composes the final key under the
 * verified principal in a later slice, after the RLS model is decided.
 */

export const STORAGE_MAX_RELATIVE_KEY_BYTES = 512;
export const STORAGE_MAX_KEY_SEGMENTS = 8;
export const STORAGE_MAX_SEGMENT_BYTES = 128;
/** Raw bytes accepted inline in one `storage_put` or returned inline by `storage_get`. */
export const STORAGE_MAX_INLINE_BYTES = 32 * 1024;
/** Largest object size a signed upload or download may declare. */
export const STORAGE_MAX_OBJECT_BYTES = 5 * 1024 * 1024;
export const STORAGE_MAX_LIST_ITEMS = 100;
export const STORAGE_SIGNED_URL_TTL_SECONDS = 60;

const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const BUCKET_ID = /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/;
const STRICT_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/**
 * Fixed extension to MIME map. The extension decides the content type; a
 * caller-declared type must match it exactly. Active content types (HTML, SVG,
 * JavaScript, XML) are deliberately absent.
 */
export const STORAGE_MIME_BY_EXTENSION: Readonly<Record<string, string>> = Object.freeze({
  txt: 'text/plain',
  md: 'text/markdown',
  csv: 'text/csv',
  json: 'application/json',
  pdf: 'application/pdf',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  webp: 'image/webp',
});

export const STORAGE_ALLOWED_MIME_TYPES = Object.freeze([
  ...new Set(Object.values(STORAGE_MIME_BY_EXTENSION)),
] as readonly string[]);

export type StorageBoundsRejection =
  | 'not_a_string'
  | 'empty'
  | 'too_long'
  | 'absolute_path'
  | 'backslash'
  | 'empty_segment'
  | 'dot_segment'
  | 'too_many_segments'
  | 'segment_too_long'
  | 'disallowed_character'
  | 'missing_extension'
  | 'disallowed_extension'
  | 'disallowed_mime'
  | 'mime_extension_mismatch'
  | 'invalid_size'
  | 'size_exceeded'
  | 'invalid_base64'
  | 'invalid_bucket';

export type StorageBoundsResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly reason: StorageBoundsRejection };

function reject(reason: StorageBoundsRejection): {
  readonly ok: false;
  readonly reason: StorageBoundsRejection;
} {
  return Object.freeze({ ok: false as const, reason });
}

function accept<T>(value: T): { readonly ok: true; readonly value: T } {
  return Object.freeze({ ok: true as const, value });
}

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

export interface StorageRelativeKey {
  readonly key: string;
  readonly segments: readonly string[];
  readonly extension: string;
  readonly mimeType: string;
}

/**
 * Validates a caller-supplied relative object key. No normalization is
 * applied: a key that would need normalizing (`a//b`, `./a`, `a/../b`, `/a`,
 * `a\\b`, percent or Unicode tricks) is rejected rather than rewritten, so the
 * key checked here is byte-for-byte the key a later slice sends.
 */
export function parseStorageRelativeKey(input: unknown): StorageBoundsResult<StorageRelativeKey> {
  if (typeof input !== 'string') return reject('not_a_string');
  if (input.length === 0) return reject('empty');
  if (utf8Bytes(input) > STORAGE_MAX_RELATIVE_KEY_BYTES) return reject('too_long');
  if (input.startsWith('/')) return reject('absolute_path');
  if (input.includes('\\')) return reject('backslash');

  const segments = input.split('/');
  if (segments.length > STORAGE_MAX_KEY_SEGMENTS) return reject('too_many_segments');
  for (const segment of segments) {
    if (segment.length === 0) return reject('empty_segment');
    if (segment === '.' || segment === '..') return reject('dot_segment');
    if (utf8Bytes(segment) > STORAGE_MAX_SEGMENT_BYTES) return reject('segment_too_long');
    if (!SEGMENT.test(segment) || segment.includes('..')) return reject('disallowed_character');
  }

  const leaf = segments[segments.length - 1] ?? '';
  const dot = leaf.lastIndexOf('.');
  if (dot <= 0 || dot === leaf.length - 1) return reject('missing_extension');
  const extension = leaf.slice(dot + 1);
  const mimeType = Object.hasOwn(STORAGE_MIME_BY_EXTENSION, extension)
    ? STORAGE_MIME_BY_EXTENSION[extension]
    : undefined;
  if (mimeType === undefined) return reject('disallowed_extension');

  return accept(
    Object.freeze({ key: input, segments: Object.freeze([...segments]), extension, mimeType }),
  );
}

/**
 * Validates a relative key prefix for listing. The empty string lists the
 * principal's root. A non-empty prefix follows the same segment rules as a key
 * but needs no extension and may not end with `/`.
 */
export function parseStorageListPrefix(input: unknown): StorageBoundsResult<string> {
  if (typeof input !== 'string') return reject('not_a_string');
  if (input.length === 0) return accept('');
  if (utf8Bytes(input) > STORAGE_MAX_RELATIVE_KEY_BYTES) return reject('too_long');
  if (input.startsWith('/')) return reject('absolute_path');
  if (input.includes('\\')) return reject('backslash');
  const segments = input.split('/');
  if (segments.length > STORAGE_MAX_KEY_SEGMENTS) return reject('too_many_segments');
  for (const segment of segments) {
    if (segment.length === 0) return reject('empty_segment');
    if (segment === '.' || segment === '..') return reject('dot_segment');
    if (utf8Bytes(segment) > STORAGE_MAX_SEGMENT_BYTES) return reject('segment_too_long');
    if (!SEGMENT.test(segment) || segment.includes('..')) return reject('disallowed_character');
  }
  return accept(input);
}

/**
 * Checks a caller-declared MIME type against the type the key's extension
 * implies. Only the exact lowercase essence is accepted; parameters such as
 * `; charset=` are rejected rather than parsed.
 */
export function checkStorageMimeType(
  key: StorageRelativeKey,
  declared: unknown,
): StorageBoundsResult<string> {
  if (typeof declared !== 'string') return reject('not_a_string');
  if (!STORAGE_ALLOWED_MIME_TYPES.includes(declared)) return reject('disallowed_mime');
  if (declared !== key.mimeType) return reject('mime_extension_mismatch');
  return accept(declared);
}

export type StorageSizeMode = 'inline' | 'signed';

/** Validates a byte count. NaN, Infinity, fractions, negatives and unsafe integers fail closed. */
export function checkStorageSize(
  size: unknown,
  mode: StorageSizeMode,
): StorageBoundsResult<number> {
  if (typeof size !== 'number' || !Number.isSafeInteger(size) || size < 0) {
    return reject('invalid_size');
  }
  const limit = mode === 'inline' ? STORAGE_MAX_INLINE_BYTES : STORAGE_MAX_OBJECT_BYTES;
  if (size > limit) return reject('size_exceeded');
  return accept(size);
}

/**
 * Validates canonical, padded base64 inline content and returns the
 * decoded byte length without decoding. The encoded length is checked before
 * the regular expression runs so oversized input is rejected in O(1).
 */
export function checkStorageInlineBase64(content: unknown): StorageBoundsResult<number> {
  if (typeof content !== 'string') return reject('not_a_string');
  const maxEncoded = Math.ceil(STORAGE_MAX_INLINE_BYTES / 3) * 4;
  if (content.length > maxEncoded) return reject('size_exceeded');
  if (content.length % 4 !== 0 || !STRICT_BASE64.test(content)) return reject('invalid_base64');
  const padding = content.endsWith('==') ? 2 : content.endsWith('=') ? 1 : 0;
  const decoded = (content.length / 4) * 3 - padding;
  if (padding > 0 && Buffer.from(content, 'base64').toString('base64') !== content) {
    return reject('invalid_base64');
  }
  return checkStorageSize(decoded, 'inline');
}

/** Validates a fixed, server-configured bucket id. Never accepted from tool input. */
export function checkStorageBucketId(bucket: unknown): StorageBoundsResult<string> {
  if (typeof bucket !== 'string' || !BUCKET_ID.test(bucket) || bucket.includes('--')) {
    return reject('invalid_bucket');
  }
  return accept(bucket);
}

export const StorageRelativeKeySchema = z
  .string()
  .refine((value) => parseStorageRelativeKey(value).ok, 'Expected a bounded relative object key.');

export const StorageListPrefixSchema = z
  .string()
  .refine((value) => parseStorageListPrefix(value).ok, 'Expected a bounded relative key prefix.');

export const StorageMimeTypeSchema = z.enum(
  STORAGE_ALLOWED_MIME_TYPES as unknown as [string, ...string[]],
);

/**
 * Compile-time and load-time guard: one inline object, base64-encoded, must
 * fit inside the shared read-tool response budget with room for its envelope.
 */
export const STORAGE_INLINE_ENVELOPE_HEADROOM_BYTES =
  MAX_RESPONSE_BYTES - Math.ceil(STORAGE_MAX_INLINE_BYTES / 3) * 4;
if (STORAGE_INLINE_ENVELOPE_HEADROOM_BYTES < 16 * 1024) {
  throw new RangeError('Storage inline limit leaves too little response headroom.');
}
