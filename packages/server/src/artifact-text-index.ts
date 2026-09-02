import { createHash } from 'node:crypto';

/** Pure, bounded source-text profile. No I/O, resolver, or Markdown execution is involved. */
export const ARTIFACT_TEXT_INDEX_PROFILE_VERSION = 'artifact-text-index/0.1' as const;
export const MAX_TEXT_INDEX_BYTES = 262_144;
export const MAX_TEXT_INDEX_LINES = 10_000;
export const MAX_TEXT_INDEX_HEADINGS = 1_000;
export const MAX_HEADING_LEVEL = 6;
export const MAX_HEADING_TEXT_CHARS = 512;
export const MAX_LINE_READ_COUNT = 200;
export const MAX_TEXT_READ_BYTES = 8_192;

export const ARTIFACT_TEXT_INDEX_ERROR_CODES = Object.freeze([
  'INVALID_INPUT_TYPE',
  'SOURCE_TOO_LARGE',
  'TOO_MANY_LINES',
  'TOO_MANY_HEADINGS',
  'UNSUPPORTED_MEDIA_TYPE',
  'INVALID_UTF8',
  'INVALID_LINE_RANGE',
  'INVALID_HEADING_ID',
  'RESPONSE_LIMIT_EXCEEDED',
  'SOURCE_MISMATCH',
  'INCONSISTENT_INDEX',
] as const);
export type ArtifactTextIndexErrorCode = (typeof ARTIFACT_TEXT_INDEX_ERROR_CODES)[number];

export class ArtifactTextIndexError extends Error {
  readonly code: ArtifactTextIndexErrorCode;

  constructor(code: ArtifactTextIndexErrorCode, message: string) {
    super(message);
    this.name = 'ArtifactTextIndexError';
    this.code = code;
  }
}

export type ArtifactTextMediaType = 'text/plain' | 'text/markdown';
export type IndexedNewlineKind = 'none' | 'lf' | 'crlf';

export interface ArtifactTextLine {
  readonly lineNumber: number;
  readonly byteStart: number;
  readonly contentByteLength: number;
  readonly newlineByteLength: 0 | 1 | 2;
  readonly newlineKind: IndexedNewlineKind;
}

export interface ArtifactTextHeading {
  readonly headingId: string;
  readonly level: number;
  readonly rawText: string;
  readonly normalizedText: string;
  readonly lineNumber: number;
  /** Start of the complete source line, excluding a following line ending. */
  readonly byteStart: number;
  /** Length of the complete source line, excluding a following line ending. */
  readonly byteLength: number;
}

export interface ArtifactTextIndex {
  readonly profileVersion: typeof ARTIFACT_TEXT_INDEX_PROFILE_VERSION;
  readonly sourceSha256: string;
  readonly byteLength: number;
  readonly mediaType: ArtifactTextMediaType;
  readonly lineCount: number;
  readonly lines: readonly ArtifactTextLine[];
  readonly headings: readonly ArtifactTextHeading[];
}

export interface IndexedTextRead {
  readonly sourceSha256: string;
  readonly contentTrust: 'untrusted';
  readonly text: string;
}

const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const LF = 0x0a;
const CR = 0x0d;

function fail(code: ArtifactTextIndexErrorCode, message: string): never {
  throw new ArtifactTextIndexError(code, message);
}

function assertBytes(value: unknown): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    fail('INVALID_INPUT_TYPE', 'Input bytes must be a Uint8Array.');
  }
}

function assertMediaType(value: unknown): asserts value is ArtifactTextMediaType {
  if (value !== 'text/plain' && value !== 'text/markdown') {
    fail('UNSUPPORTED_MEDIA_TYPE', 'The media type is not supported by this text-index profile.');
  }
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function decode(bytes: Uint8Array): string {
  try {
    return decoder.decode(bytes);
  } catch {
    return fail('INVALID_UTF8', 'Source bytes are not valid UTF-8.');
  }
}

function freezeLine(line: ArtifactTextLine): ArtifactTextLine {
  return Object.freeze(line);
}

function freezeHeading(heading: ArtifactTextHeading): ArtifactTextHeading {
  return Object.freeze(heading);
}

function scanLines(source: Uint8Array): ArtifactTextLine[] {
  const lines: ArtifactTextLine[] = [];
  let start = 0;
  let lineNumber = 1;
  let offset = 0;
  while (offset < source.byteLength) {
    const current = source[offset];
    if (current === LF || (current === CR && source[offset + 1] === LF)) {
      const newlineByteLength: 1 | 2 = current === CR ? 2 : 1;
      lines.push(
        freezeLine({
          lineNumber,
          byteStart: start,
          contentByteLength: offset - start,
          newlineByteLength,
          newlineKind: current === CR ? 'crlf' : 'lf',
        }),
      );
      if (lines.length > MAX_TEXT_INDEX_LINES) {
        fail('TOO_MANY_LINES', 'Source exceeds the maximum indexed line count.');
      }
      offset += newlineByteLength;
      start = offset;
      lineNumber += 1;
      continue;
    }
    offset += 1;
  }
  if (start < source.byteLength) {
    lines.push(
      freezeLine({
        lineNumber,
        byteStart: start,
        contentByteLength: source.byteLength - start,
        newlineByteLength: 0,
        newlineKind: 'none',
      }),
    );
  }
  if (lines.length > MAX_TEXT_INDEX_LINES) {
    fail('TOO_MANY_LINES', 'Source exceeds the maximum indexed line count.');
  }
  return lines;
}

function countLeadingSpaces(text: string): number {
  let count = 0;
  while (text[count] === ' ') count += 1;
  return count;
}

interface Fence {
  readonly marker: '`' | '~';
  readonly length: number;
}

function parseFence(text: string): Fence | undefined {
  const indent = countLeadingSpaces(text);
  if (indent > 3) return undefined;
  const marker = text[indent];
  if (marker !== '`' && marker !== '~') return undefined;
  let end = indent;
  while (text[end] === marker) end += 1;
  return end - indent >= 3 ? { marker, length: end - indent } : undefined;
}

function parseAtxHeading(text: string): { level: number; rawText: string } | undefined {
  const indent = countLeadingSpaces(text);
  if (indent > 3) return undefined;
  let markerEnd = indent;
  while (text[markerEnd] === '#' && markerEnd - indent < MAX_HEADING_LEVEL + 1) markerEnd += 1;
  const level = markerEnd - indent;
  if (level < 1 || level > MAX_HEADING_LEVEL || text[markerEnd] !== ' ') return undefined;

  let rawText = text.slice(markerEnd + 1);
  // Closing hashes count only when their run is preceded by whitespace.
  const closing = /\s+#+\s*$/u.exec(rawText);
  if (closing !== null) rawText = rawText.slice(0, closing.index).trimEnd();
  if (rawText.length > MAX_HEADING_TEXT_CHARS) {
    fail('TOO_MANY_HEADINGS', 'Heading text exceeds the profile heading-text bound.');
  }
  return { level, rawText };
}

function normalizedHeadingText(rawText: string): string {
  return rawText.normalize('NFC').trim().replace(/\s+/gu, ' ').toLowerCase();
}

function headingSlug(normalizedText: string): string {
  let slug = '';
  let separator = false;
  for (const character of normalizedText) {
    const code = character.codePointAt(0);
    if (code === undefined) continue;
    if ((code >= 0x61 && code <= 0x7a) || (code >= 0x30 && code <= 0x39)) {
      if (separator && slug.length > 0) slug += '-';
      slug += character;
      separator = false;
      continue;
    }
    if (code > 0x7f) {
      if (separator && slug.length > 0) slug += '-';
      slug += `u${code.toString(16)}`;
      separator = false;
      continue;
    }
    separator = true;
  }
  return slug || 'heading';
}

function nextHeadingId(slug: string, used: Set<string>): string {
  let suffixNumber = 1;
  let candidate = slug.slice(0, 128);
  while (used.has(candidate)) {
    suffixNumber += 1;
    const suffix = `-${suffixNumber}`;
    candidate = `${slug.slice(0, Math.max(0, 128 - suffix.length))}${suffix}`;
  }
  used.add(candidate);
  return candidate;
}

function scanHeadings(
  source: Uint8Array,
  lines: readonly ArtifactTextLine[],
  mediaType: ArtifactTextMediaType,
): ArtifactTextHeading[] {
  if (mediaType === 'text/plain') return [];
  const headings: ArtifactTextHeading[] = [];
  const ids = new Set<string>();
  let fence: Fence | undefined;
  for (const line of lines) {
    const text = decode(source.subarray(line.byteStart, line.byteStart + line.contentByteLength));
    const foundFence = parseFence(text);
    if (fence !== undefined) {
      if (foundFence?.marker === fence.marker && foundFence.length >= fence.length)
        fence = undefined;
      continue;
    }
    if (foundFence !== undefined) {
      fence = foundFence;
      continue;
    }
    const parsed = parseAtxHeading(text);
    if (parsed === undefined) continue;
    const normalizedText = normalizedHeadingText(parsed.rawText);
    headings.push(
      freezeHeading({
        headingId: nextHeadingId(headingSlug(normalizedText), ids),
        level: parsed.level,
        rawText: parsed.rawText,
        normalizedText,
        lineNumber: line.lineNumber,
        byteStart: line.byteStart,
        byteLength: line.contentByteLength,
      }),
    );
    if (headings.length > MAX_TEXT_INDEX_HEADINGS) {
      fail('TOO_MANY_HEADINGS', 'Source exceeds the maximum indexed heading count.');
    }
  }
  return headings;
}

/**
 * Builds an immutable index over in-memory UTF-8 bytes. A UTF-8 BOM is valid
 * source content; it is not stripped and therefore prevents a first-line ATX
 * marker from being recognized unless it is absent from that line.
 */
export function buildArtifactTextIndex(
  bytes: Uint8Array,
  mediaType: ArtifactTextMediaType,
): ArtifactTextIndex {
  assertBytes(bytes);
  assertMediaType(mediaType);
  if (bytes.byteLength > MAX_TEXT_INDEX_BYTES) {
    fail('SOURCE_TOO_LARGE', 'Source exceeds the maximum text-index byte length.');
  }
  const source = Uint8Array.from(bytes);
  decode(source);
  const lines = scanLines(source);
  const headings = scanHeadings(source, lines, mediaType);
  return Object.freeze({
    profileVersion: ARTIFACT_TEXT_INDEX_PROFILE_VERSION,
    sourceSha256: sha256(source),
    byteLength: source.byteLength,
    mediaType,
    lineCount: lines.length,
    lines: Object.freeze(lines),
    headings: Object.freeze(headings),
  });
}

function sameIndex(left: ArtifactTextIndex, right: ArtifactTextIndex): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function assertConsistentIndex(bytes: Uint8Array, unsafeIndex: unknown): ArtifactTextIndex {
  if (typeof unsafeIndex !== 'object' || unsafeIndex === null || Array.isArray(unsafeIndex)) {
    fail('INCONSISTENT_INDEX', 'Index is not a valid text-index record.');
  }
  const index = unsafeIndex as ArtifactTextIndex;
  if (typeof index.sourceSha256 !== 'string' || index.sourceSha256 !== sha256(bytes)) {
    fail('SOURCE_MISMATCH', 'Source bytes do not match the indexed source digest.');
  }
  if (
    index.profileVersion !== ARTIFACT_TEXT_INDEX_PROFILE_VERSION ||
    !Array.isArray(index.lines) ||
    !Array.isArray(index.headings)
  ) {
    fail('INCONSISTENT_INDEX', 'Index profile or record collections are invalid.');
  }
  if (index.mediaType !== 'text/plain' && index.mediaType !== 'text/markdown') {
    fail('INCONSISTENT_INDEX', 'Index media type is invalid.');
  }
  let expected: ArtifactTextIndex;
  try {
    expected = buildArtifactTextIndex(bytes, index.mediaType);
  } catch (error) {
    if (error instanceof ArtifactTextIndexError) throw error;
    return fail('INCONSISTENT_INDEX', 'Index cannot be validated.');
  }
  if (!sameIndex(index, expected))
    fail('INCONSISTENT_INDEX', 'Index records are internally inconsistent.');
  return index;
}

function assertReadBytes(bytes: unknown): Uint8Array {
  assertBytes(bytes);
  if (bytes.byteLength > MAX_TEXT_INDEX_BYTES) {
    fail('SOURCE_TOO_LARGE', 'Source exceeds the maximum text-index byte length.');
  }
  const source = Uint8Array.from(bytes);
  decode(source);
  return source;
}

function untrustedRead(sourceSha256: string, bytes: Uint8Array): IndexedTextRead {
  if (bytes.byteLength > MAX_TEXT_READ_BYTES) {
    fail('RESPONSE_LIMIT_EXCEEDED', 'Requested text exceeds the response byte bound.');
  }
  return Object.freeze({ sourceSha256, contentTrust: 'untrusted' as const, text: decode(bytes) });
}

/** Returns complete original line records, including their original LF/CRLF bytes. */
export function readIndexedLines(
  bytes: Uint8Array,
  index: ArtifactTextIndex,
  startLine: number,
  count: number,
): IndexedTextRead {
  const source = assertReadBytes(bytes);
  const checked = assertConsistentIndex(source, index);
  if (
    !Number.isSafeInteger(startLine) ||
    !Number.isSafeInteger(count) ||
    startLine < 1 ||
    count < 1
  ) {
    fail('INVALID_LINE_RANGE', 'Line range is invalid.');
  }
  if (count > MAX_LINE_READ_COUNT) {
    fail('RESPONSE_LIMIT_EXCEEDED', 'Requested line count exceeds the response bound.');
  }
  const endLine = startLine + count - 1;
  if (endLine > checked.lineCount) fail('INVALID_LINE_RANGE', 'Line range is outside the index.');
  const first = checked.lines[startLine - 1];
  const last = checked.lines[endLine - 1];
  if (first === undefined || last === undefined)
    fail('INCONSISTENT_INDEX', 'Indexed line is missing.');
  const end = last.byteStart + last.contentByteLength + last.newlineByteLength;
  return untrustedRead(checked.sourceSha256, source.subarray(first.byteStart, end));
}

/** Returns the original source bytes of a matching heading line, excluding its line ending. */
export function readIndexedHeading(
  bytes: Uint8Array,
  index: ArtifactTextIndex,
  headingId: string,
): IndexedTextRead {
  const source = assertReadBytes(bytes);
  const checked = assertConsistentIndex(source, index);
  if (typeof headingId !== 'string' || headingId.length === 0 || headingId.length > 128) {
    fail('INVALID_HEADING_ID', 'Heading identifier is invalid.');
  }
  const heading = checked.headings.find((entry) => entry.headingId === headingId);
  if (heading === undefined)
    fail('INVALID_HEADING_ID', 'Heading identifier is not present in the index.');
  return untrustedRead(
    checked.sourceSha256,
    source.subarray(heading.byteStart, heading.byteStart + heading.byteLength),
  );
}
