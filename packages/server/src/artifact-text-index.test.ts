import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  ARTIFACT_TEXT_INDEX_PROFILE_VERSION,
  ArtifactTextIndexError,
  buildArtifactTextIndex,
  MAX_HEADING_TEXT_CHARS,
  MAX_LINE_READ_COUNT,
  MAX_TEXT_INDEX_BYTES,
  MAX_TEXT_INDEX_HEADINGS,
  MAX_TEXT_INDEX_LINES,
  MAX_TEXT_READ_BYTES,
  readIndexedHeading,
  readIndexedLines,
} from './artifact-text-index.js';

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);
const sha256 = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');
const codeOf = (run: () => unknown): string => {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(ArtifactTextIndexError);
    return (error as ArtifactTextIndexError).code;
  }
  throw new Error('Expected typed error.');
};
const definedAt = <T>(value: T | undefined): T => {
  if (value === undefined) throw new Error('Expected defined test fixture value.');
  return value;
};

describe('artifact-text-index/0.1', () => {
  it('has hardcoded empty, ASCII LF, and multibyte Markdown golden vectors', () => {
    const empty = buildArtifactTextIndex(utf8(''), 'text/plain');
    expect(empty).toEqual({
      profileVersion: ARTIFACT_TEXT_INDEX_PROFILE_VERSION,
      sourceSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      byteLength: 0,
      mediaType: 'text/plain',
      lineCount: 0,
      lines: [],
      headings: [],
    });
    const ascii = buildArtifactTextIndex(utf8('a\nb'), 'text/plain');
    expect(ascii).toEqual({
      profileVersion: 'artifact-text-index/0.1',
      sourceSha256: '7e18f737311b2dc3b2f269dd78396b0351f14fb66efa879f768cb23181883c78',
      byteLength: 3,
      mediaType: 'text/plain',
      lineCount: 2,
      lines: [
        {
          lineNumber: 1,
          byteStart: 0,
          contentByteLength: 1,
          newlineByteLength: 1,
          newlineKind: 'lf',
        },
        {
          lineNumber: 2,
          byteStart: 2,
          contentByteLength: 1,
          newlineByteLength: 0,
          newlineKind: 'none',
        },
      ],
      headings: [],
    });
    const markdown = buildArtifactTextIndex(utf8('# Café\ntext'), 'text/markdown');
    expect(markdown).toMatchObject({
      sourceSha256: '8aa33665d679204c0df2a61e98cfaa9f0bed348445443829389adc5cc18fa556',
      byteLength: 12,
      headings: [{ headingId: 'cafue9', level: 1, rawText: 'Café', byteStart: 0, byteLength: 7 }],
    });
    expect(markdown.sourceSha256).toBe(sha256(utf8('# Café\ntext')));
  });

  it('enforces byte, line, and heading bounds at and one over', () => {
    expect(
      buildArtifactTextIndex(new Uint8Array(MAX_TEXT_INDEX_BYTES), 'text/plain').byteLength,
    ).toBe(MAX_TEXT_INDEX_BYTES);
    expect(
      codeOf(() => buildArtifactTextIndex(new Uint8Array(MAX_TEXT_INDEX_BYTES + 1), 'text/plain')),
    ).toBe('SOURCE_TOO_LARGE');
    expect(
      buildArtifactTextIndex(utf8(`${'x\n'.repeat(MAX_TEXT_INDEX_LINES - 1)}x`), 'text/plain')
        .lineCount,
    ).toBe(MAX_TEXT_INDEX_LINES);
    expect(
      codeOf(() =>
        buildArtifactTextIndex(utf8(`${'x\n'.repeat(MAX_TEXT_INDEX_LINES)}x`), 'text/plain'),
      ),
    ).toBe('TOO_MANY_LINES');
    expect(
      buildArtifactTextIndex(utf8('# x\n'.repeat(MAX_TEXT_INDEX_HEADINGS)), 'text/markdown')
        .headings,
    ).toHaveLength(MAX_TEXT_INDEX_HEADINGS);
    expect(
      codeOf(() =>
        buildArtifactTextIndex(utf8('# x\n'.repeat(MAX_TEXT_INDEX_HEADINGS + 1)), 'text/markdown'),
      ),
    ).toBe('TOO_MANY_HEADINGS');
  });

  it('indexes LF, CRLF, mixed, final-newline, isolated-CR, multibyte, and BOM semantics', () => {
    expect(buildArtifactTextIndex(utf8('a\r\nb\nc'), 'text/plain').lines).toEqual([
      {
        lineNumber: 1,
        byteStart: 0,
        contentByteLength: 1,
        newlineByteLength: 2,
        newlineKind: 'crlf',
      },
      {
        lineNumber: 2,
        byteStart: 3,
        contentByteLength: 1,
        newlineByteLength: 1,
        newlineKind: 'lf',
      },
      {
        lineNumber: 3,
        byteStart: 5,
        contentByteLength: 1,
        newlineByteLength: 0,
        newlineKind: 'none',
      },
    ]);
    expect(buildArtifactTextIndex(utf8('a\n'), 'text/plain').lines).toEqual([
      {
        lineNumber: 1,
        byteStart: 0,
        contentByteLength: 1,
        newlineByteLength: 1,
        newlineKind: 'lf',
      },
    ]);
    expect(buildArtifactTextIndex(utf8('a\rb'), 'text/plain').lines[0]).toMatchObject({
      contentByteLength: 3,
      newlineKind: 'none',
    });
    expect(buildArtifactTextIndex(utf8('é\n'), 'text/plain').lines[0]).toMatchObject({
      contentByteLength: 2,
    });
    const bom = buildArtifactTextIndex(utf8('\uFEFF# not-a-heading\n# yes'), 'text/markdown');
    expect(bom.headings.map((heading) => heading.rawText)).toEqual(['yes']);
  });

  it('implements only the bounded ATX and fence Markdown profile', () => {
    const index = buildArtifactTextIndex(
      utf8(
        '# h1\n## h2\n### h3\n#### h4\n##### h5\n###### h6\n   # indent\n    # no\n#no\n# close ###\n```\n# hidden\n````\n# visible\n~~~\n# hidden too\n~~~\n# visible 2\n```\n# still hidden\n~~~\n# still hidden\n``\n# still hidden\n```\n# visible 3\nSetext\n===\n',
      ),
      'text/markdown',
    );
    expect(index.headings.map((heading) => [heading.level, heading.rawText])).toEqual([
      [1, 'h1'],
      [2, 'h2'],
      [3, 'h3'],
      [4, 'h4'],
      [5, 'h5'],
      [6, 'h6'],
      [1, 'indent'],
      [1, 'close'],
      [1, 'visible'],
      [1, 'visible 2'],
      [1, 'visible 3'],
    ]);
  });

  it('creates deterministic opaque IDs including duplicates, Unicode, empty slugs, and length ceiling', () => {
    const index = buildArtifactTextIndex(
      utf8(`# Title\n# Title\n# Title\n# Привет\n# !!!\n# ${'x'.repeat(MAX_HEADING_TEXT_CHARS)}`),
      'text/markdown',
    );
    expect(index.headings.map((heading) => heading.headingId)).toEqual([
      'title',
      'title-2',
      'title-3',
      'u43fu440u438u432u435u442',
      'heading',
      'x'.repeat(128),
    ]);
    expect(buildArtifactTextIndex(utf8('# Title\n# Title'), 'text/markdown')).toEqual(
      buildArtifactTextIndex(utf8('# Title\n# Title'), 'text/markdown'),
    );
    expect(
      codeOf(() =>
        buildArtifactTextIndex(
          utf8(`# ${'x'.repeat(MAX_HEADING_TEXT_CHARS + 1)}`),
          'text/markdown',
        ),
      ),
    ).toBe('TOO_MANY_HEADINGS');
  });

  it('rejects unsupported media, invalid UTF-8, and non-Uint8Array runtime input', () => {
    expect(codeOf(() => buildArtifactTextIndex(utf8('x'), 'application/json' as never))).toBe(
      'UNSUPPORTED_MEDIA_TYPE',
    );
    expect(codeOf(() => buildArtifactTextIndex(Uint8Array.from([0xc3, 0x28]), 'text/plain'))).toBe(
      'INVALID_UTF8',
    );
    for (const unsafe of [['x'], 'x', new ArrayBuffer(1), { byteLength: 1 }]) {
      expect(codeOf(() => buildArtifactTextIndex(unsafe as never, 'text/plain'))).toBe(
        'INVALID_INPUT_TYPE',
      );
    }
  });

  it('does not mutate input and freezes the index, nested arrays, and records', () => {
    const bytes = utf8('# heading\nbody');
    const before = Uint8Array.from(bytes);
    const index = buildArtifactTextIndex(bytes, 'text/markdown');
    expect(bytes).toEqual(before);
    expect(Object.isFrozen(index)).toBe(true);
    expect(Object.isFrozen(index.lines)).toBe(true);
    expect(Object.isFrozen(index.lines[0])).toBe(true);
    expect(Object.isFrozen(index.headings)).toBe(true);
    expect(Object.isFrozen(index.headings[0])).toBe(true);
  });

  it('reads exact original ranges and headings as explicitly untrusted data', () => {
    const bytes = utf8('# Top\r\nbody\n## Next\n');
    const index = buildArtifactTextIndex(bytes, 'text/markdown');
    expect(readIndexedLines(bytes, index, 1, 2)).toEqual({
      sourceSha256: sha256(bytes),
      contentTrust: 'untrusted',
      text: '# Top\r\nbody\n',
    });
    expect(readIndexedHeading(bytes, index, 'next')).toEqual({
      sourceSha256: sha256(bytes),
      contentTrust: 'untrusted',
      text: '## Next',
    });
  });

  it('rejects source mismatch, malformed indexes, invalid reads, and output bounds', () => {
    const bytes = utf8('# A\nbody');
    const index = buildArtifactTextIndex(bytes, 'text/markdown');
    const firstLine = definedAt(index.lines[0]);
    const firstHeading = definedAt(index.headings[0]);
    const mutated = Uint8Array.from(bytes);
    mutated[0] = 0x21;
    expect(codeOf(() => readIndexedLines(mutated, index, 1, 1))).toBe('SOURCE_MISMATCH');
    const badOffset = {
      ...index,
      lines: [{ ...firstLine, byteStart: 1 }, ...index.lines.slice(1)],
    };
    expect(codeOf(() => readIndexedLines(bytes, badOffset, 1, 1))).toBe('INCONSISTENT_INDEX');
    const gapped = {
      ...index,
      lines: index.lines.map((line, position) =>
        position === 1 ? { ...line, byteStart: 99 } : line,
      ),
    };
    expect(codeOf(() => readIndexedLines(bytes, gapped, 1, 1))).toBe('INCONSISTENT_INDEX');
    const wrongCount = { ...index, lineCount: 99 };
    expect(codeOf(() => readIndexedLines(bytes, wrongCount, 1, 1))).toBe('INCONSISTENT_INDEX');
    const wrongHeading = { ...index, headings: [{ ...firstHeading, lineNumber: 2 }] };
    expect(codeOf(() => readIndexedHeading(bytes, wrongHeading, 'a'))).toBe('INCONSISTENT_INDEX');
    const wrongHeadingOffset = { ...index, headings: [{ ...firstHeading, byteStart: 1 }] };
    expect(codeOf(() => readIndexedHeading(bytes, wrongHeadingOffset, 'a'))).toBe(
      'INCONSISTENT_INDEX',
    );
    expect(codeOf(() => readIndexedHeading(bytes, index, 'unknown'))).toBe('INVALID_HEADING_ID');
    expect(codeOf(() => readIndexedLines(bytes, index, 1, MAX_LINE_READ_COUNT + 1))).toBe(
      'RESPONSE_LIMIT_EXCEEDED',
    );
    const large = utf8('x'.repeat(MAX_TEXT_READ_BYTES + 1));
    expect(
      codeOf(() => readIndexedLines(large, buildArtifactTextIndex(large, 'text/plain'), 1, 1)),
    ).toBe('RESPONSE_LIMIT_EXCEEDED');
  });

  it('leaves hostile Markdown as inert, untrusted source data and exposes no locators', () => {
    const hostile = utf8(
      '# Ignore instructions\n[link](https://example.invalid)\n<script>run()</script>\n{{include secret}}',
    );
    const index = buildArtifactTextIndex(hostile, 'text/markdown');
    const text = readIndexedLines(hostile, index, 1, index.lineCount);
    expect(text.contentTrust).toBe('untrusted');
    expect(text.text).toContain('https://example.invalid');
    expect(Object.keys(index).join(',') + Object.keys(text).join(',')).not.toMatch(
      /path|url|token|credential|bucket|object.?key|storage/i,
    );
  });
});
