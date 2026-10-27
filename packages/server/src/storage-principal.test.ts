import { describe, expect, it } from 'vitest';

import {
  createPathPrefixStoragePrincipalResolver,
  StoragePrincipalError,
} from './storage-principal.js';

const HUMAN = '1a1a1a1a-0000-4000-8000-000000000001';
const OTHER = '2b2b2b2b-0000-4000-8000-000000000002';
const AGENT = '3c3c3c3c-0000-4000-8000-000000000003';
const signal = new AbortController().signal;

async function scopeFor(principal: string) {
  return createPathPrefixStoragePrincipalResolver(async () => principal).resolve(
    { principalId: AGENT },
    signal,
  );
}

describe('storage principal seam (option A path prefix)', () => {
  it('uses the database-resolved principal, not the session identity', async () => {
    const scope = await scopeFor(HUMAN);
    expect(scope.toObjectKey('notes/a.md')).toBe(`${HUMAN}/notes/a.md`);
    expect(scope.toObjectKey('notes/a.md').startsWith(AGENT)).toBe(false);
  });

  it('maps list prefixes to folder paths without trailing slashes', async () => {
    const scope = await scopeFor(HUMAN);
    expect(scope.toListPrefix('')).toBe(HUMAN);
    expect(scope.toListPrefix('notes/deep')).toBe(`${HUMAN}/notes/deep`);
  });

  it('round-trips in-scope keys and refuses everything else', async () => {
    const scope = await scopeFor(HUMAN);
    expect(scope.toRelativeKey(`${HUMAN}/notes/a.md`)).toBe('notes/a.md');
    expect(scope.toRelativePrefix(`${HUMAN}/notes`)).toBe('notes');
    expect(scope.contains(`${HUMAN}/x.txt`)).toBe(true);
    for (const foreign of [
      `${OTHER}/notes/a.md`,
      `${HUMAN}x/notes/a.md`,
      `${HUMAN.slice(0, -1)}/a.md`,
      `/${HUMAN}/a.md`,
      'a.md',
      HUMAN,
    ]) {
      expect(scope.contains(foreign)).toBe(false);
      expect(scope.toRelativeKey(foreign)).toBeUndefined();
    }
    expect(scope.toRelativeKey(`${HUMAN}/../x.txt`)).toBeUndefined();
    expect(scope.toRelativeKey(`${HUMAN}/bad.exe`)).toBeUndefined();
    expect(scope.toRelativePrefix(`${HUMAN}/`)).toBeUndefined();
  });

  it('refuses to compose keys that fail S1 bounds', async () => {
    const scope = await scopeFor(HUMAN);
    for (const key of ['../x.txt', '/x.txt', 'x.exe', '']) {
      expect(() => scope.toObjectKey(key)).toThrow(StoragePrincipalError);
    }
    expect(() => scope.toListPrefix('../x')).toThrow(StoragePrincipalError);
  });

  it.each([
    'not-a-uuid',
    '',
    `${HUMAN}/`,
    HUMAN.toUpperCase(),
    '00000000-0000-0000-0000-000000000000',
  ])('rejects an unusable principal %s', async (principal) => {
    await expect(scopeFor(principal)).rejects.toBeInstanceOf(StoragePrincipalError);
  });

  it('rejects a non-string principal', async () => {
    await expect(
      createPathPrefixStoragePrincipalResolver(async () => 42 as unknown as string).resolve(
        { principalId: HUMAN },
        signal,
      ),
    ).rejects.toBeInstanceOf(StoragePrincipalError);
  });
});
