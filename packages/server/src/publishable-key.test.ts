import { describe, expect, it } from 'vitest';
import {
  isPublishableProjectKey,
  isSecretProjectKey,
  PUBLISHABLE_KEY_PATTERN,
  SECRET_KEY_PATTERN,
} from './publishable-key.js';

describe('shared project key allowlist', () => {
  it('pins the exact allowlist and secret-key patterns', () => {
    expect(PUBLISHABLE_KEY_PATTERN.source).toBe('^sb_publishable_[A-Za-z0-9_-]+$');
    expect(PUBLISHABLE_KEY_PATTERN.flags).toBe('');
    expect(SECRET_KEY_PATTERN.source).toBe('^sb_secret_');
    expect(SECRET_KEY_PATTERN.flags).toBe('i');
  });

  it.each(['sb_publishable_synthetic', '  sb_publishable_synthetic  ', '\tsb_publishable_a-B_9\n'])(
    'accepts publishable key %j after trimming',
    (key) => {
      expect(isPublishableProjectKey(key)).toBe(true);
      expect(isSecretProjectKey(key)).toBe(false);
    },
  );

  it.each([
    'sb_secret_synthetic',
    'SB_SECRET_synthetic',
    'Sb_SeCrEt_synthetic',
    '  sb_secret_synthetic\n',
  ])('flags secret key %j in any letter case after trimming', (key) => {
    expect(isSecretProjectKey(key)).toBe(true);
    expect(isPublishableProjectKey(key)).toBe(false);
  });

  it.each([
    '',
    '   ',
    'key',
    'sb_publishable_',
    'SB_PUBLISHABLE_synthetic',
    'sb_publishable_a.b.c',
    'xsb_publishable_synthetic',
    'sb_publishable_synthetic!',
    '\u200bsb_publishable_synthetic',
  ])('refuses non-publishable key %j', (key) => {
    expect(isPublishableProjectKey(key)).toBe(false);
  });
});
