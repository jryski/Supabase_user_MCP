/**
 * Shared allowlist for the project key slot. Only a publishable project key,
 * exactly `sb_publishable_<token chars>` after trimming, is accepted. Every
 * other shape fails closed, including secret project keys in any letter case,
 * legacy JWT-shaped keys, and look-alike or zero-width obfuscations.
 */
export const PUBLISHABLE_KEY_PATTERN = /^sb_publishable_[A-Za-z0-9_-]+$/;

/** Secret project keys (any letter case) get their own refusal code. */
export const SECRET_KEY_PATTERN = /^sb_secret_/i;

/** True only for a key that is `sb_publishable_<token chars>` after trimming. */
export function isPublishableProjectKey(value: string): boolean {
  return PUBLISHABLE_KEY_PATTERN.test(value.trim());
}

/** True for a key that starts with `sb_secret_` (any letter case) after trimming. */
export function isSecretProjectKey(value: string): boolean {
  return SECRET_KEY_PATTERN.test(value.trim());
}
