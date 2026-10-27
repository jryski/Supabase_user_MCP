import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { isPublishableProjectKey, isSecretProjectKey } from './publishable-key.js';

const MAX_CREDENTIAL_BYTES = 16_384;
const TOKEN_SEGMENT_PATTERN = /^[A-Za-z0-9_-]+$/;
const TOKEN_SUBJECT_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const USER_TOKEN_ROLE = 'authenticated';

export type LocalCredentialErrorCode =
  | 'CREDENTIAL_FILE_MISSING'
  | 'CREDENTIAL_SYMLINK'
  | 'CREDENTIAL_NOT_FILE'
  | 'CREDENTIAL_FILE_TOO_LARGE'
  | 'CREDENTIAL_INSECURE_PERMISSIONS'
  | 'CREDENTIAL_PERMISSION_CHECK_UNSUPPORTED'
  | 'CREDENTIAL_READ_FAILED'
  | 'CREDENTIAL_MALFORMED'
  | 'CREDENTIAL_SCHEMA_INVALID'
  | 'CREDENTIAL_BLANK'
  | 'CREDENTIAL_CONFLATED'
  | 'CREDENTIAL_SECRET_KEY'
  | 'CREDENTIAL_KEY_NOT_PUBLISHABLE'
  | 'CREDENTIAL_TOKEN_INVALID'
  | 'CREDENTIAL_TOKEN_EXPIRED';

export class LocalCredentialError extends Error {
  readonly code: LocalCredentialErrorCode;

  constructor(code: LocalCredentialErrorCode) {
    super(code);
    this.name = 'LocalCredentialError';
    this.code = code;
  }
}

export interface LocalCredentials {
  readonly projectPublishableKey: string;
  readonly userAccessToken: string;
}

export type PermissionInspection = 'secure' | 'insecure' | 'unsupported';
export type PermissionInspector = (
  path: string,
  mode: number,
  ownerUid: number,
) => PermissionInspection | Promise<PermissionInspection>;

export interface LocalCredentialLoaderOptions {
  /** Trusted controller seam for deterministic ACL inspection in environments such as Windows. */
  readonly permissionInspector?: PermissionInspector;
  readonly now?: () => number;
}

function fail(code: LocalCredentialErrorCode): never {
  throw new LocalCredentialError(code);
}

const defaultPermissionInspector: PermissionInspector = (_path, mode, ownerUid) => {
  if (process.platform === 'win32') return 'unsupported';
  const currentUid = process.getuid?.();
  if (currentUid === undefined) return 'unsupported';
  return ownerUid === currentUid && (mode & 0o077) === 0 ? 'secure' : 'insecure';
};

/**
 * Decodes the user access token payload WITHOUT verifying its signature and
 * returns its `exp`. The token must be a signed-in user's: `role` exactly
 * `authenticated` and a lowercase UUID `sub`. Signature verification stays
 * with the upstream identity check; this only refuses tokens that are plainly
 * not a user's (for example `service_role` or `anon`) before they are used.
 */
function parseTokenExpiry(token: string): number {
  const parts = token.split('.');
  if (parts.length !== 3 || !parts.every((part) => TOKEN_SEGMENT_PATTERN.test(part))) {
    fail('CREDENTIAL_TOKEN_INVALID');
  }
  try {
    const payload: unknown = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(parts[1] ?? '', 'base64url')),
    );
    if (
      typeof payload !== 'object' ||
      payload === null ||
      !('exp' in payload) ||
      typeof payload.exp !== 'number' ||
      !Number.isSafeInteger(payload.exp) ||
      !('role' in payload) ||
      payload.role !== USER_TOKEN_ROLE ||
      !('sub' in payload) ||
      typeof payload.sub !== 'string' ||
      !TOKEN_SUBJECT_PATTERN.test(payload.sub)
    ) {
      fail('CREDENTIAL_TOKEN_INVALID');
    }
    return payload.exp;
  } catch (error) {
    if (error instanceof LocalCredentialError) throw error;
    fail('CREDENTIAL_TOKEN_INVALID');
  }
}

export async function loadLocalCredentials(
  startupPath: string,
  options: LocalCredentialLoaderOptions = {},
): Promise<LocalCredentials> {
  let handle: Awaited<ReturnType<typeof open>>;
  try {
    const noFollow = process.platform === 'win32' ? 0 : constants.O_NOFOLLOW;
    handle = await open(startupPath, constants.O_RDONLY | noFollow);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') fail('CREDENTIAL_FILE_MISSING');
    if (code === 'ELOOP') fail('CREDENTIAL_SYMLINK');
    fail('CREDENTIAL_READ_FAILED');
  }

  let body: string;
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile()) fail('CREDENTIAL_NOT_FILE');
    if (metadata.size > MAX_CREDENTIAL_BYTES) fail('CREDENTIAL_FILE_TOO_LARGE');

    let permission: PermissionInspection;
    try {
      permission = await (options.permissionInspector ?? defaultPermissionInspector)(
        startupPath,
        metadata.mode,
        metadata.uid,
      );
    } catch {
      fail('CREDENTIAL_PERMISSION_CHECK_UNSUPPORTED');
    }
    if (permission === 'unsupported') fail('CREDENTIAL_PERMISSION_CHECK_UNSUPPORTED');
    if (permission !== 'secure') fail('CREDENTIAL_INSECURE_PERMISSIONS');

    const bytes = Buffer.allocUnsafe(MAX_CREDENTIAL_BYTES + 1);
    let length = 0;
    while (length < bytes.byteLength) {
      const result = await handle.read(bytes, length, bytes.byteLength - length, null);
      if (result.bytesRead === 0) break;
      length += result.bytesRead;
    }
    if (length > MAX_CREDENTIAL_BYTES) fail('CREDENTIAL_FILE_TOO_LARGE');
    body = bytes.subarray(0, length).toString('utf8');
  } catch (error) {
    if (error instanceof LocalCredentialError) throw error;
    fail('CREDENTIAL_READ_FAILED');
  } finally {
    await handle.close().catch(() => undefined);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    fail('CREDENTIAL_MALFORMED');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    fail('CREDENTIAL_SCHEMA_INVALID');
  }
  const keys = Object.keys(parsed).sort();
  if (keys.length !== 2 || keys[0] !== 'projectPublishableKey' || keys[1] !== 'userAccessToken') {
    fail('CREDENTIAL_SCHEMA_INVALID');
  }
  const record = parsed as Record<string, unknown>;
  if (
    typeof record.projectPublishableKey !== 'string' ||
    typeof record.userAccessToken !== 'string'
  ) {
    fail('CREDENTIAL_SCHEMA_INVALID');
  }
  const projectPublishableKey = record.projectPublishableKey.trim();
  const userAccessToken = record.userAccessToken.trim();
  if (projectPublishableKey.length === 0 || userAccessToken.length === 0) fail('CREDENTIAL_BLANK');
  // Only an `sb_publishable_` key may fill the key slot. A secret key (any
  // letter case) and a JWT-shaped key keep their specific codes; every other
  // shape is refused as not publishable.
  if (isSecretProjectKey(projectPublishableKey)) fail('CREDENTIAL_SECRET_KEY');
  if (projectPublishableKey === userAccessToken || projectPublishableKey.split('.').length === 3) {
    fail('CREDENTIAL_CONFLATED');
  }
  if (!isPublishableProjectKey(projectPublishableKey)) fail('CREDENTIAL_KEY_NOT_PUBLISHABLE');
  const expiresAt = parseTokenExpiry(userAccessToken);
  if (expiresAt <= Math.floor((options.now?.() ?? Date.now()) / 1000)) {
    fail('CREDENTIAL_TOKEN_EXPIRED');
  }
  return Object.freeze({ projectPublishableKey, userAccessToken });
}
