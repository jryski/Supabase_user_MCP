import { lstat, readFile } from 'node:fs/promises';

const MAX_CREDENTIAL_BYTES = 16_384;

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
) => PermissionInspection | Promise<PermissionInspection>;

export interface LocalCredentialLoaderOptions {
  /** Trusted controller seam for deterministic ACL inspection in environments such as Windows. */
  readonly permissionInspector?: PermissionInspector;
  readonly now?: () => number;
}

function fail(code: LocalCredentialErrorCode): never {
  throw new LocalCredentialError(code);
}

const defaultPermissionInspector: PermissionInspector = (_path, mode) => {
  if (process.platform === 'win32') return 'unsupported';
  return (mode & 0o077) === 0 ? 'secure' : 'insecure';
};

function parseTokenExpiry(token: string): number {
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    fail('CREDENTIAL_TOKEN_INVALID');
  }
  try {
    const payload: unknown = JSON.parse(Buffer.from(parts[1] ?? '', 'base64url').toString('utf8'));
    if (
      typeof payload !== 'object' ||
      payload === null ||
      !('exp' in payload) ||
      typeof payload.exp !== 'number' ||
      !Number.isSafeInteger(payload.exp)
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
  let metadata: Awaited<ReturnType<typeof lstat>>;
  try {
    metadata = await lstat(startupPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') fail('CREDENTIAL_FILE_MISSING');
    fail('CREDENTIAL_READ_FAILED');
  }
  if (metadata.isSymbolicLink()) fail('CREDENTIAL_SYMLINK');
  if (!metadata.isFile()) fail('CREDENTIAL_NOT_FILE');
  if (metadata.size > MAX_CREDENTIAL_BYTES) fail('CREDENTIAL_FILE_TOO_LARGE');

  let permission: PermissionInspection;
  try {
    permission = await (options.permissionInspector ?? defaultPermissionInspector)(
      startupPath,
      metadata.mode,
    );
  } catch {
    fail('CREDENTIAL_PERMISSION_CHECK_UNSUPPORTED');
  }
  if (permission === 'unsupported') fail('CREDENTIAL_PERMISSION_CHECK_UNSUPPORTED');
  if (permission !== 'secure') fail('CREDENTIAL_INSECURE_PERMISSIONS');

  let body: string;
  try {
    body = await readFile(startupPath, { encoding: 'utf8' });
  } catch {
    fail('CREDENTIAL_READ_FAILED');
  }
  if (Buffer.byteLength(body) > MAX_CREDENTIAL_BYTES) fail('CREDENTIAL_FILE_TOO_LARGE');

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
  if (projectPublishableKey === userAccessToken || projectPublishableKey.split('.').length === 3) {
    fail('CREDENTIAL_CONFLATED');
  }
  const expiresAt = parseTokenExpiry(userAccessToken);
  if (expiresAt <= Math.floor((options.now?.() ?? Date.now()) / 1000)) {
    fail('CREDENTIAL_TOKEN_EXPIRED');
  }
  return Object.freeze({ projectPublishableKey, userAccessToken });
}
