import { parseStorageListPrefix, parseStorageRelativeKey } from '@supabase-user-mcp/contracts';

import type { VerifiedUserIdentity } from './fixed-supabase-client.js';

/**
 * THE storage principal seam (issue #123).
 *
 * Every mapping between a tool-facing relative key and a storage object key
 * goes through one {@link StorageKeyScope}, produced by one
 * {@link StoragePrincipalResolver}. Tool handlers and the storage client never
 * build or parse principal-qualified keys themselves, so swapping the RLS
 * model (A: path prefix, B: owner column, C: registry) means replacing only
 * the resolver implementation below.
 *
 * DB-side counterpart: `storage_principal()` (S4 migration). The resolver must
 * obtain the principal from that function via the caller's own user JWT and
 * must never derive it locally; RLS remains the enforcing layer.
 */
export interface StorageKeyScope {
  /** Storage object key for a tool-facing relative key that already passed S1 bounds. */
  readonly toObjectKey: (relativeKey: string) => string;
  /**
   * Storage folder path (no trailing slash) for a tool-facing list prefix that
   * already passed S1 bounds; `''` maps to the scope root folder.
   */
  readonly toListPrefix: (relativePrefix: string) => string;
  /** Whether an upstream object key or folder path lies inside this scope. */
  readonly contains: (objectKeyOrPrefix: string) => boolean;
  /**
   * Tool-facing relative key for a storage object key returned upstream, or
   * `undefined` when the key is outside this scope or fails S1 bounds.
   */
  readonly toRelativeKey: (objectKey: string) => string | undefined;
  /** Same as {@link toRelativeKey} for folder entries (prefixes). */
  readonly toRelativePrefix: (objectPrefix: string) => string | undefined;
}

export interface StoragePrincipalResolver {
  readonly resolve: (
    identity: VerifiedUserIdentity,
    signal: AbortSignal,
  ) => Promise<StorageKeyScope>;
}

export class StoragePrincipalError extends Error {
  readonly code = 'STORAGE_PRINCIPAL_UNRESOLVED' as const;

  constructor() {
    super('Storage principal could not be resolved.');
    this.name = 'StoragePrincipalError';
  }
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/**
 * Option A (path prefix): objects live at `<storage principal uuid>/<relative key>`.
 *
 * `fetchStoragePrincipal` must call the DB `storage_principal()` function with
 * the caller's user JWT. For a human it equals `auth.uid()`; for a delegated
 * agent it is the delegating human, resolved by the database, not by this code.
 *
 * `credentialSubject` is the `sub` of the user token `fetchStoragePrincipal`
 * sends. The verified caller identity must equal it, so the principal is
 * always resolved for the caller that the server verified.
 */
export function createPathPrefixStoragePrincipalResolver(
  fetchStoragePrincipal: (signal: AbortSignal) => Promise<string>,
  credentialSubject: string,
): StoragePrincipalResolver {
  return Object.freeze({
    async resolve(identity: VerifiedUserIdentity, signal: AbortSignal): Promise<StorageKeyScope> {
      // The principal lookup runs with the client's user token, so that token
      // must belong to the verified caller. Anything else fails closed before
      // the database is asked.
      if (
        typeof identity?.principalId !== 'string' ||
        !UUID_PATTERN.test(identity.principalId) ||
        identity.principalId !== credentialSubject
      ) {
        throw new StoragePrincipalError();
      }
      const principal = await fetchStoragePrincipal(signal);
      if (typeof principal !== 'string' || !UUID_PATTERN.test(principal)) {
        throw new StoragePrincipalError();
      }
      const root = `${principal}/`;
      const strip = (value: string): string | undefined =>
        typeof value === 'string' && value.startsWith(root) ? value.slice(root.length) : undefined;
      return Object.freeze({
        contains: (value: string) => strip(value) !== undefined,
        toObjectKey: (relativeKey: string) => {
          if (!parseStorageRelativeKey(relativeKey).ok) throw new StoragePrincipalError();
          return `${root}${relativeKey}`;
        },
        toListPrefix: (relativePrefix: string) => {
          if (!parseStorageListPrefix(relativePrefix).ok) throw new StoragePrincipalError();
          return relativePrefix === '' ? principal : `${root}${relativePrefix}`;
        },
        toRelativeKey: (objectKey: string) => {
          const relative = strip(objectKey);
          return relative !== undefined && parseStorageRelativeKey(relative).ok
            ? relative
            : undefined;
        },
        toRelativePrefix: (objectPrefix: string) => {
          const relative = strip(objectPrefix);
          return relative !== undefined && relative !== '' && parseStorageListPrefix(relative).ok
            ? relative
            : undefined;
        },
      });
    },
  });
}
