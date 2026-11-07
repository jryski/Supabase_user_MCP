import { createReadToolError } from '@supabase-user-mcp/contracts';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { ReadToolOperationalEvent } from './read-tool-governor.js';
import { createPathPrefixStoragePrincipalResolver } from './storage-principal.js';
import { createStorageReadTools } from './storage-read-tools.js';
import type { UserScopedStorageClient } from './user-scoped-storage-client.js';

const PRINCIPAL = 'da1a1a1a-0000-4000-8000-000000000001';

function storageClient(
  uploadObject: UserScopedStorageClient['uploadObject'],
): UserScopedStorageClient {
  return {
    tokenSubject: PRINCIPAL,
    fetchStorageGrants: async () => ['storage:read', 'storage:write'],
    fetchStoragePrincipal: async () => PRINCIPAL,
    listObjects: async () => ({ entries: [], hasMore: false }),
    getObjectInfo: async () => null,
    downloadObject: async () => null,
    createSignedDownloadUrl: async () => null,
    uploadObject,
    deleteObject: async () => false,
  };
}

afterEach(() => vi.useRealTimers());

describe('storage provider deadline regression', () => {
  it('bounds a hung upload, suppresses late success and retains its concurrency lease', async () => {
    vi.useFakeTimers();
    let finish: (value: boolean) => void = () => undefined;
    const upload = vi
      .fn<UserScopedStorageClient['uploadObject']>()
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            finish = resolve;
          }),
      )
      .mockResolvedValue(true);
    const client = storageClient(upload);
    const scope = await createPathPrefixStoragePrincipalResolver(
      client.fetchStoragePrincipal,
      PRINCIPAL,
    ).resolve({ principalId: PRINCIPAL }, new AbortController().signal);
    const tools = createStorageReadTools({
      client,
      scope,
      capabilities: ['storage:read', 'storage:write'],
      toolNames: [
        'storage_put',
        'storage_get',
        'storage_list',
        'storage_delete',
        'storage_capabilities',
      ],
      governance: { maxConcurrentExecutions: 1, maxRequestsPerWindow: 100 },
    });
    const events: ReadToolOperationalEvent[] = [];
    const input = {
      key: 'deadline.md',
      mimeType: 'text/markdown',
      contentBase64: Buffer.from('synthetic').toString('base64'),
    };
    const context = {
      principalId: PRINCIPAL,
      emitOperationalEvent: (event: ReadToolOperationalEvent) => events.push(event),
    };
    const pending = tools.put(input, context);
    await vi.advanceTimersByTimeAsync(2_001);
    expect(await pending).toEqual(createReadToolError('DEADLINE_EXCEEDED'));
    expect(upload).toHaveBeenCalledTimes(1);
    expect(await tools.put(input, { principalId: PRINCIPAL })).toEqual(
      createReadToolError('RESOURCE_UNAVAILABLE'),
    );
    finish(true); // Storage could have committed; the public outcome remains uncertain.
    await vi.advanceTimersByTimeAsync(0);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ outcome: 'blocked', denialClass: 'DEADLINE_EXCEEDED' });
    expect(
      (await tools.put({ ...input, key: 'after-settlement.md' }, { principalId: PRINCIPAL })).ok,
    ).toBe(true);
    expect(upload).toHaveBeenCalledTimes(2);
  });
});
