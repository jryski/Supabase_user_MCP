import { describe, expect, it } from 'vitest';

import {
  createUserScopedStorageClient,
  STORAGE_RPC_SCHEMA,
  StorageClientError,
} from './user-scoped-storage-client.js';

const ORIGIN = 'https://storage.example.test';
const USER_TOKEN = 'synthetic-header.synthetic-payload.synthetic-signature';
const PUBLISHABLE = 'sb_publishable_synthetic_key';
const PRINCIPAL = '1a1a1a1a-0000-4000-8000-000000000001';
const signal = new AbortController().signal;

interface Captured {
  readonly url: string;
  readonly method: string;
  readonly headers: Record<string, string>;
  readonly body?: string;
  readonly redirect?: string;
}

function harness(respond: (request: Captured) => Response) {
  const requests: Captured[] = [];
  const fetch = (async (url: string, init: RequestInit) => {
    const captured: Captured = {
      url,
      method: init.method ?? 'GET',
      headers: init.headers as Record<string, string>,
      ...(typeof init.body === 'string' ? { body: init.body } : {}),
      ...(init.redirect === undefined ? {} : { redirect: init.redirect }),
    };
    requests.push(captured);
    return respond(captured);
  }) as unknown as typeof globalThis.fetch;
  const client = createUserScopedStorageClient({
    origin: ORIGIN,
    bucket: 'user-files',
    credentials: { projectPublishableKey: PUBLISHABLE, userAccessToken: USER_TOKEN },
    fetch,
  });
  return { client, requests };
}

const json = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });

describe('user-scoped storage client', () => {
  it('sends only the caller user token and the publishable key on every request', async () => {
    const { client, requests } = harness((request) => {
      if (request.url.endsWith('/rpc/storage_principal')) return json(PRINCIPAL);
      if (request.url.endsWith('/rpc/storage_session_capabilities')) return json(['storage:read']);
      if (request.url.includes('/object/list/')) return json([]);
      if (request.url.includes('/object/sign/'))
        return json({ signedURL: '/object/sign/x?token=t' });
      if (request.method === 'HEAD') {
        return new Response(null, {
          status: 200,
          headers: {
            'content-length': '3',
            'content-type': 'text/plain',
            'last-modified': 'Thu, 01 Oct 2026 00:00:00 GMT',
          },
        });
      }
      return new Response('abc');
    });
    await client.fetchStoragePrincipal(signal);
    await client.fetchStorageGrants(signal);
    await client.listObjects({ folder: PRINCIPAL, limit: 10, offset: 0 }, signal);
    await client.getObjectInfo(`${PRINCIPAL}/a.txt`, signal);
    await client.downloadObject(`${PRINCIPAL}/a.txt`, 10, signal);
    await client.createSignedDownloadUrl(`${PRINCIPAL}/a.txt`, 60, signal);
    expect(requests).toHaveLength(6);
    for (const request of requests) {
      expect(request.url.startsWith(`${ORIGIN}/`)).toBe(true);
      expect(request.headers.Authorization).toBe(`Bearer ${USER_TOKEN}`);
      expect(request.headers.apikey).toBe(PUBLISHABLE);
      expect(request.redirect).toBe('error');
      expect(JSON.stringify(request)).not.toMatch(/service_role|secret/i);
    }
    expect(requests[0]?.headers['Content-Profile']).toBe(STORAGE_RPC_SCHEMA);
  });

  it.each([
    ['http origin', { origin: 'http://storage.example.test' }],
    ['origin with path', { origin: 'https://storage.example.test/x' }],
    ['bad bucket', { bucket: '../b' }],
    ['jwt in the key slot', { key: 'a.b.c' }],
    ['non-jwt user token', { token: 'opaque' }],
    ['same key and token', { key: USER_TOKEN, token: USER_TOKEN }],
  ])('refuses construction with %s', (_label, override) => {
    const values = override as { origin?: string; bucket?: string; key?: string; token?: string };
    expect(() =>
      createUserScopedStorageClient({
        origin: values.origin ?? ORIGIN,
        bucket: values.bucket ?? 'user-files',
        credentials: {
          projectPublishableKey: values.key ?? PUBLISHABLE,
          userAccessToken: values.token ?? USER_TOKEN,
        },
      }),
    ).toThrow(StorageClientError);
  });

  it('maps list rows to scoped keys and detects more pages', async () => {
    const { client, requests } = harness(() =>
      json([
        { name: 'deep', id: null },
        {
          name: 'a.txt',
          id: 'x',
          updated_at: '2026-10-01T00:00:00Z',
          metadata: { size: 3, mimetype: 'text/plain' },
        },
        {
          name: 'b.txt',
          id: 'y',
          updated_at: '2026-10-01T00:00:00Z',
          metadata: { size: 1, mimetype: 'text/plain' },
        },
      ]),
    );
    const page = await client.listObjects({ folder: PRINCIPAL, limit: 2, offset: 4 }, signal);
    expect(page.hasMore).toBe(true);
    expect(page.entries).toEqual([
      { kind: 'folder', objectPrefix: `${PRINCIPAL}/deep` },
      {
        kind: 'object',
        objectKey: `${PRINCIPAL}/a.txt`,
        size: 3,
        mimeType: 'text/plain',
        updatedAt: '2026-10-01T00:00:00.000Z',
      },
    ]);
    expect(JSON.parse(requests[0]?.body ?? '{}')).toMatchObject({
      prefix: PRINCIPAL,
      limit: 3,
      offset: 4,
    });
  });

  it('rejects list rows whose names try to leave the folder', async () => {
    const { client } = harness(() => json([{ name: '../x.txt', id: 'x' }]));
    await expect(
      client.listObjects({ folder: PRINCIPAL, limit: 2, offset: 0 }, signal),
    ).rejects.toMatchObject({ code: 'STORAGE_CLIENT_MALFORMED_RESPONSE' });
  });

  it.each([400, 401, 403, 404])('treats status %i as not visible', async (status) => {
    const { client } = harness(() => new Response('{}', { status }));
    expect(await client.getObjectInfo(`${PRINCIPAL}/a.txt`, signal)).toBeNull();
    expect(await client.downloadObject(`${PRINCIPAL}/a.txt`, 10, signal)).toBeNull();
    expect(await client.createSignedDownloadUrl(`${PRINCIPAL}/a.txt`, 60, signal)).toBeNull();
    expect(await client.listObjects({ folder: PRINCIPAL, limit: 1, offset: 0 }, signal)).toEqual({
      entries: [],
      hasMore: false,
    });
  });

  it('bounds downloads by the requested byte limit', async () => {
    const { client } = harness(() => new Response(new Uint8Array(11)));
    await expect(client.downloadObject(`${PRINCIPAL}/a.txt`, 10, signal)).rejects.toMatchObject({
      code: 'STORAGE_CLIENT_RESPONSE_TOO_LARGE',
    });
  });

  it('composes signed URLs on the configured origin', async () => {
    const { client, requests } = harness(() =>
      json({ signedURL: `/object/sign/user-files/${PRINCIPAL}/a.txt?token=t` }),
    );
    expect(await client.createSignedDownloadUrl(`${PRINCIPAL}/a.txt`, 60, signal)).toBe(
      `${ORIGIN}/storage/v1/object/sign/user-files/${PRINCIPAL}/a.txt?token=t`,
    );
    expect(JSON.parse(requests[0]?.body ?? '{}')).toEqual({ expiresIn: 60 });
  });

  it('surfaces upstream errors for session RPCs', async () => {
    const { client } = harness(() => new Response('{}', { status: 500 }));
    await expect(client.fetchStoragePrincipal(signal)).rejects.toMatchObject({
      code: 'STORAGE_CLIENT_UPSTREAM_ERROR',
    });
    const denied = harness(() => new Response('{}', { status: 401 }));
    await expect(denied.client.fetchStorageGrants(signal)).rejects.toBeInstanceOf(
      StorageClientError,
    );
  });
});
