import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

import { describe, expect, it } from 'vitest';

import { performLiveUpstreamOperation } from './live-gotrue-lab-upstream.js';
import {
  fetchLabCredentialRequest,
  registerLocalPublicOAuthClient,
} from './local-oauth-pkce-client.js';

const SERVICE_ROLE = 'sb_secret_lab_registration_only';
const PUBLISHABLE = 'sb_publishable_lab_key';
const USER_TOKEN = 'user-access-token';
const CLIENT_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const REDIRECT = 'http://127.0.0.1:9/lab/oauth/callback';
const RESOURCE = 'http://127.0.0.1:9/rest/v1';

interface SeenRequest {
  readonly method: string;
  readonly url: string;
  readonly authorization: string | undefined;
  readonly apikey: string | undefined;
}

interface LoopbackServer {
  readonly origin: string;
  readonly requests: readonly SeenRequest[];
  close: () => Promise<void>;
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function listen(
  handler: (request: SeenRequest, response: ServerResponse) => void,
): Promise<LoopbackServer> {
  const requests: SeenRequest[] = [];
  const server = createServer((incoming: IncomingMessage, response: ServerResponse) => {
    incoming.resume();
    const seen: SeenRequest = {
      method: incoming.method ?? 'GET',
      url: incoming.url ?? '/',
      authorization: headerValue(incoming.headers.authorization),
      apikey: headerValue(incoming.headers.apikey),
    };
    requests.push(seen);
    handler(seen, response);
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address() as AddressInfo;
      resolve({
        origin: `http://127.0.0.1:${address.port}`,
        requests,
        close: () =>
          new Promise((done, reject) => {
            server.closeAllConnections();
            server.close((error) => (error ? reject(error) : done()));
          }),
      });
    });
  });
}

async function crossHostPair(): Promise<{
  readonly source: LoopbackServer;
  readonly capture: LoopbackServer;
}> {
  const capture = await listen((_request, response) => {
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end('captured');
  });
  const source = await listen((_request, response) => {
    response.writeHead(302, { Location: `${capture.origin}/capture` });
    response.end();
  });
  return { source, capture };
}

function assertCaptureUntouched(capture: LoopbackServer, secret: string): void {
  expect(capture.requests).toEqual([]);
  expect(capture.requests.map((request) => request.authorization)).toEqual([]);
  expect(capture.requests.map((request) => request.apikey)).toEqual([]);
  expect(JSON.stringify(capture.requests)).not.toContain(secret);
}

async function rejectionMessage(run: () => Promise<unknown>): Promise<string> {
  try {
    await run();
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  return '';
}

describe('lab credential redirect containment', () => {
  it('rejects a cross-host 302 before a harness fetch forwards Authorization or apikey', async () => {
    const { source, capture } = await crossHostPair();
    try {
      const message = await rejectionMessage(() =>
        fetchLabCredentialRequest(globalThis.fetch, `${source.origin}/auth/v1/user`, {
          headers: {
            Authorization: `Bearer ${USER_TOKEN}`,
            apikey: PUBLISHABLE,
          },
        }),
      );
      expect(message).toBe('lab credential redirect was rejected');
      expect(message).not.toContain(USER_TOKEN);
      expect(message).not.toContain(PUBLISHABLE);
      expect(source.requests).toEqual([
        expect.objectContaining({
          authorization: `Bearer ${USER_TOKEN}`,
          apikey: PUBLISHABLE,
        }),
      ]);
      assertCaptureUntouched(capture, USER_TOKEN);
      assertCaptureUntouched(capture, PUBLISHABLE);
    } finally {
      await source.close();
      await capture.close();
    }
  });

  it('rejects a later cross-host hop before that capture host is contacted', async () => {
    const capture = await listen((_request, response) => {
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end('captured');
    });
    let origin = '';
    const source = await listen((request, response) => {
      if (request.url === '/start') {
        response.writeHead(302, { Location: `${origin}/next` });
        response.end();
        return;
      }
      response.writeHead(302, { Location: `${capture.origin}/capture` });
      response.end();
    });
    origin = source.origin;
    try {
      const message = await rejectionMessage(() =>
        fetchLabCredentialRequest(globalThis.fetch, `${origin}/start`, {
          headers: {
            Authorization: `Bearer ${SERVICE_ROLE}`,
            apikey: SERVICE_ROLE,
          },
        }),
      );
      expect(message).toBe('lab credential redirect was rejected');
      expect(message).not.toContain(SERVICE_ROLE);
      expect(source.requests.map((request) => request.url)).toEqual(['/start', '/next']);
      expect(source.requests.every((request) => request.apikey === SERVICE_ROLE)).toBe(true);
      expect(
        source.requests.every((request) => request.authorization === `Bearer ${SERVICE_ROLE}`),
      ).toBe(true);
      assertCaptureUntouched(capture, SERVICE_ROLE);
    } finally {
      await source.close();
      await capture.close();
    }
  });

  it('follows a same-host harness redirect and keeps Authorization and apikey', async () => {
    let origin = '';
    const source = await listen((request, response) => {
      if (request.url === '/start') {
        response.writeHead(302, { Location: `${origin}/done` });
        response.end();
        return;
      }
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end('{"ok":true}');
    });
    origin = source.origin;
    try {
      const response = await fetchLabCredentialRequest(globalThis.fetch, `${origin}/start`, {
        headers: {
          Authorization: `Bearer ${USER_TOKEN}`,
          apikey: PUBLISHABLE,
        },
      });
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ ok: true });
      expect(source.requests).toEqual([
        expect.objectContaining({
          url: '/start',
          authorization: `Bearer ${USER_TOKEN}`,
          apikey: PUBLISHABLE,
        }),
        expect.objectContaining({
          url: '/done',
          authorization: `Bearer ${USER_TOKEN}`,
          apikey: PUBLISHABLE,
        }),
      ]);
      expect(new URL(source.requests[1]?.url ?? '', origin).host).toBe(new URL(origin).host);
    } finally {
      await source.close();
    }
  });

  it('rejects a cross-host 302 from admin registration before the capture host is contacted', async () => {
    const { source, capture } = await crossHostPair();
    try {
      const message = await rejectionMessage(() =>
        registerLocalPublicOAuthClient({
          authOrigin: source.origin,
          serviceRoleKey: SERVICE_ROLE,
          clientName: 'lab-dg-upstream',
          redirectUri: REDIRECT,
        }),
      );
      expect(message).toBe('lab credential redirect was rejected');
      expect(message).not.toContain(SERVICE_ROLE);
      expect(source.requests).toEqual([
        expect.objectContaining({
          method: 'POST',
          url: '/auth/v1/admin/oauth/clients',
          authorization: `Bearer ${SERVICE_ROLE}`,
          apikey: SERVICE_ROLE,
        }),
      ]);
      assertCaptureUntouched(capture, SERVICE_ROLE);
    } finally {
      await source.close();
      await capture.close();
    }
  });

  it('follows a same-host admin registration redirect and keeps Authorization and apikey', async () => {
    let origin = '';
    const source = await listen((request, response) => {
      if (request.url === '/auth/v1/admin/oauth/clients') {
        response.writeHead(302, {
          Location: `${origin}/auth/v1/admin/oauth/clients/result`,
        });
        response.end();
        return;
      }
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ client_id: CLIENT_ID, redirect_uris: [REDIRECT] }));
    });
    origin = source.origin;
    try {
      const registered = await registerLocalPublicOAuthClient({
        authOrigin: origin,
        serviceRoleKey: SERVICE_ROLE,
        clientName: 'lab-dg-upstream',
        redirectUri: REDIRECT,
      });
      expect(registered.clientId).toBe(CLIENT_ID);
      expect(source.requests).toEqual([
        expect.objectContaining({
          method: 'POST',
          url: '/auth/v1/admin/oauth/clients',
          authorization: `Bearer ${SERVICE_ROLE}`,
          apikey: SERVICE_ROLE,
        }),
        expect.objectContaining({
          method: 'GET',
          url: '/auth/v1/admin/oauth/clients/result',
          authorization: `Bearer ${SERVICE_ROLE}`,
          apikey: SERVICE_ROLE,
        }),
      ]);
      expect(new URL(source.requests[1]?.url ?? '', origin).origin).toBe(origin);
    } finally {
      await source.close();
    }
  });

  it('rejects a cross-host 302 from the upstream worker before the capture host is contacted', async () => {
    const { source, capture } = await crossHostPair();
    try {
      const message = await rejectionMessage(() =>
        performLiveUpstreamOperation({
          op: 'revokeGrant',
          authOrigin: source.origin,
          publishableKey: PUBLISHABLE,
          clientId: CLIENT_ID,
          userAccessToken: USER_TOKEN,
          refreshToken: 'refresh-token',
          resource: RESOURCE,
        }),
      );
      expect(message).toBe('lab credential redirect was rejected');
      expect(message).not.toContain(USER_TOKEN);
      expect(message).not.toContain(PUBLISHABLE);
      expect(source.requests).toEqual([
        expect.objectContaining({
          method: 'DELETE',
          authorization: `Bearer ${USER_TOKEN}`,
          apikey: PUBLISHABLE,
        }),
      ]);
      assertCaptureUntouched(capture, USER_TOKEN);
      assertCaptureUntouched(capture, PUBLISHABLE);
    } finally {
      await source.close();
      await capture.close();
    }
  });

  it('follows a same-host upstream worker redirect and keeps Authorization and apikey', async () => {
    let origin = '';
    const source = await listen((request, response) => {
      if (request.url?.startsWith('/auth/v1/user/oauth/grants')) {
        response.writeHead(302, { Location: `${origin}/revoked` });
        response.end();
        return;
      }
      if (request.url === '/revoked') {
        response.writeHead(204);
        response.end();
        return;
      }
      response.writeHead(400, { 'content-type': 'application/json' });
      response.end('{"error":"invalid_grant"}');
    });
    origin = source.origin;
    try {
      const measured = await performLiveUpstreamOperation({
        op: 'revokeGrant',
        authOrigin: origin,
        publishableKey: PUBLISHABLE,
        clientId: CLIENT_ID,
        userAccessToken: USER_TOKEN,
        refreshToken: 'refresh-token',
        resource: RESOURCE,
      });
      expect(measured).toMatchObject({ httpStatus: 204, refreshDenied: true });
      expect(source.requests[0]).toMatchObject({
        method: 'DELETE',
        authorization: `Bearer ${USER_TOKEN}`,
        apikey: PUBLISHABLE,
      });
      expect(source.requests[1]).toMatchObject({
        method: 'DELETE',
        url: '/revoked',
        authorization: `Bearer ${USER_TOKEN}`,
        apikey: PUBLISHABLE,
      });
      expect(new URL(source.requests[1]?.url ?? '', origin).origin).toBe(origin);
    } finally {
      await source.close();
    }
  });
});
