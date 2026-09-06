import http from 'node:http';
import type { IncomingMessage } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import type { AddressInfo } from 'node:net';
import { Readable } from 'node:stream';

import { LOCAL_LAB_MCP_RESOURCE_URI, MAX_RESPONSE_BYTES } from '@supabase-user-mcp/contracts';
import { describe, expect, it } from 'vitest';

import { createAuthorizationServerMetadata } from './authorization-server-metadata.js';
import {
  OAUTH_CLIENT_ID_ENV,
  REMOTE_HTTP_INGRESS_MAX_BYTES,
  REMOTE_HTTP_STARTUP_ERROR,
  RemoteHttpIngressError,
  createRemoteHttpHandlerFromEnvironment,
  listenRemoteHttpHandler,
  readBoundedIncomingMessage,
} from './remote-http-startup.js';

const ISSUER = 'http://127.0.0.1:62421/auth/v1';
const CLIENT = 'smp-lab-inspector';

function validEnv(): Record<string, string> {
  return {
    SUPABASE_USER_MCP_RESOURCE_URI: LOCAL_LAB_MCP_RESOURCE_URI,
    SUPABASE_USER_MCP_AUTHORIZATION_SERVER: ISSUER,
    SUPABASE_USER_MCP_ORIGIN: 'https://m2-loopback.invalid',
    SUPABASE_USER_MCP_PUBLISHABLE_KEY: 'sb_publishable_lab_key',
    [OAUTH_CLIENT_ID_ENV]: CLIENT,
  };
}

function incomingMessage(input: {
  readonly chunks: readonly Buffer[];
  readonly headers?: Record<string, string>;
  readonly method?: string;
}): IncomingMessage {
  const stream = Readable.from(input.chunks);
  Object.assign(stream, {
    headers: { host: '127.0.0.1', ...input.headers },
    method: input.method ?? 'POST',
    url: '/mcp',
  });
  return stream as IncomingMessage;
}

function hangingRequest(): IncomingMessage {
  const stream = new Readable({
    read() {
      /* never push; the deadline timer must cancel the read */
    },
  });
  Object.assign(stream, {
    headers: { host: '127.0.0.1' },
    method: 'POST',
    url: '/mcp',
  });
  return stream as IncomingMessage;
}

async function reservedLoopbackPort(): Promise<number> {
  return await new Promise((resolve, reject) => {
    const probe = createNetServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address() as AddressInfo;
      probe.close((error) => {
        if (error) reject(error);
        else resolve(address.port);
      });
    });
  });
}

describe('remote HTTP startup', () => {
  it('rejects argv, credential files, user tokens, service_role, and HMAC signing secrets', () => {
    const metadata = createAuthorizationServerMetadata(ISSUER);
    const authority = { inspectAccessToken: async () => 'active' as const };
    const valid = validEnv();

    expect(() =>
      createRemoteHttpHandlerFromEnvironment({
        argv: ['--help'],
        env: valid,
        revocationAuthority: authority,
        authorizationServerMetadata: metadata,
      }),
    ).toThrow(REMOTE_HTTP_STARTUP_ERROR);

    for (const forbidden of [
      'SUPABASE_USER_MCP_CREDENTIAL_FILE',
      'SUPABASE_USER_MCP_USER_ACCESS_TOKEN',
      'SUPABASE_SERVICE_ROLE_KEY',
      'SUPABASE_SECRET_KEY',
      'SUPABASE_USER_MCP_JWT_HMAC_SECRET',
      'SUPABASE_JWT_SECRET',
    ]) {
      expect(() =>
        createRemoteHttpHandlerFromEnvironment({
          env: { ...valid, [forbidden]: 'present' },
          revocationAuthority: authority,
          authorizationServerMetadata: metadata,
        }),
      ).toThrow(REMOTE_HTTP_STARTUP_ERROR);
    }
  });

  it('builds a JWKS-only loopback handler without a user bearer cache or HMAC secret', () => {
    const handler = createRemoteHttpHandlerFromEnvironment({
      env: validEnv(),
      revocationAuthority: { inspectAccessToken: async () => 'active' },
      authorizationServerMetadata: createAuthorizationServerMetadata(ISSUER),
    });
    expect(typeof handler).toBe('function');
  });

  it('rejects a missing OAuth client id or authorization-server JWKS URI', () => {
    const authority = { inspectAccessToken: async () => 'active' as const };
    const valid = validEnv();
    const withoutClient = { ...valid };
    delete withoutClient[OAUTH_CLIENT_ID_ENV];
    expect(() =>
      createRemoteHttpHandlerFromEnvironment({
        env: withoutClient,
        revocationAuthority: authority,
        authorizationServerMetadata: createAuthorizationServerMetadata(ISSUER),
      }),
    ).toThrow(REMOTE_HTTP_STARTUP_ERROR);

    const withoutJwks = { ...createAuthorizationServerMetadata(ISSUER), jwks_uri: '' };
    expect(() =>
      createRemoteHttpHandlerFromEnvironment({
        env: valid,
        revocationAuthority: authority,
        authorizationServerMetadata: withoutJwks,
      }),
    ).toThrow(REMOTE_HTTP_STARTUP_ERROR);
  });

  it('rejects a 4MiB chunked body without Content-Length before concatenating it', async () => {
    expect(REMOTE_HTTP_INGRESS_MAX_BYTES).toBe(MAX_RESPONSE_BYTES);
    const oversized = incomingMessage({ chunks: [Buffer.alloc(4_194_304, 7)] });
    await expect(readBoundedIncomingMessage(oversized)).rejects.toMatchObject({
      name: 'RemoteHttpIngressError',
      code: 'payload_too_large',
    });
  });

  it('accepts an exact ingress ceiling and rejects one extra byte', async () => {
    const exact = incomingMessage({ chunks: [Buffer.alloc(REMOTE_HTTP_INGRESS_MAX_BYTES, 1)] });
    const request = await readBoundedIncomingMessage(exact);
    expect(Buffer.byteLength(await request.arrayBuffer())).toBe(REMOTE_HTTP_INGRESS_MAX_BYTES);

    const over = incomingMessage({ chunks: [Buffer.alloc(REMOTE_HTTP_INGRESS_MAX_BYTES + 1, 1)] });
    await expect(readBoundedIncomingMessage(over)).rejects.toBeInstanceOf(RemoteHttpIngressError);
  });

  it('rejects Content-Length above the ceiling without reading the body', async () => {
    const req = incomingMessage({
      chunks: [Buffer.alloc(8, 1)],
      headers: { 'content-length': String(REMOTE_HTTP_INGRESS_MAX_BYTES + 1) },
    });
    await expect(readBoundedIncomingMessage(req)).rejects.toMatchObject({
      code: 'payload_too_large',
    });
  });

  it('cancels on deadline and treats a destroyed stream as disconnected', async () => {
    let nowMs = 0;
    const slow = incomingMessage({ chunks: [Buffer.alloc(8, 1)] });
    await expect(
      readBoundedIncomingMessage(slow, {
        deadlineMs: 5,
        now: () => {
          nowMs += 10;
          return nowMs;
        },
      }),
    ).rejects.toMatchObject({ code: 'deadline_exceeded' });

    const hanging = hangingRequest();
    try {
      await expect(readBoundedIncomingMessage(hanging, { deadlineMs: 30 })).rejects.toMatchObject({
        code: 'deadline_exceeded',
      });
    } finally {
      hanging.destroy();
    }

    const destroyed = incomingMessage({ chunks: [Buffer.from('x')] });
    destroyed.on('error', () => {});
    destroyed.destroy(new Error('socket hang up'));
    await expect(readBoundedIncomingMessage(destroyed)).rejects.toMatchObject({
      code: 'disconnected',
    });
  });

  it('rejects a 4MiB chunked body at the listener without invoking the MCP handler', async () => {
    let handlerCalls = 0;
    const port = await reservedLoopbackPort();
    const server = listenRemoteHttpHandler(async () => {
      handlerCalls += 1;
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }, port);
    await new Promise<void>((resolve, reject) => {
      if (server.listening) {
        resolve();
        return;
      }
      server.once('listening', () => resolve());
      server.once('error', reject);
    });
    try {
      const status = await new Promise<number>((resolve, reject) => {
        const req = http.request(
          {
            hostname: '127.0.0.1',
            port,
            path: '/mcp',
            method: 'POST',
            headers: {
              Host: '127.0.0.1',
              'Transfer-Encoding': 'chunked',
            },
          },
          (res) => {
            res.resume();
            res.once('end', () => resolve(res.statusCode ?? 0));
          },
        );
        req.on('error', (error) => {
          if (req.destroyed) return;
          reject(error);
        });
        req.write(Buffer.alloc(4_194_304, 7));
        req.end();
      });
      expect(status).toBe(413);
      expect(handlerCalls).toBe(0);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) reject(error);
          else resolve();
        });
      });
    }
  });
});
