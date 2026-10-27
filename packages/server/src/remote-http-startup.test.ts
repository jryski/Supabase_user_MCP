import type { IncomingMessage, ServerResponse } from 'node:http';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { createServer as createNetServer } from 'node:net';
import { Readable } from 'node:stream';

import { LOCAL_LAB_MCP_RESOURCE_URI, MAX_RESPONSE_BYTES } from '@supabase-user-mcp/contracts';
import { describe, expect, it } from 'vitest';

import { createAuthorizationServerMetadata } from './authorization-server-metadata.js';
import {
  createRemoteHttpHandlerFromEnvironment,
  handleRemoteHttpConnection,
  listenRemoteHttpHandler,
  OAUTH_CLIENT_ID_ENV,
  REMOTE_HTTP_INGRESS_MAX_BYTES,
  REMOTE_HTTP_STARTUP_ERROR,
  RemoteHttpIngressError,
  readBoundedIncomingMessage,
} from './remote-http-startup.js';

// Remote key-slot cases, built at runtime. Synthetic only; none is a credential.
const REMOTE_KEY_SECRET_SENTINEL = ['sb', 'SeCrEt', 'remote_key_sentinel_must_not_echo'].join('_');
const REMOTE_KEY_LEGACY_ANON = [
  Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url'),
  Buffer.from(JSON.stringify({ role: 'anon' })).toString('base64url'),
  'synthetic-signature',
].join('.');
const REMOTE_KEY_REFUSED: ReadonlyArray<readonly [string, string]> = [
  ['secret key, mixed case', REMOTE_KEY_SECRET_SENTINEL],
  ['secret key, upper case', 'SB_SECRET_REMOTE_KEY_SENTINEL'],
  ['secret key, padded', `  ${['sb', 'secret', 'padded_sentinel'].join('_')}\t`],
  ['publishable key, padded', ' sb_publishable_remote_padded '],
  ['legacy JWT-shaped anon key', REMOTE_KEY_LEGACY_ANON],
  ['empty', ''],
  ['blank', '   '],
  ['lookalike prefix', 'sb_publishab1e_remote_lookalike'],
  ['lookalike case', 'SB_PUBLISHABLE_remote_lookalike'],
  ['zero-width lookalike', 'sb_publishable\u200b_remote_lookalike'],
  ['bare prefix', 'sb_publishable_'],
  ['unprefixed', 'synthetic-remote-key'],
];
const REMOTE_KEY_ACCEPTED = 'sb_publishable_remote_valid_Key-123';

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

function recordingResponse(): ServerResponse & { readonly body: string } {
  let body = '';
  const response = {
    headersSent: false,
    statusCode: 0,
    writeHead(status: number) {
      response.statusCode = status;
      response.headersSent = true;
      return response;
    },
    end(chunk?: unknown) {
      if (typeof chunk === 'string') body = chunk;
      else if (chunk instanceof Uint8Array) body = Buffer.from(chunk).toString('utf8');
      return response;
    },
    get body() {
      return body;
    },
  };
  return response as unknown as ServerResponse & { readonly body: string };
}

async function withProcessExceptionMonitor<T>(
  run: () => Promise<T>,
): Promise<{ readonly outcome: PromiseSettledResult<T>; readonly escaped: readonly unknown[] }> {
  const escaped: unknown[] = [];
  const onMonitor = (error: unknown): void => {
    escaped.push(error);
  };
  const onRejection = (reason: unknown): void => {
    escaped.push(reason);
  };
  process.on('uncaughtExceptionMonitor', onMonitor);
  process.on('unhandledRejection', onRejection);
  try {
    const outcome = await Promise.allSettled([run()]).then(
      (results) => results[0] as PromiseSettledResult<T>,
    );
    await new Promise<void>((resolve) => setImmediate(resolve));
    return { outcome, escaped };
  } finally {
    process.off('uncaughtExceptionMonitor', onMonitor);
    process.off('unhandledRejection', onRejection);
  }
}

function assertReaderCleanedUp(req: IncomingMessage): void {
  expect(req.listenerCount('data')).toBe(0);
  expect(req.listenerCount('end')).toBe(0);
  expect(req.listenerCount('close')).toBe(0);
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

  it('accepts only an sb_publishable_ project key and never echoes a refused key', () => {
    const metadata = createAuthorizationServerMetadata(ISSUER);
    const authority = { inspectAccessToken: async () => 'active' as const };
    for (const [label, key] of REMOTE_KEY_REFUSED) {
      let caught: unknown;
      try {
        createRemoteHttpHandlerFromEnvironment({
          env: { ...validEnv(), SUPABASE_USER_MCP_PUBLISHABLE_KEY: key },
          revocationAuthority: authority,
          authorizationServerMetadata: metadata,
        });
      } catch (error) {
        caught = error;
      }
      expect(caught, label).toBeInstanceOf(Error);
      const error = caught as Error;
      expect(error.message, label).toBe(REMOTE_HTTP_STARTUP_ERROR);
      const rendered = `${error.message} ${error.stack ?? ''} ${JSON.stringify(error)}`;
      if (key.trim().length > 0) expect(rendered, label).not.toContain(key.trim());
    }
    expect(
      typeof createRemoteHttpHandlerFromEnvironment({
        env: { ...validEnv(), SUPABASE_USER_MCP_PUBLISHABLE_KEY: REMOTE_KEY_ACCEPTED },
        revocationAuthority: authority,
        authorizationServerMetadata: metadata,
      }),
    ).toBe('function');
  });

  it('builds a JWKS-only loopback handler without a user bearer cache or HMAC secret', () => {
    const handler = createRemoteHttpHandlerFromEnvironment({
      env: validEnv(),
      revocationAuthority: { inspectAccessToken: async () => 'active' },
      authorizationServerMetadata: createAuthorizationServerMetadata(ISSUER),
    });
    expect(typeof handler).toBe('function');
  });

  it('refuses plaintext issuers unless the parsed host is exactly 127.0.0.1', () => {
    const authority = { inspectAccessToken: async () => 'active' as const };
    for (const issuer of [
      'http://127.0.0.1.evil.example/auth/v1',
      'http://127.0.0.1.evil.example:62421/auth/v1',
      'http://evil.example/auth/v1',
      'http://evil.example@127.0.0.1:62421/auth/v1',
      'http://127.0.0.1:62421@evil.example/auth/v1',
      'http://127.0.0.1.:62421/auth/v1',
      'http://127.1:62421/auth/v1',
      'http://localhost:62421/auth/v1',
      'http://[::1]:62421/auth/v1',
      'http://[::ffff:127.0.0.1]:62421/auth/v1',
    ]) {
      // Some of these cannot even produce metadata; hand startup metadata that
      // names the hostile issuer so only the startup issuer policy is tested.
      let metadata: ReturnType<typeof createAuthorizationServerMetadata>;
      try {
        metadata = createAuthorizationServerMetadata(issuer);
      } catch {
        metadata = { ...createAuthorizationServerMetadata(ISSUER), issuer };
      }
      expect(
        () =>
          createRemoteHttpHandlerFromEnvironment({
            env: { ...validEnv(), SUPABASE_USER_MCP_AUTHORIZATION_SERVER: issuer },
            revocationAuthority: authority,
            authorizationServerMetadata: metadata,
          }),
        issuer,
      ).toThrow(REMOTE_HTTP_STARTUP_ERROR);
    }
  });

  it('serves metadata for an https lookalike issuer without the insecure-issuer exception', async () => {
    const issuer = 'https://127.0.0.1.evil.example/auth/v1';
    const handler = createRemoteHttpHandlerFromEnvironment({
      env: { ...validEnv(), SUPABASE_USER_MCP_AUTHORIZATION_SERVER: issuer },
      revocationAuthority: { inspectAccessToken: async () => 'active' },
      authorizationServerMetadata: createAuthorizationServerMetadata(issuer),
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

  it('derives the scheme from the socket and ignores forwarded headers', async () => {
    const forwarded = incomingMessage({ chunks: [Buffer.from('{}')] });
    forwarded.headers['x-forwarded-proto'] = 'https';
    forwarded.headers['x-forwarded-host'] = 'evil.example';
    const plain = await readBoundedIncomingMessage(forwarded);
    expect(plain.url.startsWith('http://127.0.0.1/mcp')).toBe(true);
    expect(plain.url).not.toContain('evil.example');

    const tls = incomingMessage({ chunks: [Buffer.from('{}')] });
    Object.assign(tls, { socket: { encrypted: true } });
    tls.headers['x-forwarded-proto'] = 'http';
    const secure = await readBoundedIncomingMessage(tls);
    expect(secure.url.startsWith('https://127.0.0.1/mcp')).toBe(true);
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

  it('rejects TRACE and a malformed Host through the reader cleanup path without an uncaught exception', async () => {
    const trace = incomingMessage({ chunks: [], method: 'TRACE' });
    const traced = await withProcessExceptionMonitor(() =>
      readBoundedIncomingMessage(trace, { deadlineMs: 40 }),
    );
    expect(traced.escaped).toEqual([]);
    expect(traced.outcome).toMatchObject({
      status: 'rejected',
      reason: { name: 'RemoteHttpIngressError', code: 'invalid_request' },
    });
    assertReaderCleanedUp(trace);
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(traced.escaped).toEqual([]);

    const malformed = incomingMessage({
      chunks: [],
      headers: { host: '[invalid' },
    });
    const malformedRun = await withProcessExceptionMonitor(() =>
      readBoundedIncomingMessage(malformed, { deadlineMs: 40 }),
    );
    expect(malformedRun.escaped).toEqual([]);
    expect(malformedRun.outcome).toMatchObject({
      status: 'rejected',
      reason: { name: 'RemoteHttpIngressError', code: 'invalid_request' },
    });
    assertReaderCleanedUp(malformed);
  });

  it('returns a bounded 4xx for TRACE and malformed Host without invoking the MCP handler', async () => {
    let handlerCalls = 0;
    const handler = async () => {
      handlerCalls += 1;
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    };

    const traceResponse = recordingResponse();
    await handleRemoteHttpConnection(
      incomingMessage({ chunks: [], method: 'TRACE' }),
      traceResponse,
      handler,
    );
    expect(traceResponse.statusCode).toBe(400);
    expect(JSON.parse(traceResponse.body)).toEqual({ error: 'invalid_request' });

    const malformedResponse = recordingResponse();
    await handleRemoteHttpConnection(
      incomingMessage({ chunks: [], headers: { host: '[invalid' } }),
      malformedResponse,
      handler,
    );
    expect(malformedResponse.statusCode).toBe(400);
    expect(JSON.parse(malformedResponse.body)).toEqual({ error: 'invalid_request' });
    expect(handlerCalls).toBe(0);
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
