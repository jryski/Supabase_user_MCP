import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';

import type { AuthorizationServerMetadata } from '@modelcontextprotocol/server';
import {
  MAX_RESPONSE_BYTES,
  MAX_TOOL_EXECUTION_MS,
  canonicalizeResourceUri,
} from '@supabase-user-mcp/contracts';

import { createRemoteHttpProfile, type RemoteHttpHandler } from './remote-http-profile.js';
import type { AccessTokenRevocationAuthority } from './remote-token-verifier.js';

export const REMOTE_HTTP_STARTUP_ERROR = 'REMOTE_HTTP_STARTUP_INVALID_CONFIGURATION';
export const RESOURCE_URI_ENV = 'SUPABASE_USER_MCP_RESOURCE_URI';
export const AUTHORIZATION_SERVER_ENV = 'SUPABASE_USER_MCP_AUTHORIZATION_SERVER';
export const SUPABASE_ORIGIN_ENV = 'SUPABASE_USER_MCP_ORIGIN';
export const PUBLISHABLE_KEY_ENV = 'SUPABASE_USER_MCP_PUBLISHABLE_KEY';
export const OAUTH_CLIENT_ID_ENV = 'SUPABASE_USER_MCP_OAUTH_CLIENT_ID';
export const JWT_HMAC_SECRET_ENV = 'SUPABASE_USER_MCP_JWT_HMAC_SECRET';
export const LISTEN_PORT_ENV = 'SUPABASE_USER_MCP_LISTEN_PORT';
export const REMOTE_HTTP_INGRESS_MAX_BYTES = MAX_RESPONSE_BYTES;
export const REMOTE_HTTP_INGRESS_DEADLINE_MS = MAX_TOOL_EXECUTION_MS;

const FORBIDDEN_ENV = Object.freeze([
  'SUPABASE_USER_MCP_CREDENTIAL_FILE',
  'SUPABASE_USER_MCP_USER_ACCESS_TOKEN',
  'SUPABASE_SERVICE_ROLE_KEY',
  'SUPABASE_SECRET_KEY',
  JWT_HMAC_SECRET_ENV,
  'SUPABASE_JWT_SECRET',
]);

export class RemoteHttpStartupError extends Error {
  constructor() {
    super(REMOTE_HTTP_STARTUP_ERROR);
    this.name = 'RemoteHttpStartupError';
  }
}

export class RemoteHttpIngressError extends Error {
  readonly code: 'payload_too_large' | 'deadline_exceeded' | 'disconnected';

  constructor(code: RemoteHttpIngressError['code']) {
    super(code);
    this.name = 'RemoteHttpIngressError';
    this.code = code;
  }
}

export interface RemoteHttpStartupOptions {
  readonly argv?: readonly string[];
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly revocationAuthority: AccessTokenRevocationAuthority;
  readonly authorizationServerMetadata: AuthorizationServerMetadata;
  readonly fetch?: typeof globalThis.fetch;
}

export interface BoundedIngressOptions {
  readonly maxBytes?: number;
  readonly deadlineMs?: number;
  readonly now?: () => number;
  readonly signal?: AbortSignal;
}

function invalid(): never {
  throw new RemoteHttpStartupError();
}

function jwksUrlFromMetadata(metadata: AuthorizationServerMetadata): URL {
  const jwksUri = metadata.jwks_uri;
  if (typeof jwksUri !== 'string' || jwksUri.length === 0) invalid();
  return new URL(jwksUri);
}

export function createRemoteHttpHandlerFromEnvironment(
  options: RemoteHttpStartupOptions,
): RemoteHttpHandler {
  const argv = options.argv ?? [];
  if (argv.length !== 0) invalid();
  const env = options.env ?? {};
  for (const name of FORBIDDEN_ENV) {
    if (typeof env[name] === 'string' && env[name].length > 0) invalid();
  }
  const resourceUri = env[RESOURCE_URI_ENV];
  const issuer = env[AUTHORIZATION_SERVER_ENV];
  const origin = env[SUPABASE_ORIGIN_ENV];
  const publishableKey = env[PUBLISHABLE_KEY_ENV];
  const expectedClientId = env[OAUTH_CLIENT_ID_ENV];
  if (
    typeof resourceUri !== 'string' ||
    typeof issuer !== 'string' ||
    typeof origin !== 'string' ||
    typeof publishableKey !== 'string' ||
    typeof expectedClientId !== 'string' ||
    publishableKey.split('.').length === 3
  ) {
    invalid();
  }
  return createRemoteHttpProfile({
    resourceUri: canonicalizeResourceUri(resourceUri),
    issuer: canonicalizeResourceUri(issuer),
    expectedClientId,
    signingKey: { kind: 'jwks', jwksUrl: jwksUrlFromMetadata(options.authorizationServerMetadata) },
    revocationAuthority: options.revocationAuthority,
    authorizationServerMetadata: options.authorizationServerMetadata,
    allowInsecureIssuer: issuer.startsWith('http://127.0.0.1'),
    ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
  });
}

function headerRecord(req: IncomingMessage): Headers {
  return new Headers(
    Object.entries(req.headers).flatMap(([key, value]) => {
      if (typeof value === 'string') return [[key, value]];
      if (Array.isArray(value)) return value.map((entry) => [key, entry]);
      return [];
    }),
  );
}

function declaredContentLength(req: IncomingMessage): number | undefined {
  const raw = req.headers['content-length'];
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== 'string' || value.length === 0) return undefined;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new RemoteHttpIngressError('payload_too_large');
  }
  return parsed;
}

function pauseIncoming(req: IncomingMessage): void {
  req.pause();
  req.removeAllListeners('data');
  if (req.listenerCount('error') === 0) {
    req.on('error', () => {});
  }
}

export async function readBoundedIncomingMessage(
  req: IncomingMessage,
  options: BoundedIngressOptions = {},
): Promise<Request> {
  const host = req.headers.host;
  if (typeof host !== 'string' || host.length === 0 || req.url === undefined) {
    throw new RemoteHttpStartupError();
  }
  const maxBytes = options.maxBytes ?? REMOTE_HTTP_INGRESS_MAX_BYTES;
  const deadlineMs = options.deadlineMs ?? REMOTE_HTTP_INGRESS_DEADLINE_MS;
  const now = options.now ?? Date.now;
  const deadlineAt = now() + deadlineMs;
  const declared = declaredContentLength(req);
  if (declared !== undefined && declared > maxBytes) {
    pauseIncoming(req);
    throw new RemoteHttpIngressError('payload_too_large');
  }
  if (req.destroyed || req.errored) {
    throw new RemoteHttpIngressError('disconnected');
  }

  return await new Promise<Request>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;

    const fail = (error: RemoteHttpIngressError): void => {
      if (settled) return;
      settled = true;
      cleanup();
      pauseIncoming(req);
      reject(error);
    };

    const succeed = (request: Request): void => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(request);
    };

    const onAbort = (): void => {
      fail(new RemoteHttpIngressError('disconnected'));
    };
    const onData = (chunk: string | Buffer): void => {
      if (settled) return;
      if (now() > deadlineAt) {
        fail(new RemoteHttpIngressError('deadline_exceeded'));
        return;
      }
      const buf = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
      if (total + buf.byteLength > maxBytes) {
        fail(new RemoteHttpIngressError('payload_too_large'));
        return;
      }
      chunks.push(buf);
      total += buf.byteLength;
    };
    const onEnd = (): void => {
      if (settled) return;
      const method = req.method ?? 'GET';
      const body =
        method === 'GET' || method === 'HEAD' || total === 0
          ? undefined
          : new Uint8Array(Buffer.concat(chunks));
      succeed(
        new Request(`https://${host}${req.url}`, {
          method,
          headers: headerRecord(req),
          ...(body === undefined ? {} : { body }),
        }),
      );
    };
    const onError = (): void => {
      fail(new RemoteHttpIngressError('disconnected'));
    };
    const onClose = (): void => {
      fail(new RemoteHttpIngressError('disconnected'));
    };

    const cleanup = (): void => {
      clearTimeout(timer);
      options.signal?.removeEventListener('abort', onAbort);
      req.off('data', onData);
      req.off('end', onEnd);
      req.off('error', onError);
      req.off('close', onClose);
    };

    const timer = setTimeout(
      () => fail(new RemoteHttpIngressError('deadline_exceeded')),
      Math.max(1, deadlineAt - now()),
    );

    if (options.signal?.aborted) {
      fail(new RemoteHttpIngressError('disconnected'));
      return;
    }
    options.signal?.addEventListener('abort', onAbort, { once: true });
    req.on('data', onData);
    req.on('end', onEnd);
    req.on('error', onError);
    req.on('close', onClose);
  });
}

export async function toWebRequest(req: IncomingMessage): Promise<Request> {
  return readBoundedIncomingMessage(req);
}

function ingressStatus(error: RemoteHttpIngressError): number {
  if (error.code === 'payload_too_large') return 413;
  if (error.code === 'deadline_exceeded') return 408;
  return 400;
}

export function listenRemoteHttpHandler(
  handler: RemoteHttpHandler,
  port: number,
): ReturnType<typeof createServer> {
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) invalid();
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    req.on('error', () => {});
    res.on('error', () => {});
    void (async () => {
      try {
        const request = await readBoundedIncomingMessage(req);
        const response = await handler(request);
        const headers: Record<string, string> = {};
        response.headers.forEach((value, key) => {
          headers[key] = value;
        });
        res.writeHead(response.status, headers);
        res.end(Buffer.from(await response.arrayBuffer()));
      } catch (error) {
        if (error instanceof RemoteHttpIngressError) {
          if (!res.headersSent) {
            res.writeHead(ingressStatus(error), {
              'content-type': 'application/json',
              connection: 'close',
            });
            res.end(JSON.stringify({ error: error.code }));
          }
          req.resume();
          return;
        }
        if (!res.headersSent) {
          res.writeHead(500, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'server_error' }));
        }
      }
    })();
  });
  server.listen(port, '127.0.0.1');
  return server;
}
