import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';

import type { AuthorizationServerMetadata } from '@modelcontextprotocol/server';
import { canonicalizeResourceUri } from '@supabase-user-mcp/contracts';

import { createRemoteHttpProfile, type RemoteHttpHandler } from './remote-http-profile.js';
import type { AccessTokenRevocationAuthority } from './remote-token-verifier.js';

export const REMOTE_HTTP_STARTUP_ERROR = 'REMOTE_HTTP_STARTUP_INVALID_CONFIGURATION';
export const RESOURCE_URI_ENV = 'SUPABASE_USER_MCP_RESOURCE_URI';
export const AUTHORIZATION_SERVER_ENV = 'SUPABASE_USER_MCP_AUTHORIZATION_SERVER';
export const SUPABASE_ORIGIN_ENV = 'SUPABASE_USER_MCP_ORIGIN';
export const PUBLISHABLE_KEY_ENV = 'SUPABASE_USER_MCP_PUBLISHABLE_KEY';
export const JWT_HMAC_SECRET_ENV = 'SUPABASE_USER_MCP_JWT_HMAC_SECRET';
export const LISTEN_PORT_ENV = 'SUPABASE_USER_MCP_LISTEN_PORT';

const FORBIDDEN_ENV = Object.freeze([
  'SUPABASE_USER_MCP_CREDENTIAL_FILE',
  'SUPABASE_USER_MCP_USER_ACCESS_TOKEN',
  'SUPABASE_SERVICE_ROLE_KEY',
]);

export class RemoteHttpStartupError extends Error {
  constructor() {
    super(REMOTE_HTTP_STARTUP_ERROR);
    this.name = 'RemoteHttpStartupError';
  }
}

export interface RemoteHttpStartupOptions {
  readonly argv?: readonly string[];
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly revocationAuthority: AccessTokenRevocationAuthority;
  readonly authorizationServerMetadata: AuthorizationServerMetadata;
  readonly fetch?: typeof globalThis.fetch;
}

function invalid(): never {
  throw new RemoteHttpStartupError();
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
  const hmacSecret = env[JWT_HMAC_SECRET_ENV];
  if (
    typeof resourceUri !== 'string' ||
    typeof issuer !== 'string' ||
    typeof origin !== 'string' ||
    typeof publishableKey !== 'string' ||
    typeof hmacSecret !== 'string' ||
    hmacSecret.length < 32 ||
    publishableKey.split('.').length === 3
  ) {
    invalid();
  }
  return createRemoteHttpProfile({
    resourceUri: canonicalizeResourceUri(resourceUri),
    issuer: canonicalizeResourceUri(issuer),
    supabaseOrigin: origin,
    publishableKey,
    signingKey: { kind: 'hmac', secret: new TextEncoder().encode(hmacSecret) },
    revocationAuthority: options.revocationAuthority,
    authorizationServerMetadata: options.authorizationServerMetadata,
    allowInsecureIssuer: issuer.startsWith('http://127.0.0.1'),
    ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
  });
}

async function toWebRequest(req: IncomingMessage): Promise<Request> {
  const host = req.headers.host;
  if (typeof host !== 'string' || host.length === 0 || req.url === undefined) {
    throw new RemoteHttpStartupError();
  }
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
  }
  const method = req.method ?? 'GET';
  const body = method === 'GET' || method === 'HEAD' ? undefined : Buffer.concat(chunks);
  return new Request(`https://${host}${req.url}`, {
    method,
    headers: new Headers(
      Object.entries(req.headers).flatMap(([key, value]) => {
        if (typeof value === 'string') return [[key, value]];
        if (Array.isArray(value)) return value.map((entry) => [key, entry]);
        return [];
      }),
    ),
    ...(body === undefined ? {} : { body }),
  });
}

export function listenRemoteHttpHandler(
  handler: RemoteHttpHandler,
  port: number,
): ReturnType<typeof createServer> {
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) invalid();
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      try {
        const request = await toWebRequest(req);
        const response = await handler(request);
        const headers: Record<string, string> = {};
        response.headers.forEach((value, key) => {
          headers[key] = value;
        });
        res.writeHead(response.status, headers);
        res.end(Buffer.from(await response.arrayBuffer()));
      } catch {
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'server_error' }));
      }
    })();
  });
  server.listen(port, '127.0.0.1');
  return server;
}
