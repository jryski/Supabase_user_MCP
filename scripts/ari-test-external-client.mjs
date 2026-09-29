/**
 * TEST-only external MCP child.
 * Pre-registered public PKCE client. No DCR and no client secret.
 * IPC carries authorization URLs, codes, and state only. Token A stays in
 * memory. refresh_token is dropped. This file does not contact hosted TEST
 * unless a controller runs it after G5.
 */

import { pathToFileURL } from 'node:url';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';

export const EXTERNAL_CLIENT_PROFILE = 'TEST_ONLY_PUBLIC_PKCE';

const SECRET_KEY = /"(access_token|refresh_token|code_verifier|id_token)"/i;
const JWT_SHAPE = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\./;

export function assertIpcHasNoSecrets(value) {
  const encoded = JSON.stringify(value);
  if (SECRET_KEY.test(encoded) || JWT_SHAPE.test(encoded)) {
    throw new Error('ipc_refused_secret');
  }
  return encoded;
}

export function createExternalPublicPkceProvider(options) {
  let accessToken;
  let codeVerifier;
  return {
    profile: EXTERNAL_CLIENT_PROFILE,
    get redirectUrl() {
      return options.redirectUrl;
    },
    get clientMetadata() {
      return {
        client_name: 'ari-test-external-public-pkce',
        redirect_uris: [String(options.redirectUrl)],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
        scope: 'email',
      };
    },
    clientInformation() {
      return { client_id: options.clientId };
    },
    tokens() {
      if (accessToken === undefined) return undefined;
      return { access_token: accessToken, token_type: 'Bearer' };
    },
    saveTokens(tokens) {
      if (typeof tokens.access_token !== 'string' || tokens.access_token.length === 0) {
        throw new Error('missing_access_token');
      }
      accessToken = tokens.access_token;
      void tokens.refresh_token;
    },
    async redirectToAuthorization(authorizationUrl) {
      const state = authorizationUrl.searchParams.get('state') ?? '';
      options.writeIpc(
        assertIpcHasNoSecrets({
          type: 'authorization_request',
          authorizationUrl: authorizationUrl.toString(),
          state,
        }),
      );
      const reply = JSON.parse(await options.readIpc());
      if (
        reply.type !== 'authorization_code' ||
        reply.state !== state ||
        typeof reply.code !== 'string'
      ) {
        throw new Error('authorization_code_refused');
      }
      return reply.code;
    },
    saveCodeVerifier(value) {
      codeVerifier = value;
    },
    codeVerifier() {
      if (codeVerifier === undefined) throw new Error('missing_code_verifier');
      return codeVerifier;
    },
  };
}

export function publishDownstreamAuthorization(body, writeIpc) {
  const parsed = typeof body === 'string' ? JSON.parse(body) : body;
  if (parsed?.error !== 'downstream_authorization_required') return false;
  writeIpc(
    assertIpcHasNoSecrets({
      type: 'downstream_authorization_required',
      authorizationUrl: parsed.authorization_url,
      state: parsed.state,
      handshakeId: parsed.handshake_id,
    }),
  );
  return true;
}

export async function connectExternalClient(options) {
  const provider = createExternalPublicPkceProvider(options);
  if ('saveClientInformation' in provider) {
    throw new Error('dcr_enabled');
  }
  const client = new Client(
    { name: 'ari-test-external-public-pkce', version: '0.0.0' },
    { capabilities: {} },
  );
  const transport = new StreamableHTTPClientTransport(new URL(options.mcpUrl), {
    authProvider: provider,
  });
  await client.connect(transport);
  return { client, provider };
}

async function main() {
  const forbidden = [
    'SUPABASE_SERVICE_ROLE_KEY',
    'SUPABASE_SECRET_KEY',
    'SERVICE_ROLE_KEY',
    'SUPABASE_SERVICE_KEY',
  ];
  for (const name of forbidden) {
    if (typeof process.env[name] === 'string' && process.env[name].length > 0) {
      process.stderr.write('service_role_refused\n');
      process.exitCode = 2;
      return;
    }
  }
  if (process.env.ARI_LANE_B_LIVE !== 'controller-g5') {
    process.stderr.write('live_gate_closed\n');
    process.exitCode = 2;
    return;
  }
  process.stderr.write('external client live connect is a controller step after G5\n');
  process.exitCode = 2;
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(invokedPath).href) {
  await main();
}
