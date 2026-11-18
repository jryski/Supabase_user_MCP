#!/usr/bin/env node

import { createAuthorizationServerMetadata } from './authorization-server-metadata.js';
import { createGoTrueSessionRevocationAuthority } from './gotrue-revocation-authority.js';
import type { RemoteHttpHandler } from './remote-http-profile.js';
import {
  AUTHORIZATION_SERVER_ENV,
  LISTEN_PORT_ENV,
  OAUTH_CLIENT_ID_ENV,
  PUBLISHABLE_KEY_ENV,
  RESOURCE_URI_ENV,
  SUPABASE_ORIGIN_ENV,
  createRemoteHttpHandlerFromEnvironment,
  listenRemoteHttpHandler,
} from './remote-http-startup.js';

const env = process.env;
const origin = env[SUPABASE_ORIGIN_ENV];
const issuer = env[AUTHORIZATION_SERVER_ENV];
const publishableKey = env[PUBLISHABLE_KEY_ENV];
const resourceUri = env[RESOURCE_URI_ENV];
const expectedClientId = env[OAUTH_CLIENT_ID_ENV];
const listenPort = env[LISTEN_PORT_ENV];
if (
  typeof origin !== 'string' ||
  typeof issuer !== 'string' ||
  typeof publishableKey !== 'string' ||
  typeof resourceUri !== 'string' ||
  typeof expectedClientId !== 'string' ||
  typeof listenPort !== 'string'
) {
  process.stderr.write('Supabase User MCP remote HTTP profile failed to start.\n');
  process.exit(1);
}

const port = Number(listenPort);
let handler: RemoteHttpHandler;
try {
  handler = createRemoteHttpHandlerFromEnvironment({
    env,
    revocationAuthority: createGoTrueSessionRevocationAuthority({
      origin,
      publishableKey,
    }),
    authorizationServerMetadata: createAuthorizationServerMetadata(issuer),
  });
} catch {
  process.stderr.write('Supabase User MCP remote HTTP profile failed to start.\n');
  process.exit(1);
}

const server = listenRemoteHttpHandler(handler, port);
server.on('listening', () => {
  process.stderr.write(
    'Supabase User MCP experimental remote HTTP profile listening on loopback.\n',
  );
});
server.on('error', () => {
  process.stderr.write('Supabase User MCP remote HTTP profile failed to start.\n');
  process.exit(1);
});
