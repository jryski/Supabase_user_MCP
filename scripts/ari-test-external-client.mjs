/**
 * TEST-only external MCP child.
 * Pre-registered public PKCE client. No DCR and no client secret.
 * IPC carries authorization URLs, codes, and state only. Token A stays in
 * memory. refresh_token is dropped. Official SDK completion is redirect,
 * then finishAuth, then a new connect. This file does not contact hosted
 * TEST unless a controller runs the parent after G5 with ARI_LANE_B_EXECUTE=1.
 */

import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';
import {
  Client,
  StreamableHTTPClientTransport,
  UnauthorizedError,
} from '@modelcontextprotocol/client';

export const EXTERNAL_CLIENT_PROFILE = 'TEST_ONLY_PUBLIC_PKCE';
export const MARKER_TOOL_NAME = 'ari_test_marker_get';

const SECRET_KEY = /"(access_token|refresh_token|code_verifier|id_token|password)"/i;
const JWT_SHAPE = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\./;
const SAFE_CODE = /^[a-z0-9_]{1,64}$/;

function coded(code) {
  return Object.assign(new Error(code), { code });
}

export function assertIpcHasNoSecrets(value) {
  const encoded = JSON.stringify(value);
  if (SECRET_KEY.test(encoded) || JWT_SHAPE.test(encoded)) {
    throw coded('ipc_refused_secret');
  }
  return encoded;
}

function safeCode(value) {
  return typeof value === 'string' && SAFE_CODE.test(value) ? value : 'child_failed';
}

export function createExternalPublicPkceProvider(options) {
  let accessToken;
  let tokenIssuer;
  let codeVerifier;
  let pendingState = '';
  const oauthState = crypto.randomUUID();
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
    state() {
      return oauthState;
    },
    tokens() {
      if (accessToken === undefined) return undefined;
      return {
        access_token: accessToken,
        token_type: 'Bearer',
        ...(tokenIssuer === undefined ? {} : { issuer: tokenIssuer }),
      };
    },
    saveTokens(tokens) {
      if (typeof tokens.access_token !== 'string' || tokens.access_token.length === 0) {
        throw coded('missing_access_token');
      }
      accessToken = tokens.access_token;
      tokenIssuer = typeof tokens.issuer === 'string' ? tokens.issuer : undefined;
      void tokens.refresh_token;
    },
    redirectToAuthorization(authorizationUrl) {
      const state = authorizationUrl.searchParams.get('state') ?? '';
      if (state !== oauthState) throw coded('authorization_code_refused');
      pendingState = state;
      options.writeIpc(
        assertIpcHasNoSecrets({
          type: 'authorization_request',
          authorizationUrl: authorizationUrl.toString(),
          state,
        }),
      );
    },
    async takeAuthorizationCode() {
      const reply = JSON.parse(await options.readIpc());
      assertIpcHasNoSecrets(reply);
      if (
        reply.type !== 'authorization_code' ||
        reply.state !== pendingState ||
        pendingState.length === 0 ||
        typeof reply.code !== 'string' ||
        reply.code.length < 1 ||
        reply.code.length > 512 ||
        /\s/u.test(reply.code) ||
        JWT_SHAPE.test(reply.code)
      ) {
        throw coded('authorization_code_refused');
      }
      return reply.code;
    },
    saveCodeVerifier(value) {
      codeVerifier = value;
    },
    codeVerifier() {
      if (codeVerifier === undefined) throw coded('missing_code_verifier');
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

function errorText(error) {
  const dataText = error?.data?.text;
  if (typeof dataText === 'string' && dataText.length > 0) return dataText;
  return typeof error?.message === 'string' ? error.message : '';
}

function isAuthorizationRedirect(error) {
  const seen = new Set();
  let current = error;
  while (current !== undefined && current !== null && !seen.has(current)) {
    seen.add(current);
    if (current instanceof UnauthorizedError || current?.name === 'UnauthorizedError') return true;
    if (typeof current?.message === 'string' && current.message.includes('redirect initiated')) {
      return true;
    }
    current = current.cause;
  }
  return false;
}

function downstreamPayload(error) {
  const seen = new Set();
  let current = error;
  while (current !== undefined && current !== null && !seen.has(current)) {
    seen.add(current);
    const text = errorText(current);
    const start = text.indexOf('{');
    const end = text.lastIndexOf('}');
    if (start !== -1 && end > start) {
      try {
        const parsed = JSON.parse(text.slice(start, end + 1));
        if (parsed?.error === 'downstream_authorization_required') return parsed;
      } catch {
        // keep walking; the SDK may wrap the HTTP body
      }
    }
    current = current.cause;
  }
  return undefined;
}

async function openClient(mcpUrl, provider) {
  const client = new Client(
    { name: 'ari-test-external-public-pkce', version: '0.0.0' },
    { capabilities: {} },
  );
  const transport = new StreamableHTTPClientTransport(new URL(mcpUrl), {
    authProvider: provider,
  });
  try {
    await client.connect(transport);
    return { client, transport, error: undefined };
  } catch (error) {
    return { client, transport, error };
  }
}

async function closeOpened(opened) {
  await opened.client.close().catch(() => undefined);
}

/**
 * SDK OAuth completion, then the B handshake, then initialize.
 * finishAuth runs on the transport that observed the 401 challenge.
 * Callers list tools and call the marker on the returned client.
 */
export async function connectExternalClient(options) {
  const provider = createExternalPublicPkceProvider(options);
  if ('saveClientInformation' in provider) throw coded('dcr_enabled');
  const first = await openClient(options.mcpUrl, provider);
  if (first.error !== undefined) {
    if (!isAuthorizationRedirect(first.error)) {
      await closeOpened(first);
      throw first.error?.code ? first.error : coded('child_failed');
    }
    try {
      const code = await provider.takeAuthorizationCode();
      await first.transport.finishAuth(new URLSearchParams({ code, state: provider.state() }));
    } finally {
      await closeOpened(first);
    }
  }
  const second = first.error === undefined ? first : await openClient(options.mcpUrl, provider);
  if (second.error === undefined) return { client: second.client, provider };
  const downstream = downstreamPayload(second.error);
  await closeOpened(second);
  if (downstream === undefined || !publishDownstreamAuthorization(downstream, options.writeIpc)) {
    throw second.error?.code ? second.error : coded('child_failed');
  }
  const bound = JSON.parse(await options.readIpc());
  assertIpcHasNoSecrets(bound);
  if (bound.type !== 'downstream_bound' || bound.state !== downstream.state) {
    throw coded('downstream_callback_failed');
  }
  const third = await openClient(options.mcpUrl, provider);
  if (third.error !== undefined) {
    await closeOpened(third);
    throw third.error?.code ? third.error : coded('downstream_not_bound');
  }
  return { client: third.client, provider };
}

function credentialEnvNames(env) {
  return Object.keys(env)
    .filter((name) =>
      /TOKEN|SECRET|PASSWORD|BEARER|REFRESH|SERVICE_ROLE|APIKEY|API_KEY|PUBLISHABLE|JWKS|SUPABASE_/i.test(
        name,
      ),
    )
    .filter((name) => /^[A-Z0-9_]+$/u.test(name))
    .sort();
}

function toolNames(listed) {
  const tools = listed?.tools;
  if (!Array.isArray(tools)) return [];
  return tools
    .map((tool) => tool?.name)
    .filter((name) => typeof name === 'string' && /^[a-z0-9_-]{1,80}$/u.test(name));
}

function errorBlob(error) {
  const seen = new Set();
  const parts = [];
  let current = error;
  while (current !== undefined && current !== null && !seen.has(current)) {
    seen.add(current);
    if (typeof current.message === 'string') parts.push(current.message);
    if (typeof current.text === 'string') parts.push(current.text);
    current = current.cause;
  }
  return parts.join('\n');
}

function failClosedText(text) {
  return (
    typeof text === 'string' &&
    text.includes('downstream_credential_unresolved') &&
    !JWT_SHAPE.test(text)
  );
}

async function markerFailClosed(client) {
  try {
    const marker = await client.callTool({ name: MARKER_TOOL_NAME, arguments: {} });
    const text = Array.isArray(marker?.content)
      ? marker.content.find((block) => block?.type === 'text')?.text
      : undefined;
    return marker?.isError === true && failClosedText(text);
  } catch (error) {
    return failClosedText(errorBlob(error));
  }
}

export async function runExternalClientSession(options) {
  const connected = await connectExternalClient(options);
  try {
    const listed = await connected.client.listTools();
    const names = toolNames(listed);
    const marker = await connected.client.callTool({ name: MARKER_TOOL_NAME, arguments: {} });
    const text = Array.isArray(marker?.content)
      ? marker.content.find((block) => block?.type === 'text')?.text
      : undefined;
    const markerCalled =
      marker?.isError !== true &&
      typeof text === 'string' &&
      text.length > 0 &&
      text.length <= 256 &&
      !JWT_SHAPE.test(text);
    if (!names.includes(MARKER_TOOL_NAME) || !markerCalled) throw coded('marker_call_failed');
    options.writeIpc(assertIpcHasNoSecrets({ type: 'checkpoint', id: 'P5' }));
    const revocation = {};
    for (const id of ['N4', 'N5']) {
      const reply = JSON.parse(await options.readIpc());
      assertIpcHasNoSecrets(reply);
      if (reply.type !== 'retry_tool' || reply.id !== id) throw coded('revocation_retry_refused');
      revocation[id] = await markerFailClosed(connected.client);
      options.writeIpc(
        assertIpcHasNoSecrets({
          type: 'checkpoint_result',
          id,
          failClosed: revocation[id] === true,
        }),
      );
    }
    return assertIpcHasNoSecrets({
      type: 'receipt',
      initialized: true,
      toolsListed: true,
      markerCalled: true,
      downstreamBound: true,
      externalAuthorizationCompleted: true,
      toolNames: names,
      childEnvNames: credentialEnvNames(options.env ?? {}),
      n4FailClosed: revocation.N4 === true,
      n5FailClosed: revocation.N5 === true,
    });
  } finally {
    await connected.client.close().catch(() => undefined);
  }
}

function lineReader(stream) {
  const rl = createInterface({ input: stream, crlfDelay: Infinity });
  const queue = [];
  let waiter;
  let ended = false;
  const deliver = (value) => {
    if (waiter === undefined) {
      if (value !== null) queue.push(value);
      return;
    }
    const resolve = waiter;
    waiter = undefined;
    resolve(value);
  };
  rl.on('line', (line) => {
    if (line.length > 8192) {
      deliver(null);
      return;
    }
    deliver(line);
  });
  const finish = () => {
    if (ended) return;
    ended = true;
    deliver(null);
  };
  rl.on('close', finish);
  stream.on('end', finish);
  return {
    next() {
      if (queue.length > 0) return Promise.resolve(queue.shift() ?? null);
      if (ended) return Promise.resolve(null);
      return new Promise((resolve) => {
        waiter = resolve;
      });
    },
  };
}

function withTimeout(promise, timeoutMs) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(coded('orchestration_timeout')), timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function loopbackMcpUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw coded('live_configuration_incomplete');
  }
  if (url.protocol !== 'http:' || (url.hostname !== '127.0.0.1' && url.hostname !== 'localhost')) {
    throw coded('mcp_resource_not_loopback');
  }
  if (url.pathname !== '/mcp' || url.username !== '' || url.search !== '' || url.hash !== '') {
    throw coded('live_configuration_incomplete');
  }
  const port = Number(url.port);
  if (!Number.isSafeInteger(port) || port < 1) throw coded('live_configuration_incomplete');
  return url;
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
  if (process.env.ARI_LANE_B_EXECUTE !== '1') {
    process.stderr.write('external client live connect is a controller step after G5\n');
    process.exitCode = 2;
    return;
  }
  const reader = lineReader(process.stdin);
  const timeoutMs = Number(process.env.ARI_LANE_B_TIMEOUT_MS ?? '120000');
  try {
    const mcpUrl = loopbackMcpUrl(process.env.ARI_EXTERNAL_MCP_URL ?? '');
    const clientId = process.env.ARI_EXTERNAL_A_CLIENT_ID ?? '';
    const redirectUrl = process.env.ARI_EXTERNAL_A_REDIRECT_URI ?? '';
    if (clientId.length === 0 || redirectUrl.length === 0) {
      throw coded('live_configuration_incomplete');
    }
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000) {
      throw coded('live_configuration_incomplete');
    }
    const receipt = await withTimeout(
      runExternalClientSession({
        mcpUrl: mcpUrl.toString(),
        clientId,
        redirectUrl,
        env: process.env,
        writeIpc(line) {
          process.stdout.write(`${line}\n`);
        },
        readIpc() {
          return withTimeout(reader.next(), timeoutMs).then((line) => {
            if (line === null) throw coded('authorization_code_refused');
            return line;
          });
        },
      }),
      timeoutMs,
    );
    process.stdout.write(`${receipt}\n`);
  } catch (error) {
    const code = safeCode(error?.code);
    try {
      process.stdout.write(`${assertIpcHasNoSecrets({ type: 'error', code })}\n`);
    } catch {
      process.stdout.write(`${JSON.stringify({ type: 'error', code: 'ipc_refused_secret' })}\n`);
    }
    process.stderr.write(`${code}\n`);
    process.exitCode = 2;
  }
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(invokedPath).href) {
  await main();
}
