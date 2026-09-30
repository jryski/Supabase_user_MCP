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
const CANARY_SHAPE = /^ari-probe-marker-[a-z0-9]{20}$/u;

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

export const DIAGNOSTIC_STAGES = Object.freeze(['initialize', 'liveness', 'list', 'tool']);
export const DIAGNOSTIC_CATEGORIES = Object.freeze([
  'rpc_validation',
  'auth_denial',
  'service_error',
  'malformed_response',
  'false',
  'timeout',
]);

function boundedRpcCode(value) {
  return Number.isSafeInteger(value) && value <= -32000 && value >= -32768 ? value : undefined;
}

function boundedHttpStatus(value) {
  return Number.isSafeInteger(value) && value >= 100 && value <= 599 ? value : undefined;
}

function categoryForRpc(code) {
  if (code === -32700) return 'malformed_response';
  if (code === -32600 || code === -32601 || code === -32602) return 'rpc_validation';
  return 'service_error';
}

function categoryForHttp(status) {
  if (status === 401 || status === 403) return 'auth_denial';
  if (status >= 500) return 'service_error';
  if (
    status === 400 ||
    status === 404 ||
    status === 406 ||
    status === 409 ||
    status === 415 ||
    status === 422
  ) {
    return 'rpc_validation';
  }
  return 'malformed_response';
}

function firstJsonObject(text) {
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start < 0 || end <= start || end - start > 4096) return undefined;
  try {
    return JSON.parse(text.slice(start, end + 1));
  } catch {
    return undefined;
  }
}

function diagnosticFromDenial(parsed) {
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined;
  if (parsed.error !== 'downstream_credential_unresolved') return undefined;
  if (!DIAGNOSTIC_STAGES.includes(parsed.stage)) return undefined;
  if (!DIAGNOSTIC_CATEGORIES.includes(parsed.category)) return undefined;
  const diagnostic = { stage: parsed.stage, category: parsed.category };
  if (parsed.httpStatus !== undefined) {
    const httpStatus = boundedHttpStatus(parsed.httpStatus);
    if (httpStatus === undefined) return undefined;
    diagnostic.httpStatus = httpStatus;
  }
  if (parsed.rpcCode !== undefined) {
    const rpcCode = boundedRpcCode(parsed.rpcCode);
    if (rpcCode === undefined) return undefined;
    diagnostic.rpcCode = rpcCode;
  }
  return diagnostic;
}

function walkErrors(error, visit) {
  const seen = new Set();
  let current = error;
  while (
    current !== undefined &&
    current !== null &&
    typeof current === 'object' &&
    !seen.has(current)
  ) {
    seen.add(current);
    const found = visit(current);
    if (found !== undefined) return found;
    current = current.cause;
  }
  return undefined;
}

function embeddedDiagnostic(error) {
  return walkErrors(error, (current) => {
    const texts = [];
    if (typeof current.message === 'string') texts.push(current.message);
    if (typeof current.data?.text === 'string') texts.push(current.data.text);
    for (const text of texts) {
      const diagnostic = diagnosticFromDenial(firstJsonObject(text));
      if (diagnostic !== undefined) return diagnostic;
    }
    return undefined;
  });
}

function findRpcCode(error) {
  return walkErrors(error, (current) => {
    const direct = boundedRpcCode(current.code);
    if (direct !== undefined) return direct;
    const texts = [];
    if (typeof current.message === 'string') texts.push(current.message);
    if (typeof current.data?.text === 'string') texts.push(current.data.text);
    for (const text of texts) {
      const parsed = firstJsonObject(text);
      if (parsed === undefined || parsed.error === 'downstream_credential_unresolved') continue;
      const nested = boundedRpcCode(parsed.error?.code ?? parsed.code);
      if (nested !== undefined) return nested;
    }
    return undefined;
  });
}

function findHttpStatus(error) {
  return walkErrors(error, (current) => {
    const direct = boundedHttpStatus(current.status);
    if (direct !== undefined) return direct;
    const dataStatus = boundedHttpStatus(current.data?.status);
    if (dataStatus !== undefined) return dataStatus;
    if (typeof current.message === 'string') {
      const match = /HTTP (\d{3})/u.exec(current.message);
      if (match !== null) return boundedHttpStatus(Number(match[1]));
    }
    return undefined;
  });
}

function isTimeout(error) {
  return (
    walkErrors(error, (current) => {
      if (current.name === 'AbortError' || current.name === 'TimeoutError') return true;
      if (current.code === 'REQUEST_TIMEOUT' || current.code === 'ABORT_ERR') return true;
      return undefined;
    }) === true
  );
}

function isMalformed(error) {
  return (
    walkErrors(error, (current) => {
      if (current.name === 'SyntaxError') return true;
      if (current.code === 'CLIENT_HTTP_UNEXPECTED_CONTENT') return true;
      return undefined;
    }) === true
  );
}

export function sanitizeChildDiagnostic(value) {
  if (value === null || typeof value !== 'object') return undefined;
  const stage = DIAGNOSTIC_STAGES.includes(value.stage) ? value.stage : undefined;
  const category = DIAGNOSTIC_CATEGORIES.includes(value.category) ? value.category : undefined;
  if (stage === undefined || category === undefined) return undefined;
  const diagnostic = { stage, category };
  if (value.rpcCode !== undefined) {
    const rpcCode = boundedRpcCode(value.rpcCode);
    if (rpcCode === undefined) return undefined;
    diagnostic.rpcCode = rpcCode;
  }
  if (value.httpStatus !== undefined) {
    const httpStatus = boundedHttpStatus(value.httpStatus);
    if (httpStatus === undefined) return undefined;
    diagnostic.httpStatus = httpStatus;
  }
  return diagnostic;
}

/**
 * Bounded stage and category for a child failure. Numeric RPC and HTTP
 * codes are copied only when they are integers in range. The error message,
 * response body, URL, and stderr are not copied.
 */
export function projectChildFailure(error, stageHint) {
  if (error?.diagnostic?.reason !== undefined) {
    const kept = sanitizeChildDiagnostic(error.diagnostic);
    return {
      reason: safeCode(error.diagnostic.reason),
      ...(kept ?? {}),
    };
  }
  const named =
    typeof error?.code === 'string' && SAFE_CODE.test(error.code) ? error.code : undefined;
  const embedded = embeddedDiagnostic(error);
  const rpcCode = embedded?.rpcCode ?? (embedded === undefined ? findRpcCode(error) : undefined);
  const httpStatus =
    embedded?.httpStatus ?? (embedded === undefined ? findHttpStatus(error) : undefined);
  let category = embedded?.category;
  const stage = embedded?.stage ?? (DIAGNOSTIC_STAGES.includes(stageHint) ? stageHint : undefined);
  if (category === undefined && rpcCode !== undefined) category = categoryForRpc(rpcCode);
  if (category === undefined && httpStatus !== undefined) category = categoryForHttp(httpStatus);
  if (category === undefined && isTimeout(error)) category = 'timeout';
  if (category === undefined && isMalformed(error)) category = 'malformed_response';
  return {
    reason: named ?? 'child_failed',
    ...(stage === undefined ? {} : { stage }),
    ...(category === undefined ? {} : { category }),
    ...(category !== undefined && rpcCode !== undefined ? { rpcCode } : {}),
    ...(category !== undefined && httpStatus !== undefined ? { httpStatus } : {}),
  };
}

function throwProjected(error, stage) {
  const projected = projectChildFailure(error, stage);
  const wrapped = coded(safeCode(projected.reason));
  wrapped.diagnostic = projected;
  throw wrapped;
}

function diagnosticIpc(projected) {
  const safe = sanitizeChildDiagnostic(projected) ?? {};
  return {
    type: 'error',
    code: safeCode(projected?.reason),
    ...safe,
  };
}

export function createExternalPublicPkceProvider(options) {
  let accessToken;
  let tokenIssuer;
  let codeVerifier;
  let pendingState = '';
  let authorizationDiscovered = false;
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
    authorizationDiscovered() {
      return authorizationDiscovered;
    },
    redirectToAuthorization(authorizationUrl) {
      const state = authorizationUrl.searchParams.get('state') ?? '';
      if (state !== oauthState) throw coded('authorization_code_refused');
      pendingState = state;
      authorizationDiscovered = true;
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
      throwProjected(first.error, 'initialize');
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
    throwProjected(second.error, 'initialize');
  }
  const bound = JSON.parse(await options.readIpc());
  assertIpcHasNoSecrets(bound);
  if (bound.type !== 'downstream_bound' || bound.state !== downstream.state) {
    throw coded('downstream_callback_failed');
  }
  const third = await openClient(options.mcpUrl, provider);
  if (third.error !== undefined) {
    await closeOpened(third);
    throwProjected(third.error, 'initialize');
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

function markerText(marker) {
  return Array.isArray(marker?.content)
    ? marker.content.find((block) => block?.type === 'text')?.text
    : undefined;
}

function markerAccepted(marker) {
  const text = markerText(marker);
  return (
    marker?.isError !== true &&
    typeof text === 'string' &&
    text.length > 0 &&
    text.length <= 256 &&
    !JWT_SHAPE.test(text)
  );
}

export async function runExternalClientSession(options) {
  const connected = await connectExternalClient(options);
  let client = connected.client;
  let clientAlive = true;
  let stage = 'list';
  try {
    const listed = await client.listTools();
    stage = 'tool';
    const names = toolNames(listed);
    const marker = await client.callTool({ name: MARKER_TOOL_NAME, arguments: {} });
    const text = markerText(marker);
    const markerCalled = markerAccepted(marker);
    const canaryShapeOk = markerCalled && typeof text === 'string' && CANARY_SHAPE.test(text);
    if (!names.includes(MARKER_TOOL_NAME) || !markerCalled) throw coded('marker_call_failed');
    options.writeIpc(
      assertIpcHasNoSecrets({
        type: 'checkpoint',
        id: 'P5',
        initialized: true,
        discovered: connected.provider.authorizationDiscovered() === true,
        toolsListed: true,
        markerCalled: true,
        canaryShapeOk,
        downstreamBound: true,
        externalAuthorizationCompleted: true,
        toolNames: names,
      }),
    );
    for (;;) {
      const message = JSON.parse(await options.readIpc());
      assertIpcHasNoSecrets(message);
      if (message.type === 'finish') break;
      if (message.type !== 'call_tool_once' || (message.id !== 'N4' && message.id !== 'N5')) {
        throw coded('probe_refused');
      }
      let failed = true;
      if (!clientAlive) {
        const opened = await openClient(options.mcpUrl, connected.provider);
        if (opened.error !== undefined) {
          await closeOpened(opened);
          clientAlive = false;
        } else {
          client = opened.client;
          clientAlive = true;
        }
      }
      if (clientAlive && client !== undefined) {
        try {
          const probe = await client.callTool({ name: MARKER_TOOL_NAME, arguments: {} });
          failed = !markerAccepted(probe);
        } catch {
          failed = true;
          clientAlive = false;
          await client.close().catch(() => undefined);
        }
      }
      options.writeIpc(
        assertIpcHasNoSecrets({
          type: 'tool_call_result',
          id: message.id,
          failed,
        }),
      );
    }
    return assertIpcHasNoSecrets({
      type: 'receipt',
      childEnvNames: credentialEnvNames(options.env ?? {}),
    });
  } catch (error) {
    throwProjected(error, stage);
  } finally {
    await client?.close().catch(() => undefined);
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
    const projected = error?.diagnostic ?? projectChildFailure(error, undefined);
    const code = safeCode(projected.reason);
    try {
      process.stdout.write(
        `${assertIpcHasNoSecrets(diagnosticIpc({ ...projected, reason: code }))}\n`,
      );
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
