/**
 * Controller probe for Ari TEST only.
 * Does not install the Auth hook and does not call the MCP tool path.
 * Token B is the synthetic user's own session, used as a positive control.
 */
import { pathToFileURL } from 'node:url';
import {
  ALLOWED_PROJECT_REF,
  assertTarget,
  authRowVerdict,
  classifyRealtimeReply,
  classifyTokenA,
  classifyTokenB,
  dataRowVerdict,
  decodeJwtClaims,
  EXPECTED_ORIGIN,
  INGRESS_ROLE,
  MARKER,
  MCP_RESOURCE,
  matrixBlocked,
  mcpEdgeAcceptance,
  plan,
  publicJwks,
  publishableKeyRejected,
  REALTIME_TOPIC,
  realtimeVerdict,
  SERVICE_ROLE_ENV_NAMES,
  serviceRoleEnvPresent,
  storageSeedVerdict,
  tokenBAuthUserVerdict,
  verifyTokenA,
} from './decisions.mjs';

const AUTH_ROWS = [
  { id: 'L6-auth-get-user', method: 'GET', path: '/auth/v1/user', mutation: false },
  {
    id: 'L6-auth-put-user',
    method: 'PUT',
    path: '/auth/v1/user',
    mutation: true,
    body: { data: { ari_probe: 'must-not-apply' } },
  },
  {
    id: 'L6-auth-post-factors',
    method: 'POST',
    path: '/auth/v1/factors',
    mutation: true,
    body: { factor_type: 'totp', friendly_name: 'ari-probe-must-not-enroll' },
  },
  {
    id: 'L6-auth-post-logout',
    method: 'POST',
    path: '/auth/v1/logout',
    mutation: true,
    body: { scope: 'local' },
  },
];

const GRAPHQL_QUERY = {
  query: 'query { ariProbeMarkerCollection(first: 1) { edges { node { marker } } } }',
};

function receiptBase() {
  return {
    packet: 'ari-test-probe',
    projectRef: ALLOWED_PROJECT_REF,
    ingressRole: INGRESS_ROLE,
    mcpResource: MCP_RESOURCE,
    roleFlipShipped: true,
    hookInstalledByThisPacket: false,
    tokenBLabel: 'POSITIVE_CONTROL_NOT_MCP',
    wiredIntoMcp: false,
    acceptance: false,
    rows: [],
  };
}

function guard(options) {
  const target = assertTarget({
    projectRef: options.projectRef,
    supabaseUrl: options.supabaseUrl,
    allowLoopback: options.allowLoopback === true,
  });
  if (!target.ok) return target;
  const present = serviceRoleEnvPresent(options.env ?? {});
  if (present.length > 0) {
    return {
      ok: false,
      exitCode: 2,
      reason: 'service_role_forbidden_in_probe_shell',
      present: present,
    };
  }
  const publishable = publishableKeyRejected(options.publishableKey);
  if (publishable !== undefined) return { ok: false, exitCode: 2, reason: publishable };
  return { ok: true };
}

async function readBody(response) {
  try {
    return await response.text();
  } catch {
    return '';
  }
}

function summarizeClaims(claims) {
  const text = (key) => (typeof claims[key] === 'string' ? claims[key] : null);
  return {
    role: text('role'),
    aud: claims.aud ?? null,
    iss: text('iss'),
    sub: text('sub'),
    session_id: text('session_id'),
    source_session_id: text('source_session_id'),
    agent_id: text('agent_id'),
    client_id: text('client_id'),
  };
}

export async function runProbe(options) {
  const blocked = guard(options);
  if (!blocked.ok) return { ...receiptBase(), ...blocked, requests: 0 };

  if (options.tokenA === options.tokenB) {
    return { ...receiptBase(), ok: false, exitCode: 3, reason: 'token_a_is_token_b', requests: 0 };
  }

  let claimsA;
  let claimsB;
  try {
    claimsA = decodeJwtClaims(options.tokenA);
    claimsB = decodeJwtClaims(options.tokenB);
  } catch (error) {
    return {
      ...receiptBase(),
      ok: false,
      exitCode: 3,
      reason: error instanceof Error ? error.message : 'jwt_malformed',
      requests: 0,
    };
  }

  const tokenA = classifyTokenA(claimsA);
  const tokenB = classifyTokenB(claimsB);
  if (!tokenA.ok || !tokenB.ok) {
    return {
      ...receiptBase(),
      ok: false,
      exitCode: 3,
      reason: tokenA.ok ? tokenB.reason : tokenA.reason,
      tokenA: summarizeClaims(claimsA),
      tokenB: summarizeClaims(claimsB),
      requests: 0,
    };
  }
  if (tokenA.sub !== tokenB.sub) {
    return {
      ...receiptBase(),
      ok: false,
      exitCode: 3,
      reason: 'subject_mismatch',
      requests: 0,
    };
  }

  const expectedClientId = options.expectedClientId;
  if (typeof expectedClientId !== 'string' || expectedClientId.length === 0) {
    return {
      ...receiptBase(),
      ok: false,
      exitCode: 3,
      reason: 'oauth_client_id_required',
      requests: 0,
    };
  }
  const verified = await verifyTokenA(options.tokenA, options.jwks, expectedClientId);
  if (!verified.ok) {
    return {
      ...receiptBase(),
      ok: false,
      exitCode: 3,
      reason: verified.reason,
      tokenA: summarizeClaims(claimsA),
      requests: 0,
    };
  }

  const edge = options.mcpEdge ?? defaultMcpEdge;
  let edgeResponse;
  try {
    edgeResponse = await edge({
      token: options.tokenA,
      jwks: options.jwks,
      expectedClientId,
      publishableKey: options.publishableKey,
      supabaseUrl: options.supabaseUrl,
    });
  } catch {
    edgeResponse = { status: 0, body: '' };
  }
  const acceptance = mcpEdgeAcceptance(edgeResponse?.status, edgeResponse?.body ?? '');
  if (!acceptance.ok) {
    return {
      ...receiptBase(),
      ok: false,
      exitCode: 4,
      reason: acceptance.reason,
      rows: [
        {
          id: 'L0-token-a-mcp-edge',
          credential: 'token_a',
          status: edgeResponse?.status ?? 0,
          verdict: 'inconclusive',
        },
      ],
      requests: 0,
      tokenA: summarizeClaims(claimsA),
    };
  }

  const fetchImpl = options.fetch ?? globalThis.fetch;
  const rows = [];
  let requests = 0;
  const origin = options.supabaseUrl;

  async function call(path, method, token, body) {
    requests += 1;
    const headers = {
      apikey: options.publishableKey,
      accept: 'application/json',
    };
    if (token !== undefined) headers.authorization = `Bearer ${token}`;
    let payload;
    if (body !== undefined) {
      headers['content-type'] = 'application/json';
      payload = JSON.stringify(body);
    }
    try {
      const response = await fetchImpl(`${origin}${path}`, {
        method,
        headers,
        body: payload,
        redirect: 'manual',
        signal: AbortSignal.timeout(options.timeoutMs ?? 8000),
      });
      return { status: response.status, body: await readBody(response) };
    } catch {
      return { status: 0, body: '' };
    }
  }

  function finish(exitCode, reason) {
    return {
      ...receiptBase(),
      ok: exitCode === 0,
      exitCode,
      reason,
      rows,
      requests,
      tokenA: summarizeClaims(claimsA),
      tokenB: summarizeClaims(claimsB),
    };
  }

  rows.push({
    id: 'L0-token-a-mcp-edge',
    credential: 'token_a',
    status: edgeResponse.status,
    verdict: acceptance.verdict,
  });

  const tokenBUser = await call('/auth/v1/user', 'GET', options.tokenB);
  const tokenBUserVerdict = tokenBAuthUserVerdict(tokenBUser.status, tokenBUser.body, tokenA.sub);
  rows.push({
    id: 'L6-auth-token-b-get-user-NOT-MCP',
    credential: 'token_b',
    label: 'POSITIVE_CONTROL_NOT_MCP',
    status: tokenBUser.status,
    verdict: tokenBUserVerdict.verdict,
  });
  if (tokenBUserVerdict.stop) return finish(4, tokenBUserVerdict.verdict);

  for (const row of AUTH_ROWS) {
    const result = await call(row.path, row.method, options.tokenA, row.body);
    const verdict = authRowVerdict(result.status, row.mutation, result.body);
    rows.push({
      id: row.id,
      credential: 'token_a',
      status: result.status,
      verdict: verdict.verdict,
    });
    if (verdict.stop) return finish(4, verdict.verdict);
  }

  const surfaces = [
    {
      id: 'L5-rest',
      surface: 'rest',
      path: '/rest/v1/ari_probe_marker?select=marker',
      method: 'GET',
    },
    {
      id: 'L5-graphql',
      surface: 'graphql',
      path: '/graphql/v1',
      method: 'POST',
      body: GRAPHQL_QUERY,
    },
  ];

  for (const surface of surfaces) {
    const stopped = await runDataSurface(surface, call, rows, options);
    if (stopped !== undefined) return finish(4, stopped);
  }

  requests += 1;
  let seededStatus = 0;
  let seededBody = '';
  try {
    const seededResponse = await fetchImpl(
      `${origin}/storage/v1/object/ari-probe-synthetic/marker.txt`,
      {
        method: 'POST',
        headers: {
          apikey: options.publishableKey,
          authorization: `Bearer ${options.tokenB}`,
          'content-type': 'text/plain',
          'x-upsert': 'true',
        },
        body: MARKER,
        redirect: 'manual',
        signal: AbortSignal.timeout(options.timeoutMs ?? 8000),
      },
    );
    seededStatus = seededResponse.status;
    seededBody = await readBody(seededResponse);
  } catch {
    seededStatus = 0;
  }
  const seeded = storageSeedVerdict(seededStatus, seededBody);
  rows.push({
    id: 'L5-storage-token-b-seed-NOT-MCP',
    credential: 'token_b',
    label: 'POSITIVE_CONTROL_NOT_MCP',
    status: seededStatus,
    verdict: seeded.verdict,
  });
  if (seeded.stop) return finish(4, seeded.verdict);

  const storageStopped = await runDataSurface(
    {
      id: 'L5-storage',
      surface: 'storage',
      path: '/storage/v1/object/ari-probe-synthetic/marker.txt',
      method: 'GET',
    },
    call,
    rows,
    options,
  );
  if (storageStopped !== undefined) return finish(4, storageStopped);

  const joinRealtime = options.joinRealtime ?? defaultJoinRealtime;
  for (const kind of ['token_a', 'token_b']) {
    const token = kind === 'token_a' ? options.tokenA : options.tokenB;
    const status = await joinRealtime({
      supabaseUrl: origin,
      publishableKey: options.publishableKey,
      token,
      topic: REALTIME_TOPIC,
    });
    requests += 1;
    const verdict = realtimeVerdict(kind, status);
    rows.push({
      id: `L5-realtime-${kind === 'token_a' ? 'token-a' : 'token-b'}`,
      credential: kind,
      label: kind === 'token_b' ? 'POSITIVE_CONTROL_NOT_MCP' : undefined,
      status,
      verdict: verdict.verdict,
    });
    if (verdict.stop) return finish(4, verdict.verdict);
  }

  const blockedRow = matrixBlocked(rows);
  if (blockedRow !== undefined) {
    return finish(4, blockedRow.verdict === 'inconclusive' ? 'inconclusive' : blockedRow.verdict);
  }
  return finish(0, 'matrix_held');
}

async function defaultMcpEdge({ token, jwks, expectedClientId, publishableKey, supabaseUrl }) {
  const moduleUrl = new URL('../../../packages/server/dist/native-user-mcp.js', import.meta.url);
  const { createNativeUserMcpHandler } = await import(moduleUrl.href);
  const loaded = publicJwks(jwks);
  if (!loaded.ok) return { status: 0, body: '' };
  const handler = createNativeUserMcpHandler({
    resourceServer: MCP_RESOURCE,
    supabaseUrl,
    expectedClientId,
    ingressRole: INGRESS_ROLE,
    publishableKey,
    jwks: loaded.jwks,
  });
  const response = await handler(
    new Request(MCP_RESOURCE, {
      method: 'POST',
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
      },
      body: '{"jsonrpc":"2.0","id":1,"method":"initialize"}',
    }),
  );
  return { status: response.status, body: await response.text() };
}

async function runDataSurface(surface, call, rows, options) {
  const attempts = [
    ['publishable', undefined],
    ['token_a', options.tokenA],
    ['token_b', options.tokenB],
  ];
  for (const [kind, token] of attempts) {
    const result = await call(surface.path, surface.method, token, surface.body);
    const verdict = dataRowVerdict(surface.surface, kind, result.status, result.body);
    rows.push({
      id: `${surface.id}-${kind}`,
      credential: kind,
      label: kind === 'token_b' ? 'POSITIVE_CONTROL_NOT_MCP' : undefined,
      status: result.status,
      verdict: verdict.verdict,
    });
    if (verdict.stop) return verdict.verdict;
  }
  return undefined;
}

async function defaultJoinRealtime({ supabaseUrl, publishableKey, token, topic }) {
  const url = new URL(supabaseUrl);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  url.pathname = '/realtime/v1/websocket';
  url.search = `apikey=${encodeURIComponent(publishableKey)}&vsn=1.0.0`;
  const socket = new WebSocket(url);
  const timeout = AbortSignal.timeout(8000);
  try {
    await new Promise((resolve, reject) => {
      socket.addEventListener('open', resolve, { once: true });
      socket.addEventListener('error', () => reject(new Error('realtime_socket')), { once: true });
      timeout.addEventListener('abort', () => reject(new Error('realtime_timeout')), {
        once: true,
      });
    });
    const reply = new Promise((resolve, reject) => {
      socket.addEventListener(
        'message',
        (event) => {
          try {
            const message = JSON.parse(String(event.data));
            if (message.event === 'phx_reply') resolve(message);
          } catch {
            resolve(null);
          }
        },
        { once: true },
      );
      timeout.addEventListener('abort', () => reject(new Error('realtime_timeout')), {
        once: true,
      });
    });
    socket.send(
      JSON.stringify({
        topic: `realtime:${topic}`,
        event: 'phx_join',
        payload: {
          config: { private: true },
          access_token: token,
        },
        ref: '1',
        join_ref: '1',
      }),
    );
    const replyStatus = await reply;
    return classifyRealtimeReply(replyStatus);
  } catch {
    return 'transport';
  } finally {
    socket.close();
  }
}

function readEnv(env) {
  return {
    projectRef: env.ARI_TEST_PROJECT_REF,
    supabaseUrl: env.ARI_TEST_SUPABASE_URL ?? EXPECTED_ORIGIN,
    publishableKey: env.ARI_TEST_PUBLISHABLE_KEY,
    expectedClientId: env.ARI_TEST_EXPECTED_CLIENT_ID,
    jwks: env.ARI_TEST_JWKS_JSON,
    tokenA: env.ARI_TEST_TOKEN_A,
    tokenB: env.ARI_TEST_TOKEN_B,
    env,
    allowLoopback: env.ARI_TEST_ALLOW_LOOPBACK === '1',
  };
}

async function main() {
  const command = process.argv[2] ?? 'plan';
  if (command === 'plan') {
    process.stdout.write(`${JSON.stringify(plan(), null, 2)}\n`);
    return;
  }
  if (command !== 'run') {
    process.stderr.write('usage: node docs/evidence/ari-test-probe/probe.mjs [plan|run]\n');
    process.exitCode = 2;
    return;
  }
  const result = await runProbe(readEnv(process.env));
  const text = JSON.stringify(result);
  for (const name of SERVICE_ROLE_ENV_NAMES) {
    const secret = process.env[name];
    if (secret !== undefined && secret.length > 0 && text.includes(secret)) {
      process.stderr.write('probe output included a forbidden secret\n');
      process.exitCode = 2;
      return;
    }
  }
  if (
    (process.env.ARI_TEST_TOKEN_A && text.includes(process.env.ARI_TEST_TOKEN_A)) ||
    (process.env.ARI_TEST_TOKEN_B && text.includes(process.env.ARI_TEST_TOKEN_B)) ||
    (process.env.ARI_TEST_PUBLISHABLE_KEY && text.includes(process.env.ARI_TEST_PUBLISHABLE_KEY))
  ) {
    process.stderr.write('probe output included a credential\n');
    process.exitCode = 2;
    return;
  }
  process.stdout.write(`${text}\n`);
  process.exitCode = result.exitCode ?? 4;
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(invokedPath).href) {
  main();
}
