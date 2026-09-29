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
  classifyTokenA,
  classifyTokenB,
  dataRowVerdict,
  decodeJwtClaims,
  EXPECTED_ORIGIN,
  INGRESS_ROLE,
  MARKER,
  MCP_RESOURCE,
  plan,
  publishableKeyRejected,
  REALTIME_TOPIC,
  realtimeVerdict,
  SERVICE_ROLE_ENV_NAMES,
  serviceRoleEnvPresent,
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
    roleFlipShipped: false,
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
  return {
    role: typeof claims.role === 'string' ? claims.role : null,
    aud: claims.aud ?? null,
    iss: typeof claims.iss === 'string' ? claims.iss : null,
    sub: typeof claims.sub === 'string' ? claims.sub : null,
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
    const response = await fetchImpl(`${origin}${path}`, {
      method,
      headers,
      body: payload,
      redirect: 'manual',
      signal: AbortSignal.timeout(options.timeoutMs ?? 8000),
    });
    return { status: response.status, body: await readBody(response) };
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

  for (const row of AUTH_ROWS) {
    const result = await call(row.path, row.method, options.tokenA, row.body);
    const verdict = authRowVerdict(result.status, row.mutation);
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
      path: '/rest/v1/ari_probe_marker?select=marker',
      method: 'GET',
    },
    { id: 'L5-graphql', path: '/graphql/v1', method: 'POST', body: GRAPHQL_QUERY },
  ];

  for (const surface of surfaces) {
    const stopped = await runDataSurface(surface, call, rows, options);
    if (stopped !== undefined) return finish(4, stopped);
  }

  requests += 1;
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
  const seededStatus = seededResponse.status;
  await readBody(seededResponse);
  rows.push({
    id: 'L5-storage-token-b-seed-NOT-MCP',
    credential: 'token_b',
    label: 'POSITIVE_CONTROL_NOT_MCP',
    status: seededStatus,
    verdict: seededStatus >= 200 && seededStatus < 300 ? 'seeded' : 'seed_status_recorded',
  });

  const storageStopped = await runDataSurface(
    {
      id: 'L5-storage',
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

  return finish(0, 'matrix_held');
}

async function runDataSurface(surface, call, rows, options) {
  const attempts = [
    ['publishable', undefined],
    ['token_a', options.tokenA],
    ['token_b', options.tokenB],
  ];
  for (const [kind, token] of attempts) {
    const result = await call(surface.path, surface.method, token, surface.body);
    const verdict = dataRowVerdict(kind, result.body);
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
            if (message.event === 'phx_reply') {
              resolve(message.payload?.status === 'ok' ? 'ok' : 'error');
            }
          } catch {
            resolve('error');
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
    return await reply;
  } catch {
    return 'error';
  } finally {
    socket.close();
  }
}

function readEnv(env) {
  return {
    projectRef: env.ARI_TEST_PROJECT_REF,
    supabaseUrl: env.ARI_TEST_SUPABASE_URL ?? EXPECTED_ORIGIN,
    publishableKey: env.ARI_TEST_PUBLISHABLE_KEY,
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
