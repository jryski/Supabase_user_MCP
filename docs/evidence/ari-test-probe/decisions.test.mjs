import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import {
  ALLOWED_PROJECT_REF,
  assertTarget,
  authErrorCode,
  authRowVerdict,
  classifyRealtimeReply,
  classifyTokenA,
  classifyTokenB,
  dataRowVerdict,
  EXPECTED_CLIENT_ID,
  FORBIDDEN_PROJECT_REFS,
  GRAPHQL_COLLECTION,
  graphqlPrerequisiteMissing,
  INGRESS_ROLE,
  isJoinPhxReply,
  MARKER,
  MCP_EDGE_ACCEPTANCE,
  MCP_RESOURCE,
  plan,
  realtimeDiagnostic,
  realtimeVerdict,
  scrubRealtimeReason,
  storageSeedVerdict,
} from './decisions.mjs';
import { readJoinReply, runProbe } from './probe.mjs';

const SUBJECT = '11111111-1111-4111-8111-111111111111';
const SESSION = '22222222-2222-4222-8222-222222222222';
const ISSUER = `https://${ALLOWED_PROJECT_REF}.supabase.co/auth/v1`;
const REST_DENY = JSON.stringify({ code: '42501', message: 'permission denied' });
const AUTH_DENY = JSON.stringify({ error_code: 'session_not_found', msg: 'session not found' });
const GRAPHQL_DENY = JSON.stringify({ data: {} });
const GRAPHQL_OK = JSON.stringify({
  data: { [GRAPHQL_COLLECTION]: { edges: [{ node: { marker: MARKER } }] } },
});
const REST_OK = JSON.stringify([{ marker: MARKER }]);

function unsignedJwt(claims) {
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  return `eyJhbGciOiJFUzI1NiJ9.${payload}.c2ln`;
}

function tokenBClaims(extra = {}) {
  return {
    iss: ISSUER,
    sub: SUBJECT,
    role: 'authenticated',
    aud: 'authenticated',
    ...extra,
  };
}

async function keyMaterial() {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  return {
    privateKey,
    jwks: { keys: [{ ...jwk, kid: 'ari-probe', alg: 'ES256', use: 'sig' }] },
  };
}

async function sign(
  privateKey,
  { role, audience, clientId = EXPECTED_CLIENT_ID, expiresIn = '2m' },
) {
  return new SignJWT({ role, client_id: clientId, session_id: SESSION })
    .setProtectedHeader({ alg: 'ES256', kid: 'ari-probe', typ: 'JWT' })
    .setSubject(SUBJECT)
    .setIssuer(ISSUER)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .sign(privateKey);
}

function acceptingEdge() {
  return async () => ({
    status: 403,
    body: JSON.stringify({ error: MCP_EDGE_ACCEPTANCE }),
  });
}

async function readyProbe(overrides = {}) {
  const { privateKey, jwks } = await keyMaterial();
  const tokenA = await sign(privateKey, { role: INGRESS_ROLE, audience: MCP_RESOURCE });
  const tokenB = unsignedJwt(tokenBClaims());
  return {
    projectRef: ALLOWED_PROJECT_REF,
    supabaseUrl: `https://${ALLOWED_PROJECT_REF}.supabase.co`,
    publishableKey: 'sb_publishable_test_only',
    expectedClientId: EXPECTED_CLIENT_ID,
    env: {},
    mcpEdge: acceptingEdge(),
    fetch: async () => {
      throw new Error('unexpected_fetch');
    },
    joinRealtime: async () => 'transport',
    ...overrides,
    tokenA: overrides.tokenA ?? tokenA,
    tokenB: overrides.tokenB ?? tokenB,
    jwks: overrides.jwks ?? jwks,
  };
}

function userResponse(id) {
  return new Response(JSON.stringify({ id }), { status: 200 });
}

test('refuses the production alias and any other project ref', () => {
  const forbidden = FORBIDDEN_PROJECT_REFS[0];
  assert.equal(
    assertTarget({ projectRef: forbidden, supabaseUrl: 'https://example.test' }).reason,
    'forbidden_target',
  );
  assert.equal(
    assertTarget({
      projectRef: ALLOWED_PROJECT_REF,
      supabaseUrl: `https://${forbidden}.supabase.co`,
    }).reason,
    'forbidden_target',
  );
});

test('Token A eligibility ignores user_metadata and rejects role=authenticated', () => {
  const ignored = classifyTokenA({
    iss: ISSUER,
    sub: SUBJECT,
    role: INGRESS_ROLE,
    aud: MCP_RESOURCE,
    user_metadata: { role: 'authenticated', client_id: 'forged' },
  });
  assert.equal(ignored.ok, true);
  assert.equal(
    classifyTokenA({
      iss: ISSUER,
      sub: SUBJECT,
      role: 'authenticated',
      aud: MCP_RESOURCE,
    }).reason,
    'role_flip_prerequisite_missing',
  );
  assert.equal(classifyTokenB(tokenBClaims()).label, 'POSITIVE_CONTROL_NOT_MCP');
  assert.equal(classifyTokenB(tokenBClaims()).wiredIntoMcp, false);
});

test('does not send a role=authenticated bearer as Token A', async () => {
  let calls = 0;
  const result = await runProbe(
    await readyProbe({
      tokenA: unsignedJwt({
        iss: ISSUER,
        sub: SUBJECT,
        role: 'authenticated',
        aud: MCP_RESOURCE,
      }),
      fetch: async () => {
        calls += 1;
        return new Response('', { status: 401 });
      },
    }),
  );
  assert.equal(result.exitCode, 3);
  assert.equal(result.reason, 'role_flip_prerequisite_missing');
  assert.equal(calls, 0);
});

test('malformed and expired Token A cannot become matrix_held', async () => {
  let calls = 0;
  const fetch = async () => {
    calls += 1;
    return new Response('', { status: 401 });
  };
  const malformed = await runProbe(
    await readyProbe({
      tokenA: unsignedJwt({
        iss: ISSUER,
        sub: SUBJECT,
        role: INGRESS_ROLE,
        aud: MCP_RESOURCE,
        client_id: EXPECTED_CLIENT_ID,
        session_id: SESSION,
      }),
      fetch,
    }),
  );
  assert.equal(malformed.exitCode, 3);
  assert.equal(malformed.reason, 'token_a_signature');
  assert.notEqual(malformed.reason, 'matrix_held');
  assert.equal(calls, 0);

  const { privateKey, jwks } = await keyMaterial();
  const expired = await sign(privateKey, {
    role: INGRESS_ROLE,
    audience: MCP_RESOURCE,
    expiresIn: '-2m',
  });
  const expiredResult = await runProbe(await readyProbe({ tokenA: expired, jwks, fetch }));
  assert.equal(expiredResult.exitCode, 3);
  assert.equal(expiredResult.reason, 'token_a_expired');
  assert.equal(calls, 0);
});

test('503 auth responses and realtime transport are not a pass', async () => {
  const seen = [];
  const probe = await readyProbe();
  const result = await runProbe(
    await readyProbe({
      tokenA: probe.tokenA,
      tokenB: probe.tokenB,
      jwks: probe.jwks,
      fetch: async (url, init) => {
        const path = new URL(url).pathname;
        seen.push(`${init.method} ${path}`);
        const token = init.headers.authorization ?? '';
        const tokenB = token.includes(probe.tokenB);
        if (path === '/auth/v1/user' && init.method === 'GET' && tokenB)
          return userResponse(SUBJECT);
        if (path.startsWith('/auth/')) return new Response('unavailable', { status: 503 });
        if (path === '/rest/v1/ari_probe_marker') {
          if (!token) return new Response('[]', { status: 200 });
          if (tokenB) return new Response(REST_OK, { status: 200 });
          return new Response(REST_DENY, { status: 403 });
        }
        if (path === '/graphql/v1') {
          if (!token)
            return new Response(
              `{"errors":[{"message":"Unknown field \\"${GRAPHQL_COLLECTION}\\" on type \\"Query\\"."}]}`,
              { status: 200 },
            );
          if (tokenB) return new Response(GRAPHQL_OK, { status: 200 });
          return new Response(GRAPHQL_DENY, { status: 200 });
        }
        if (path.startsWith('/storage/') && init.method === 'POST') {
          return new Response('', { status: 200 });
        }
        if (path.startsWith('/storage/')) {
          if (tokenB) return new Response(MARKER, { status: 200 });
          return new Response('{"error":"not_found"}', { status: 404 });
        }
        return new Response('', { status: 500 });
      },
      joinRealtime: async ({ token }) => (token === probe.tokenB ? 'ok' : 'transport'),
    }),
  );
  assert.notEqual(result.exitCode, 0);
  assert.notEqual(result.reason, 'matrix_held');
  for (const path of ['/auth/v1/user', '/auth/v1/factors', '/auth/v1/logout']) {
    assert.equal(
      seen.some((entry) => entry.endsWith(path)),
      true,
    );
  }
  assert.equal(
    result.rows.filter((row) => row.credential === 'token_a' && row.status === 503).length,
    4,
  );
  const realtime = result.rows.find((row) => row.id === 'L5-realtime-token-a');
  assert.equal(realtime.verdict, 'realtime_transport');
  assert.notEqual(realtime.verdict, 'deny');
  assert.equal(realtimeVerdict('token_a', 'transport').verdict, 'realtime_transport');
  assert.equal(realtimeVerdict('token_a', 'denied').verdict, 'deny');
  assert.notEqual(realtimeVerdict('token_a', 'transport').verdict, 'deny');
  assert.equal(authRowVerdict(503, false).verdict, 'inconclusive');
  assert.equal(authRowVerdict(429, true).verdict, 'inconclusive');
  assert.equal(authRowVerdict(302, true).verdict, 'inconclusive');
  assert.equal(authRowVerdict(403, false, AUTH_DENY).verdict, 'deny');
  assert.equal(authRowVerdict(403, false, '{}').verdict, 'inconclusive');
  assert.notEqual(authRowVerdict(401, true, REST_DENY).verdict, 'deny');
});

test('graphql prerequisite and realtime transport are not deny', async () => {
  const planned = plan();
  assert.equal(planned.graphqlPositivePrerequisite, 'pg_graphql');
  assert.equal(planned.realtimeTokenATransport, 'realtime_transport');
  assert.match(planned.rows.join('\n'), /does not enable it/);
  const missing = JSON.stringify({
    errors: [{ message: 'extension "pg_graphql" is not installed' }],
  });
  assert.equal(graphqlPrerequisiteMissing(missing), true);
  assert.equal(graphqlPrerequisiteMissing(GRAPHQL_OK), false);
  const tokenBMissing = dataRowVerdict('graphql', 'token_b', 200, missing);
  assert.equal(tokenBMissing.verdict, 'graphql_prerequisite_missing');
  assert.equal(tokenBMissing.stop, true);
  assert.notEqual(tokenBMissing.verdict, 'deny');
  assert.notEqual(tokenBMissing.verdict, 'positive_control');
  assert.notEqual(tokenBMissing.verdict, 'inconclusive');
  const tokenAMissing = dataRowVerdict('graphql', 'token_a', 200, missing);
  assert.equal(tokenAMissing.verdict, 'graphql_prerequisite_missing');
  assert.notEqual(tokenAMissing.verdict, 'deny');
  assert.equal(dataRowVerdict('graphql', 'token_b', 200, GRAPHQL_OK).verdict, 'positive_control');

  const probe = await readyProbe();
  const heldExcept = async (override, joinRealtime) =>
    runProbe(
      await readyProbe({
        tokenA: probe.tokenA,
        tokenB: probe.tokenB,
        jwks: probe.jwks,
        joinRealtime,
        fetch: async (url, init) => {
          const path = new URL(url).pathname;
          const token = init.headers.authorization ?? '';
          const tokenB = token.includes(probe.tokenB);
          const kind = token.length === 0 ? 'publishable' : tokenB ? 'token_b' : 'token_a';
          const replaced = override(path, kind);
          if (replaced !== undefined) return replaced;
          if (path === '/auth/v1/user' && init.method === 'GET' && tokenB)
            return userResponse(SUBJECT);
          if (path.startsWith('/auth/')) return new Response(AUTH_DENY, { status: 403 });
          if (path === '/rest/v1/ari_probe_marker') {
            if (!token) return new Response('[]', { status: 200 });
            if (tokenB) return new Response(REST_OK, { status: 200 });
            return new Response(REST_DENY, { status: 401 });
          }
          if (path === '/graphql/v1') {
            if (!token) return new Response('{"data":{}}', { status: 200 });
            if (tokenB) return new Response(GRAPHQL_OK, { status: 200 });
            return new Response(GRAPHQL_DENY, { status: 200 });
          }
          if (init.method === 'POST') return new Response('', { status: 200 });
          if (tokenB) return new Response(MARKER, { status: 200 });
          return new Response('missing', { status: 404 });
        },
      }),
    );

  const graphql = await heldExcept(
    (path, kind) =>
      path === '/graphql/v1' && kind === 'token_b'
        ? new Response(missing, { status: 200 })
        : undefined,
    async ({ token }) => (token === probe.tokenB ? 'ok' : 'denied'),
  );
  assert.equal(graphql.exitCode, 4);
  assert.equal(graphql.reason, 'graphql_prerequisite_missing');
  assert.notEqual(graphql.reason, 'matrix_held');
  assert.notEqual(graphql.reason, 'deny');
  const graphqlRow = graphql.rows.find((row) => row.id === 'L5-graphql-token_b');
  assert.equal(graphqlRow.verdict, 'graphql_prerequisite_missing');
  assert.equal(graphqlRow.status, 200);

  const transport = await heldExcept(
    () => undefined,
    async ({ token }) => (token === probe.tokenB ? 'ok' : 'transport'),
  );
  assert.equal(transport.exitCode, 4);
  assert.equal(transport.reason, 'realtime_transport');
  assert.notEqual(transport.reason, 'deny');
  assert.notEqual(transport.reason, 'matrix_held');
  const transportRow = transport.rows.find((row) => row.id === 'L5-realtime-token-a');
  assert.equal(transportRow.status, 'transport');
  assert.equal(transportRow.verdict, 'realtime_transport');
});

test('stops on the first Token A mutation success', async () => {
  const seen = [];
  const probe = await readyProbe();
  const result = await runProbe(
    await readyProbe({
      tokenA: probe.tokenA,
      jwks: probe.jwks,
      fetch: async (url, init) => {
        seen.push(`${init.method} ${new URL(url).pathname}`);
        const tokenB = (init.headers.authorization ?? '').includes(probe.tokenB);
        if (tokenB && init.method === 'GET') return userResponse(SUBJECT);
        if (init.method === 'PUT') return new Response('{}', { status: 200 });
        return new Response('{}', { status: 401 });
      },
    }),
  );
  assert.equal(result.exitCode, 4);
  assert.equal(result.reason, 'NO_GO_TOKEN_A_MUTATION');
  assert.equal(seen.includes('POST /auth/v1/factors'), false);
  assert.equal(seen.includes('POST /auth/v1/logout'), false);
});

test('holds only explicit denials plus status-and-body positive controls', async () => {
  const probe = await readyProbe();
  const result = await runProbe(
    await readyProbe({
      tokenA: probe.tokenA,
      tokenB: probe.tokenB,
      jwks: probe.jwks,
      fetch: async (url, init) => {
        const path = new URL(url).pathname;
        const token = init.headers.authorization ?? '';
        const tokenB = token.includes(probe.tokenB);
        if (path === '/auth/v1/user' && init.method === 'GET' && tokenB)
          return userResponse(SUBJECT);
        if (path.startsWith('/auth/')) return new Response(AUTH_DENY, { status: 403 });
        if (path === '/rest/v1/ari_probe_marker') {
          if (!token) return new Response('[]', { status: 200 });
          if (tokenB) return new Response(REST_OK, { status: 200 });
          return new Response(REST_DENY, { status: 401 });
        }
        if (path === '/graphql/v1') {
          if (!token) return new Response('{"data":{}}', { status: 200 });
          if (tokenB) return new Response(GRAPHQL_OK, { status: 200 });
          return new Response(GRAPHQL_DENY, { status: 200 });
        }
        if (init.method === 'POST') return new Response('', { status: 200 });
        if (tokenB) return new Response(MARKER, { status: 200 });
        return new Response('missing', { status: 404 });
      },
      joinRealtime: async ({ token }) => (token === probe.tokenB ? 'ok' : 'denied'),
    }),
  );
  assert.equal(result.exitCode, 0);
  assert.equal(result.reason, 'matrix_held');
  const authRow = result.rows.find((row) => row.id === 'L6-auth-get-user');
  assert.equal(authRow.error_code, 'session_not_found');
  assert.equal(authRow.verdict, 'deny');
  assert.equal(result.wiredIntoMcp, false);
  assert.equal(result.roleFlipShipped, true);
  assert.equal(result.hookInstalledByThisPacket, false);
  assert.equal(result.acceptance, false);
  const encoded = JSON.stringify(result);
  assert.equal(encoded.includes(probe.tokenA), false);
  assert.equal(encoded.includes(probe.tokenB), false);
  assert.equal(
    dataRowVerdict('rest', 'token_a', 401, JSON.stringify({ code: 'PGRST301' })).verdict,
    'inconclusive',
  );
  assert.equal(dataRowVerdict('rest', 'token_b', 200, 'ok').verdict, 'inconclusive');
  assert.equal(dataRowVerdict('storage', 'token_a', 401, 'no').verdict, 'inconclusive');
  assert.equal(dataRowVerdict('storage', 'token_a', 404, 'missing').verdict, 'deny');
});

test('Warden falsifiers never produce matrix_held', async () => {
  const roleQuoted = JSON.stringify({
    code: '22023',
    message: 'role "mcp_ingress" does not exist',
  });
  const roleEllipsis = JSON.stringify({
    error: 'DatabaseError',
    message: 'role … does not exist',
  });
  const badRequest = JSON.stringify({ message: 'bad request' });
  assert.equal(
    dataRowVerdict('graphql', 'token_a', 400, roleQuoted).verdict,
    'ingress_role_missing',
  );
  assert.notEqual(dataRowVerdict('graphql', 'token_a', 400, roleQuoted).verdict, 'deny');
  assert.equal(dataRowVerdict('graphql', 'token_a', 401, badRequest).verdict, 'inconclusive');
  assert.equal(
    dataRowVerdict('storage', 'token_a', 400, roleEllipsis).verdict,
    'ingress_role_missing',
  );
  assert.equal(dataRowVerdict('storage', 'token_a', 400, badRequest).verdict, 'inconclusive');
  assert.equal(dataRowVerdict('rest', 'token_a', 400, roleQuoted).verdict, 'inconclusive');
  assert.notEqual(dataRowVerdict('rest', 'token_a', 400, roleQuoted).verdict, 'deny');
  assert.notEqual(storageSeedVerdict(400).verdict, 'seeded');
  assert.equal(storageSeedVerdict(400).verdict, 'inconclusive');
  assert.equal(dataRowVerdict('graphql', 'token_a', 200, '{}').verdict, 'inconclusive');
  assert.equal(
    dataRowVerdict(
      'graphql',
      'token_a',
      200,
      JSON.stringify({ errors: [{ message: 'Unknown field "ariProbeMarkerCollection"' }] }),
    ).verdict,
    'inconclusive',
  );
  assert.equal(
    dataRowVerdict(
      'graphql',
      'token_a',
      200,
      JSON.stringify({
        errors: [{ message: `Unknown field "${GRAPHQL_COLLECTION}" on type "Query".` }],
      }),
    ).verdict,
    'deny',
  );

  const probe = await readyProbe();
  async function runCase(override) {
    return runProbe(
      await readyProbe({
        tokenA: probe.tokenA,
        tokenB: probe.tokenB,
        jwks: probe.jwks,
        joinRealtime: async ({ token }) => (token === probe.tokenB ? 'ok' : 'denied'),
        fetch: async (url, init) => {
          const path = new URL(url).pathname;
          const header = init.headers.authorization ?? '';
          const tokenB = header.includes(probe.tokenB);
          const kind = header.length === 0 ? 'publishable' : tokenB ? 'token_b' : 'token_a';
          const replaced = override(path, init.method, kind);
          if (replaced !== undefined) return replaced;
          if (path === '/auth/v1/user' && init.method === 'GET' && tokenB)
            return userResponse(SUBJECT);
          if (path.startsWith('/auth/')) return new Response(AUTH_DENY, { status: 403 });
          if (path === '/rest/v1/ari_probe_marker') {
            if (kind === 'publishable') return new Response('[]', { status: 200 });
            if (kind === 'token_b') return new Response(REST_OK, { status: 200 });
            return new Response(REST_DENY, { status: 401 });
          }
          if (path === '/graphql/v1') {
            if (kind === 'publishable')
              return new Response(
                JSON.stringify({
                  errors: [{ message: `Unknown field "${GRAPHQL_COLLECTION}" on type "Query".` }],
                }),
                { status: 200 },
              );
            if (kind === 'token_b') return new Response(GRAPHQL_OK, { status: 200 });
            return new Response(GRAPHQL_DENY, { status: 200 });
          }
          if (init.method === 'POST') return new Response('', { status: 200 });
          if (kind === 'token_b') return new Response(MARKER, { status: 200 });
          return new Response('missing', { status: 404 });
        },
      }),
    );
  }

  const cases = [
    {
      reason: 'ingress_role_missing',
      id: 'L5-graphql-token_a',
      override: (path, _method, kind) =>
        path === '/graphql/v1' && kind === 'token_a'
          ? new Response(roleQuoted, { status: 400 })
          : undefined,
    },
    {
      reason: 'inconclusive',
      id: 'L5-graphql-token_a',
      override: (path, _method, kind) =>
        path === '/graphql/v1' && kind === 'token_a'
          ? new Response(badRequest, { status: 401 })
          : undefined,
    },
    {
      reason: 'ingress_role_missing',
      id: 'L5-storage-token_a',
      override: (path, method, kind) =>
        path.startsWith('/storage/') && method === 'GET' && kind === 'token_a'
          ? new Response(roleEllipsis, { status: 400 })
          : undefined,
    },
    {
      reason: 'inconclusive',
      id: 'L5-storage-token_a',
      override: (path, method, kind) =>
        path.startsWith('/storage/') && method === 'GET' && kind === 'token_a'
          ? new Response(badRequest, { status: 400 })
          : undefined,
    },
    {
      reason: 'inconclusive',
      id: 'L5-rest-token_a',
      override: (path, _method, kind) =>
        path === '/rest/v1/ari_probe_marker' && kind === 'token_a'
          ? new Response(roleQuoted, { status: 400 })
          : undefined,
    },
    {
      reason: 'inconclusive',
      id: 'L5-storage-token-b-seed-NOT-MCP',
      override: (path, method) =>
        path.startsWith('/storage/') && method === 'POST'
          ? new Response(badRequest, { status: 400 })
          : undefined,
    },
  ];
  for (const item of cases) {
    const result = await runCase(item.override);
    assert.notEqual(result.exitCode, 0);
    assert.notEqual(result.reason, 'matrix_held');
    assert.equal(result.reason, item.reason);
    assert.equal(
      result.rows.find((row) => row.id === item.id)?.verdict,
      item.reason === 'ingress_role_missing' ? 'ingress_role_missing' : 'inconclusive',
    );
    assert.notEqual(result.rows.find((row) => row.id === item.id)?.verdict, 'deny');
    assert.notEqual(result.rows.find((row) => row.id === item.id)?.verdict, 'seeded');
  }
});

test('built MCP edge accepts mcp_ingress Token A and does not use the network', async () => {
  const probe = await readyProbe();
  const calls = [];
  const original = globalThis.fetch;
  globalThis.fetch = async (input) => {
    calls.push(typeof input === 'string' ? input : input.url);
    throw new Error('network_forbidden');
  };
  try {
    const result = await runProbe(
      await readyProbe({
        tokenA: probe.tokenA,
        tokenB: probe.tokenB,
        jwks: probe.jwks,
        mcpEdge: undefined,
        fetch: async (url, init) => {
          const path = new URL(url).pathname;
          const token = init.headers.authorization ?? '';
          const tokenB = token.includes(probe.tokenB);
          if (path === '/auth/v1/user' && init.method === 'GET' && tokenB)
            return userResponse(SUBJECT);
          if (path.startsWith('/auth/')) return new Response(AUTH_DENY, { status: 403 });
          if (path === '/rest/v1/ari_probe_marker') {
            if (!token) return new Response('[]', { status: 200 });
            if (tokenB) return new Response(REST_OK, { status: 200 });
            return new Response(REST_DENY, { status: 401 });
          }
          if (path === '/graphql/v1') {
            if (!token) return new Response('{"data":{}}', { status: 200 });
            if (tokenB) return new Response(GRAPHQL_OK, { status: 200 });
            return new Response(GRAPHQL_DENY, { status: 200 });
          }
          if (init.method === 'POST') return new Response('', { status: 200 });
          if (tokenB) return new Response(MARKER, { status: 200 });
          return new Response('missing', { status: 404 });
        },
        joinRealtime: async ({ token }) => (token === probe.tokenB ? 'ok' : 'denied'),
      }),
    );
    assert.equal(result.exitCode, 0);
    assert.equal(result.reason, 'matrix_held');
    assert.equal(result.roleFlipShipped, true);
    assert.equal(result.hookInstalledByThisPacket, false);
    assert.equal(result.acceptance, false);
    const edge = result.rows.find((row) => row.id === 'L0-token-a-mcp-edge');
    assert.equal(edge.status, 403);
    assert.equal(edge.verdict, 'mcp_edge_accepted_fail_closed');
    assert.equal(calls.length, 0);
  } finally {
    globalThis.fetch = original;
  }
});

test('does not substitute a client id when the registered id is omitted', async () => {
  let calls = 0;
  const probe = await readyProbe();
  const result = await runProbe(
    await readyProbe({
      tokenA: probe.tokenA,
      jwks: probe.jwks,
      expectedClientId: undefined,
      fetch: async () => {
        calls += 1;
        return new Response('', { status: 401 });
      },
    }),
  );
  assert.equal(result.exitCode, 3);
  assert.equal(result.reason, 'oauth_client_id_required');
  assert.equal(calls, 0);
  assert.equal(JSON.stringify(result).includes(EXPECTED_CLIENT_ID), false);
});

test('mcp_ingress role SQL stays isolated and forbids production targets', async () => {
  const sql = await readFile(new URL('./sql/03-mcp-ingress-role.sql', import.meta.url), 'utf8');
  assert.match(sql, /create role mcp_ingress/);
  assert.match(sql, /nologin/);
  assert.match(sql, /noinherit/);
  assert.match(sql, /nosuperuser/);
  assert.match(sql, /nobypassrls/);
  assert.match(sql, /grant mcp_ingress to authenticator with admin false, inherit false, set true/);
  assert.match(
    sql,
    /mcp_ingress is not granted to authenticator with admin false, inherit false, and set true/,
  );
  assert.match(sql, /mcp_ingress has an outbound membership/);
  assert.equal(/^\s*revoke\b/imu.test(sql), false);
  assert.equal(/^\s*alter\s+role\b/imu.test(sql), false);
  assert.match(sql, /creator row lets it grant membership, not act as mcp_ingress/);
  assert.match(sql, /mcp_ingress is a member of authenticated, anon, or service_role/);
  assert.match(sql, /mcp_ingress has table grants/);
  assert.match(sql, /lygftpbjgqgvuunkwnxf/);
  assert.match(sql, /HOUSE, VAULT, or production/);
  assert.match(sql, /ari\.project_ref/);
  assert.match(sql, /one SQL-editor batch/);
  assert.match(sql, /ari-probe-synthetic@odbcejsuuqdzhabjmozi\.invalid/);
  assert.match(sql, /expected exactly one throwaway user/);
  assert.equal(sql.includes('ari-probe-synthetic-client'), false);
  assert.match(sql, /do not apply/i);
  assert.match(sql, /sql\/02-hook-for-ariadne\.sql/);
});

test('graphql uses the literal collection and ignores the camelCase field', async () => {
  const source = await readFile(new URL('./probe.mjs', import.meta.url), 'utf8');
  assert.match(source, /query \{ ari_probe_markerCollection\(first: 1\)/);
  assert.equal(source.includes('ariProbeMarkerCollection'), false);
  assert.equal(GRAPHQL_COLLECTION, 'ari_probe_markerCollection');
  const camel = JSON.stringify({
    data: { ariProbeMarkerCollection: { edges: [{ node: { marker: MARKER } }] } },
  });
  const unknownPublishable = JSON.stringify({
    errors: [{ message: `Unknown field "${GRAPHQL_COLLECTION}" on type "Query".` }],
  });
  assert.equal(dataRowVerdict('graphql', 'token_b', 200, GRAPHQL_OK).verdict, 'positive_control');
  assert.equal(dataRowVerdict('graphql', 'token_b', 200, camel).verdict, 'positive_control_missed');
  assert.equal(
    dataRowVerdict('graphql', 'publishable', 200, unknownPublishable).verdict,
    'no_marker',
  );
  assert.equal(unknownPublishable.includes(MARKER), false);
  const probe = await readyProbe();
  let graphqlQuery = '';
  const result = await runProbe(
    await readyProbe({
      tokenA: probe.tokenA,
      tokenB: probe.tokenB,
      jwks: probe.jwks,
      fetch: async (url, init) => {
        const path = new URL(url).pathname;
        if (path === '/graphql/v1') graphqlQuery = init.body;
        const token = init.headers.authorization ?? '';
        const tokenB = token.includes(probe.tokenB);
        if (path === '/auth/v1/user' && init.method === 'GET' && tokenB)
          return userResponse(SUBJECT);
        if (path.startsWith('/auth/')) return new Response(AUTH_DENY, { status: 403 });
        if (path === '/rest/v1/ari_probe_marker') {
          if (!token) return new Response('[]', { status: 200 });
          if (tokenB) return new Response(REST_OK, { status: 200 });
          return new Response(REST_DENY, { status: 401 });
        }
        if (path === '/graphql/v1') {
          if (!token) return new Response(unknownPublishable, { status: 200 });
          if (tokenB) return new Response(GRAPHQL_OK, { status: 200 });
          return new Response(GRAPHQL_DENY, { status: 200 });
        }
        if (init.method === 'POST') return new Response('', { status: 200 });
        if (tokenB) return new Response(MARKER, { status: 200 });
        return new Response('missing', { status: 404 });
      },
      joinRealtime: async ({ token }) => (token === probe.tokenB ? 'ok' : 'denied'),
    }),
  );
  assert.equal(result.reason, 'matrix_held');
  assert.match(graphqlQuery, /ari_probe_markerCollection/);
  assert.equal(graphqlQuery.includes('ariProbeMarkerCollection'), false);
  const tokenBRow = result.rows.find((row) => row.id === 'L5-graphql-token_b');
  assert.equal(tokenBRow.verdict, 'positive_control');
  const publishable = result.rows.find((row) => row.id === 'L5-graphql-publishable');
  assert.equal(publishable.verdict, 'no_marker');
});

test('auth rows record session_not_found and ignore status alone', () => {
  const body = JSON.stringify({
    error_code: 'session_not_found',
    msg: 'session not found',
    access_token: 'must-not-record-this-token',
  });
  const held = authRowVerdict(403, false, body);
  assert.equal(held.verdict, 'deny');
  assert.equal(held.errorCode, 'session_not_found');
  assert.equal(authErrorCode(body), 'session_not_found');
  assert.equal(JSON.stringify(held).includes('must-not-record-this-token'), false);
  assert.equal(
    authRowVerdict(401, true, JSON.stringify({ error: 'session_not_found' })).verdict,
    'deny',
  );
  assert.equal(
    authRowVerdict(403, false, '{"error_code":"invalid_grant"}').verdict,
    'inconclusive',
  );
  assert.equal(authRowVerdict(400, false, body).verdict, 'inconclusive');
  assert.equal(authRowVerdict(403, false).verdict, 'inconclusive');
});

test('realtime keeps the join reply and treats other frames as transport', async () => {
  const token = 'realtime-access-token-must-not-leak';
  const frames = [
    { event: 'phx_reply', ref: '9', topic: 'phoenix', payload: { status: 'ok' } },
    {
      event: 'postgres_changes',
      ref: '1',
      payload: { access_token: token, status: 'error' },
    },
    'not-json',
    {
      event: 'phx_reply',
      ref: '1',
      topic: 'realtime:ari-probe-synthetic',
      payload: {
        status: 'error',
        response: { reason: 'unauthorized', status: 403, access_token: token },
      },
    },
  ];
  assert.equal(isJoinPhxReply(frames[0]), false);
  assert.equal(isJoinPhxReply(frames[1]), false);
  assert.equal(isJoinPhxReply(frames[3]), true);
  assert.equal(classifyRealtimeReply(frames[0]), 'transport');
  assert.equal(classifyRealtimeReply(frames[3]), 'denied');
  assert.equal(
    classifyRealtimeReply({
      event: 'phx_reply',
      ref: '1',
      payload: { status: 'error', response: { reason: 'timeout' } },
    }),
    'transport',
  );
  assert.equal(realtimeVerdict('token_a', 'denied').verdict, 'deny');
  assert.equal(realtimeVerdict('token_a', 'transport').verdict, 'realtime_transport');
  const diagnostic = realtimeDiagnostic(frames[3]);
  assert.deepEqual(diagnostic, {
    event: 'phx_reply',
    topic: 'realtime:ari-probe-synthetic',
    ref: '1',
    payloadStatus: 'error',
    reason: 'unauthorized',
    code: 403,
    socketClose: false,
    timeoutClass: null,
  });
  assert.equal(JSON.stringify(diagnostic).includes(token), false);
  const listeners = new Map();
  const socket = {
    addEventListener(type, fn) {
      const list = listeners.get(type) ?? [];
      list.push(fn);
      listeners.set(type, list);
    },
    removeEventListener(type, fn) {
      listeners.set(
        type,
        (listeners.get(type) ?? []).filter((item) => item !== fn),
      );
    },
    emit(type, event) {
      for (const fn of listeners.get(type) ?? []) fn(event);
    },
  };
  const controller = new AbortController();
  const pending = readJoinReply(socket, controller.signal);
  socket.emit('message', { data: JSON.stringify(frames[0]) });
  socket.emit('message', { data: frames[2] });
  socket.emit('message', { data: JSON.stringify(frames[1]) });
  socket.emit('message', { data: JSON.stringify(frames[3]) });
  const matched = await pending;
  assert.equal(matched.ref, '1');
  assert.equal(matched.event, 'phx_reply');
  assert.equal(JSON.stringify(realtimeDiagnostic(matched)).includes(token), false);
  const timeoutListeners = new Map();
  const timeoutSocket = {
    addEventListener(type, fn) {
      const list = timeoutListeners.get(type) ?? [];
      list.push(fn);
      timeoutListeners.set(type, list);
    },
    removeEventListener(type, fn) {
      timeoutListeners.set(
        type,
        (timeoutListeners.get(type) ?? []).filter((item) => item !== fn),
      );
    },
    emit(type, event) {
      for (const fn of timeoutListeners.get(type) ?? []) fn(event);
    },
  };
  const abort = new AbortController();
  const timed = readJoinReply(timeoutSocket, abort.signal);
  timeoutSocket.emit('message', { data: JSON.stringify(frames[0]) });
  abort.abort();
  const timeoutResult = await timed;
  assert.equal(timeoutResult.timeout, true);
  assert.equal(realtimeDiagnostic(timeoutResult).timeoutClass, 'realtime_timeout');
  assert.equal(realtimeDiagnostic({ closed: true, code: 1006 }).socketClose, true);
});

test('realtime reason keeps the denial sentence and drops secrets', () => {
  const sentence =
    'Unauthorized: You do not have permissions to read from this Channel topic: ari-probe-synthetic';
  const plantedJwt =
    'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJwbGFudGVkLXJlYWx0aW1lIn0.c2lnbmF0dXJlLXBsYW50ZWQtc2VjcmV0';
  const longRun = 'abcdefghijklmnopqrstuvwxyz012345';
  const message = {
    event: 'phx_reply',
    ref: '1',
    topic: 'realtime:ari-probe-synthetic',
    payload: {
      status: 'error',
      response: {
        reason: `  ${sentence}   ${plantedJwt}\n${longRun}\u0001  `,
      },
    },
  };
  assert.equal(classifyRealtimeReply(message), 'denied');
  const diagnostic = realtimeDiagnostic(message);
  assert.equal(diagnostic.reason, sentence);
  assert.equal(diagnostic.payloadStatus, 'error');
  assert.equal(diagnostic.event, 'phx_reply');
  assert.equal(JSON.stringify(diagnostic).includes(plantedJwt), false);
  assert.equal(diagnostic.reason.includes(longRun), false);
  assert.equal(scrubRealtimeReason(plantedJwt), null);
  assert.equal(scrubRealtimeReason(longRun), null);
  assert.equal(scrubRealtimeReason(12), null);
  const capped = scrubRealtimeReason(`${'denied '.repeat(40)}\u00e9`);
  assert.equal(capped.length, 200);
  assert.equal(capped.startsWith('denied '), true);
  assert.equal(capped.includes('\u00e9'), false);
});

test('refuses a service-role shell and a service-role publishable key', async () => {
  const withSecret = await runProbe(
    await readyProbe({ env: { SUPABASE_SECRET_KEY: 'not-a-client-credential' } }),
  );
  assert.equal(withSecret.reason, 'service_role_forbidden_in_probe_shell');
  assert.equal(withSecret.requests, 0);
  const serviceJwt = unsignedJwt({ role: 'service_role' });
  const withKey = await runProbe(await readyProbe({ publishableKey: serviceJwt }));
  assert.equal(withKey.reason, 'publishable_key_is_service_role');
  assert.equal(JSON.stringify(withKey).includes(serviceJwt), false);
});
