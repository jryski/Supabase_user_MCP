import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  ALLOWED_PROJECT_REF,
  assertTarget,
  authRowVerdict,
  classifyTokenA,
  classifyTokenB,
  dataRowVerdict,
  FORBIDDEN_PROJECT_REFS,
  INGRESS_ROLE,
  MARKER,
  MCP_RESOURCE,
} from './decisions.mjs';
import { runProbe } from './probe.mjs';

const SUBJECT = '11111111-1111-4111-8111-111111111111';
const ISSUER = `https://${ALLOWED_PROJECT_REF}.supabase.co/auth/v1`;

function jwt(claims) {
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  return `eyJhbGciOiJFUzI1NiJ9.${payload}.c2ln`;
}

function tokenAClaims(extra = {}) {
  return {
    iss: ISSUER,
    sub: SUBJECT,
    role: INGRESS_ROLE,
    aud: MCP_RESOURCE,
    ...extra,
  };
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

function baseOptions(overrides = {}) {
  return {
    projectRef: ALLOWED_PROJECT_REF,
    supabaseUrl: `https://${ALLOWED_PROJECT_REF}.supabase.co`,
    publishableKey: 'sb_publishable_test_only',
    tokenA: jwt(tokenAClaims()),
    tokenB: jwt(tokenBClaims()),
    env: {},
    fetch: async () => {
      throw new Error('unexpected_fetch');
    },
    joinRealtime: async () => {
      throw new Error('unexpected_realtime');
    },
    ...overrides,
  };
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
  assert.equal(
    assertTarget({
      projectRef: ALLOWED_PROJECT_REF,
      supabaseUrl: 'http://127.0.0.1:9',
      allowLoopback: true,
    }).ok,
    true,
  );
});

test('Token A eligibility ignores user_metadata and rejects role=authenticated', () => {
  const ignored = classifyTokenA(
    tokenAClaims({ user_metadata: { role: 'authenticated', client_id: 'forged' } }),
  );
  assert.equal(ignored.ok, true);
  const blocked = classifyTokenA(tokenAClaims({ role: 'authenticated' }));
  assert.equal(blocked.reason, 'role_flip_prerequisite_missing');
  const mixed = classifyTokenA(tokenAClaims({ aud: [MCP_RESOURCE, 'https://other.example/api'] }));
  assert.equal(mixed.reason, 'aud_not_singleton_resource');
  assert.equal(classifyTokenB(tokenBClaims()).label, 'POSITIVE_CONTROL_NOT_MCP');
  assert.equal(classifyTokenB(tokenBClaims()).wiredIntoMcp, false);
});

test('does not send a role=authenticated bearer as Token A', async () => {
  let calls = 0;
  const result = await runProbe(
    baseOptions({
      tokenA: jwt(tokenAClaims({ role: 'authenticated' })),
      fetch: async () => {
        calls += 1;
        return new Response('', { status: 500 });
      },
    }),
  );
  assert.equal(result.exitCode, 3);
  assert.equal(result.reason, 'role_flip_prerequisite_missing');
  assert.equal(result.requests, 0);
  assert.equal(calls, 0);
  assert.equal(JSON.stringify(result).includes('eyJ'), false);
});

test('stops on the first Token A mutation success', async () => {
  const seen = [];
  const result = await runProbe(
    baseOptions({
      fetch: async (url, init) => {
        seen.push(`${init.method} ${new URL(url).pathname}`);
        if (init.method === 'PUT') return new Response('{}', { status: 200 });
        return new Response('{}', { status: 401 });
      },
    }),
  );
  assert.equal(result.exitCode, 4);
  assert.equal(result.reason, 'NO_GO_TOKEN_A_MUTATION');
  assert.equal(seen.includes('POST /auth/v1/factors'), false);
  assert.equal(seen.includes('POST /auth/v1/logout'), false);
  assert.equal(seen.includes('GET /rest/v1/ari_probe_marker'), false);
});

test('stops before mutations when Token A can read the Auth user', async () => {
  const seen = [];
  const result = await runProbe(
    baseOptions({
      fetch: async (url, init) => {
        seen.push(`${init.method} ${new URL(url).pathname}`);
        return new Response('{}', { status: 200 });
      },
    }),
  );
  assert.equal(result.reason, 'NO_GO_TOKEN_A_AUTH_READ');
  assert.deepEqual(seen, ['GET /auth/v1/user']);
  assert.equal(authRowVerdict(200, true).verdict, 'NO_GO_TOKEN_A_MUTATION');
});

test('holds the paired deny and positive-control matrix without echoing credentials', async () => {
  const options = baseOptions();
  const result = await runProbe(
    baseOptions({
      fetch: async (url, init) => {
        const path = new URL(url).pathname;
        const token = init.headers.authorization;
        if (path.startsWith('/auth/')) return new Response('denied', { status: 401 });
        if (
          path === '/storage/v1/object/ari-probe-synthetic/marker.txt' &&
          init.method === 'POST'
        ) {
          assert.equal(init.body, MARKER);
          assert.equal(init.headers.authorization?.includes(options.tokenB), true);
          return new Response('', { status: 200 });
        }
        const body = token?.includes(options.tokenB) ? JSON.stringify([{ marker: MARKER }]) : '[]';
        return new Response(body, { status: token === undefined ? 200 : 401 });
      },
      joinRealtime: async ({ token }) => (token === options.tokenB ? 'ok' : 'error'),
    }),
  );
  assert.equal(result.exitCode, 0);
  assert.equal(result.reason, 'matrix_held');
  assert.equal(result.wiredIntoMcp, false);
  assert.equal(result.roleFlipShipped, false);
  assert.equal(result.hookInstalledByThisPacket, false);
  const encoded = JSON.stringify(result);
  assert.equal(encoded.includes(options.tokenA), false);
  assert.equal(encoded.includes(options.tokenB), false);
  assert.equal(encoded.includes(options.publishableKey), false);
  assert.equal(dataRowVerdict('token_a', MARKER).verdict, 'NO_GO_TOKEN_A_GAINED_ACCESS');
  assert.equal(dataRowVerdict('publishable', '[]').verdict, 'no_marker');
  assert.equal(dataRowVerdict('token_b', `{"marker":"${MARKER}"}`).verdict, 'positive_control');
});

test('refuses a service-role shell and a service-role publishable key', async () => {
  const withSecret = await runProbe(
    baseOptions({ env: { SUPABASE_SECRET_KEY: 'not-a-client-credential' } }),
  );
  assert.equal(withSecret.reason, 'service_role_forbidden_in_probe_shell');
  assert.equal(withSecret.requests, 0);
  const serviceJwt = jwt({ role: 'service_role' });
  const withKey = await runProbe(baseOptions({ publishableKey: serviceJwt }));
  assert.equal(withKey.reason, 'publishable_key_is_service_role');
  assert.equal(JSON.stringify(withKey).includes(serviceJwt), false);
});
