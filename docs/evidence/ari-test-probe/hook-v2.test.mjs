import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { decideHookV2, isNonNilUuid } from './hook-v2.mjs';

const USER = '11111111-1111-4111-8111-111111111111';
const SOURCE = '22222222-2222-4222-8222-222222222222';
const FRESH = '33333333-3333-4333-8333-333333333333';
const CLIENT_A = 'registered-client-parameter';
const RESOURCE = 'https://odbcejsuuqdzhabjmozi.supabase.co/mcp';
const AGENT = 'hook-only-agent-parameter';

function mappedInput(extra = {}) {
  return {
    clients: [{ clientId: CLIENT_A, mcpResource: RESOURCE, agentId: AGENT }],
    sessions: [{ id: SOURCE, userId: USER, notAfter: null }],
    randomUuid: () => FRESH,
    now: Date.parse('2026-09-29T00:00:00Z'),
    event: {
      user_id: USER,
      authentication_method: 'oauth',
      claims: {
        sub: USER,
        client_id: CLIENT_A,
        role: 'authenticated',
        aud: 'authenticated',
        session_id: SOURCE,
        scope: 'email',
      },
    },
    ...extra,
  };
}

test('absent client_id leaves password claims unchanged', () => {
  const claims = { sub: USER, role: 'authenticated', aud: 'authenticated', session_id: SOURCE };
  const result = decideHookV2(
    mappedInput({
      event: { user_id: USER, authentication_method: 'password', claims },
    }),
  );
  assert.equal(result.action, 'unchanged');
  assert.equal(result.reason, 'absent_client_id');
  assert.equal(result.claims, claims);
  assert.equal(result.revocationClaimed, false);
});

test('openid raises for every oauth client', () => {
  const mapped = decideHookV2(
    mappedInput({
      event: {
        user_id: USER,
        claims: { ...mappedInput().event.claims, scope: 'email openid' },
      },
    }),
  );
  const other = decideHookV2(
    mappedInput({
      event: {
        user_id: USER,
        scope: ['OpenID'],
        claims: { client_id: 'some-other-registered-client', session_id: SOURCE },
      },
    }),
  );
  assert.equal(mapped.reason, 'openid_scope_refused');
  assert.equal(other.reason, 'openid_scope_refused');
  assert.equal(mapped.revocationClaimed, false);
  assert.equal(other.revocationClaimed, false);
});

test('a present unmapped client_id raises', () => {
  const result = decideHookV2(
    mappedInput({
      event: {
        user_id: USER,
        claims: { client_id: 'registered-but-unmapped', session_id: SOURCE, scope: 'email' },
      },
    }),
  );
  assert.equal(result.action, 'raise');
  assert.equal(result.reason, 'unmapped_client_id');
});

test('the mapped client rewrites aud, role, and session ids', () => {
  const original = mappedInput().event.claims;
  const result = decideHookV2(mappedInput());
  assert.equal(result.action, 'map');
  assert.equal(result.revocationClaimed, false);
  assert.equal(result.liveCheck, 'hook_issuance_or_refresh');
  assert.equal(result.claims.aud, RESOURCE);
  assert.equal(result.claims.role, 'mcp_ingress');
  assert.equal(result.claims.session_id, FRESH);
  assert.equal(result.claims.source_session_id, SOURCE);
  assert.equal(result.claims.agent_id, AGENT);
  assert.equal(original.session_id, SOURCE);
  assert.equal(original.role, 'authenticated');
  assert.equal(isNonNilUuid(result.claims.session_id), true);
});

test('a dead source session is not called revocation', () => {
  const expired = decideHookV2(
    mappedInput({
      sessions: [{ id: SOURCE, userId: USER, notAfter: '2020-01-01T00:00:00Z' }],
    }),
  );
  const missing = decideHookV2(mappedInput({ sessions: [] }));
  assert.equal(expired.reason, 'source_session_not_live');
  assert.equal(missing.reason, 'source_session_not_live');
  assert.equal(expired.revocationClaimed, false);
  assert.equal(missing.revocationClaimed, false);
});

test('a nil or colliding fresh session id is rejected', () => {
  const nil = decideHookV2(
    mappedInput({ randomUuid: () => '00000000-0000-0000-0000-000000000000' }),
  );
  const collision = decideHookV2(mappedInput({ randomUuid: () => SOURCE }));
  assert.equal(nil.reason, 'fresh_session_id_rejected');
  assert.equal(collision.reason, 'fresh_session_id_rejected');
});

test('hook v2 SQL matches the decision text and takes client ids as parameters', async () => {
  const sql = await readFile(new URL('./sql/04-hook-v2-for-ariadne.sql', import.meta.url), 'utf8');
  assert.match(sql, /openid scope is refused for every oauth client/);
  assert.match(sql, /unmapped oauth client_id/);
  assert.match(sql, /source session is not live/);
  assert.match(sql, /fresh session_id is nil or already in auth.sessions/);
  assert.match(sql, /source_session_id/);
  assert.match(sql, /pg_catalog\.gen_random_uuid\(\)/);
  assert.match(sql, /current_setting\('ari\.oauth_client_id', true\)/);
  assert.match(sql, /current_setting\('ari\.mcp_resource', true\)/);
  assert.match(sql, /current_setting\('ari\.agent_id', true\)/);
  assert.match(sql, /one SQL-editor batch/);
  assert.match(sql, /not a revocation receipt/);
  assert.match(sql, /each hook call only: token issuance and refresh/);
  assert.match(sql, /does not run on each MCP call/);
  assert.match(sql, /adapter has no liveness check/);
  assert.match(sql, /v_client_id text :=/);
  assert.equal(sql.match(/v_client_id text :=/g)?.length, 2);
  assert.match(sql, /v_mcp_resource text :=/);
  assert.match(sql, /v_agent_id text :=/);
  assert.match(sql, /mapping\.client_id = v_client_id/);
  assert.equal(sql.includes('values (client_id,'), false);
  assert.equal(sql.includes('where mapping.client_id = client_id'), false);
  assert.match(sql, /lygftpbjgqgvuunkwnxf/);
  assert.equal(sql.includes('ari-probe-synthetic-client'), false);
  assert.match(sql, /does not apply it/);
});
