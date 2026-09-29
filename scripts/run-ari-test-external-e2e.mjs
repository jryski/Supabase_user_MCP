/**
 * Parent orchestration for the TEST-only external client.
 * Default command is `plan`. It does not open a socket and does not contact
 * hosted TEST. `run` stays closed unless the controller sets the G5 gates.
 */
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';

const FORBIDDEN = [
  'SUPABASE_SERVICE_ROLE_KEY',
  'SUPABASE_SECRET_KEY',
  'SERVICE_ROLE_KEY',
  'SUPABASE_SERVICE_KEY',
];

export function controllerPlan() {
  return {
    packet: 'lane-b-external-client',
    profile: 'TEST_ONLY_PUBLIC_PKCE',
    executedByWriter: false,
    hostedContact: false,
    hookInstalled: false,
    acceptance: false,
    laneAClosedAt: '6e142ed510bab5c6b15312e0d25530f5840d0424',
    steps: [
      'Confirm Warden G5 on the exact Lane B commit before any hosted write.',
      'Do not apply sql/02. Do not edit sql/03. Keep the baseline A row.',
      'Apply sql/07, then sql/05, then sql/06 on odbcejsuuqdzhabjmozi only.',
      'If sql/05 raises STOP AND REPORT because auth.sessions is not readable, stop. Do not grant schema auth.',
      'Register external A and TEST-only public PKCE B out of band. No client secret. No openid. No DCR.',
      'N4 is the user revoking the OAuth grant from a first-party session, or an admin delete of that session.',
      'F1 in sql/06 covers public.ari_probe_marker only.',
      'node scripts/run-ari-test-external-e2e.mjs plan',
      'After G5: node scripts/run-ari-test-external-e2e.mjs run',
    ],
    rollback: [
      'drop function if exists public.ari_probe_source_session_live_v1(uuid, text)',
      'drop policy if exists ari_probe_marker_reject_a_client on public.ari_probe_marker',
      "delete from ari_probe.mcp_client where probe_label = 'ari-test-external-a'",
      'drop table if exists ari_probe.downstream_client',
      're-apply sql/04 function body if the baseline hook must be restored',
    ],
  };
}

export function controllerGate(env) {
  for (const name of FORBIDDEN) {
    if (typeof env[name] === 'string' && env[name].length > 0) {
      return { ok: false, reason: 'service_role_refused' };
    }
  }
  if (env.ARI_LANE_B_LIVE !== 'controller-g5') return { ok: false, reason: 'live_gate_closed' };
  if (env.ARI_TEST_PROJECT_REF !== 'odbcejsuuqdzhabjmozi') {
    return { ok: false, reason: 'project_ref_refused' };
  }
  if (
    typeof env.ARI_LANE_B_G5_HEAD !== 'string' ||
    !/^[0-9a-f]{40}$/.test(env.ARI_LANE_B_G5_HEAD)
  ) {
    return { ok: false, reason: 'g5_head_required' };
  }
  return { ok: true };
}

function required(env, name) {
  const value = env[name];
  if (typeof value !== 'string' || value.length === 0) {
    throw Object.assign(new Error('live_configuration_incomplete'), {
      code: 'live_configuration_incomplete',
    });
  }
  return value;
}

export async function startExternalRuntime(env) {
  const gate = controllerGate(env);
  if (!gate.ok) {
    throw Object.assign(new Error(gate.reason), { code: gate.reason });
  }
  if (env.ARI_LANE_B_EXECUTE !== '1') {
    throw Object.assign(new Error('live_runtime_not_started'), {
      code: 'live_runtime_not_started',
    });
  }
  const mcpUrl = new URL(required(env, 'ARI_EXTERNAL_MCP_URL'));
  if (mcpUrl.hostname !== '127.0.0.1' && mcpUrl.hostname !== 'localhost') {
    throw Object.assign(new Error('mcp_resource_not_loopback'), {
      code: 'mcp_resource_not_loopback',
    });
  }
  const port = Number(mcpUrl.port);
  if (!Number.isSafeInteger(port) || port < 1) {
    throw Object.assign(new Error('live_configuration_incomplete'), {
      code: 'live_configuration_incomplete',
    });
  }
  const { createNativeUserMcpReadHandler } = await import(
    '../packages/server/dist/native-user-mcp-read-handler.js'
  );
  const handler = createNativeUserMcpReadHandler({
    resourceServer: mcpUrl.origin + mcpUrl.pathname,
    supabaseUrl: required(env, 'ARI_TEST_SUPABASE_URL'),
    expectedClientId: required(env, 'ARI_EXTERNAL_A_CLIENT_ID'),
    expectedAgentId: required(env, 'ARI_AGENT_ID'),
    ingressRole: 'mcp_ingress',
    publishableKey: required(env, 'ARI_TEST_PUBLISHABLE_KEY'),
    jwks: JSON.parse(required(env, 'ARI_TEST_JWKS_JSON')),
    downstreamClientId: required(env, 'ARI_DOWNSTREAM_CLIENT_ID'),
    downstreamRedirectUri: required(env, 'ARI_DOWNSTREAM_REDIRECT_URI'),
    enableAriTestMarker: true,
  });
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const scheme = req.socket?.encrypted === true ? 'https' : 'http';
      const host = req.headers.host;
      if (typeof host !== 'string') {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_request' }));
        return;
      }
      const body = Buffer.concat(chunks);
      const request = new Request(`${scheme}://${host}${req.url}`, {
        method: req.method,
        headers: req.headers,
        ...(body.length === 0 || req.method === 'GET' || req.method === 'HEAD' ? {} : { body }),
      });
      void handler(request).then(
        async (response) => {
          const headers = {};
          response.headers.forEach((value, key) => {
            headers[key] = value;
          });
          res.writeHead(response.status, headers);
          res.end(Buffer.from(await response.arrayBuffer()));
        },
        () => {
          if (!res.headersSent) {
            res.writeHead(500, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ error: 'server_error' }));
          }
        },
      );
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve());
  });
  const child = spawn(process.execPath, ['scripts/ari-test-external-client.mjs'], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...env,
      ARI_LANE_B_LIVE: 'controller-g5',
    },
  });
  return { server, child };
}

async function main() {
  const command = process.argv[2] ?? 'plan';
  if (command === 'plan') {
    process.stdout.write(`${JSON.stringify(controllerPlan(), null, 2)}\n`);
    return;
  }
  if (command !== 'run') {
    process.stderr.write('usage: node scripts/run-ari-test-external-e2e.mjs [plan|run]\n');
    process.exitCode = 2;
    return;
  }
  const gate = controllerGate(process.env);
  if (!gate.ok) {
    process.stderr.write(`${gate.reason}\n`);
    process.exitCode = 2;
    return;
  }
  process.stderr.write('live_runtime_not_started\n');
  process.exitCode = 2;
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(invokedPath).href) {
  await main();
}
