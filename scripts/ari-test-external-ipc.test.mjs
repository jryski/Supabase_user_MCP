import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import test from 'node:test';

import {
  assertIpcHasNoSecrets,
  createExternalPublicPkceProvider,
  EXTERNAL_CLIENT_PROFILE,
  publishDownstreamAuthorization,
} from './ari-test-external-client.mjs';
import { controllerGate, controllerPlan } from './run-ari-test-external-e2e.mjs';

test('IPC refuses tokens and the provider does not register or keep refresh tokens', async () => {
  assert.throws(
    () => assertIpcHasNoSecrets({ access_token: 'header.payload.sig' }),
    /ipc_refused_secret/,
  );
  assert.throws(
    () => assertIpcHasNoSecrets({ note: 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.sig' }),
    /ipc_refused_secret/,
  );
  const lines = [];
  const provider = createExternalPublicPkceProvider({
    clientId: 'external-a-client',
    redirectUrl: 'http://127.0.0.1:8788/oauth/callback',
    writeIpc(line) {
      lines.push(line);
    },
    async readIpc() {
      return JSON.stringify({
        type: 'authorization_code',
        code: 'one-time-code',
        state: 'state-1',
      });
    },
  });
  assert.equal('saveClientInformation' in provider, false);
  assert.equal(provider.clientInformation().client_id, 'external-a-client');
  assert.equal(provider.clientMetadata.token_endpoint_auth_method, 'none');
  assert.equal(provider.clientMetadata.scope, 'email');
  assert.equal(provider.clientMetadata.client_secret, undefined);
  assert.equal(provider.profile, EXTERNAL_CLIENT_PROFILE);
  provider.saveTokens({
    access_token: 'memory-access-token',
    refresh_token: 'refresh-must-drop',
    token_type: 'Bearer',
  });
  assert.deepEqual(provider.tokens(), {
    access_token: 'memory-access-token',
    token_type: 'Bearer',
  });
  assert.equal(JSON.stringify(provider.tokens()).includes('refresh-must-drop'), false);
  const url = new URL('http://127.0.0.1:9999/authorize?state=state-1');
  await provider.redirectToAuthorization(url);
  const message = JSON.parse(lines[0]);
  assert.equal(message.type, 'authorization_request');
  assert.equal(message.state, 'state-1');
  assert.equal(message.authorizationUrl.includes('refresh'), false);
  const forwarded = [];
  assert.equal(
    publishDownstreamAuthorization(
      {
        error: 'downstream_authorization_required',
        authorization_url: 'http://127.0.0.1/auth?state=abc',
        state: 'abc',
        handshake_id: 'abc',
      },
      (line) => forwarded.push(line),
    ),
    true,
  );
  assert.equal(JSON.parse(forwarded[0]).handshakeId, 'abc');
  assert.equal(JSON.parse(forwarded[0]).access_token, undefined);
});

test('plan prints controller steps and run stays closed', async () => {
  const plan = controllerPlan();
  assert.equal(plan.executedByWriter, false);
  assert.equal(plan.hostedContact, false);
  assert.equal(plan.hookInstalled, false);
  assert.match(plan.steps.join('\n'), /STOP AND REPORT/);
  assert.match(plan.steps.join('\n'), /first-party session/);
  assert.match(plan.rollback.join('\n'), /ari-test-external-a/);
  assert.equal(controllerGate({}).ok, false);
  assert.equal(controllerGate({ ARI_LANE_B_LIVE: 'controller-g5' }).reason, 'project_ref_refused');
  assert.equal(
    controllerGate({
      ARI_LANE_B_LIVE: 'controller-g5',
      ARI_TEST_PROJECT_REF: 'odbcejsuuqdzhabjmozi',
      SUPABASE_SERVICE_ROLE_KEY: 'nope',
    }).reason,
    'service_role_refused',
  );

  const planRun = spawn(process.execPath, ['scripts/run-ari-test-external-e2e.mjs', 'plan'], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const planOut = [];
  planRun.stdout.on('data', (chunk) => planOut.push(chunk));
  const [planCode] = await once(planRun, 'exit');
  assert.equal(planCode, 0);
  const printed = JSON.parse(Buffer.concat(planOut).toString('utf8'));
  assert.equal(printed.hostedContact, false);

  const run = spawn(process.execPath, ['scripts/run-ari-test-external-e2e.mjs', 'run'], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const runErr = [];
  run.stderr.on('data', (chunk) => runErr.push(chunk));
  const [runCode] = await once(run, 'exit');
  assert.equal(runCode, 2);
  assert.match(Buffer.concat(runErr).toString('utf8'), /live_gate_closed/);
});
