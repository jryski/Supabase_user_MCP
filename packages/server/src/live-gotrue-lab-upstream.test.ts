import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { LabDualGrantError } from './lab-dual-grant-broker.js';
import {
  LAB_DUAL_GRANT_M4_MCP_VERIFIER_BOUND_MS,
  LAB_DUAL_GRANT_M4_RECEIPT_SCHEMA,
  type LiveProviderRevokeMeasurement,
  type LiveUpstreamOperation,
  type LiveUpstreamSyncBridge,
  assertLiveLabLoopbackOrigin,
  attachUpstreamIssuerToConsentRedirect,
  buildLabDualGrantM4Receipt,
  createLiveGoTrueLabUpstream,
  createLiveUpstreamWorkerBridge,
} from './live-gotrue-lab-upstream.js';

const ORIGIN = 'http://127.0.0.1:54321';
const REDIRECT = 'http://127.0.0.1:8765/lab/oauth/callback';
const ISSUER = 'http://127.0.0.1:54321/auth/v1';
const PUBLISHABLE = 'sb_publishable_lab_key';
const SERVICE_ROLE = 'sb_secret_lab_registration_only';
const ALICE = '11111111-1111-4111-9111-111111111111';
const BOB = '22222222-2222-4222-9222-222222222222';
const UPSTREAM_CLIENT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const WRONG_CLIENT = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

function principals() {
  return [
    { principalId: ALICE, userAccessToken: 'alice.access.token' },
    { principalId: BOB, userAccessToken: 'bob.access.token' },
  ] as const;
}

function measurement(refreshDenied = true): LiveProviderRevokeMeasurement {
  return {
    httpStatus: 204,
    providerRevokeLatencyMs: 12,
    refreshProbeLatencyMs: 7,
    refreshDenied,
    dataApiRevocationSlaClaimed: false as const,
    mcpVerifierBoundMs: LAB_DUAL_GRANT_M4_MCP_VERIFIER_BOUND_MS,
    mcpVerifierBoundAppliedToDataApi: false as const,
  };
}

describe('live GoTrue lab upstream guards', () => {
  it('accepts only http://127.0.0.1 coordinates', () => {
    expect(assertLiveLabLoopbackOrigin(ORIGIN).origin).toBe(ORIGIN);
    for (const value of [
      'https://127.0.0.1:54321',
      'http://localhost:54321',
      'http://0.0.0.0:54321',
      'http://127.0.0.1:54321@evil.example',
      'http://user:pass@127.0.0.1:54321',
      'http://127.0.0.1:54321/auth#fragment',
      'http://10.0.0.8:54321',
    ]) {
      expect(() => assertLiveLabLoopbackOrigin(value)).toThrowError(
        expect.objectContaining({ code: 'redirect_not_loopback' }),
      );
    }
  });

  it('keeps a provider iss and otherwise pins the configured loopback issuer', () => {
    const raw = `${REDIRECT}?code=code-1&state=state-0123456789abcdef`;
    const added = attachUpstreamIssuerToConsentRedirect({
      location: raw,
      exactRedirectUri: REDIRECT,
      upstreamIssuer: ISSUER,
    });
    expect(added.providerIncludedIss).toBe(false);
    expect(added.url.searchParams.get('iss')).toBe(ISSUER);
    expect(added.url.searchParams.get('code')).toBe('code-1');
    const present = attachUpstreamIssuerToConsentRedirect({
      location: `${raw}&iss=${encodeURIComponent(ISSUER)}`,
      exactRedirectUri: REDIRECT,
      upstreamIssuer: ISSUER,
    });
    expect(present.providerIncludedIss).toBe(true);
    expect(() =>
      attachUpstreamIssuerToConsentRedirect({
        location: `${raw}&iss=${encodeURIComponent('http://127.0.0.1:9/auth/v1')}`,
        exactRedirectUri: REDIRECT,
        upstreamIssuer: ISSUER,
      }),
    ).toThrowError(expect.objectContaining({ code: 'mixup' }));
    expect(() =>
      attachUpstreamIssuerToConsentRedirect({
        location: 'http://127.0.0.1:9/other?code=c&state=state-0123456789abcdef',
        exactRedirectUri: REDIRECT,
        upstreamIssuer: ISSUER,
      }),
    ).toThrowError(expect.objectContaining({ code: 'invalid_redirect' }));
  });

  it('builds a secret-free receipt that separates ordinary and lab dispatch', () => {
    const receipt = buildLabDualGrantM4Receipt({
      repositorySha: 'a'.repeat(40),
      treeSha: 'b'.repeat(40),
      node: 'v22.14.0',
      npm: '11.19.0',
      supabase: '2.115.0',
      providerAuthorizationRedirectIncludesIss: false,
      mcpSdkPackageName: '@modelcontextprotocol/client',
      mcpSdkVersion: '2.0.0',
      t10ProviderRevoke: measurement(),
      t10DataApiProbe: {
        latencyMs: 15,
        httpStatus: 200,
        accessJwtRejected: false,
        recordVisible: true,
        slaClaimed: false,
      },
      forbiddenSubstrings: [SERVICE_ROLE, 'alice.access.token'],
    });
    expect(receipt.schema).toBe(LAB_DUAL_GRANT_M4_RECEIPT_SCHEMA);
    expect(receipt.result).toBe('pass');
    expect(receipt.ordinaryRemoteProfile.dataDispatch).toBe('fail-closed');
    expect(receipt.labDualGrantProfile.dataDispatch).toBe('loopback-lab-only');
    expect(receipt.gates.t10DataApiProbe.slaClaimed).toBe(false);
    expect(receipt.gates.t10ProviderRevoke.mcpVerifierBoundAppliedToDataApi).toBe(false);
    expect(receipt.externalMcpBinary).toBe(false);
    expect(JSON.stringify(receipt)).not.toContain(SERVICE_ROLE);
    expect(() =>
      buildLabDualGrantM4Receipt({
        repositorySha: 'a'.repeat(40),
        treeSha: 'b'.repeat(40),
        node: 'v22.14.0',
        npm: '11.19.0',
        supabase: '2.115.0',
        providerAuthorizationRedirectIncludesIss: false,
        mcpSdkPackageName: '@modelcontextprotocol/client',
        mcpSdkVersion: '2.0.0',
        t10ProviderRevoke: measurement(),
        t10DataApiProbe: {
          latencyMs: 15,
          httpStatus: 200,
          accessJwtRejected: false,
          recordVisible: false,
          slaClaimed: false,
        },
        forbiddenSubstrings: ['v22.14.0'],
      }),
    ).toThrow(LabDualGrantError);
    expect(() =>
      buildLabDualGrantM4Receipt({
        repositorySha: 'a'.repeat(40),
        treeSha: 'b'.repeat(40),
        node: 'v22.14.0',
        npm: '11.19.0',
        supabase: '2.115.0',
        providerAuthorizationRedirectIncludesIss: false,
        mcpSdkPackageName: '@modelcontextprotocol/client',
        mcpSdkVersion: '2.0.0',
        t10ProviderRevoke: measurement(false),
        t10DataApiProbe: {
          latencyMs: 15,
          httpStatus: 401,
          accessJwtRejected: true,
          recordVisible: false,
          slaClaimed: false,
        },
        forbiddenSubstrings: [],
      }),
    ).toThrow(LabDualGrantError);
  });

  it('does not let the stock M4 script opt into dual-grant dispatch', () => {
    const stock = readFileSync(
      new URL('../../../supabase/tests/run-m4-remote-oauth-lab.sh', import.meta.url),
      'utf8',
    );
    expect(stock).not.toContain('LAB_DUAL_GRANT');
    expect(stock).not.toContain('labDualGrant');
    expect(stock).toContain('dataDispatch":"fail-closed"');
    const harness = readFileSync(
      new URL('../../../supabase/tests/run-lab-dual-grant-m4.sh', import.meta.url),
      'utf8',
    );
    expect(harness).toContain('host_binding_ipv4');
    expect(harness).toContain('Docker daemon');
    expect(harness).not.toContain('"result":"pass"');
  });

  it('registers two public clients and keeps service role off the broker operation', async () => {
    const calls: Array<{ url: string; authorization: string }> = [];
    const fetchImpl: typeof fetch = async (input, init) => {
      const url = String(input);
      const authorization = new Headers(init?.headers).get('authorization') ?? '';
      calls.push({ url, authorization });
      if (url.endsWith('/.well-known/openid-configuration')) {
        expect(authorization).toBe('');
        return Response.json({ issuer: ISSUER });
      }
      const name = (JSON.parse(String(init?.body)) as { name?: string }).name ?? '';
      return Response.json({
        client_id: name === 'lab-dg-other' ? WRONG_CLIENT : UPSTREAM_CLIENT,
      });
    };
    const operations: LiveUpstreamOperation[] = [];
    const bridge: LiveUpstreamSyncBridge = {
      call<T>(operation: LiveUpstreamOperation): T {
        operations.push(operation);
        expect(operation).not.toHaveProperty('serviceRoleKey');
        expect(JSON.stringify(operation)).not.toContain(SERVICE_ROLE);
        if (operation.op === 'startAuthorization') {
          return { authorizationId: 'auth-1' } as T;
        }
        return {
          location: `${REDIRECT}?code=code-1&state=state-0123456789abcdef`,
        } as T;
      },
      async close() {},
    };
    const upstream = await createLiveGoTrueLabUpstream(
      {
        authOrigin: ORIGIN,
        publishableKey: PUBLISHABLE,
        serviceRoleKey: SERVICE_ROLE,
        exactRedirectUri: REDIRECT,
        principals: principals(),
      },
      { fetch: fetchImpl, bridge },
    );
    expect(upstream.upstreamClientId).toBe(UPSTREAM_CLIENT);
    expect(upstream.wrongClientId).toBe(WRONG_CLIENT);
    expect(upstream.upstreamIssuer).toBe(ISSUER);
    expect(upstream.dataApiOrigin).toBe(ORIGIN);
    expect(calls.map((call) => new URL(call.url).pathname)).toEqual([
      '/auth/v1/.well-known/openid-configuration',
      '/auth/v1/admin/oauth/clients',
      '/auth/v1/admin/oauth/clients',
    ]);
    expect(calls[1]?.authorization).toBe(`Bearer ${SERVICE_ROLE}`);
    expect(calls[2]?.authorization).toBe(`Bearer ${SERVICE_ROLE}`);
    const authorizationId = upstream.startAuthorization({
      responseType: 'code',
      clientId: UPSTREAM_CLIENT,
      redirectUri: REDIRECT,
      codeChallenge: 'a'.repeat(43),
      codeChallengeMethod: 'S256',
      resource: upstream.upstreamResourceUri,
      state: 'state-0123456789abcdef',
      principalId: ALICE,
    });
    const approved = upstream.approveAuthorization(authorizationId);
    expect(approved.searchParams.get('iss')).toBe(ISSUER);
    expect(upstream.providerRedirectIncludedIss()).toBe(false);
    expect(operations).toHaveLength(2);
    expect(Object.keys(upstream)).not.toContain('serviceRoleKey');
    await upstream.close();
  });

  it('rejects non-loopback coordinates and privileged publishable keys before fetch', async () => {
    const fetchImpl = async () => {
      throw new Error('fetch must not run');
    };
    await expect(
      createLiveGoTrueLabUpstream(
        {
          authOrigin: 'https://project.supabase.co',
          publishableKey: PUBLISHABLE,
          serviceRoleKey: SERVICE_ROLE,
          exactRedirectUri: REDIRECT,
          principals: principals(),
        },
        { fetch: fetchImpl },
      ),
    ).rejects.toMatchObject({ code: 'redirect_not_loopback' });
    await expect(
      createLiveGoTrueLabUpstream(
        {
          authOrigin: ORIGIN,
          publishableKey: 'eyJhbGciOiJIUzI1NiJ9.payload.sig',
          serviceRoleKey: SERVICE_ROLE,
          exactRedirectUri: REDIRECT,
          principals: principals(),
        },
        { fetch: fetchImpl },
      ),
    ).rejects.toMatchObject({ code: 'privileged_credential' });
  });

  it('rejects a non-loopback issuer advertised by discovery', async () => {
    const fetchImpl: typeof fetch = async () =>
      Response.json({ issuer: 'https://project.supabase.co/auth/v1' });
    await expect(
      createLiveGoTrueLabUpstream(
        {
          authOrigin: ORIGIN,
          publishableKey: PUBLISHABLE,
          serviceRoleKey: SERVICE_ROLE,
          exactRedirectUri: REDIRECT,
          principals: principals(),
        },
        { fetch: fetchImpl },
      ),
    ).rejects.toMatchObject({ code: 'mixup' });
  });

  it('uses the worker bridge only for loopback operations', async () => {
    const bridge = createLiveUpstreamWorkerBridge();
    try {
      expect(() =>
        bridge.call({
          op: 'startAuthorization',
          authOrigin: 'https://project.supabase.co',
          publishableKey: PUBLISHABLE,
          clientId: UPSTREAM_CLIENT,
          redirectUri: REDIRECT,
          resource: `${ORIGIN}/rest/v1`,
          codeChallenge: 'a'.repeat(43),
          state: 'state-0123456789abcdef',
        }),
      ).toThrow(LabDualGrantError);
    } finally {
      await bridge.close();
    }
  }, 20_000);
});
