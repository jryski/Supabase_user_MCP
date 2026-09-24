import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { MessageChannel, Worker, receiveMessageOnPort } from 'node:worker_threads';

import {
  ACCESS_TOKEN_REVOCATION_LATENCY_BOUND_MS,
  canonicalizeResourceUri,
  extractServerControlledClientId,
} from '@supabase-user-mcp/contracts';

import {
  LabDualGrantError,
  type LabDualGrantReceipt,
  type LabUpstreamAuthorizationRequest,
  type LabUpstreamOAuth,
  type LabUpstreamTokenSuccess,
} from './lab-dual-grant-broker.js';
import {
  decodeJwtPayloadClaims,
  exchangeLocalAuthorizationCode,
  refreshLocalAccessToken,
  registerLocalPublicOAuthClient,
  revokeLocalGrant,
  startLocalAuthorization,
  approveLocalAuthorization,
  denyLocalAuthorization,
} from './local-oauth-pkce-client.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA = /^[0-9a-f]{40}$/;
const BRIDGE_TIMEOUT_MS = 20_000;
const FORBIDDEN_OPERATION_KEYS = new Set([
  'serviceRoleKey',
  'service_role',
  'projectJwtSecret',
  'jwtSecret',
  'jwtHmacSecret',
]);
const WORKER_ENV_BLOCK = [
  'M4_SERVICE_ROLE_KEY',
  'M4_JWT_SECRET',
  'M4_ALICE_TOKEN',
  'M4_BOB_TOKEN',
  'M4_DB_URL',
  'M4_PUBLISHABLE_KEY',
  'SUPABASE_SERVICE_ROLE_KEY',
  'SUPABASE_SECRET_KEY',
  'SUPABASE_JWT_SECRET',
  'SUPABASE_USER_MCP_JWT_HMAC_SECRET',
];

export const LAB_DUAL_GRANT_M4_RECEIPT_SCHEMA = 'supabase-user-mcp.lab-dual-grant-m4.v1' as const;
export const LAB_DUAL_GRANT_M4_MCP_VERIFIER_BOUND_MS = ACCESS_TOKEN_REVOCATION_LATENCY_BOUND_MS;

type FetchLike = typeof globalThis.fetch;

export interface LiveGoTrueLabPrincipal {
  readonly principalId: string;
  readonly userAccessToken: string;
}

export interface LiveGoTrueLabUpstreamConfig {
  readonly authOrigin: string;
  readonly publishableKey: string;
  /** Admin client registration only. Never sent on authorize, token, revoke, or Data API calls. */
  readonly serviceRoleKey: string;
  readonly exactRedirectUri: string;
  readonly principals: readonly LiveGoTrueLabPrincipal[];
}

export interface LiveUpstreamSyncBridge {
  call<T>(operation: LiveUpstreamOperation): T;
  close(): Promise<void>;
}

export interface LiveGoTrueLabUpstreamOptions {
  readonly fetch?: FetchLike;
  readonly bridge?: LiveUpstreamSyncBridge;
}

export type LiveUpstreamOperation =
  | {
      readonly op: 'startAuthorization';
      readonly authOrigin: string;
      readonly publishableKey: string;
      readonly clientId: string;
      readonly redirectUri: string;
      readonly resource: string;
      readonly codeChallenge: string;
      readonly state: string;
    }
  | {
      readonly op: 'approveAuthorization';
      readonly authOrigin: string;
      readonly publishableKey: string;
      readonly authorizationId: string;
      readonly userAccessToken: string;
    }
  | {
      readonly op: 'denyAuthorization';
      readonly authOrigin: string;
      readonly publishableKey: string;
      readonly authorizationId: string;
      readonly userAccessToken: string;
    }
  | {
      readonly op: 'revokeGrant';
      readonly authOrigin: string;
      readonly publishableKey: string;
      readonly clientId: string;
      readonly userAccessToken: string;
      readonly refreshToken: string;
      readonly resource: string;
    };

export interface LiveProviderRevokeMeasurement {
  readonly httpStatus: number;
  readonly providerRevokeLatencyMs: number;
  readonly refreshProbeLatencyMs: number;
  readonly refreshDenied: boolean;
  readonly dataApiRevocationSlaClaimed: false;
  readonly mcpVerifierBoundMs: typeof LAB_DUAL_GRANT_M4_MCP_VERIFIER_BOUND_MS;
  readonly mcpVerifierBoundAppliedToDataApi: false;
}

export interface LabDualGrantM4Receipt {
  readonly schema: typeof LAB_DUAL_GRANT_M4_RECEIPT_SCHEMA;
  readonly repositorySha: string;
  readonly treeSha: string;
  readonly node: string;
  readonly npm: string;
  readonly supabase: string;
  readonly oauthServer: 'local-cli';
  readonly dynamicClientRegistration: false;
  readonly hostedLiveOAuth: 'unmet';
  readonly encryptedRefreshAtRest: false;
  readonly refreshAtRest: false;
  readonly serviceRoleOnRequestPath: false;
  readonly ordinaryRemoteOpened: false;
  readonly loopbackBindHost: '127.0.0.1';
  readonly externalMcpBinary: false;
  readonly ordinaryRemoteProfile: {
    readonly dataDispatch: 'fail-closed';
    readonly downstreamCredential: 'unresolved';
    readonly labDualGrantEnvAloneOpensDispatch: false;
    readonly profileHookWithoutEnvOpensDispatch: false;
  };
  readonly labDualGrantProfile: {
    readonly dataDispatch: 'loopback-lab-only';
    readonly optIn: 'env-and-hook';
    readonly custody: 'memory-only';
    readonly registeredPublicClients: 2;
    readonly providerAuthorizationRedirectIncludesIss: boolean;
  };
  readonly mcpSdk: {
    readonly packageName: string;
    readonly version: string;
    readonly inProcess: true;
  };
  readonly gates: {
    readonly t3HappyPath: 'pass';
    readonly t4RlsIsolation: 'pass';
    readonly t5WrongClient: 'pass';
    readonly t10BrokerNextCallDeny: 'pass';
    readonly t10ProviderRevoke: LiveProviderRevokeMeasurement;
    readonly t10DataApiProbe: {
      readonly latencyMs: number;
      readonly httpStatus: number;
      readonly accessJwtRejected: boolean;
      readonly recordVisible: boolean;
      readonly slaClaimed: false;
    };
    readonly t17Cleanup: 'pass';
    readonly ordinaryFailClosed: 'pass';
  };
  readonly broker: {
    readonly custody: LabDualGrantReceipt['custody'];
    readonly encryptedRefreshAtRest: false;
    readonly ordinaryRemoteDataDispatch: 'fail-closed';
    readonly mcpSigningAlg: 'ES256';
    readonly activeGrantsAfterCleanup: 0;
    readonly restartProvesProviderRevoke: false;
  };
  readonly cases: readonly string[];
  readonly result: 'pass';
}

interface StoredUpstreamGrant {
  readonly principalId: string;
  readonly refreshToken: string;
  accessToken: string;
}

function fail(code: string): never {
  throw new LabDualGrantError(code);
}

export function assertLiveLabLoopbackOrigin(value: string, code = 'redirect_not_loopback'): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    fail(code);
  }
  if (
    url.protocol !== 'http:' ||
    url.hostname !== '127.0.0.1' ||
    url.username !== '' ||
    url.password !== '' ||
    url.hash !== '' ||
    url.search !== ''
  ) {
    fail(code);
  }
  return url;
}

function assertPublishableKey(value: string): void {
  if (
    value.trim().length === 0 ||
    value.split('.').length === 3 ||
    value.includes('service_role') ||
    value.includes('serviceRole')
  ) {
    fail('privileged_credential');
  }
}

function assertNoPrivilegedKeys(value: object): void {
  for (const key of Object.keys(value)) {
    if (FORBIDDEN_OPERATION_KEYS.has(key)) fail('privileged_credential');
  }
}

export function attachUpstreamIssuerToConsentRedirect(input: {
  readonly location: string;
  readonly exactRedirectUri: string;
  readonly upstreamIssuer: string;
}): { readonly url: URL; readonly providerIncludedIss: boolean } {
  const redirect = assertLiveLabLoopbackOrigin(input.exactRedirectUri, 'invalid_redirect');
  if (redirect.pathname === '/' || redirect.pathname === '') fail('invalid_redirect');
  let url: URL;
  try {
    url = new URL(input.location);
  } catch {
    fail('invalid_redirect');
  }
  if (
    url.protocol !== redirect.protocol ||
    url.host !== redirect.host ||
    url.pathname !== redirect.pathname ||
    url.username !== '' ||
    url.password !== '' ||
    url.hash !== ''
  ) {
    fail('invalid_redirect');
  }
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  if (!code || !state) fail('invalid_grant');
  const presented = url.searchParams.get('iss');
  const providerIncludedIss = presented !== null;
  if (providerIncludedIss && presented !== input.upstreamIssuer) fail('mixup');
  if (!providerIncludedIss) url.searchParams.set('iss', input.upstreamIssuer);
  return { url, providerIncludedIss };
}

function expiresInFromAccessToken(
  token: string,
  expiresIn: number | undefined,
  nowMs: number,
): number {
  if (typeof expiresIn === 'number' && Number.isSafeInteger(expiresIn) && expiresIn > 0) {
    return expiresIn;
  }
  const claims = decodeJwtPayloadClaims(token);
  const exp = claims.exp;
  const iat = claims.iat;
  if (typeof exp === 'number' && typeof iat === 'number' && exp > iat) return exp - iat;
  if (typeof exp === 'number') {
    const remaining = exp - Math.floor(nowMs / 1000);
    if (remaining > 0) return remaining;
  }
  fail('upstream_expired');
}

function workerEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (typeof value !== 'string') continue;
    if (key.startsWith('M4_') || WORKER_ENV_BLOCK.includes(key)) continue;
    env[key] = value;
  }
  return env;
}

function liveUpstreamWorkerEntry(): URL {
  const candidates = [
    new URL('./live-gotrue-lab-upstream.worker.js', import.meta.url),
    new URL('../dist/live-gotrue-lab-upstream.worker.js', import.meta.url),
  ];
  for (const candidate of candidates) {
    if (existsSync(fileURLToPath(candidate))) return candidate;
  }
  fail('live_upstream_failed');
}

export function createLiveUpstreamWorkerBridge(): LiveUpstreamSyncBridge {
  // tsx does not install its loader inside a worker thread. The bridge runs
  // the built JavaScript worker, which `npm run build` emits before the suite.
  const worker = new Worker(liveUpstreamWorkerEntry(), {
    execArgv: [],
    env: workerEnv(),
    stderr: true,
    stdout: true,
  });
  let stderr = '';
  worker.stderr?.setEncoding('utf8');
  worker.stderr?.on('data', (chunk: string) => {
    stderr = `${stderr}${chunk}`.slice(-400).replace(/eyJ[A-Za-z0-9_-]+/g, '[redacted]');
  });
  return {
    call<T>(operation: LiveUpstreamOperation): T {
      const sab = new SharedArrayBuffer(4);
      const flag = new Int32Array(sab);
      const { port1, port2 } = new MessageChannel();
      worker.postMessage({ operation, sab, port: port2 }, [port2]);
      const status = Atomics.wait(flag, 0, 0, BRIDGE_TIMEOUT_MS);
      if (status === 'timed-out') fail('live_upstream_timeout');
      const received = receiveMessageOnPort(port1) as
        | { message?: { ok?: boolean; result?: T; error?: string } }
        | undefined;
      const message = received?.message;
      if (!message?.ok) {
        const code =
          message?.error ?? (stderr.length > 0 ? 'live_upstream_failed' : 'live_upstream_empty');
        fail(code);
      }
      return message.result as T;
    },
    async close(): Promise<void> {
      await worker.terminate();
    },
  };
}

export async function performLiveUpstreamOperation(
  operation: LiveUpstreamOperation,
  fetchImpl: FetchLike = globalThis.fetch,
): Promise<
  | { readonly authorizationId: string }
  | { readonly location: string }
  | { readonly denied: true }
  | Omit<
      LiveProviderRevokeMeasurement,
      'dataApiRevocationSlaClaimed' | 'mcpVerifierBoundMs' | 'mcpVerifierBoundAppliedToDataApi'
    >
> {
  assertNoPrivilegedKeys(operation);
  assertLiveLabLoopbackOrigin(operation.authOrigin, 'redirect_not_loopback');
  assertPublishableKey(operation.publishableKey);
  if (operation.op === 'startAuthorization') {
    assertLiveLabLoopbackOrigin(operation.redirectUri, 'invalid_redirect');
    assertLiveLabLoopbackOrigin(operation.resource, 'invalid_resource');
    const started = await startLocalAuthorization({
      authOrigin: operation.authOrigin,
      clientId: operation.clientId,
      redirectUri: operation.redirectUri,
      resource: operation.resource,
      codeChallenge: operation.codeChallenge,
      state: operation.state,
      projectPublishableKey: operation.publishableKey,
      fetch: fetchImpl,
    });
    return { authorizationId: started.authorizationId };
  }
  if (operation.op === 'approveAuthorization') {
    const approved = await approveLocalAuthorization({
      authOrigin: operation.authOrigin,
      authorizationId: operation.authorizationId,
      userAccessToken: operation.userAccessToken,
      projectPublishableKey: operation.publishableKey,
      fetch: fetchImpl,
    });
    return { location: approved.location };
  }
  if (operation.op === 'denyAuthorization') {
    await denyLocalAuthorization({
      authOrigin: operation.authOrigin,
      authorizationId: operation.authorizationId,
      userAccessToken: operation.userAccessToken,
      projectPublishableKey: operation.publishableKey,
      fetch: fetchImpl,
    });
    return { denied: true };
  }
  const revokeStarted = performance.now();
  const httpStatus = await revokeLocalGrant({
    authOrigin: operation.authOrigin,
    clientId: operation.clientId,
    userAccessToken: operation.userAccessToken,
    projectPublishableKey: operation.publishableKey,
    fetch: fetchImpl,
  });
  const providerRevokeLatencyMs = Math.round(performance.now() - revokeStarted);
  const refreshStarted = performance.now();
  let refreshDenied = false;
  try {
    await refreshLocalAccessToken({
      authOrigin: operation.authOrigin,
      clientId: operation.clientId,
      refreshToken: operation.refreshToken,
      resource: operation.resource,
      fetch: fetchImpl,
    });
  } catch {
    refreshDenied = true;
  }
  return {
    httpStatus,
    providerRevokeLatencyMs,
    refreshProbeLatencyMs: Math.round(performance.now() - refreshStarted),
    refreshDenied,
  };
}

async function discoverLoopbackIssuer(authOrigin: string, fetchImpl: FetchLike): Promise<string> {
  const origin = assertLiveLabLoopbackOrigin(authOrigin);
  if (origin.pathname !== '/' && origin.pathname !== '') fail('invalid_resource');
  const response = await fetchImpl(
    new URL('/auth/v1/.well-known/openid-configuration', origin.origin),
    { headers: { accept: 'application/json' } },
  );
  if (!response.ok) fail('invalid_resource');
  const body = (await response.json()) as { issuer?: unknown };
  if (typeof body.issuer !== 'string') fail('mixup');
  const issuer = assertLiveLabLoopbackOrigin(body.issuer, 'mixup');
  if (issuer.host !== origin.host || issuer.pathname !== '/auth/v1') fail('mixup');
  return canonicalizeResourceUri(issuer.toString());
}

/**
 * Live GoTrue adapter for the lab dual-grant broker. Registers two temporary
 * public clients. Service-role is used only for that admin registration.
 */
export class LiveGoTrueLabUpstream implements LabUpstreamOAuth {
  readonly upstreamClientId: string;
  readonly wrongClientId: string;
  readonly upstreamIssuer: string;
  readonly upstreamResourceUri: string;
  readonly dataApiOrigin: string;
  readonly exactRedirectUri: string;
  private readonly authOrigin: string;
  private readonly publishableKey: string;
  private readonly fetchImpl: FetchLike;
  private readonly bridge: LiveUpstreamSyncBridge;
  private readonly principals = new Map<string, string>();
  private readonly pendingPrincipal = new Map<string, string>();
  private readonly grantsByRefresh = new Map<string, StoredUpstreamGrant>();
  private readonly grantsByPrincipal = new Map<string, StoredUpstreamGrant>();
  private providerIncludedIss: boolean | null = null;
  private revokeMeasurement: LiveProviderRevokeMeasurement | undefined;

  private constructor(input: {
    readonly authOrigin: string;
    readonly publishableKey: string;
    readonly exactRedirectUri: string;
    readonly upstreamClientId: string;
    readonly wrongClientId: string;
    readonly upstreamIssuer: string;
    readonly principals: readonly LiveGoTrueLabPrincipal[];
    readonly fetchImpl: FetchLike;
    readonly bridge: LiveUpstreamSyncBridge;
  }) {
    this.authOrigin = input.authOrigin;
    this.publishableKey = input.publishableKey;
    this.exactRedirectUri = input.exactRedirectUri;
    this.upstreamClientId = input.upstreamClientId;
    this.wrongClientId = input.wrongClientId;
    this.upstreamIssuer = input.upstreamIssuer;
    const origin = new URL(input.authOrigin);
    this.dataApiOrigin = origin.origin;
    this.upstreamResourceUri = canonicalizeResourceUri(
      new URL('/rest/v1', origin.origin).toString(),
    );
    this.fetchImpl = input.fetchImpl;
    this.bridge = input.bridge;
    for (const principal of input.principals) {
      this.principals.set(principal.principalId, principal.userAccessToken);
    }
  }

  static async create(
    config: LiveGoTrueLabUpstreamConfig,
    options: LiveGoTrueLabUpstreamOptions = {},
  ): Promise<LiveGoTrueLabUpstream> {
    assertPublishableKey(config.publishableKey);
    if (
      config.serviceRoleKey.trim().length === 0 ||
      config.serviceRoleKey === config.publishableKey
    ) {
      fail('privileged_credential');
    }
    const origin = assertLiveLabLoopbackOrigin(config.authOrigin);
    if (origin.pathname !== '/' && origin.pathname !== '') fail('redirect_not_loopback');
    const redirect = assertLiveLabLoopbackOrigin(config.exactRedirectUri, 'invalid_redirect');
    if (redirect.pathname === '/' || redirect.pathname === '') fail('invalid_redirect');
    if (config.principals.length < 2) fail('invalid_principal');
    const seen = new Set<string>();
    for (const principal of config.principals) {
      if (!UUID.test(principal.principalId) || seen.has(principal.principalId)) {
        fail('invalid_principal');
      }
      if (
        principal.userAccessToken.split('.').length !== 3 ||
        principal.userAccessToken === config.publishableKey ||
        principal.userAccessToken === config.serviceRoleKey
      ) {
        fail('invalid_grant');
      }
      seen.add(principal.principalId);
    }
    const fetchImpl = options.fetch ?? globalThis.fetch;
    const upstreamIssuer = await discoverLoopbackIssuer(origin.origin, fetchImpl);
    const upstream = await registerLocalPublicOAuthClient({
      authOrigin: origin.origin,
      serviceRoleKey: config.serviceRoleKey,
      clientName: 'lab-dg-upstream',
      redirectUri: config.exactRedirectUri,
      fetch: fetchImpl,
    });
    const wrong = await registerLocalPublicOAuthClient({
      authOrigin: origin.origin,
      serviceRoleKey: config.serviceRoleKey,
      clientName: 'lab-dg-other',
      redirectUri: config.exactRedirectUri,
      fetch: fetchImpl,
    });
    if (
      !UUID.test(upstream.clientId) ||
      !UUID.test(wrong.clientId) ||
      upstream.clientId === wrong.clientId
    ) {
      fail('invalid_client');
    }
    const bridge = options.bridge ?? createLiveUpstreamWorkerBridge();
    return new LiveGoTrueLabUpstream({
      authOrigin: origin.origin,
      publishableKey: config.publishableKey,
      exactRedirectUri: config.exactRedirectUri,
      upstreamClientId: upstream.clientId,
      wrongClientId: wrong.clientId,
      upstreamIssuer,
      principals: config.principals,
      fetchImpl,
      bridge,
    });
  }

  providerRedirectIncludedIss(): boolean | null {
    return this.providerIncludedIss;
  }

  lastProviderRevokeMeasurement(): LiveProviderRevokeMeasurement | undefined {
    return this.revokeMeasurement;
  }

  upstreamAccessTokenForProbe(principalId: string): string {
    const grant = this.grantsByPrincipal.get(principalId);
    if (!grant) fail('reauth_required');
    return grant.accessToken;
  }

  async close(): Promise<void> {
    await this.bridge.close();
  }

  secretMaterial(): readonly string[] {
    const values = [...this.principals.values()];
    for (const grant of this.grantsByRefresh.values()) {
      values.push(grant.accessToken, grant.refreshToken);
    }
    return values;
  }

  startAuthorization(request: LabUpstreamAuthorizationRequest): string {
    if (request.responseType !== 'code' || request.codeChallengeMethod !== 'S256') {
      fail('invalid_request');
    }
    if (request.clientId !== this.upstreamClientId) fail('wrong_client');
    if (request.redirectUri !== this.exactRedirectUri) fail('invalid_redirect');
    if (canonicalizeResourceUri(request.resource) !== this.upstreamResourceUri) {
      fail('invalid_resource');
    }
    if (!this.principals.has(request.principalId)) fail('invalid_principal');
    const started = this.bridge.call<{ authorizationId: string }>({
      op: 'startAuthorization',
      authOrigin: this.authOrigin,
      publishableKey: this.publishableKey,
      clientId: request.clientId,
      redirectUri: request.redirectUri,
      resource: request.resource,
      codeChallenge: request.codeChallenge,
      state: request.state,
    });
    this.pendingPrincipal.set(started.authorizationId, request.principalId);
    return started.authorizationId;
  }

  approveAuthorization(authorizationId: string): URL {
    const principalId = this.pendingPrincipal.get(authorizationId);
    const userAccessToken = principalId ? this.principals.get(principalId) : undefined;
    if (!principalId || !userAccessToken) fail('invalid_grant');
    const approved = this.bridge.call<{ location: string }>({
      op: 'approveAuthorization',
      authOrigin: this.authOrigin,
      publishableKey: this.publishableKey,
      authorizationId,
      userAccessToken,
    });
    const attached = attachUpstreamIssuerToConsentRedirect({
      location: approved.location,
      exactRedirectUri: this.exactRedirectUri,
      upstreamIssuer: this.upstreamIssuer,
    });
    this.providerIncludedIss =
      this.providerIncludedIss === null
        ? attached.providerIncludedIss
        : this.providerIncludedIss && attached.providerIncludedIss;
    return attached.url;
  }

  denyAuthorization(authorizationId: string): URL {
    const principalId = this.pendingPrincipal.get(authorizationId);
    const userAccessToken = principalId ? this.principals.get(principalId) : undefined;
    if (!principalId || !userAccessToken) fail('invalid_grant');
    this.bridge.call<{ denied: true }>({
      op: 'denyAuthorization',
      authOrigin: this.authOrigin,
      publishableKey: this.publishableKey,
      authorizationId,
      userAccessToken,
    });
    const url = new URL(this.exactRedirectUri);
    url.searchParams.set('error', 'access_denied');
    url.searchParams.set('iss', this.upstreamIssuer);
    return url;
  }

  async exchangeAuthorizationCode(input: {
    readonly grantType: 'authorization_code';
    readonly code: string;
    readonly clientId: string;
    readonly redirectUri: string;
    readonly codeVerifier: string;
    readonly resource: string;
  }): Promise<LabUpstreamTokenSuccess> {
    if (input.grantType !== 'authorization_code') fail('invalid_grant');
    if (input.redirectUri !== this.exactRedirectUri) fail('invalid_redirect');
    if (canonicalizeResourceUri(input.resource) !== this.upstreamResourceUri) {
      fail('invalid_resource');
    }
    const issued = await exchangeLocalAuthorizationCode({
      authOrigin: this.authOrigin,
      clientId: input.clientId,
      redirectUri: input.redirectUri,
      code: input.code,
      codeVerifier: input.codeVerifier,
      resource: input.resource,
      projectPublishableKey: this.publishableKey,
      fetch: this.fetchImpl,
    });
    if (!issued.refreshToken) fail('invalid_grant');
    let claims: Record<string, unknown>;
    try {
      claims = decodeJwtPayloadClaims(issued.accessToken);
    } catch {
      fail('invalid_grant');
    }
    const clientId = extractServerControlledClientId(claims);
    if (clientId !== input.clientId) fail('wrong_client');
    const subject = claims.sub;
    if (typeof subject !== 'string' || !UUID.test(subject)) fail('cross_user');
    if (
      typeof claims.iss !== 'string' ||
      canonicalizeResourceUri(claims.iss) !== this.upstreamIssuer
    ) {
      fail('mixup');
    }
    if (input.clientId === this.upstreamClientId && this.principals.has(subject)) {
      const stored: StoredUpstreamGrant = {
        principalId: subject,
        refreshToken: issued.refreshToken,
        accessToken: issued.accessToken,
      };
      this.grantsByRefresh.set(issued.refreshToken, stored);
      this.grantsByPrincipal.set(subject, stored);
    }
    return {
      accessToken: issued.accessToken,
      refreshToken: issued.refreshToken,
      expiresIn: expiresInFromAccessToken(issued.accessToken, issued.expiresIn, Date.now()),
    };
  }

  async refresh(input: {
    readonly grantType: 'refresh_token';
    readonly refreshToken: string;
    readonly clientId: string;
    readonly resource: string;
  }): Promise<LabUpstreamTokenSuccess> {
    if (input.grantType !== 'refresh_token') fail('invalid_grant');
    if (input.clientId !== this.upstreamClientId) fail('wrong_client');
    if (canonicalizeResourceUri(input.resource) !== this.upstreamResourceUri) {
      fail('invalid_resource');
    }
    const issued = await refreshLocalAccessToken({
      authOrigin: this.authOrigin,
      clientId: input.clientId,
      refreshToken: input.refreshToken,
      resource: input.resource,
      fetch: this.fetchImpl,
    });
    if (!issued.refreshToken) fail('invalid_grant');
    const previous = this.grantsByRefresh.get(input.refreshToken);
    if (previous) {
      const stored: StoredUpstreamGrant = {
        principalId: previous.principalId,
        refreshToken: issued.refreshToken,
        accessToken: issued.accessToken,
      };
      this.grantsByRefresh.delete(input.refreshToken);
      this.grantsByRefresh.set(issued.refreshToken, stored);
      this.grantsByPrincipal.set(previous.principalId, stored);
    }
    return {
      accessToken: issued.accessToken,
      refreshToken: issued.refreshToken,
      expiresIn: expiresInFromAccessToken(issued.accessToken, issued.expiresIn, Date.now()),
    };
  }

  revokeGrant(refreshToken: string): void {
    const stored = this.grantsByRefresh.get(refreshToken);
    const userAccessToken = stored ? this.principals.get(stored.principalId) : undefined;
    if (!stored || !userAccessToken) fail('reauth_required');
    const measured = this.bridge.call<
      Pick<
        LiveProviderRevokeMeasurement,
        'httpStatus' | 'providerRevokeLatencyMs' | 'refreshProbeLatencyMs' | 'refreshDenied'
      >
    >({
      op: 'revokeGrant',
      authOrigin: this.authOrigin,
      publishableKey: this.publishableKey,
      clientId: this.upstreamClientId,
      userAccessToken,
      refreshToken,
      resource: this.upstreamResourceUri,
    });
    this.revokeMeasurement = {
      ...measured,
      dataApiRevocationSlaClaimed: false,
      mcpVerifierBoundMs: LAB_DUAL_GRANT_M4_MCP_VERIFIER_BOUND_MS,
      mcpVerifierBoundAppliedToDataApi: false,
    };
  }
}

export async function createLiveGoTrueLabUpstream(
  config: LiveGoTrueLabUpstreamConfig,
  options?: LiveGoTrueLabUpstreamOptions,
): Promise<LiveGoTrueLabUpstream> {
  return LiveGoTrueLabUpstream.create(config, options);
}

const PASS_CASES = Object.freeze([
  'ordinary-remote-profile-fail-closed',
  'lab-dual-grant-env-and-hook',
  't3-in-process-mcp-sdk-gotrue-rls',
  't4-alice-bob-postgres-rls',
  't5-second-oauth-client-deny',
  't10-broker-next-call-deny',
  't10-provider-revoke-latency',
  't10-data-api-revoke-probe-no-sla',
  't17-memory-custody-cleanup',
]);

export function buildLabDualGrantM4Receipt(input: {
  readonly repositorySha: string;
  readonly treeSha: string;
  readonly node: string;
  readonly npm: string;
  readonly supabase: string;
  readonly providerAuthorizationRedirectIncludesIss: boolean;
  readonly mcpSdkPackageName: string;
  readonly mcpSdkVersion: string;
  readonly t10ProviderRevoke: LiveProviderRevokeMeasurement;
  readonly t10DataApiProbe: LabDualGrantM4Receipt['gates']['t10DataApiProbe'];
  readonly forbiddenSubstrings: readonly string[];
}): LabDualGrantM4Receipt {
  if (!SHA.test(input.repositorySha) || !SHA.test(input.treeSha)) fail('invalid_request');
  if (
    !input.t10ProviderRevoke.refreshDenied ||
    input.t10ProviderRevoke.dataApiRevocationSlaClaimed !== false ||
    input.t10ProviderRevoke.mcpVerifierBoundAppliedToDataApi !== false ||
    input.t10DataApiProbe.slaClaimed !== false ||
    !Number.isFinite(input.t10ProviderRevoke.providerRevokeLatencyMs) ||
    !Number.isFinite(input.t10ProviderRevoke.refreshProbeLatencyMs) ||
    !Number.isFinite(input.t10DataApiProbe.latencyMs)
  ) {
    fail('invalid_request');
  }
  const receipt: LabDualGrantM4Receipt = {
    schema: LAB_DUAL_GRANT_M4_RECEIPT_SCHEMA,
    repositorySha: input.repositorySha,
    treeSha: input.treeSha,
    node: input.node,
    npm: input.npm,
    supabase: input.supabase,
    oauthServer: 'local-cli',
    dynamicClientRegistration: false,
    hostedLiveOAuth: 'unmet',
    encryptedRefreshAtRest: false,
    refreshAtRest: false,
    serviceRoleOnRequestPath: false,
    ordinaryRemoteOpened: false,
    loopbackBindHost: '127.0.0.1',
    externalMcpBinary: false,
    ordinaryRemoteProfile: {
      dataDispatch: 'fail-closed',
      downstreamCredential: 'unresolved',
      labDualGrantEnvAloneOpensDispatch: false,
      profileHookWithoutEnvOpensDispatch: false,
    },
    labDualGrantProfile: {
      dataDispatch: 'loopback-lab-only',
      optIn: 'env-and-hook',
      custody: 'memory-only',
      registeredPublicClients: 2,
      providerAuthorizationRedirectIncludesIss: input.providerAuthorizationRedirectIncludesIss,
    },
    mcpSdk: {
      packageName: input.mcpSdkPackageName,
      version: input.mcpSdkVersion,
      inProcess: true,
    },
    gates: {
      t3HappyPath: 'pass',
      t4RlsIsolation: 'pass',
      t5WrongClient: 'pass',
      t10BrokerNextCallDeny: 'pass',
      t10ProviderRevoke: input.t10ProviderRevoke,
      t10DataApiProbe: input.t10DataApiProbe,
      t17Cleanup: 'pass',
      ordinaryFailClosed: 'pass',
    },
    broker: {
      custody: 'memory-only',
      encryptedRefreshAtRest: false,
      ordinaryRemoteDataDispatch: 'fail-closed',
      mcpSigningAlg: 'ES256',
      activeGrantsAfterCleanup: 0,
      restartProvesProviderRevoke: false,
    },
    cases: PASS_CASES,
    result: 'pass',
  };
  const serialized = JSON.stringify(receipt);
  if (serialized.includes('eyJ')) fail('invalid_request');
  for (const secret of input.forbiddenSubstrings) {
    if (secret.length > 0 && serialized.includes(secret)) fail('invalid_request');
  }
  return receipt;
}
