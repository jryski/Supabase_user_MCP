import { createNativeUserMcpReadHandler } from './native-user-mcp-read-handler.js';
import { MCP_INGRESS_ROLE, NativeUserMcpConfigError } from './native-user-mcp.js';
import {
  LISTEN_PORT_ENV,
  listenRemoteHttpHandler,
  PUBLISHABLE_KEY_ENV,
  REMOTE_HTTP_FORBIDDEN_ENV,
  RESOURCE_URI_ENV,
} from './remote-http-startup.js';

/**
 * Opt-in remote pilot entrypoint for the native user MCP read composition (#110).
 *
 * Reuses `createNativeUserMcpReadHandler` unchanged in behavior: token A is
 * verified, a distinct downstream grant B is bound through a one-time PKCE
 * handshake, source-session liveness is checked with B before every dispatch,
 * and the fixed read tools run with B only. TEST diagnostics are off and
 * cannot be enabled here. Read-only storage tools are added only when
 * `SUPABASE_USER_MCP_STORAGE_BUCKET` names a bucket and B holds `storage:read`.
 *
 * Transport: the listener binds 127.0.0.1 only. An operator TLS terminator
 * (reverse proxy or tunnel) publishes `https://<host>` and forwards to it.
 *
 * This is a synthetic, read-only pilot surface, not a production deployment.
 */

export const NATIVE_REMOTE_PILOT_OPT_IN_ENV = 'SUPABASE_USER_MCP_NATIVE_REMOTE_PILOT';
export const NATIVE_REMOTE_PILOT_OPT_IN_VALUE = 'synthetic-readonly-memory-only-grants';
export const NATIVE_REMOTE_PILOT_SUPABASE_URL_ENV = 'SUPABASE_USER_MCP_SUPABASE_URL';
export const NATIVE_REMOTE_PILOT_A_CLIENT_ID_ENV = 'SUPABASE_USER_MCP_A_CLIENT_ID';
export const NATIVE_REMOTE_PILOT_AGENT_ID_ENV = 'SUPABASE_USER_MCP_AGENT_ID';
export const NATIVE_REMOTE_PILOT_JWKS_URL_ENV = 'SUPABASE_USER_MCP_JWKS_URL';
export const NATIVE_REMOTE_PILOT_B_CLIENT_ID_ENV = 'SUPABASE_USER_MCP_B_CLIENT_ID';
export const NATIVE_REMOTE_PILOT_B_REDIRECT_URI_ENV = 'SUPABASE_USER_MCP_B_REDIRECT_URI';

/**
 * Optional. A Storage bucket name (never a key or URL). Unset or empty keeps
 * storage off. When set, read-only storage tools are listed for a session
 * whose grant B holds `storage:read`; other sessions see no storage tools.
 */
export const NATIVE_REMOTE_PILOT_STORAGE_BUCKET_ENV = 'SUPABASE_USER_MCP_STORAGE_BUCKET';

/** Names only. Values are never logged or echoed. */
export const NATIVE_REMOTE_PILOT_REQUIRED_ENV = Object.freeze([
  NATIVE_REMOTE_PILOT_OPT_IN_ENV,
  RESOURCE_URI_ENV,
  NATIVE_REMOTE_PILOT_SUPABASE_URL_ENV,
  NATIVE_REMOTE_PILOT_A_CLIENT_ID_ENV,
  NATIVE_REMOTE_PILOT_AGENT_ID_ENV,
  PUBLISHABLE_KEY_ENV,
  NATIVE_REMOTE_PILOT_JWKS_URL_ENV,
  NATIVE_REMOTE_PILOT_B_CLIENT_ID_ENV,
  NATIVE_REMOTE_PILOT_B_REDIRECT_URI_ENV,
  LISTEN_PORT_ENV,
]);

/** Optional names. Unset means the feature is off. */
export const NATIVE_REMOTE_PILOT_OPTIONAL_ENV = Object.freeze([
  NATIVE_REMOTE_PILOT_STORAGE_BUCKET_ENV,
]);

/**
 * Grant custody disclosure. B grants live in process memory only. Refresh
 * tokens are discarded at exchange. A restart loses every B grant, and a B
 * grant ends at its access-token expiry. Either case requires the user to
 * authorize B again. Nothing here is a durable production custody claim.
 */
export const NATIVE_REMOTE_PILOT_CUSTODY = Object.freeze({
  grantStorage: 'process-memory-only',
  refreshTokens: 'discarded-at-exchange',
  onRestart: 'all-b-grants-lost-reauthorization-required',
  onExpiry: 'b-grant-ends-at-b-access-token-exp-reauthorization-required',
  durableProductionCustody: false,
} as const);

export interface NativeUserMcpRemotePilotOptions {
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly argv?: readonly string[];
  readonly fetch?: typeof globalThis.fetch;
  readonly now?: () => number;
}

export interface NativeUserMcpRemotePilot {
  readonly handler: (request: Request) => Promise<Response>;
  readonly listenPort: number;
  readonly custody: typeof NATIVE_REMOTE_PILOT_CUSTODY;
}

function invalid(): never {
  throw new NativeUserMcpConfigError();
}

function httpsUrl(value: string | undefined): URL {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) invalid();
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    invalid();
  }
  if (
    url.protocol !== 'https:' ||
    url.username !== '' ||
    url.password !== '' ||
    url.hash !== '' ||
    url.search !== ''
  ) {
    invalid();
  }
  return url;
}

function requiredText(value: string | undefined): string {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) invalid();
  return value;
}

/**
 * Build the pilot handler from environment names. Starts no listener.
 * Fails closed with `NativeUserMcpConfigError` on any missing, insecure, or
 * forbidden input, including a service-role or user-bearer variable.
 */
export function createNativeUserMcpRemotePilotFromEnvironment(
  options: NativeUserMcpRemotePilotOptions,
): NativeUserMcpRemotePilot {
  if ((options.argv ?? []).length !== 0) invalid();
  const env = options.env;
  for (const name of REMOTE_HTTP_FORBIDDEN_ENV) {
    const value = env[name];
    if (typeof value === 'string' && value.length > 0) invalid();
  }
  if (env[NATIVE_REMOTE_PILOT_OPT_IN_ENV] !== NATIVE_REMOTE_PILOT_OPT_IN_VALUE) invalid();

  const resource = httpsUrl(env[RESOURCE_URI_ENV]);
  const supabase = httpsUrl(env[NATIVE_REMOTE_PILOT_SUPABASE_URL_ENV]);
  const jwks = httpsUrl(env[NATIVE_REMOTE_PILOT_JWKS_URL_ENV]);
  const redirect = httpsUrl(env[NATIVE_REMOTE_PILOT_B_REDIRECT_URI_ENV]);
  // The callback is served by this process, behind the same TLS terminator.
  if (redirect.host !== resource.host) invalid();
  if (redirect.pathname === resource.pathname) invalid();
  // Keys come from the project that issues A and B.
  if (jwks.origin !== supabase.origin) invalid();

  const listenPort = Number(requiredText(env[LISTEN_PORT_ENV]));
  if (!Number.isSafeInteger(listenPort) || listenPort < 1 || listenPort > 65_535) invalid();

  // Storage is off unless a bucket name is configured. The read handler
  // validates the name and fails closed on an invalid one.
  const storageBucketValue = env[NATIVE_REMOTE_PILOT_STORAGE_BUCKET_ENV];
  const storageBucket =
    storageBucketValue === undefined || storageBucketValue === ''
      ? undefined
      : requiredText(storageBucketValue);

  const handler = createNativeUserMcpReadHandler({
    resourceServer: resource.href,
    supabaseUrl: supabase.href,
    expectedClientId: requiredText(env[NATIVE_REMOTE_PILOT_A_CLIENT_ID_ENV]),
    expectedAgentId: requiredText(env[NATIVE_REMOTE_PILOT_AGENT_ID_ENV]),
    ingressRole: MCP_INGRESS_ROLE,
    publishableKey: requiredText(env[PUBLISHABLE_KEY_ENV]),
    jwks,
    downstreamClientId: requiredText(env[NATIVE_REMOTE_PILOT_B_CLIENT_ID_ENV]),
    downstreamRedirectUri: redirect.href,
    httpsCallbackBehindTlsTerminator: true,
    downstreamAuthorizationViaToolResult: true,
    ...(storageBucket === undefined ? {} : { storageBucket, storageReadOnly: true }),
    ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
    ...(options.now === undefined ? {} : { now: options.now }),
  });
  return { handler, listenPort, custody: NATIVE_REMOTE_PILOT_CUSTODY };
}

/** Loopback-only listener, reusing the existing bounded Node transport. */
export function listenNativeUserMcpRemotePilot(
  pilot: NativeUserMcpRemotePilot,
): ReturnType<typeof listenRemoteHttpHandler> {
  return listenRemoteHttpHandler(pilot.handler, pilot.listenPort);
}
