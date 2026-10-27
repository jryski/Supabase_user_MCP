import { RemoteOAuthClientIdSchema, RemotePrincipalIdSchema } from '@supabase-user-mcp/contracts';

/** Lives in public so PostgREST can expose it to authenticated. */
export const SOURCE_SESSION_LIVENESS_RPC = 'ari_probe_source_session_live_v1' as const;

const DEFAULT_TIMEOUT_MS = 5_000;

type FetchLike = typeof globalThis.fetch;

/** Bounded diagnostic. The raw response body is not part of this result. */
export const LIVENESS_CATEGORIES = [
  'rpc_validation',
  'auth_denial',
  'service_error',
  'malformed_response',
  'false',
  'timeout',
] as const;

export type LivenessCategory = (typeof LIVENESS_CATEGORIES)[number];

export interface SourceSessionLivenessResult {
  readonly live: boolean;
  readonly category?: LivenessCategory;
  readonly httpStatus?: number;
}

export interface SourceSessionLivenessConfig {
  readonly supabaseUrl: string;
  readonly publishableKey: string;
  readonly fetch?: FetchLike;
  readonly timeoutMs?: number;
}

export interface SourceSessionLivenessInput {
  /** Token B. Token A must not be passed here. */
  readonly accessToken: string;
  readonly sourceSessionId: string;
  readonly aClientId: string;
}

function isLoopbackHostname(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '::1' || hostname.startsWith('127.');
}

/** https anywhere. http only when the host is loopback. */
function originOf(supabaseUrl: string): string | undefined {
  try {
    const parsed = new URL(supabaseUrl);
    if (parsed.username !== '' || parsed.password !== '') return undefined;
    if (parsed.protocol === 'https:') return parsed.origin;
    if (parsed.protocol === 'http:' && isLoopbackHostname(parsed.hostname)) return parsed.origin;
    return undefined;
  } catch {
    return undefined;
  }
}

function denied(category: LivenessCategory, httpStatus?: number): SourceSessionLivenessResult {
  return httpStatus === undefined
    ? { live: false, category }
    : { live: false, category, httpStatus };
}

function boundedHttpStatus(value: number): number | undefined {
  return Number.isSafeInteger(value) && value >= 100 && value <= 599 ? value : undefined;
}

function categoryForHttp(status: number): LivenessCategory {
  if (status === 401 || status === 403) return 'auth_denial';
  if (status >= 500) return 'service_error';
  if (
    status === 400 ||
    status === 404 ||
    status === 406 ||
    status === 409 ||
    status === 415 ||
    status === 422
  ) {
    return 'rpc_validation';
  }
  return 'malformed_response';
}

/**
 * Calls `public.ari_probe_source_session_live_v1` with Token B.
 * Anything other than JSON `true` fails closed, including timeout and error.
 * The category is a bounded label. The response body is not returned.
 */
export async function classifySourceSessionLiveness(
  config: SourceSessionLivenessConfig,
  input: SourceSessionLivenessInput,
): Promise<SourceSessionLivenessResult> {
  if (input.accessToken.length === 0 || input.accessToken.split('.').length !== 3) {
    return denied('rpc_validation');
  }
  if (!RemotePrincipalIdSchema.safeParse(input.sourceSessionId).success) {
    return denied('rpc_validation');
  }
  if (input.sourceSessionId.toLowerCase() === '00000000-0000-0000-0000-000000000000') {
    return denied('rpc_validation');
  }
  if (!RemoteOAuthClientIdSchema.safeParse(input.aClientId).success) {
    return denied('rpc_validation');
  }
  const origin = originOf(config.supabaseUrl);
  if (origin === undefined || config.publishableKey.length === 0) return denied('rpc_validation');
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10_000) {
    return denied('rpc_validation');
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await (config.fetch ?? globalThis.fetch)(
      `${origin}/rest/v1/rpc/${SOURCE_SESSION_LIVENESS_RPC}`,
      {
        method: 'POST',
        redirect: 'error',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          Authorization: `Bearer ${input.accessToken}`,
          apikey: config.publishableKey,
        },
        body: JSON.stringify({
          source_session_id: input.sourceSessionId,
          a_client_id: input.aClientId,
        }),
        signal: controller.signal,
      },
    );
    const httpStatus = boundedHttpStatus(response.status);
    if (httpStatus === undefined) {
      await response.body?.cancel().catch(() => undefined);
      return denied('malformed_response');
    }
    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      return denied(categoryForHttp(httpStatus), httpStatus);
    }
    let body: string;
    try {
      body = await response.text();
    } catch {
      return denied('malformed_response', httpStatus);
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(body);
    } catch {
      return denied('malformed_response', httpStatus);
    }
    if (parsed === true) return { live: true };
    if (parsed === false) return denied('false', httpStatus);
    return denied('malformed_response', httpStatus);
  } catch (error) {
    const name = error instanceof Error ? error.name : '';
    if (name === 'AbortError' || name === 'TimeoutError') return denied('timeout');
    return denied('service_error');
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Calls `public.ari_probe_source_session_live_v1` with Token B.
 * Anything other than JSON `true` fails closed, including timeout and error.
 */
export async function probeSourceSessionLive(
  config: SourceSessionLivenessConfig,
  input: SourceSessionLivenessInput,
): Promise<boolean> {
  const result = await classifySourceSessionLiveness(config, input);
  return result.live;
}
