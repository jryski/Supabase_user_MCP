import { RemoteOAuthClientIdSchema, RemotePrincipalIdSchema } from '@supabase-user-mcp/contracts';

/** Lives in public so PostgREST can expose it to authenticated. */
export const SOURCE_SESSION_LIVENESS_RPC = 'ari_probe_source_session_live_v1' as const;

const DEFAULT_TIMEOUT_MS = 5_000;

type FetchLike = typeof globalThis.fetch;

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

/**
 * Calls `public.ari_probe_source_session_live_v1` with Token B.
 * Anything other than JSON `true` fails closed, including timeout and error.
 */
export async function probeSourceSessionLive(
  config: SourceSessionLivenessConfig,
  input: SourceSessionLivenessInput,
): Promise<boolean> {
  if (input.accessToken.length === 0 || input.accessToken.split('.').length !== 3) return false;
  if (!RemotePrincipalIdSchema.safeParse(input.sourceSessionId).success) return false;
  if (input.sourceSessionId.toLowerCase() === '00000000-0000-0000-0000-000000000000') return false;
  if (!RemoteOAuthClientIdSchema.safeParse(input.aClientId).success) return false;
  const origin = originOf(config.supabaseUrl);
  if (origin === undefined || config.publishableKey.length === 0) return false;
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10_000) return false;

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
    if (!response.ok) return false;
    const body = await response.text();
    return JSON.parse(body) === true;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}
