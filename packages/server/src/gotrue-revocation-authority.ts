import { ACCESS_TOKEN_REVOCATION_LATENCY_BOUND_MS } from '@supabase-user-mcp/contracts';

import type {
  AccessTokenRevocationAuthority,
  AccessTokenRevocationInspectInput,
  AccessTokenRevocationVerdict,
} from './remote-token-verifier.js';

export interface GoTrueSessionRevocationAuthorityConfig {
  readonly origin: string;
  readonly publishableKey: string;
  readonly fetch?: typeof globalThis.fetch;
}

/**
 * Live access-token check against GoTrue `GET /auth/v1/user`.
 * Signature validity is not used. This is a session liveness probe, distinct
 * from grant/refresh rotation. No cache; callers must complete within the
 * 5s bound enforced by the verifier.
 */
export function createGoTrueSessionRevocationAuthority(
  config: GoTrueSessionRevocationAuthorityConfig,
): AccessTokenRevocationAuthority {
  const origin = new URL(config.origin);
  const fetchImpl = config.fetch ?? globalThis.fetch;
  const userUrl = new URL('/auth/v1/user', origin.origin).href;

  return {
    async inspectAccessToken(
      input: AccessTokenRevocationInspectInput,
    ): Promise<AccessTokenRevocationVerdict> {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), ACCESS_TOKEN_REVOCATION_LATENCY_BOUND_MS);
      try {
        const response = await fetchImpl(userUrl, {
          method: 'GET',
          redirect: 'error',
          headers: {
            Accept: 'application/json',
            Authorization: `Bearer ${input.accessToken}`,
            apikey: config.publishableKey,
          },
          signal: controller.signal,
        });
        if (response.redirected) return 'revoked';
        if (response.status === 401 || response.status === 403) return 'revoked';
        if (!response.ok) return 'revoked';
        return 'active';
      } catch {
        return 'revoked';
      } finally {
        clearTimeout(timer);
      }
    },
  };
}
