import type { SupabaseClient } from '@supabase/supabase-js';
import { RemoteOAuthClientIdSchema, RemotePrincipalIdSchema } from '@supabase-user-mcp/contracts';

/**
 * Consent block for the Supabase Auth OAuth 2.1 server.
 *
 * `@supabase/server` 1.9.2 ships no consent screen. Its MCP guide says the
 * project needs "a consent screen hosted in the app's frontend". The official
 * building blocks are the `supabase.auth.oauth.*` methods in supabase-js
 * (`getAuthorizationDetails`, `approveAuthorization`, `denyAuthorization`).
 * This module wraps exactly those three calls and puts the existing client
 * binding in front of them:
 *
 * - the client must be the one pre-registered client id this server binds;
 * - the redirect URI must be one of the exact, pre-registered URIs;
 * - every requested scope must be in the configured allowlist;
 * - the authorization must belong to the signed-in user.
 *
 * Anything else is refused and never approved. The block reuses the caller's
 * existing signed-in session (the `oauth` namespace of a supabase-js client
 * that already holds it). It adds no sign-in method and does not touch the
 * Site URL or the authorization path, which stay in Auth configuration.
 * Browser redirects are always skipped; the caller decides what to do with a
 * returned redirect URL.
 */

export type OAuthConsentApi = Pick<
  SupabaseClient['auth']['oauth'],
  'getAuthorizationDetails' | 'approveAuthorization' | 'denyAuthorization'
>;

/** Scopes Supabase Auth's OAuth 2.1 server can issue. */
export const SUPABASE_OAUTH_SCOPES = Object.freeze([
  'openid',
  'email',
  'profile',
  'phone',
] as const);
export type SupabaseOAuthScope = (typeof SUPABASE_OAUTH_SCOPES)[number];

export const OAUTH_CONSENT_CONFIG_ERROR = 'OAUTH_CONSENT_INVALID_CONFIGURATION' as const;

export class OAuthConsentConfigError extends Error {
  readonly code = OAUTH_CONSENT_CONFIG_ERROR;

  constructor() {
    super(OAUTH_CONSENT_CONFIG_ERROR);
    this.name = 'OAuthConsentConfigError';
  }
}

export interface OAuthConsentBinding {
  /** The one server-controlled OAuth client id this deployment serves. */
  readonly expectedClientId: string;
  /** Exact redirect URIs registered for that client. No prefixes or patterns. */
  readonly redirectUris: readonly string[];
  /** Scopes the client may be granted. Each must be a Supabase OAuth scope. */
  readonly allowedScopes: readonly SupabaseOAuthScope[];
}

export type OAuthConsentRefusal =
  | 'invalid_authorization_id'
  | 'invalid_user'
  | 'sign_in_required'
  | 'authorization_unavailable'
  | 'client_not_bound'
  | 'redirect_not_bound'
  | 'scope_not_bound'
  | 'user_mismatch';

export type OAuthConsentView =
  | {
      readonly kind: 'consent_required';
      readonly authorizationId: string;
      readonly clientId: string;
      readonly clientName: string;
      readonly redirectUri: string;
      readonly scopes: readonly SupabaseOAuthScope[];
    }
  | { readonly kind: 'redirect'; readonly redirectUrl: string }
  | { readonly kind: 'refused'; readonly reason: OAuthConsentRefusal };

export type OAuthConsentDecision = 'approve' | 'deny';

export type OAuthConsentOutcome =
  | { readonly kind: 'redirect'; readonly redirectUrl: string }
  | { readonly kind: 'refused'; readonly reason: OAuthConsentRefusal };

export interface OAuthConsentBlock {
  /** Load the pending authorization and check it against the binding. */
  readonly inspect: (
    api: OAuthConsentApi,
    authorizationId: string,
    signedInUserId: string,
  ) => Promise<OAuthConsentView>;
  /**
   * Apply the user's decision. Approval re-reads the authorization first and
   * approves only if it still matches the binding. A request that fails the
   * binding is denied upstream and reported as refused, without a redirect.
   */
  readonly decide: (
    api: OAuthConsentApi,
    authorizationId: string,
    signedInUserId: string,
    decision: OAuthConsentDecision,
  ) => Promise<OAuthConsentOutcome>;
}

const AUTHORIZATION_ID = /^[A-Za-z0-9_-]{1,128}$/u;
const SKIP_REDIRECT = Object.freeze({ skipBrowserRedirect: true });

function invalidConfig(): never {
  throw new OAuthConsentConfigError();
}

function exactRedirectUri(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    invalidConfig();
  }
  if (parsed.username !== '' || parsed.password !== '' || parsed.hash !== '') invalidConfig();
  if (parsed.search !== '') invalidConfig();
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') invalidConfig();
  if (parsed.href !== value) invalidConfig();
  return value;
}

function resolveBinding(binding: OAuthConsentBinding): {
  readonly clientId: string;
  readonly redirectUris: ReadonlySet<string>;
  readonly scopes: ReadonlySet<SupabaseOAuthScope>;
} {
  const clientId = RemoteOAuthClientIdSchema.safeParse(binding.expectedClientId);
  if (!clientId.success) invalidConfig();
  if (binding.redirectUris.length === 0) invalidConfig();
  const redirectUris = new Set(binding.redirectUris.map(exactRedirectUri));
  if (binding.allowedScopes.length === 0) invalidConfig();
  for (const scope of binding.allowedScopes) {
    if (!(SUPABASE_OAUTH_SCOPES as readonly string[]).includes(scope)) invalidConfig();
  }
  return { clientId: clientId.data, redirectUris, scopes: new Set(binding.allowedScopes) };
}

function redirectBase(value: string): string | undefined {
  try {
    const parsed = new URL(value);
    if (parsed.username !== '' || parsed.password !== '') return undefined;
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return undefined;
  }
}

function errorName(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null) return undefined;
  const name = (error as { name?: unknown }).name;
  return typeof name === 'string' ? name : undefined;
}

function upstreamRefusal(error: unknown): OAuthConsentRefusal {
  return errorName(error) === 'AuthSessionMissingError'
    ? 'sign_in_required'
    : 'authorization_unavailable';
}

function refused(reason: OAuthConsentRefusal): {
  readonly kind: 'refused';
  readonly reason: OAuthConsentRefusal;
} {
  return { kind: 'refused', reason };
}

export function createOAuthConsentBlock(binding: OAuthConsentBinding): OAuthConsentBlock {
  const bound = resolveBinding(binding);

  const redirectAllowed = (redirectUrl: unknown): redirectUrl is string => {
    if (typeof redirectUrl !== 'string') return false;
    const base = redirectBase(redirectUrl);
    return base !== undefined && bound.redirectUris.has(base);
  };

  const inspect = async (
    api: OAuthConsentApi,
    authorizationId: string,
    signedInUserId: string,
  ): Promise<OAuthConsentView> => {
    if (!AUTHORIZATION_ID.test(authorizationId)) return refused('invalid_authorization_id');
    if (!RemotePrincipalIdSchema.safeParse(signedInUserId).success) return refused('invalid_user');
    let result: Awaited<ReturnType<OAuthConsentApi['getAuthorizationDetails']>>;
    try {
      result = await api.getAuthorizationDetails(authorizationId);
    } catch {
      return refused('authorization_unavailable');
    }
    if (result.error !== null || result.data === null)
      return refused(upstreamRefusal(result.error));
    const data = result.data;
    if (!('authorization_id' in data)) {
      // Consent already on record upstream. Follow it only to a bound URI.
      return redirectAllowed(data.redirect_url)
        ? { kind: 'redirect', redirectUrl: data.redirect_url }
        : refused('redirect_not_bound');
    }
    if (data.authorization_id !== authorizationId) return refused('authorization_unavailable');
    if (data.user?.id !== signedInUserId) return refused('user_mismatch');
    if (data.client?.id !== bound.clientId) return refused('client_not_bound');
    if (!bound.redirectUris.has(data.redirect_uri)) return refused('redirect_not_bound');
    const requested =
      typeof data.scope === 'string' ? data.scope.split(' ').filter((s) => s !== '') : [];
    const scopes: SupabaseOAuthScope[] = [];
    for (const scope of requested) {
      if (!bound.scopes.has(scope as SupabaseOAuthScope)) return refused('scope_not_bound');
      scopes.push(scope as SupabaseOAuthScope);
    }
    return {
      kind: 'consent_required',
      authorizationId,
      clientId: data.client.id,
      clientName: data.client.name,
      redirectUri: data.redirect_uri,
      scopes: Object.freeze(scopes),
    };
  };

  const finish = (
    result: Awaited<ReturnType<OAuthConsentApi['approveAuthorization']>>,
  ): OAuthConsentOutcome => {
    if (result.error !== null || result.data === null)
      return refused(upstreamRefusal(result.error));
    return redirectAllowed(result.data.redirect_url)
      ? { kind: 'redirect', redirectUrl: result.data.redirect_url }
      : refused('redirect_not_bound');
  };

  const decide = async (
    api: OAuthConsentApi,
    authorizationId: string,
    signedInUserId: string,
    decision: OAuthConsentDecision,
  ): Promise<OAuthConsentOutcome> => {
    const view = await inspect(api, authorizationId, signedInUserId);
    if (view.kind === 'redirect') return view;
    if (view.kind === 'refused') {
      const binding =
        view.reason === 'client_not_bound' ||
        view.reason === 'redirect_not_bound' ||
        view.reason === 'scope_not_bound';
      if (binding) {
        // Close the pending request upstream; never hand back its redirect.
        try {
          await api.denyAuthorization(authorizationId, SKIP_REDIRECT);
        } catch {
          // The refusal stands either way.
        }
      }
      return view;
    }
    try {
      return finish(
        decision === 'approve'
          ? await api.approveAuthorization(authorizationId, SKIP_REDIRECT)
          : await api.denyAuthorization(authorizationId, SKIP_REDIRECT),
      );
    } catch {
      return refused('authorization_unavailable');
    }
  };

  return Object.freeze({ inspect, decide });
}
