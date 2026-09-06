import { createHash } from 'node:crypto';

import {
  type AuthInfo,
  OAuthError,
  OAuthErrorCode,
  type OAuthTokenVerifier,
} from '@modelcontextprotocol/server';
import {
  ACCESS_TOKEN_REVOCATION_LATENCY_BOUND_MS,
  DATA_API_AUDIENCE,
  RemoteOAuthClientIdSchema,
  RemotePrincipalIdSchema,
  audienceValues,
  canonicalizeResourceUri,
  extractServerControlledClientId,
} from '@supabase-user-mcp/contracts';
import {
  createRemoteJWKSet,
  customFetch,
  jwtVerify,
  type JWTPayload,
  type JWTVerifyGetKey,
} from 'jose';

const UUID_SESSION = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export type RemoteTokenSigningKey =
  | { readonly kind: 'hmac'; readonly secret: Uint8Array }
  | { readonly kind: 'jwks'; readonly jwksUrl: URL };

export type AccessTokenRevocationVerdict = 'active' | 'revoked';

export interface AccessTokenRevocationInspectInput {
  readonly sessionId: string;
  readonly tokenFingerprint: string;
  readonly nowMs: number;
  readonly accessToken: string;
}

export interface AccessTokenRevocationAuthority {
  inspectAccessToken(
    input: AccessTokenRevocationInspectInput,
  ): Promise<AccessTokenRevocationVerdict>;
}

export interface RemoteAccessTokenVerifierConfig {
  readonly issuer: string;
  readonly resourceUri: string;
  readonly expectedClientId: string;
  readonly signingKey: RemoteTokenSigningKey;
  readonly revocationAuthority: AccessTokenRevocationAuthority;
  readonly now?: () => number;
  readonly fetch?: typeof globalThis.fetch;
}

export class RemoteAccessTokenVerificationError extends OAuthError {
  readonly denialClass: string;

  constructor(denialClass: string) {
    super(OAuthErrorCode.InvalidToken, 'invalid_token');
    this.name = 'RemoteAccessTokenVerificationError';
    this.denialClass = denialClass;
  }
}

function fail(denialClass: string): never {
  throw new RemoteAccessTokenVerificationError(denialClass);
}

function joseErrorCode(error: unknown): string | undefined {
  if (typeof error === 'object' && error !== null && 'code' in error) {
    const code = (error as { code?: unknown }).code;
    return typeof code === 'string' ? code : undefined;
  }
  return undefined;
}

function joseErrorClaim(error: unknown): string | undefined {
  if (typeof error === 'object' && error !== null && 'claim' in error) {
    const claim = (error as { claim?: unknown }).claim;
    return typeof claim === 'string' ? claim : undefined;
  }
  return undefined;
}

export function fingerprintAccessToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

function payloadRecord(payload: JWTPayload): Readonly<Record<string, unknown>> {
  return payload as Readonly<Record<string, unknown>>;
}

function resourceCandidates(claims: Readonly<Record<string, unknown>>): readonly string[] {
  const values = [...audienceValues(claims.aud)];
  if (typeof claims.resource === 'string' && claims.resource.length > 0) {
    values.push(claims.resource);
  }
  return values;
}

function hasExactResourceBinding(
  claims: Readonly<Record<string, unknown>>,
  canonicalResource: string,
): boolean {
  return resourceCandidates(claims).some((value) => {
    try {
      return canonicalizeResourceUri(value) === canonicalResource;
    } catch {
      return false;
    }
  });
}

export function createRemoteAccessTokenVerifier(
  config: RemoteAccessTokenVerifierConfig,
): OAuthTokenVerifier {
  const canonicalIssuer = canonicalizeResourceUri(config.issuer);
  const canonicalResource = canonicalizeResourceUri(config.resourceUri);
  const expectedClientId = RemoteOAuthClientIdSchema.parse(config.expectedClientId);
  const resourceUrl = new URL(canonicalResource);
  const now = config.now ?? Date.now;
  const hmacKey = config.signingKey.kind === 'hmac' ? config.signingKey.secret : undefined;
  const fetchImpl = config.fetch;
  const jwks: JWTVerifyGetKey | undefined =
    config.signingKey.kind === 'jwks'
      ? createRemoteJWKSet(config.signingKey.jwksUrl, {
          timeoutDuration: ACCESS_TOKEN_REVOCATION_LATENCY_BOUND_MS,
          ...(fetchImpl === undefined
            ? {}
            : {
                [customFetch]: (url: string, options: RequestInit) => fetchImpl(url, options),
              }),
        })
      : undefined;
  if (hmacKey === undefined && jwks === undefined) {
    throw new TypeError('Remote access-token verifier requires a signing key.');
  }

  return {
    async verifyAccessToken(token: string): Promise<AuthInfo> {
      if (typeof token !== 'string' || token.split('.').length !== 3) {
        fail('malformed_bearer');
      }
      let payload: JWTPayload;
      try {
        const verified = hmacKey
          ? await jwtVerify(token, hmacKey, {
              issuer: canonicalIssuer,
              algorithms: ['HS256'],
              clockTolerance: 0,
              currentDate: new Date(now()),
            })
          : await jwtVerify(token, jwks as JWTVerifyGetKey, {
              issuer: canonicalIssuer,
              algorithms: ['RS256', 'ES256', 'ES384'],
              clockTolerance: 0,
              currentDate: new Date(now()),
            });
        payload = verified.payload;
      } catch (error) {
        if (error instanceof RemoteAccessTokenVerificationError) throw error;
        const code = joseErrorCode(error);
        const claim = joseErrorClaim(error);
        if (code === 'ERR_JWT_EXPIRED' || claim === 'exp') fail('expired');
        if (claim === 'iss') fail('wrong_issuer');
        if (claim === 'nbf') fail('not_yet_valid');
        fail('invalid_signature');
      }

      const claims = payloadRecord(payload);
      if (
        typeof payload.sub !== 'string' ||
        !RemotePrincipalIdSchema.safeParse(payload.sub).success
      ) {
        fail('missing_subject');
      }
      if (claims.role !== 'authenticated') {
        fail('wrong_role');
      }
      if (typeof payload.exp !== 'number' || !Number.isSafeInteger(payload.exp)) {
        fail('expired');
      }
      const audiences = audienceValues(payload.aud);
      if (!audiences.includes(DATA_API_AUDIENCE)) {
        fail('missing_data_api_audience');
      }
      if (!hasExactResourceBinding(claims, canonicalResource)) {
        fail(
          audiences.length === 1 && audiences[0] === DATA_API_AUDIENCE
            ? 'missing_resource_binding'
            : 'wrong_resource',
        );
      }
      const clientId = extractServerControlledClientId(claims);
      if (clientId === undefined) {
        fail('missing_client_id');
      }
      if (clientId !== expectedClientId) {
        fail('wrong_client');
      }
      const sessionId = claims.session_id;
      if (typeof sessionId !== 'string' || !UUID_SESSION.test(sessionId)) {
        fail('revoked_session');
      }

      const inspectStarted = now();
      const tokenFingerprint = fingerprintAccessToken(token);
      let verdict: AccessTokenRevocationVerdict;
      try {
        verdict = await config.revocationAuthority.inspectAccessToken({
          sessionId,
          tokenFingerprint,
          nowMs: inspectStarted,
          accessToken: token,
        });
      } catch {
        fail('revoked_access_token');
      }
      if (now() - inspectStarted > ACCESS_TOKEN_REVOCATION_LATENCY_BOUND_MS) {
        fail('revoked_access_token');
      }
      if (verdict !== 'active') {
        fail('revoked_access_token');
      }

      const scopes =
        typeof claims.scope === 'string'
          ? claims.scope.split(' ').filter((scope) => scope.length > 0)
          : [];
      return {
        token,
        clientId,
        scopes,
        expiresAt: payload.exp,
        resource: resourceUrl,
        extra: Object.freeze({
          principalId: payload.sub,
          sessionId,
          tokenFingerprint,
        }),
      };
    },
  };
}
