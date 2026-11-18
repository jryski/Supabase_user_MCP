import { createHash, randomBytes, randomUUID } from 'node:crypto';

import { DATA_API_AUDIENCE, canonicalizeResourceUri } from '@supabase-user-mcp/contracts';
import { SignJWT } from 'jose';

import {
  fingerprintAccessToken,
  type AccessTokenRevocationAuthority,
  type AccessTokenRevocationInspectInput,
  type AccessTokenRevocationVerdict,
} from './remote-token-verifier.js';

export const SYNTHETIC_OAUTH_HMAC_SECRET = new TextEncoder().encode(
  'supabase-user-mcp-synthetic-oauth-hs256-key',
);

const CODE_CHALLENGE = /^[A-Za-z0-9_-]{43,128}$/;
const CODE_VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;

export interface SyntheticOAuthClient {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly tokenEndpointAuthMethod: 'none';
}

export interface SyntheticOAuthLabConfig {
  readonly issuer: string;
  readonly resourceUri: string;
  readonly client: SyntheticOAuthClient;
  readonly now?: () => number;
}

interface PendingAuthorization {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly codeChallenge: string;
  readonly resource: string;
  readonly principalId: string;
  readonly sessionId: string;
  readonly state?: string;
  consent: 'pending' | 'approved' | 'denied';
}

interface IssuedGrant {
  readonly clientId: string;
  readonly principalId: string;
  readonly sessionId: string;
  readonly resource: string;
  refreshToken: string;
  refreshFamily: number;
  revoked: boolean;
}

interface IssuedAccessToken {
  readonly fingerprint: string;
  readonly sessionId: string;
  readonly grantId: string;
  revoked: boolean;
}

export interface SyntheticAuthorizationRequest {
  readonly responseType: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly codeChallenge: string;
  readonly codeChallengeMethod: string;
  readonly resource: string;
  readonly state?: string;
  readonly principalId: string;
}

export interface SyntheticTokenSuccess {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly tokenType: 'Bearer';
  readonly expiresIn: number;
}

export class SyntheticOAuthLabError extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.name = 'SyntheticOAuthLabError';
    this.code = code;
  }
}

function pkceS256(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

function opaqueToken(prefix: string): string {
  return `${prefix}_${randomBytes(24).toString('base64url')}`;
}

export class SyntheticOAuthLab implements AccessTokenRevocationAuthority {
  readonly issuer: string;
  readonly resourceUri: string;
  readonly client: SyntheticOAuthClient;
  private readonly now: () => number;
  private readonly authorizations = new Map<string, PendingAuthorization>();
  private readonly codes = new Map<
    string,
    { readonly authorizationId: string; readonly expiresAtMs: number }
  >();
  private readonly grants = new Map<string, IssuedGrant>();
  private readonly refreshIndex = new Map<string, string>();
  private readonly accessTokens = new Map<string, IssuedAccessToken>();

  constructor(config: SyntheticOAuthLabConfig) {
    this.issuer = canonicalizeResourceUri(config.issuer);
    this.resourceUri = canonicalizeResourceUri(config.resourceUri);
    this.client = config.client;
    this.now = config.now ?? Date.now;
  }

  authorizationServerMetadata(): Readonly<Record<string, unknown>> {
    return Object.freeze({
      issuer: this.issuer,
      authorization_endpoint: `${this.issuer}/oauth/authorize`,
      token_endpoint: `${this.issuer}/oauth/token`,
      revocation_endpoint: `${this.issuer}/oauth/revoke`,
      jwks_uri: `${this.issuer}/.well-known/jwks.json`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none'],
      authorization_response_iss_parameter_supported: true,
    });
  }

  startAuthorization(request: SyntheticAuthorizationRequest): string {
    if (request.responseType !== 'code') throw new SyntheticOAuthLabError('invalid_request');
    if (request.clientId !== this.client.clientId)
      throw new SyntheticOAuthLabError('invalid_client');
    if (request.redirectUri !== this.client.redirectUri) {
      throw new SyntheticOAuthLabError('invalid_redirect_uri');
    }
    if (request.codeChallengeMethod !== 'S256' || !CODE_CHALLENGE.test(request.codeChallenge)) {
      throw new SyntheticOAuthLabError('invalid_pkce');
    }
    if (canonicalizeResourceUri(request.resource) !== this.resourceUri) {
      throw new SyntheticOAuthLabError('invalid_resource');
    }
    const authorizationId = randomUUID();
    this.authorizations.set(authorizationId, {
      clientId: request.clientId,
      redirectUri: request.redirectUri,
      codeChallenge: request.codeChallenge,
      resource: this.resourceUri,
      principalId: request.principalId,
      sessionId: randomUUID(),
      ...(request.state === undefined ? {} : { state: request.state }),
      consent: 'pending',
    });
    return authorizationId;
  }

  approveAuthorization(authorizationId: string): URL {
    const pending = this.authorizations.get(authorizationId);
    if (!pending || pending.consent !== 'pending') {
      throw new SyntheticOAuthLabError('invalid_grant');
    }
    pending.consent = 'approved';
    const code = opaqueToken('code');
    this.codes.set(code, {
      authorizationId,
      expiresAtMs: this.now() + 10 * 60_000,
    });
    const redirect = new URL(pending.redirectUri);
    redirect.searchParams.set('code', code);
    redirect.searchParams.set('iss', this.issuer);
    if (pending.state !== undefined) redirect.searchParams.set('state', pending.state);
    return redirect;
  }

  denyAuthorization(authorizationId: string): URL {
    const pending = this.authorizations.get(authorizationId);
    if (!pending || pending.consent !== 'pending') {
      throw new SyntheticOAuthLabError('invalid_grant');
    }
    pending.consent = 'denied';
    const redirect = new URL(pending.redirectUri);
    redirect.searchParams.set('error', 'access_denied');
    redirect.searchParams.set('iss', this.issuer);
    if (pending.state !== undefined) redirect.searchParams.set('state', pending.state);
    return redirect;
  }

  async exchangeAuthorizationCode(input: {
    readonly grantType: string;
    readonly code: string;
    readonly clientId: string;
    readonly redirectUri: string;
    readonly codeVerifier: string;
    readonly resource: string;
  }): Promise<SyntheticTokenSuccess> {
    if (input.grantType !== 'authorization_code') throw new SyntheticOAuthLabError('invalid_grant');
    if (input.clientId !== this.client.clientId) throw new SyntheticOAuthLabError('invalid_client');
    if (input.redirectUri !== this.client.redirectUri) {
      throw new SyntheticOAuthLabError('invalid_redirect_uri');
    }
    if (canonicalizeResourceUri(input.resource) !== this.resourceUri) {
      throw new SyntheticOAuthLabError('invalid_resource');
    }
    if (!CODE_VERIFIER.test(input.codeVerifier)) throw new SyntheticOAuthLabError('invalid_pkce');
    const issued = this.codes.get(input.code);
    this.codes.delete(input.code);
    if (!issued || issued.expiresAtMs <= this.now())
      throw new SyntheticOAuthLabError('invalid_grant');
    const pending = this.authorizations.get(issued.authorizationId);
    if (!pending || pending.consent !== 'approved')
      throw new SyntheticOAuthLabError('invalid_grant');
    if (pkceS256(input.codeVerifier) !== pending.codeChallenge) {
      throw new SyntheticOAuthLabError('invalid_pkce');
    }
    return this.issueTokens(pending);
  }

  async refresh(input: {
    readonly grantType: string;
    readonly refreshToken: string;
    readonly clientId: string;
    readonly resource: string;
  }): Promise<SyntheticTokenSuccess> {
    if (input.grantType !== 'refresh_token') throw new SyntheticOAuthLabError('invalid_grant');
    if (input.clientId !== this.client.clientId) throw new SyntheticOAuthLabError('invalid_client');
    if (canonicalizeResourceUri(input.resource) !== this.resourceUri) {
      throw new SyntheticOAuthLabError('invalid_resource');
    }
    const grantId = this.refreshIndex.get(input.refreshToken);
    if (grantId === undefined) throw new SyntheticOAuthLabError('invalid_grant');
    const grant = this.grants.get(grantId);
    if (!grant || grant.revoked || grant.refreshToken !== input.refreshToken) {
      throw new SyntheticOAuthLabError('invalid_grant');
    }
    this.refreshIndex.delete(input.refreshToken);
    grant.refreshFamily += 1;
    const rotated = opaqueToken('rt');
    grant.refreshToken = rotated;
    this.refreshIndex.set(rotated, grantId);
    const tokens = await this.mintAccessToken(grant, grantId);
    return { ...tokens, refreshToken: rotated };
  }

  revokeAccessToken(accessToken: string): void {
    const fingerprint = fingerprintAccessToken(accessToken);
    const record = this.accessTokens.get(fingerprint);
    if (record) record.revoked = true;
  }

  revokeGrant(refreshToken: string): void {
    const grantId = this.refreshIndex.get(refreshToken);
    if (grantId === undefined) return;
    const grant = this.grants.get(grantId);
    if (!grant) return;
    grant.revoked = true;
    this.refreshIndex.delete(refreshToken);
    for (const access of this.accessTokens.values()) {
      if (access.grantId === grantId) access.revoked = true;
    }
  }

  async inspectAccessToken(
    input: AccessTokenRevocationInspectInput,
  ): Promise<AccessTokenRevocationVerdict> {
    const access = this.accessTokens.get(input.tokenFingerprint);
    if (!access || access.revoked || access.sessionId !== input.sessionId) return 'revoked';
    const grant = this.grants.get(access.grantId);
    if (!grant || grant.revoked) return 'revoked';
    return 'active';
  }

  private async issueTokens(pending: PendingAuthorization): Promise<SyntheticTokenSuccess> {
    const grantId = randomUUID();
    const refreshToken = opaqueToken('rt');
    const grant: IssuedGrant = {
      clientId: pending.clientId,
      principalId: pending.principalId,
      sessionId: pending.sessionId,
      resource: pending.resource,
      refreshToken,
      refreshFamily: 0,
      revoked: false,
    };
    this.grants.set(grantId, grant);
    this.refreshIndex.set(refreshToken, grantId);
    const minted = await this.mintAccessToken(grant, grantId);
    return { ...minted, refreshToken };
  }

  private async mintAccessToken(
    grant: IssuedGrant,
    grantId: string,
  ): Promise<Omit<SyntheticTokenSuccess, 'refreshToken'> & { refreshToken?: undefined }> {
    const expiresIn = 3_600;
    const issuedAt = Math.floor(this.now() / 1000);
    const accessToken = await new SignJWT({
      role: 'authenticated',
      aud: [DATA_API_AUDIENCE, this.resourceUri],
      resource: this.resourceUri,
      client_id: grant.clientId,
      session_id: grant.sessionId,
      user_id: grant.principalId,
    })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setIssuer(this.issuer)
      .setSubject(grant.principalId)
      .setIssuedAt(issuedAt)
      .setExpirationTime(issuedAt + expiresIn)
      .sign(SYNTHETIC_OAUTH_HMAC_SECRET);
    const fingerprint = fingerprintAccessToken(accessToken);
    this.accessTokens.set(fingerprint, {
      fingerprint,
      sessionId: grant.sessionId,
      grantId,
      revoked: false,
    });
    return {
      accessToken,
      tokenType: 'Bearer',
      expiresIn,
    };
  }
}

export async function mintSyntheticAccessToken(options: {
  readonly issuer: string;
  readonly resourceUri: string;
  readonly principalId: string;
  readonly clientId: string;
  readonly sessionId: string;
  readonly secret?: Uint8Array;
  readonly now?: () => number;
  readonly aud?: readonly string[];
  readonly resource?: string | null;
  readonly role?: string;
  readonly extraClaims?: Readonly<Record<string, unknown>>;
  readonly expiresInSec?: number;
}): Promise<string> {
  const now = options.now ?? Date.now;
  const issuedAt = Math.floor(now() / 1000);
  const aud = options.aud ?? [DATA_API_AUDIENCE, canonicalizeResourceUri(options.resourceUri)];
  const token = new SignJWT({
    role: options.role ?? 'authenticated',
    aud: [...aud],
    client_id: options.clientId,
    session_id: options.sessionId,
    user_id: options.principalId,
    ...(options.resource === null
      ? {}
      : { resource: options.resource ?? canonicalizeResourceUri(options.resourceUri) }),
    ...(options.extraClaims ?? {}),
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setIssuer(canonicalizeResourceUri(options.issuer))
    .setSubject(options.principalId)
    .setIssuedAt(issuedAt)
    .setExpirationTime(issuedAt + (options.expiresInSec ?? 3_600));
  return token.sign(options.secret ?? SYNTHETIC_OAUTH_HMAC_SECRET);
}
