import type { SupabaseEnv } from '@supabase/server';
import { RemoteOAuthClientIdSchema, RemotePrincipalIdSchema } from '@supabase-user-mcp/contracts';
import {
  createLocalJWKSet,
  createRemoteJWKSet,
  type JSONWebKeySet,
  type JWTPayload,
  type JWTVerifyGetKey,
  jwtVerify,
} from 'jose';
import {
  buildLocalAuthorizationUrl,
  exchangeLocalAuthorizationCode,
  generateS256PkceChallenge,
} from './local-oauth-pkce-client.js';
import { MCP_INGRESS_ROLE } from './native-user-mcp.js';

/** TEST-only public PKCE. Not a confidential client and not a durable store. */
export const DOWNSTREAM_B_GRANT_PROFILE = 'TEST_ONLY_PUBLIC_PKCE' as const;
export const DOWNSTREAM_AUTHORIZATION_REQUIRED = 'downstream_authorization_required' as const;
export const DOWNSTREAM_B_SCOPE = 'email' as const;

const DEFAULT_HANDSHAKE_TTL_MS = 5 * 60 * 1000;
const MAX_HANDSHAKE_TTL_MS = 15 * 60 * 1000;
const DATA_API_AUDIENCE = 'authenticated';

export class DownstreamOAuthGrantError extends Error {
  readonly code = 'DOWNSTREAM_OAUTH_GRANT_REJECTED' as const;

  constructor() {
    super('DOWNSTREAM_OAUTH_GRANT_REJECTED');
    this.name = 'DownstreamOAuthGrantError';
  }
}

export interface DownstreamHandshakePrincipal {
  readonly sourceSessionId: string;
  readonly sub: string;
  readonly agentId: string;
  readonly aClientId: string;
}

export interface DownstreamHandshake {
  readonly id: string;
  readonly state: string;
  readonly expiresAtMs: number;
  readonly authorizationUrl: string;
}

export type DownstreamGrantResolution =
  | { readonly status: 'missing' }
  | { readonly status: 'expired' }
  | { readonly status: 'mismatched' }
  | {
      readonly status: 'live';
      readonly accessToken: string;
      readonly bClientId: string;
      readonly expiresAtMs: number;
    };

interface HandshakeRecord extends DownstreamHandshakePrincipal {
  readonly id: string;
  readonly expectedBClientId: string;
  readonly redirectUri: string;
  readonly codeVerifier: string;
  readonly authorizationUrl: string;
  readonly expiresAtMs: number;
}

interface GrantRecord extends DownstreamHandshakePrincipal {
  readonly accessToken: string;
  readonly bClientId: string;
  readonly sessionId: string;
  readonly expiresAtMs: number;
}

type FetchLike = typeof globalThis.fetch;

/** Public grant fact. Session and subject UUIDs only. Never a bearer. */
export interface DownstreamGrantPublicFact {
  readonly event:
    | 'unknown_state'
    | 'replay'
    | 'redirect_mismatch'
    | 'exchange_failed'
    | 'exchange_rejected'
    | 'bound';
  readonly sessionId: string | null;
  readonly sub: string | null;
  readonly subjectMismatch: boolean;
}

export interface DownstreamOAuthGrantConfig {
  readonly issuer: string;
  readonly authOrigin: string;
  readonly expectedBClientId: string;
  readonly expectedAgentId: string;
  readonly redirectUri: string;
  readonly jwks: Exclude<SupabaseEnv['jwks'], null>;
  readonly handshakeTtlMs?: number;
  readonly now?: () => number;
  readonly randomId?: () => string;
  readonly fetch?: FetchLike;
  /** Called with UUIDs only, including a B session rejected after verification. */
  readonly onGrantFact?: (fact: DownstreamGrantPublicFact) => void;
}

function reject(): never {
  throw new DownstreamOAuthGrantError();
}

function pairKey(principal: DownstreamHandshakePrincipal): string {
  return [principal.sourceSessionId, principal.sub, principal.agentId, principal.aClientId].join(
    '\n',
  );
}

function assertUuid(value: string): string {
  if (!RemotePrincipalIdSchema.safeParse(value).success) reject();
  if (value.toLowerCase() === '00000000-0000-0000-0000-000000000000') reject();
  return value;
}

function verificationKey(jwks: Exclude<SupabaseEnv['jwks'], null>): JWTVerifyGetKey {
  if (jwks instanceof URL) return createRemoteJWKSet(jwks);
  return createLocalJWKSet(jwks as JSONWebKeySet);
}

function audienceValues(aud: unknown): readonly string[] {
  if (typeof aud === 'string' && aud.length > 0) return [aud];
  if (Array.isArray(aud) && aud.every((value) => typeof value === 'string' && value.length > 0)) {
    return aud;
  }
  return [];
}

/**
 * In-memory Token B custody for one process.
 *
 * B is bound only from a one-time handshake that was created for a verified
 * Token A. There is no first-seen or unbound candidate path. refresh_token
 * is discarded before the access token is stored. Restart drops the grant.
 */
export class DownstreamOAuthGrantStore {
  private readonly handshakes = new Map<string, HandshakeRecord>();
  private readonly grants = new Map<string, GrantRecord>();
  private readonly consumedStates = new Set<string>();
  private readonly keys: JWTVerifyGetKey;
  private readonly now: () => number;
  private readonly randomId: () => string;
  private readonly ttlMs: number;
  private readonly fetchImpl: FetchLike | undefined;

  constructor(private readonly config: DownstreamOAuthGrantConfig) {
    if (!RemoteOAuthClientIdSchema.safeParse(config.expectedBClientId).success) reject();
    if (config.expectedAgentId.length === 0 || /\s/u.test(config.expectedAgentId)) reject();
    let redirect: URL;
    try {
      redirect = new URL(config.redirectUri);
    } catch {
      reject();
    }
    if (
      redirect.username !== '' ||
      redirect.password !== '' ||
      redirect.hash !== '' ||
      redirect.search !== ''
    ) {
      reject();
    }
    const loopback =
      redirect.protocol === 'http:' &&
      (redirect.hostname === 'localhost' ||
        redirect.hostname === '::1' ||
        redirect.hostname.startsWith('127.'));
    if (redirect.protocol !== 'https:' && !loopback) reject();
    const ttl = config.handshakeTtlMs ?? DEFAULT_HANDSHAKE_TTL_MS;
    if (!Number.isSafeInteger(ttl) || ttl < 1_000 || ttl > MAX_HANDSHAKE_TTL_MS) reject();
    this.ttlMs = ttl;
    this.now = config.now ?? Date.now;
    this.randomId = config.randomId ?? (() => crypto.randomUUID());
    this.keys = verificationKey(config.jwks);
    this.fetchImpl = config.fetch;
  }

  beginHandshake(principal: DownstreamHandshakePrincipal): DownstreamHandshake {
    const sourceSessionId = assertUuid(principal.sourceSessionId);
    const sub = assertUuid(principal.sub);
    if (principal.agentId !== this.config.expectedAgentId) reject();
    if (!RemoteOAuthClientIdSchema.safeParse(principal.aClientId).success) reject();
    if (principal.aClientId === this.config.expectedBClientId) reject();
    const bound: DownstreamHandshakePrincipal = {
      sourceSessionId,
      sub,
      agentId: principal.agentId,
      aClientId: principal.aClientId,
    };
    const key = pairKey(bound);
    for (const [id, existing] of this.handshakes) {
      if (pairKey(existing) === key) this.handshakes.delete(id);
    }
    const id = assertUuid(this.randomId());
    const { codeVerifier, codeChallenge } = generateS256PkceChallenge();
    const authorizationUrl = buildLocalAuthorizationUrl({
      authOrigin: this.config.authOrigin,
      clientId: this.config.expectedBClientId,
      redirectUri: this.config.redirectUri,
      state: id,
      codeChallenge,
      scope: DOWNSTREAM_B_SCOPE,
    });
    const record: HandshakeRecord = {
      ...bound,
      id,
      expectedBClientId: this.config.expectedBClientId,
      redirectUri: this.config.redirectUri,
      codeVerifier,
      authorizationUrl,
      expiresAtMs: this.now() + this.ttlMs,
    };
    this.handshakes.set(id, record);
    return {
      id,
      state: id,
      expiresAtMs: record.expiresAtMs,
      authorizationUrl,
    };
  }

  /**
   * Bind B only when state, redirect, and every handshake field match the
   * verified access token. The handshake is one-time either way.
   */
  async completeCallback(input: {
    readonly code: string;
    readonly state: string;
    readonly redirectUri: string;
  }): Promise<boolean> {
    const handshake = this.handshakes.get(input.state);
    if (handshake === undefined) {
      this.emitFact({
        event: this.consumedStates.has(input.state) ? 'replay' : 'unknown_state',
        sessionId: null,
        sub: null,
        subjectMismatch: false,
      });
      return false;
    }
    this.handshakes.delete(input.state);
    this.consumedStates.add(input.state);
    if (this.now() >= handshake.expiresAtMs) return false;
    if (input.redirectUri !== handshake.redirectUri) {
      this.emitFact({
        event: 'redirect_mismatch',
        sessionId: null,
        sub: null,
        subjectMismatch: false,
      });
      return false;
    }
    if (input.code.length === 0) return false;
    let accessToken: string;
    try {
      const exchanged = await exchangeLocalAuthorizationCode({
        authOrigin: this.config.authOrigin,
        clientId: handshake.expectedBClientId,
        redirectUri: handshake.redirectUri,
        code: input.code,
        codeVerifier: handshake.codeVerifier,
        ...(this.fetchImpl === undefined ? {} : { fetch: this.fetchImpl }),
      });
      accessToken = dropRefreshToken(exchanged);
    } catch {
      this.emitFact({
        event: 'exchange_failed',
        sessionId: null,
        sub: null,
        subjectMismatch: false,
      });
      return false;
    }
    const accepted = await this.acceptAccessToken(accessToken, handshake, true);
    if (accepted === undefined) return false;
    this.grants.set(pairKey(handshake), accepted);
    this.emitFact({
      event: 'bound',
      sessionId: accepted.sessionId,
      sub: accepted.sub,
      subjectMismatch: false,
    });
    return true;
  }

  resolve(principal: DownstreamHandshakePrincipal): DownstreamGrantResolution {
    const key = pairKey(principal);
    const grant = this.grants.get(key);
    if (grant === undefined) return { status: 'missing' };
    if (
      grant.sub !== principal.sub ||
      grant.sourceSessionId !== principal.sourceSessionId ||
      grant.agentId !== principal.agentId ||
      grant.aClientId !== principal.aClientId ||
      grant.bClientId !== this.config.expectedBClientId ||
      grant.agentId !== this.config.expectedAgentId
    ) {
      return { status: 'mismatched' };
    }
    if (grant.expiresAtMs <= this.now()) {
      this.grants.delete(key);
      return { status: 'expired' };
    }
    return {
      status: 'live',
      accessToken: grant.accessToken,
      bClientId: grant.bClientId,
      expiresAtMs: grant.expiresAtMs,
    };
  }

  /**
   * Offer a bearer to the B store. Token A must be rejected. The offer is
   * never inserted into the grant map.
   */
  async rejectsOfferedAccessToken(
    accessToken: string,
    principal: DownstreamHandshakePrincipal,
  ): Promise<boolean> {
    if (accessToken.length === 0) return true;
    const handshake: HandshakeRecord = {
      sourceSessionId: principal.sourceSessionId,
      sub: principal.sub,
      agentId: principal.agentId,
      aClientId: principal.aClientId,
      id: principal.sourceSessionId,
      expectedBClientId: this.config.expectedBClientId,
      redirectUri: this.config.redirectUri,
      codeVerifier: 'offer-not-retained',
      authorizationUrl: 'https://offer.invalid/not-used',
      expiresAtMs: this.now() + this.ttlMs,
    };
    const accepted = await this.acceptAccessToken(accessToken, handshake, false);
    return accepted === undefined;
  }

  /** B auth session id for a live grant. Not an access token. */
  boundSessionId(principal: DownstreamHandshakePrincipal): string | null {
    const grant = this.grants.get(pairKey(principal));
    if (grant === undefined || grant.expiresAtMs <= this.now()) return null;
    return grant.sessionId;
  }

  /** True when the needle is still in memory. Refresh tokens must not be. */
  containsRetainedMaterial(needle: string): boolean {
    if (needle.length === 0) return false;
    for (const grant of this.grants.values()) {
      if (grant.accessToken.includes(needle)) return true;
    }
    for (const handshake of this.handshakes.values()) {
      if (handshake.codeVerifier.includes(needle) || handshake.authorizationUrl.includes(needle)) {
        return true;
      }
    }
    return false;
  }

  private emitFact(fact: DownstreamGrantPublicFact): void {
    this.config.onGrantFact?.(fact);
  }

  private rejectVerified(
    payload: JWTPayload,
    subjectMismatch: boolean,
    notify: boolean,
  ): undefined {
    if (!notify) return undefined;
    this.emitFact({
      event: 'exchange_rejected',
      sessionId: publicUuid(payload.session_id),
      sub: publicUuid(payload.sub),
      subjectMismatch,
    });
    return undefined;
  }

  private async acceptAccessToken(
    accessToken: string,
    handshake: HandshakeRecord,
    notify: boolean,
  ): Promise<GrantRecord | undefined> {
    let payload: JWTPayload;
    try {
      const verified = await jwtVerify(accessToken, this.keys, {
        issuer: this.config.issuer,
        audience: DATA_API_AUDIENCE,
        algorithms: ['ES256', 'RS256', 'EdDSA'],
      });
      payload = verified.payload;
    } catch {
      return undefined;
    }
    if (payload.sub !== handshake.sub) return this.rejectVerified(payload, true, notify);
    if (payload.role === MCP_INGRESS_ROLE) return this.rejectVerified(payload, false, notify);
    if (payload.role !== DATA_API_AUDIENCE) return this.rejectVerified(payload, false, notify);
    const audiences = audienceValues(payload.aud);
    if (!audiences.includes(DATA_API_AUDIENCE)) return this.rejectVerified(payload, false, notify);
    if (payload.client_id !== handshake.expectedBClientId) {
      return this.rejectVerified(payload, false, notify);
    }
    if (payload.client_id === handshake.aClientId)
      return this.rejectVerified(payload, false, notify);
    if (payload.agent_id !== handshake.agentId) return this.rejectVerified(payload, false, notify);
    if (publicUuid(payload.session_id) === null) return this.rejectVerified(payload, false, notify);
    if (typeof payload.exp !== 'number' || !Number.isSafeInteger(payload.exp)) {
      return this.rejectVerified(payload, false, notify);
    }
    if (payload.exp * 1000 <= this.now()) return this.rejectVerified(payload, false, notify);
    if (payload.iss !== this.config.issuer) return this.rejectVerified(payload, false, notify);
    const sessionId = publicUuid(payload.session_id);
    if (sessionId === null) return undefined;
    return {
      sourceSessionId: handshake.sourceSessionId,
      sub: handshake.sub,
      agentId: handshake.agentId,
      aClientId: handshake.aClientId,
      accessToken,
      bClientId: handshake.expectedBClientId,
      sessionId,
      expiresAtMs: payload.exp * 1000,
    };
  }
}

function publicUuid(value: unknown): string | null {
  if (typeof value !== 'string' || !RemotePrincipalIdSchema.safeParse(value).success) return null;
  if (value.toLowerCase() === '00000000-0000-0000-0000-000000000000') return null;
  return value;
}

function dropRefreshToken(exchanged: {
  readonly accessToken: string;
  readonly refreshToken: string | null;
}): string {
  // TEST-only public PKCE. The refresh token is dropped immediately and is
  // not stored, logged, or returned.
  void exchanged.refreshToken;
  if (exchanged.accessToken.length === 0) reject();
  return exchanged.accessToken;
}
