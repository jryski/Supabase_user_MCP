import { createHash, randomBytes } from 'node:crypto';
import { isLoopbackRedirectHttpUrl } from './loopback-host.js';
import {
  createOAuthConsentBlock,
  type OAuthConsentApi,
  type OAuthConsentBinding,
  type OAuthConsentView,
} from './oauth-consent.js';

/** The host must verify the session server-side on EVERY request. No bearer is rendered. */
export interface VerifiedHostedConsentSession {
  readonly userId: string;
  /** Opaque host session identifier, never an access/refresh token. */
  readonly sessionId: string;
  readonly oauth: OAuthConsentApi;
}

export interface HostedConsentChallenge {
  readonly userId: string;
  readonly sessionId: string;
  readonly authorizationId: string;
  readonly viewSha256: string;
  readonly expiresAt: number;
}

/**
 * Store operations must be atomic across the host's instances. `take` deletes
 * before returning, including expired entries; a lost decision reply is never
 * permission to replay. Stores must bound entries, expire them, and store only
 * these metadata fields. No token or business data belongs in this store.
 */
export interface HostedConsentChallengeStore {
  readonly putIfAbsent: (nonce: string, challenge: HostedConsentChallenge) => Promise<boolean>;
  readonly take: (nonce: string) => Promise<HostedConsentChallenge | undefined>;
}

export interface HostedOAuthConsentConfig {
  /** Exact public HTTPS URL mounted by the signed-in application. */
  readonly routeUrl: string;
  readonly binding: OAuthConsentBinding;
  readonly getVerifiedSession: (
    request: Request,
    signal: AbortSignal,
  ) => Promise<VerifiedHostedConsentSession | undefined>;
  readonly challenges: HostedConsentChallengeStore;
  readonly now?: () => number;
}

const TTL_MS = 5 * 60_000;
const MAX_FORM_BYTES = 2048;
export const HOSTED_CONSENT_DEADLINE_MS = 15_000;
const AUTH_ID = /^[A-Za-z0-9_-]{1,128}$/u;
const NONCE = /^[A-Za-z0-9_-]{43}$/u;
const HEADERS = Object.freeze({
  'cache-control': 'no-store',
  pragma: 'no-cache',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'content-security-policy':
    "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
});

function response(status: number, text: string): Response {
  return new Response(text, {
    status,
    headers: { ...HEADERS, 'content-type': 'text/plain; charset=utf-8' },
  });
}

function escapeHtml(value: string): string {
  return value.replace(
    /[&<>"']/gu,
    (character) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character] ?? '',
  );
}

function fingerprint(view: Extract<OAuthConsentView, { kind: 'consent_required' }>): string {
  return createHash('sha256')
    .update(
      JSON.stringify([
        view.authorizationId,
        view.clientId,
        view.clientName,
        view.redirectUri,
        view.scopes,
      ]),
    )
    .digest('hex');
}

function viewIsBounded(view: Extract<OAuthConsentView, { kind: 'consent_required' }>): boolean {
  return (
    typeof view.clientName === 'string' &&
    view.clientName.length <= 256 &&
    view.redirectUri.length <= 2048 &&
    view.scopes.length >= 1 &&
    view.scopes.length <= 4 &&
    new Set(view.scopes).size === view.scopes.length
  );
}

function redirect(url: string): Response {
  return new Response(null, { status: 303, headers: { ...HEADERS, location: url } });
}

async function readForm(
  request: Request,
  signal: AbortSignal,
): Promise<URLSearchParams | undefined> {
  if (request.headers.get('content-type') !== 'application/x-www-form-urlencoded') return;
  const length = request.headers.get('content-length');
  if (length !== null && (!/^\d+$/u.test(length) || Number(length) > MAX_FORM_BYTES)) return;
  if (request.body === null) return;
  const reader = request.body.getReader();
  let abortRead: (() => void) | undefined;
  const aborted = new Promise<never>((_resolve, reject) => {
    abortRead = () => {
      // The stream's cancel hook can itself hang; never wait for it.
      void reader.cancel().catch(() => {});
      reject(new Error('CONSENT_REQUEST_ABORTED'));
    };
    signal.addEventListener('abort', abortRead, { once: true });
  });
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    while (true) {
      if (signal.aborted) return;
      const chunk = await Promise.race([reader.read(), aborted]);
      if (chunk.done) break;
      bytes += chunk.value.byteLength;
      if (bytes > MAX_FORM_BYTES) {
        void reader.cancel().catch(() => {});
        return;
      }
      chunks.push(chunk.value);
    }
    const data = new Uint8Array(bytes);
    let position = 0;
    for (const chunk of chunks) {
      data.set(chunk, position);
      position += chunk.byteLength;
    }
    const form = new URLSearchParams(new TextDecoder('utf-8', { fatal: true }).decode(data));
    if ([...form.keys()].some((key) => key !== 'nonce' && key !== 'decision')) return;
    if (form.getAll('nonce').length !== 1 || form.getAll('decision').length !== 1) return;
    return form;
  } catch {
    return;
  } finally {
    if (abortRead !== undefined) signal.removeEventListener('abort', abortRead);
    reader.releaseLock();
  }
}

/**
 * Mount this exact handler at Auth's configured authorization path in the
 * existing signed-in application. It adds no login or MCP bearer path.
 * It uses only the host's freshly verified user's official auth.oauth API.
 */
export function createHostedOAuthConsentHandler(
  config: HostedOAuthConsentConfig,
): (request: Request) => Promise<Response> {
  const route = new URL(config.routeUrl);
  if (
    route.protocol !== 'https:' ||
    route.username !== '' ||
    route.password !== '' ||
    route.hash !== '' ||
    route.search !== '' ||
    route.href !== config.routeUrl ||
    route.href.length > 2048
  )
    throw new Error('HOSTED_CONSENT_INVALID_CONFIGURATION');
  for (const value of config.binding.redirectUris) {
    const callback = new URL(value);
    if (callback.protocol !== 'https:' && !isLoopbackRedirectHttpUrl(callback)) {
      throw new Error('HOSTED_CONSENT_INVALID_CONFIGURATION');
    }
  }
  const block = createOAuthConsentBlock(config.binding);
  const now = config.now ?? Date.now;
  const getSession = config.getVerifiedSession;
  const store = config.challenges;

  return async (request: Request): Promise<Response> => {
    const controller = new AbortController();
    const abort = () => controller.abort();
    let completeAbort: (() => void) | undefined;
    const cancelled = new Promise<Response>((resolve) => {
      completeAbort = () =>
        resolve(
          response(503, 'Consent outcome unavailable. Restart authorization to check its status.'),
        );
      controller.signal.addEventListener('abort', completeAbort, { once: true });
    });
    request.signal.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(abort, HOSTED_CONSENT_DEADLINE_MS);
    if (request.signal.aborted) abort();
    const execute = async (): Promise<Response> => {
      try {
        if (controller.signal.aborted) return response(503, 'Consent request cancelled.');
        const url = new URL(request.url);
        if (url.origin !== route.origin || url.pathname !== route.pathname)
          return response(404, 'Not found.');
        if (request.method !== 'GET' && request.method !== 'POST')
          return response(405, 'Method not allowed.');
        // Consent cannot be submitted cross-origin, even with a valid nonce.
        if (
          request.method === 'POST' &&
          (request.headers.get('origin') !== route.origin ||
            url.search !== '' ||
            (request.headers.has('sec-fetch-site') &&
              request.headers.get('sec-fetch-site') !== 'same-origin'))
        )
          return response(403, 'Consent request refused.');
        const session = await getSession(request, controller.signal);
        if (controller.signal.aborted) return response(503, 'Consent request cancelled.');
        if (
          session === undefined ||
          session.sessionId.length === 0 ||
          session.sessionId.length > 256 ||
          session.sessionId.trim() !== session.sessionId
        )
          return response(401, 'Sign in with your own account, then restart authorization.');

        if (request.method === 'GET') {
          const authorizationId = url.searchParams.get('authorization_id');
          if (
            authorizationId === null ||
            !AUTH_ID.test(authorizationId) ||
            url.searchParams.getAll('authorization_id').length !== 1 ||
            [...url.searchParams.keys()].some((key) => key !== 'authorization_id')
          )
            return response(400, 'Invalid consent request.');
          const view = await block.inspect(session.oauth, authorizationId, session.userId);
          if (controller.signal.aborted) return response(503, 'Consent request cancelled.');
          if (view.kind === 'redirect') return redirect(view.redirectUrl);
          if (view.kind === 'refused') return response(403, 'Consent request refused.');
          if (!viewIsBounded(view)) return response(403, 'Consent request refused.');
          const nonce = randomBytes(32).toString('base64url');
          if (
            !(await store.putIfAbsent(
              nonce,
              Object.freeze({
                userId: session.userId,
                sessionId: session.sessionId,
                authorizationId,
                viewSha256: fingerprint(view),
                expiresAt: now() + TTL_MS,
              }),
            ))
          )
            return response(503, 'Consent temporarily unavailable.');
          const html = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Connect your account</title><h1>Connect your account</h1><p>Application: ${escapeHtml(view.clientName)}</p><p>Client: ${escapeHtml(view.clientId)}</p><p>Permissions: ${escapeHtml(view.scopes.join(', '))}</p><p>Return address: ${escapeHtml(view.redirectUri)}</p><p>Approve only if you started this connection. This grants access for your signed-in account.</p><form method="post" action="${escapeHtml(route.href)}"><input type="hidden" name="nonce" value="${nonce}"><button type="submit" name="decision" value="approve">Approve connection</button><button type="submit" name="decision" value="deny">Deny connection</button></form></html>`;
          return new Response(html, {
            status: 200,
            headers: { ...HEADERS, 'content-type': 'text/html; charset=utf-8' },
          });
        }

        const form = await readForm(request, controller.signal);
        if (controller.signal.aborted) return response(503, 'Consent request cancelled.');
        const nonce = form?.get('nonce');
        const decision = form?.get('decision');
        if (
          nonce === null ||
          nonce === undefined ||
          !NONCE.test(nonce) ||
          (decision !== 'approve' && decision !== 'deny')
        )
          return response(400, 'Invalid consent request.');
        // Take once BEFORE any upstream write. Unknown outcome consumes the
        // form: reload/restart and inspect upstream state rather than retry.
        const challenge = await store.take(nonce);
        if (controller.signal.aborted) return response(503, 'Consent request cancelled.');
        if (
          challenge === undefined ||
          !Number.isFinite(challenge.expiresAt) ||
          challenge.expiresAt <= now() ||
          challenge.userId !== session.userId ||
          challenge.sessionId !== session.sessionId
        )
          return response(409, 'Consent expired or account changed. Restart authorization.');
        // The block re-reads before deciding. Validate THAT response against
        // the rendered form, rather than validating an earlier read and then
        // allowing a changed (but still broadly allowlisted) request through.
        const checkedApi: OAuthConsentApi = {
          async getAuthorizationDetails(id) {
            const result = await session.oauth.getAuthorizationDetails(id);
            const capturedApi: OAuthConsentApi = {
              getAuthorizationDetails: async () => result,
              approveAuthorization: (...args) => session.oauth.approveAuthorization(...args),
              denyAuthorization: (...args) => session.oauth.denyAuthorization(...args),
            };
            const current = await block.inspect(capturedApi, id, session.userId);
            if (
              current.kind !== 'redirect' &&
              (current.kind !== 'consent_required' ||
                !viewIsBounded(current) ||
                fingerprint(current) !== challenge.viewSha256)
            )
              throw new Error('CONSENT_REQUEST_CHANGED');
            return result;
          },
          approveAuthorization: (...args) => {
            if (controller.signal.aborted) throw new Error('CONSENT_REQUEST_ABORTED');
            return session.oauth.approveAuthorization(...args);
          },
          denyAuthorization: (...args) => {
            if (controller.signal.aborted) throw new Error('CONSENT_REQUEST_ABORTED');
            return session.oauth.denyAuthorization(...args);
          },
        };
        const outcome = await block.decide(
          checkedApi,
          challenge.authorizationId,
          session.userId,
          decision,
        );
        return outcome.kind === 'redirect'
          ? redirect(outcome.redirectUrl)
          : response(
              409,
              'Consent outcome unavailable. Restart authorization to check its status.',
            );
      } catch {
        // Never echo upstream errors, session data, authorization details or tokens.
        return response(
          503,
          'Consent temporarily unavailable. Restart authorization to check its status.',
        );
      }
    };
    try {
      return await Promise.race([execute(), cancelled]);
    } finally {
      clearTimeout(timer);
      request.signal.removeEventListener('abort', abort);
      if (completeAbort !== undefined)
        controller.signal.removeEventListener('abort', completeAbort);
    }
  };
}
