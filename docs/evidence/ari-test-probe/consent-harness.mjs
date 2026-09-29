/**
 * Loopback consent checklist for the controller host.
 * Plan and redact do not dial a network. This packet does not install a hook
 * and does not mint a token. Do not put owner keys, refresh tokens, or access
 * tokens in a URL, log, channel, or artifact.
 */
import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';

export const FORBIDDEN_PROJECT_REF = 'lygftpbjgqgvuunkwnxf';
export const DISCOVERY = Object.freeze({
  oauthAuthorizationServer: '/.well-known/oauth-authorization-server',
  oidc: '/.well-known/openid-configuration',
  fetchedByThisPacket: false,
  pkce: 'S256',
  oidcDiscoveryDoesNotAuthorizeIdToken: true,
  note: 'OAuth AS metadata is the code+PKCE coverage note. OIDC discovery is recorded and not used to mint. An id_token in a token body fails the receipt.',
});

export const CONTROLS = Object.freeze([
  'a_mint',
  'auth_session_not_found',
  'openid_exchange_no_id_token',
  'unmapped_client_fails',
  'password_login_unchanged',
  'data_api_deny_with_b_positive',
  'mcp_edge_downstream_credential_unresolved',
]);

const TOKEN_KEYS = new Set([
  'access_token',
  'refresh_token',
  'id_token',
  'provider_token',
  'provider_refresh_token',
]);

function parseJson(body) {
  if (typeof body !== 'string') return body;
  try {
    return JSON.parse(body);
  } catch {
    return undefined;
  }
}

export function isLoopbackHostname(hostname) {
  return hostname === '127.0.0.1' || hostname === 'localhost' || hostname === '::1';
}

export function assertRedirectUri(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    return { ok: false, reason: 'redirect_not_loopback' };
  }
  if (url.protocol !== 'http:' || !isLoopbackHostname(url.hostname)) {
    return { ok: false, reason: 'redirect_not_loopback' };
  }
  if (
    url.username !== '' ||
    url.password !== '' ||
    url.search !== '' ||
    url.hash !== '' ||
    url.pathname !== '/callback'
  ) {
    return { ok: false, reason: 'redirect_not_exact' };
  }
  return { ok: true, redirectUri: url.origin + url.pathname };
}

export function assertScopes(scopes) {
  if (!Array.isArray(scopes) || scopes.length === 0) {
    return { ok: false, reason: 'scope_not_configured' };
  }
  if (scopes.some((item) => typeof item !== 'string' || item.length === 0)) {
    return { ok: false, reason: 'scope_not_configured' };
  }
  if (scopes.some((item) => item.toLowerCase() === 'openid')) {
    return { ok: false, reason: 'openid_scope_refused' };
  }
  return { ok: true, scope: scopes.join(' ') };
}

export function createPkce() {
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
  return { codeVerifier, codeChallenge, codeChallengeMethod: 'S256' };
}

export function buildAuthorizeUrl(input) {
  if (`${input.authorizeEndpoint ?? ''} ${input.resource ?? ''}`.includes(FORBIDDEN_PROJECT_REF)) {
    return { ok: false, reason: 'forbidden_target' };
  }
  const redirect = assertRedirectUri(input.redirectUri);
  if (!redirect.ok) return redirect;
  const scopes = assertScopes(input.scopes);
  if (!scopes.ok) return scopes;
  if (typeof input.clientId !== 'string' || input.clientId.length === 0) {
    return { ok: false, reason: 'oauth_client_id_required' };
  }
  if (typeof input.resource !== 'string' || input.resource.length === 0) {
    return { ok: false, reason: 'mcp_resource_required' };
  }
  if (typeof input.codeChallenge !== 'string' || input.codeChallenge.length === 0) {
    return { ok: false, reason: 'pkce_challenge_required' };
  }
  let authorize;
  try {
    authorize = new URL(input.authorizeEndpoint);
  } catch {
    return { ok: false, reason: 'authorize_endpoint_unreadable' };
  }
  authorize.searchParams.set('response_type', 'code');
  authorize.searchParams.set('client_id', input.clientId);
  authorize.searchParams.set('redirect_uri', redirect.redirectUri);
  authorize.searchParams.set('scope', scopes.scope);
  authorize.searchParams.set('code_challenge', input.codeChallenge);
  authorize.searchParams.set('code_challenge_method', 'S256');
  authorize.searchParams.set('resource', input.resource);
  if (typeof input.state === 'string' && input.state.length > 0) {
    authorize.searchParams.set('state', input.state);
  }
  return { ok: true, url: authorize.toString() };
}

export function redactCallback(value) {
  let url;
  try {
    url = new URL(value, 'http://127.0.0.1');
  } catch {
    return { ok: false, reason: 'callback_unreadable' };
  }
  if (!isLoopbackHostname(url.hostname)) return { ok: false, reason: 'redirect_not_loopback' };
  const keys = [...url.searchParams.keys()];
  return {
    ok: true,
    hasCode: url.searchParams.has('code'),
    hasToken: keys.some((key) => /token/iu.test(key)),
  };
}

export function redactTokenBody(body) {
  const parsed = parseJson(body);
  if (parsed === undefined || parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, reason: 'token_body_unreadable', revocationClaimed: false };
  }
  const keys = Object.keys(parsed);
  if (keys.includes('id_token')) {
    return { ok: false, reason: 'id_token_present', revocationClaimed: false };
  }
  return {
    ok: true,
    reason: 'redacted',
    secretKeyNames: keys.filter((key) => TOKEN_KEYS.has(key)),
    revocationClaimed: false,
  };
}

export function authSessionControl(status, body) {
  const text = typeof body === 'string' ? body : JSON.stringify(body ?? '');
  if (/access_token|refresh_token|id_token/u.test(text)) {
    return { ok: false, reason: 'credential_in_body', revocationClaimed: false };
  }
  const parsed = parseJson(body);
  if (
    status === 403 &&
    parsed !== null &&
    typeof parsed === 'object' &&
    !Array.isArray(parsed) &&
    parsed.error === 'session_not_found'
  ) {
    return { ok: true, reason: 'session_not_found', revocationClaimed: false };
  }
  return { ok: false, reason: 'auth_session_control_missed', revocationClaimed: false };
}

export function planConsent() {
  return {
    packet: 'ari-test-consent',
    executed: false,
    hookInstalledByThisPacket: false,
    roleSqlAppliedByThisPacket: false,
    acceptance: false,
    revocationClaimed: false,
    tokenBCustody: false,
    redirectShape: 'http://127.0.0.1:<port>/callback',
    scopeConfiguredByController: true,
    openidScopeRefused: true,
    discovery: DISCOVERY,
    controls: CONTROLS,
    forbiddenProjectRef: FORBIDDEN_PROJECT_REF,
  };
}

export function listenOnce({ port = 0 } = {}) {
  const server = createServer((request, response) => {
    let receipt = { ok: false, reason: 'callback_unreadable' };
    try {
      receipt = redactCallback(new URL(request.url ?? '/', 'http://127.0.0.1'));
    } catch {
      receipt = { ok: false, reason: 'callback_unreadable' };
    }
    server.receipt = receipt;
    response.writeHead(200, { 'content-type': 'text/plain', 'cache-control': 'no-store' });
    response.end(receipt.hasToken === true ? 'rejected' : 'received');
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      const address = server.address();
      resolve({
        port: typeof address === 'object' && address !== null ? address.port : port,
        receipt: () => server.receipt,
        close: () =>
          new Promise((done, fail) => {
            server.close((error) => (error ? fail(error) : done()));
          }),
      });
    });
  });
}

async function readStdin() {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 65_536) throw new Error('token_body_too_large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function main() {
  const command = process.argv[2] ?? 'plan';
  if (command === 'plan') {
    process.stdout.write(`${JSON.stringify(planConsent(), null, 2)}\n`);
    return;
  }
  if (command === 'redact') {
    try {
      const receipt = redactTokenBody(await readStdin());
      process.stdout.write(`${JSON.stringify(receipt)}\n`);
      process.exitCode = receipt.ok ? 0 : 4;
    } catch {
      process.stderr.write('token body was not redacted\n');
      process.exitCode = 2;
    }
    return;
  }
  process.stderr.write('usage: node docs/evidence/ari-test-probe/consent-harness.mjs [plan|redact]\n');
  process.exitCode = 2;
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(invokedPath).href) {
  main();
}
