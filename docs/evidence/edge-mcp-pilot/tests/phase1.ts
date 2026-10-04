// Phase 1 local acceptance runner for the Edge MCP pilot. Synthetic local stack only.
// Prints one JSON receipt. Secrets (tokens, codes, keys) are never printed.
import { decodeJwt, importJWK, SignJWT, generateKeyPair } from 'npm:jose@6.2.9'

const API = Deno.env.get('PILOT_API')!
const ANON = Deno.env.get('PILOT_ANON_KEY')!
const MCP = `${API}/functions/v1/mcp`
const ISSUER = `${API}/auth/v1`
const REDIRECT_A = 'http://127.0.0.1:47811/callback'
const REDIRECT_B = 'http://127.0.0.1:47812/callback'
const CLIENTS_FILE = Deno.env.get('PILOT_CLIENTS_FILE')!
const PHASE = Deno.env.get('PILOT_PHASE') ?? 'run'

const results: Record<string, unknown>[] = []
function record(id: string, pass: boolean, facts: Record<string, unknown> = {}) {
  results.push({ id, pass, ...facts })
}

function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}
async function pkce() {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)))
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)))
  return { verifier, challenge: b64url(digest) }
}
async function json(res: Response) {
  const text = await res.text()
  try {
    return JSON.parse(text)
  } catch {
    return { _text: text.slice(0, 200) }
  }
}
function shape(token: string) {
  const c = decodeJwt(token) as Record<string, unknown>
  return {
    keys: Object.keys(c).sort(),
    aud: c.aud,
    iss: c.iss,
    role: c.role,
    client_id_present: typeof c.client_id === 'string',
    session_id_present: typeof c.session_id === 'string',
    ttl_seconds: typeof c.exp === 'number' && typeof c.iat === 'number' ? c.exp - c.iat : null,
  }
}

async function asMetadata() {
  for (const path of ['/.well-known/oauth-authorization-server/auth/v1', '/auth/v1/.well-known/oauth-authorization-server']) {
    const res = await fetch(`${API}${path}`)
    if (res.status === 200) return { path, meta: await json(res) }
    await res.body?.cancel()
  }
  return { path: null, meta: {} as any }
}

async function signup(email: string, password: string) {
  await fetch(`${API}/auth/v1/signup`, {
    method: 'POST',
    headers: { apikey: ANON, 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  }).then((r) => r.body?.cancel())
  const res = await fetch(`${API}/auth/v1/token?grant_type=password`, {
    method: 'POST',
    headers: { apikey: ANON, 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  const body = await json(res)
  if (typeof body.access_token !== 'string') throw new Error(`login_failed_${res.status}`)
  return body.access_token as string
}

async function register(name: string, redirect: string) {
  const { meta } = await asMetadata()
  if (typeof meta.registration_endpoint !== 'string') return { status: 0, clientId: null }
  const res = await fetch(meta.registration_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: name,
      redirect_uris: [redirect],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    }),
  })
  const body = await json(res)
  return { status: res.status, clientId: typeof body.client_id === 'string' ? body.client_id : null }
}

async function oauthGrant(session: string, clientId: string, redirect: string, resource: string | null) {
  const { verifier, challenge } = await pkce()
  const auth = new URL(`${API}/auth/v1/oauth/authorize`)
  auth.searchParams.set('response_type', 'code')
  auth.searchParams.set('client_id', clientId)
  auth.searchParams.set('redirect_uri', redirect)
  auth.searchParams.set('code_challenge', challenge)
  auth.searchParams.set('code_challenge_method', 'S256')
  auth.searchParams.set('state', 'pilot')
  if (resource !== null) auth.searchParams.set('resource', resource)
  const authorize = await fetch(auth, { redirect: 'manual' })
  await authorize.body?.cancel()
  const location = authorize.headers.get('location') ?? ''
  const authorizationId = new URL(location, API).searchParams.get('authorization_id')
  if (!authorizationId) return { ok: false, step: 'authorize', status: authorize.status }
  const headers = { apikey: ANON, authorization: `Bearer ${session}`, 'content-type': 'application/json' }
  const details = await fetch(`${API}/auth/v1/oauth/authorizations/${authorizationId}`, { headers })
  const detailBody = await json(details)
  let redirectUrl: string | undefined = detailBody.redirect_url
  if (!redirectUrl) {
    const consent = await fetch(`${API}/auth/v1/oauth/authorizations/${authorizationId}/consent`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ action: 'approve' }),
    })
    redirectUrl = (await json(consent)).redirect_url
  }
  const code = redirectUrl ? new URL(redirectUrl).searchParams.get('code') : null
  if (!code) return { ok: false, step: 'consent', status: details.status }
  const form = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirect,
    client_id: clientId,
    code_verifier: verifier,
  })
  if (resource !== null) form.set('resource', resource)
  const token = await fetch(`${API}/auth/v1/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form,
  })
  const tokenBody = await json(token)
  if (typeof tokenBody.access_token !== 'string') {
    return { ok: false, step: 'token', status: token.status, error: tokenBody.error ?? null }
  }
  return {
    ok: true,
    access: tokenBody.access_token as string,
    refresh: tokenBody.refresh_token as string | undefined,
  }
}

async function mcpCall(token: string | null, method: string, params: unknown, extraBody = '') {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    'mcp-protocol-version': '2025-06-18',
  }
  if (token !== null) headers.authorization = `Bearer ${token}`
  const res = await fetch(MCP, {
    method: 'POST',
    headers,
    body: JSON.stringify(
      extraBody.length > 0
        ? { jsonrpc: '2.0', id: 1, method, params: { ...(params as object), _meta: { pad: extraBody } } }
        : { jsonrpc: '2.0', id: 1, method, params },
    ),
  })
  const text = await res.text()
  let payload: any = null
  const line = text.split('\n').find((l) => l.startsWith('data: '))
  try {
    payload = JSON.parse(line ? line.slice(6) : text)
  } catch {
    payload = null
  }
  return { status: res.status, www: res.headers.get('www-authenticate'), payload, raw: text.slice(0, 160) }
}

function toolText(payload: any) {
  try {
    return JSON.parse(payload.result.content[0].text)
  } catch {
    return null
  }
}

if (PHASE === 'register') {
  const a = await register('pilot-client-a', REDIRECT_A)
  const b = await register('pilot-client-b', REDIRECT_B)
  await Deno.writeTextFile(CLIENTS_FILE, JSON.stringify({ a: a.clientId, b: b.clientId }))
  console.log(JSON.stringify({ phase: 'register', a: a.status, b: b.status, ok: !!a.clientId && !!b.clientId }))
  Deno.exit(a.clientId && b.clientId ? 0 : 1)
}

const clients = JSON.parse(await Deno.readTextFile(CLIENTS_FILE))

// T1 authorization-server metadata
const { path: asPath, meta: asMeta } = await asMetadata()
record('as_metadata', asMeta.issuer === ISSUER && typeof asMeta.registration_endpoint === 'string', {
  metadata_path: asPath,
  issuer_matches: asMeta.issuer === ISSUER,
  dcr: typeof asMeta.registration_endpoint === 'string',
})

// T2 unauthenticated request -> 401 with resource metadata pointer
const anon = await mcpCall(null, 'tools/list', {})
const metaUrl = /resource_metadata="([^"]+)"/.exec(anon.www ?? '')?.[1] ?? null
record('unauthenticated_401', anon.status === 401 && metaUrl !== null, { status: anon.status, metadata_url: metaUrl })

// T3 protected resource metadata
let prm: any = null
if (metaUrl) prm = await json(await fetch(metaUrl))
record('protected_resource_metadata', prm?.resource === MCP && prm?.authorization_servers?.includes(ISSUER), {
  resource: prm?.resource ?? null,
  authorization_servers: prm?.authorization_servers ?? null,
})

// Users
const alice = await signup('pilot-alice@example.test', 'pilot-alice-synthetic-1')
const bob = await signup('pilot-bob@example.test', 'pilot-bob-synthetic-1')

// T4 OAuth grant for client A with resource indicator; redacted claim trace
const grantA = await oauthGrant(alice, clients.a, REDIRECT_A, MCP)
record('oauth_grant_client_a', grantA.ok === true, grantA.ok ? { claims: shape(grantA.access!) } : grantA)
// Same flow without resource, to compare audience handling
const grantNoRes = await oauthGrant(bob, clients.a, REDIRECT_A, null)
record('oauth_grant_without_resource', grantNoRes.ok === true, grantNoRes.ok ? { claims: shape(grantNoRes.access!) } : grantNoRes)

// T5 whoami with the OAuth token
if (grantA.ok) {
  const who = await mcpCall(grantA.access!, 'tools/call', { name: 'whoami', arguments: {} })
  const body = toolText(who.payload)
  const sub = decodeJwt(alice).sub
  record('whoami_oauth_token', who.status === 200 && body?.sub === sub && body?.client_id === clients.a, {
    status: who.status,
    sub_matches: body?.sub === sub,
    client_matches: body?.client_id === clients.a,
    raw: who.status === 200 ? undefined : who.raw,
  })
  // T6 data tool fail-closed
  const data = await mcpCall(grantA.access!, 'tools/call', { name: 'memory_search', arguments: { query: 'x' } })
  const dataBody = toolText(data.payload)
  record('data_tool_fail_closed', data.payload?.result?.isError === true && dataBody?.error === 'downstream_credential_unresolved', {
    status: data.status,
  })
  // T7 oversized body
  const big = await mcpCall(grantA.access!, 'tools/list', {}, 'x'.repeat(70_000))
  record('oversized_body_413', big.status === 413, { status: big.status })
}

// T8 ordinary first-party session (no OAuth client) refused
const plain = await mcpCall(alice, 'tools/list', {})
record('first_party_session_refused', plain.status === 403 || plain.status === 401, {
  status: plain.status,
  error: plain.payload?.error ?? null,
})

// T9 client B: allowed only if allowlist permits
const grantB = await oauthGrant(bob, clients.b, REDIRECT_B, MCP)
if (grantB.ok) {
  const res = await mcpCall(grantB.access!, 'tools/call', { name: 'whoami', arguments: {} })
  record('client_b_not_allowlisted_refused', res.status === 403 && res.payload?.error === 'client_not_allowed', {
    status: res.status,
  })
} else record('client_b_not_allowlisted_refused', false, grantB)

// T10 forged tokens: unknown key; correct key with wrong issuer/audience/expired
const forgedKey = await generateKeyPair('ES256')
const base = grantA.ok ? (decodeJwt(grantA.access!) as Record<string, unknown>) : {}
const forged = await new SignJWT({ ...base }).setProtectedHeader({ alg: 'ES256', kid: 'unknown' }).sign(forgedKey.privateKey)
const forgedRes = await mcpCall(forged, 'tools/list', {})
record('unknown_key_refused', forgedRes.status === 401, { status: forgedRes.status })
const keys = JSON.parse(await Deno.readTextFile(Deno.env.get('PILOT_SIGNING_KEYS')!))
const jwk = keys[0]
const real = await importJWK({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d }, 'ES256')
const now = Math.floor(Date.now() / 1000)
async function mint(overrides: Record<string, unknown>) {
  return await new SignJWT({ ...base, iat: now, exp: now + 60, ...overrides })
    .setProtectedHeader({ alg: 'ES256', kid: jwk.kid, typ: 'JWT' })
    .sign(real)
}
for (const [id, claims] of [
  ['wrong_issuer_refused', { iss: 'https://evil.example/auth/v1' }],
  ['wrong_audience_refused', { aud: 'some-other-api' }],
  ['expired_refused', { iat: now - 600, exp: now - 300 }],
] as const) {
  const res = await mcpCall(await mint(claims), 'tools/list', {})
  record(id, res.status === 401, { status: res.status })
}
const positiveControl = await mcpCall(await mint({}), 'tools/list', {})
record('minted_positive_control', positiveControl.status === 200, { status: positiveControl.status })

// T11 revocation: revoke client A grant, then measure behaviour of the already-issued token
if (grantA.ok) {
  const revoke = await fetch(`${API}/auth/v1/user/oauth/grants?client_id=${clients.a}`, {
    method: 'DELETE',
    headers: { apikey: ANON, authorization: `Bearer ${alice}` },
  })
  await revoke.body?.cancel()
  const after = await mcpCall(grantA.access!, 'tools/list', {})
  const refresh = await fetch(`${API}/auth/v1/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: grantA.refresh ?? '', client_id: clients.a }),
  })
  const refreshBody = await json(refresh)
  const userinfo = await fetch(`${API}/auth/v1/oauth/userinfo`, { headers: { authorization: `Bearer ${grantA.access}` } })
  await userinfo.body?.cancel()
  const userEp = await fetch(`${API}/auth/v1/user`, { headers: { apikey: ANON, authorization: `Bearer ${grantA.access}` } })
  await userEp.body?.cancel()
  record('revocation_observed', true, {
    revoke_status: revoke.status,
    access_token_still_accepted_after_revoke: after.status === 200,
    refresh_after_revoke_status: refresh.status,
    refresh_error: refreshBody.error ?? refreshBody.error_code ?? null,
    userinfo_after_revoke_status: userinfo.status,
    auth_user_after_revoke_status: userEp.status,
  })
}

const failed = results.filter((r) => r.pass !== true).map((r) => r.id)
console.log(JSON.stringify({ phase: 'run', results, failed }, null, 1))
Deno.exit(failed.length === 0 ? 0 : 1)
