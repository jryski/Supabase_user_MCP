// SACD minimal first proof runner (profile v0.3 section 8). Local synthetic stack only.
// Prints one JSON receipt. Tokens, codes and keys are never printed.
import { decodeJwt, importJWK, SignJWT } from 'npm:jose@6.2.9';

const API = Deno.env.get('PILOT_API')!;
const ANON = Deno.env.get('PILOT_ANON_KEY')!;
const MCP = `${API}/functions/v1/mcp`;
const ISSUER = `${API}/auth/v1`;
const DB = 'supabase_db_user-mcp-edge-pilot';
const RUN = crypto.randomUUID().slice(0, 8);

type Rec = Record<string, unknown>;
const results: Rec[] = [];
const measurements: Rec[] = [];
function record(id: string, pass: boolean, facts: Rec = {}) {
  results.push({ id, pass, ...facts });
}

async function sql(query: string, user = 'postgres'): Promise<string> {
  const out = await new Deno.Command('docker', {
    args: [
      'exec',
      '-i',
      DB,
      'psql',
      '-U',
      user,
      '-d',
      'postgres',
      '-v',
      'ON_ERROR_STOP=1',
      '-At',
      '-c',
      query,
    ],
  }).output();
  const text = new TextDecoder().decode(out.stdout).trim();
  if (!out.success)
    throw new Error(`sql_failed: ${new TextDecoder().decode(out.stderr).slice(0, 300)}`);
  return text;
}
const lit = (s: string) => `'${s.replaceAll("'", "''")}'`;

function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
}
async function pkce() {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const digest = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)),
  );
  return { verifier, challenge: b64url(digest) };
}
async function json(res: Response) {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    return { _text: text.slice(0, 200) };
  }
}
async function signup(email: string, password: string) {
  await fetch(`${API}/auth/v1/signup`, {
    method: 'POST',
    headers: { apikey: ANON, 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  }).then((r) => r.body?.cancel());
  const res = await fetch(`${API}/auth/v1/token?grant_type=password`, {
    method: 'POST',
    headers: { apikey: ANON, 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const body = await json(res);
  if (typeof body.access_token !== 'string') throw new Error(`login_failed_${res.status}`);
  return body.access_token as string;
}
async function register(name: string, redirect: string) {
  const res = await fetch(asMeta.registration_endpoint as string, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: name,
      redirect_uris: [redirect],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    }),
  });
  const body = await json(res);
  if (typeof body.client_id !== 'string') throw new Error(`register_failed_${res.status}`);
  return body.client_id as string;
}
async function oauthGrant(session: string, clientId: string, redirect: string) {
  const { verifier, challenge } = await pkce();
  const auth = new URL(`${API}/auth/v1/oauth/authorize`);
  auth.searchParams.set('response_type', 'code');
  auth.searchParams.set('client_id', clientId);
  auth.searchParams.set('redirect_uri', redirect);
  auth.searchParams.set('code_challenge', challenge);
  auth.searchParams.set('code_challenge_method', 'S256');
  auth.searchParams.set('state', 'sacd');
  auth.searchParams.set('resource', MCP);
  const authorize = await fetch(auth, { redirect: 'manual' });
  await authorize.body?.cancel();
  const authorizationId = new URL(authorize.headers.get('location') ?? '', API).searchParams.get(
    'authorization_id',
  );
  if (!authorizationId) return { ok: false, step: 'authorize', status: authorize.status };
  const headers = {
    apikey: ANON,
    authorization: `Bearer ${session}`,
    'content-type': 'application/json',
  };
  const details = await fetch(`${API}/auth/v1/oauth/authorizations/${authorizationId}`, {
    headers,
  });
  let redirectUrl: string | undefined = (await json(details)).redirect_url;
  if (!redirectUrl) {
    const consent = await fetch(`${API}/auth/v1/oauth/authorizations/${authorizationId}/consent`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ action: 'approve' }),
    });
    redirectUrl = (await json(consent)).redirect_url;
  }
  const code = redirectUrl ? new URL(redirectUrl).searchParams.get('code') : null;
  if (!code) return { ok: false, step: 'consent', status: details.status };
  const token = await fetch(`${API}/auth/v1/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirect,
      client_id: clientId,
      code_verifier: verifier,
      resource: MCP,
    }),
  });
  const body = await json(token);
  if (typeof body.access_token !== 'string') {
    return {
      ok: false,
      step: 'token',
      status: token.status,
      error: body.error ?? body.error_code ?? null,
      message: String(body.error_description ?? body.msg ?? body.message ?? '').slice(0, 160),
    };
  }
  return { ok: true, access: body.access_token as string, refresh: body.refresh_token as string };
}
async function refresh(clientId: string, refreshToken: string) {
  const res = await fetch(`${API}/auth/v1/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: clientId,
    }),
  });
  const body = await json(res);
  return {
    status: res.status,
    access: typeof body.access_token === 'string' ? (body.access_token as string) : null,
    error: body.error ?? body.error_code ?? null,
    message: String(body.error_description ?? body.msg ?? '').slice(0, 160),
  };
}
function claimsOf(token: string) {
  const c = decodeJwt(token) as Rec;
  return {
    aud: c.aud,
    role: c.role,
    iss: c.iss,
    client_id: c.client_id,
    session_id_present: typeof c.session_id === 'string',
    keys: Object.keys(c).sort(),
  };
}
async function rest(
  token: string | null,
  method: string,
  path: string,
  profile: string,
  body?: unknown,
) {
  const headers: Record<string, string> = { apikey: ANON, 'content-type': 'application/json' };
  if (token) headers.authorization = `Bearer ${token}`;
  if (method === 'GET') headers['accept-profile'] = profile;
  else headers['content-profile'] = profile;
  const res = await fetch(`${API}/rest/v1/${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const payload = await json(res);
  return { status: res.status, payload };
}
const listOwn = (token: string, args: Rec = {}, query = '') =>
  rest(token, 'POST', `rpc/list_own_v1${query}`, 'mcp_api', args);
const guardReason = (p: any) =>
  typeof p?.message === 'string' && p.message.startsWith('sacd_guard:') ? p.message : null;

const sleepMs = (ms: number) => new Promise((res) => setTimeout(res, ms));
const probe = (token: string, sleepFor: number) =>
  rest(token, 'POST', 'rpc/proof_probe_v1', 'mcp_api', { sleep_ms: sleepFor });
async function freshSacd(user: string, clientId: string) {
  const g = await oauthGrant(user, clientId, REDIRECT);
  if (!g.ok) throw new Error(`fresh_grant_failed ${JSON.stringify(g)}`);
  return {
    access: g.access!,
    refresh: g.refresh!,
    session: decodeJwt(g.access!).session_id as string,
  };
}

// ---------- setup ----------
const asMeta = await json(await fetch(`${API}/auth/v1/.well-known/oauth-authorization-server`));
if (asMeta.issuer !== ISSUER) throw new Error('issuer_mismatch_setup');
const REDIRECT = 'http://127.0.0.1:47811/callback';
const clientA = await register(`sacd-a-${RUN}`, REDIRECT);
const clientB = await register(`sacd-b-${RUN}`, REDIRECT);
const clientUnknown = await register(`sacd-unknown-${RUN}`, REDIRECT);
const clientDeclared = await register(`sacd-declared-${RUN}`, REDIRECT);
await sql(`insert into mcp_cap.client_registry(client_id, mcp_resource) values (${lit(clientA)}, ${lit(MCP)}), (${lit(clientB)}, ${lit(MCP)});
insert into mcp_cap.declared_non_mcp_client(client_id, note) values (${lit(clientDeclared)}, 'synthetic declared non-MCP client');`);
const alice = await signup(`sacd-alice-${RUN}@example.test`, `alice-synthetic-${RUN}`);
const bob = await signup(`sacd-bob-${RUN}@example.test`, `bob-synthetic-${RUN}`);
const aliceSub = decodeJwt(alice).sub as string;
const bobSub = decodeJwt(bob).sub as string;
await sql(`insert into mcp_cap.fixture(owner_sub, label) select ${lit(aliceSub)}::uuid, 'alice-' || lpad(g::text, 3, '0') from generate_series(1, 120) g;
insert into mcp_cap.fixture(owner_sub, label) values (${lit(bobSub)}::uuid, 'bob-001'), (${lit(bobSub)}::uuid, 'bob-002');
insert into public.app_notes(owner_sub, body) values (${lit(aliceSub)}::uuid, 'alice note');
notify pgrst, 'reload config';
notify pgrst, 'reload schema';`);
// Wait until the schema cache knows every capability route, so no denial can come from a stale cache.
for (let i = 0; i < 40; i++) {
  const probes = await Promise.all(
    ['list_own_v1', 'proof_probe_v1', 'proof_lock_v1'].map((fn) =>
      rest(null, 'POST', `rpc/${fn}`, 'mcp_api', {}),
    ),
  );
  if (probes.every((p) => p.payload?.code !== 'PGRST202')) break;
  await new Promise((res) => setTimeout(res, 250));
}
// Role settings (statement and lock timeouts) are loaded on PostgREST config reload.
await sleepMs(1500);

// ---------- CT-2: SACD token claims on issuance and refresh ----------
const gA = await oauthGrant(alice, clientA, REDIRECT);
if (!gA.ok) throw new Error(`grant_a_failed ${JSON.stringify(gA)}`);
const tA = gA.access!;
const cA = claimsOf(tA);
const sacdShape = (c: ReturnType<typeof claimsOf>) =>
  c.aud === MCP && c.role === 'mcp_ingress' && c.iss === ISSUER && c.session_id_present;
record('CT-2_issuance_claims', sacdShape(cA) && cA.client_id === clientA, { claims: cA });
const rA = await refresh(clientA, gA.refresh!);
const cAr = rA.access ? claimsOf(rA.access) : null;
record(
  'CT-2_refresh_claims',
  rA.status === 200 && cAr !== null && sacdShape(cAr) && cAr.client_id === clientA,
  { status: rA.status, claims: cAr },
);
const tA2 = rA.access ?? tA;

// ---------- CT-9: positive nonempty own-user control FIRST ----------
const pos = await listOwn(tA2, {});
const posRows = Array.isArray(pos.payload) ? pos.payload : [];
record(
  'CT-9_positive_own_rows',
  pos.status === 200 &&
    posRows.length === 50 &&
    posRows.every((r: any) => String(r.label).startsWith('alice-')),
  { status: pos.status, rows: posRows.length },
);
const capped = await listOwn(tA2, { max_rows: 100000 });
record(
  'CT-9_row_cap_100',
  capped.status === 200 && Array.isArray(capped.payload) && capped.payload.length === 100,
  { status: capped.status, rows: Array.isArray(capped.payload) ? capped.payload.length : null },
);
const qp = await listOwn(tA2, { max_rows: 100000 }, '?select=id,label&limit=1000&order=id.desc');
record(
  'CT-9_query_params_cannot_exceed_cap',
  qp.status === 200 &&
    Array.isArray(qp.payload) &&
    qp.payload.length > 0 &&
    qp.payload.length <= 100,
  {
    status: qp.status,
    rows: Array.isArray(qp.payload) ? qp.payload.length : null,
    message: qp.status === 200 ? undefined : String(qp.payload?.message ?? '').slice(0, 160),
  },
);
const big = await listOwn(tA2, { label_prefix: 'x'.repeat(65) });
record(
  'CT-9_input_cap',
  big.status >= 400 && String(big.payload?.message ?? '').includes('input_too_large'),
  { status: big.status },
);

// ---------- CT-10: other users' rows ----------
const gB = await oauthGrant(bob, clientB, REDIRECT);
if (!gB.ok) throw new Error(`grant_b_failed ${JSON.stringify(gB)}`);
const bobRows = await listOwn(gB.access!, {});
const aliceBob = await listOwn(tA2, { label_prefix: 'bob' });
record(
  'CT-10_isolation',
  bobRows.status === 200 &&
    Array.isArray(bobRows.payload) &&
    bobRows.payload.length === 2 &&
    bobRows.payload.every((r: any) => String(r.label).startsWith('bob-')) &&
    aliceBob.status === 200 &&
    Array.isArray(aliceBob.payload) &&
    aliceBob.payload.length === 0,
  {
    bob_rows: Array.isArray(bobRows.payload) ? bobRows.payload.length : null,
    alice_prefix_bob_rows: Array.isArray(aliceBob.payload) ? aliceBob.payload.length : null,
  },
);

// ---------- CT-3 / CT-4: other client classes ----------
const gDecl = await oauthGrant(alice, clientDeclared, REDIRECT);
const cDecl = gDecl.ok ? claimsOf(gDecl.access!) : null;
const declRpc = gDecl.ok ? await listOwn(gDecl.access!, {}) : null;
record(
  'CT-3_declared_non_mcp_unchanged_and_refused',
  !!cDecl &&
    cDecl.aud === 'authenticated' &&
    cDecl.role === 'authenticated' &&
    declRpc !== null &&
    declRpc.status >= 400,
  { claims: cDecl, rpc_status: declRpc?.status ?? null },
);
const firstParty = await listOwn(alice, {});
record('CT-3_first_party_refused', firstParty.status >= 400, {
  status: firstParty.status,
  code: firstParty.payload?.code ?? null,
});
const gUnknown = await oauthGrant(alice, clientUnknown, REDIRECT);
const { access: _ua, refresh: _ur, ...gUnknownFacts } = gUnknown as Rec;
record(
  'CT-4_unknown_client_refused_by_hook',
  gUnknown.ok === false && (gUnknown as Rec).step === 'token',
  { result: gUnknownFacts, token_issued: typeof _ua === 'string' },
);
// Missing-client downgrade, exercised directly on the hook as supabase_auth_admin.
const sessionA = decodeJwt(tA2).session_id as string;
const firstPartySession = decodeJwt(alice).session_id as string;
const hookCall = async (claims: Rec) =>
  JSON.parse(
    (
      await sql(
        `set role supabase_auth_admin; select mcp_cap.custom_access_token_hook(${lit(JSON.stringify({ user_id: aliceSub, claims, authentication_method: 'oauth' }))}::jsonb)`,
        'supabase_admin',
      )
    )
      .split('\n')
      .pop()!,
  );
const downgrade = await hookCall({
  sub: aliceSub,
  role: 'authenticated',
  aud: 'authenticated',
  session_id: sessionA,
});
const fpHook = await hookCall({
  sub: aliceSub,
  role: 'authenticated',
  aud: 'authenticated',
  session_id: firstPartySession,
});
record(
  'CT-4_missing_client_refresh_not_downgraded',
  downgrade?.error?.message === 'sacd_hook:oauth_session_missing_client' &&
    fpHook?.claims?.role === 'authenticated',
  {
    oauth_session: downgrade?.error ?? null,
    first_party_unchanged: fpHook?.claims?.aud === 'authenticated',
  },
);

// ---------- CT-5D: direct negatives accepted by the gateway, refused by the guard ----------
const keys = JSON.parse(await Deno.readTextFile(Deno.env.get('PILOT_SIGNING_KEYS')!));
const jwk = keys[0];
const realKey = await importJWK(
  { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d },
  'ES256',
);
const base = decodeJwt(tA2) as Rec;
const now = Math.floor(Date.now() / 1000);
async function mint(overrides: Rec, drop: string[] = []) {
  const claims: Rec = { ...base, iat: now, exp: now + 120, ...overrides };
  for (const k of drop) delete claims[k];
  return await new SignJWT(claims)
    .setProtectedHeader({ alg: 'ES256', kid: jwk.kid, typ: 'JWT' })
    .sign(realKey);
}
const control = await listOwn(await mint({}), {});
record(
  'CT-5D_minted_positive_control',
  control.status === 200 && Array.isArray(control.payload) && control.payload.length > 0,
  { status: control.status },
);
const singletonArray = await listOwn(await mint({ aud: [MCP] }), {});
record('CT-5D_singleton_array_aud_accepted', singletonArray.status === 200, {
  status: singletonArray.status,
});
const bobSession = decodeJwt(gB.access!).session_id as string;
const negatives: [string, Rec, string[], string][] = [
  ['wrong_issuer', { iss: 'https://evil.example/auth/v1' }, [], 'sacd_guard:issuer_mismatch'],
  ['extra_audience', { aud: [MCP, 'authenticated'] }, [], 'sacd_guard:audience_not_singleton'],
  ['general_audience', { aud: 'authenticated' }, [], 'sacd_guard:audience_mismatch'],
  ['missing_client_id', {}, ['client_id'], 'sacd_guard:client_id_missing'],
  [
    'client_not_in_registry',
    { client_id: crypto.randomUUID() },
    [],
    'sacd_guard:client_not_approved',
  ],
  ['client_b_claim_on_session_a', { client_id: clientB }, [], 'sacd_guard:session_client_mismatch'],
  [
    'session_of_other_user',
    { session_id: bobSession, client_id: clientA },
    [],
    'sacd_guard:session_user_mismatch',
  ],
  [
    'first_party_session',
    { session_id: firstPartySession },
    [],
    'sacd_guard:session_client_mismatch',
  ],
  ['unknown_session', { session_id: crypto.randomUUID() }, [], 'sacd_guard:session_not_live'],
  ['missing_session', {}, ['session_id'], 'sacd_guard:session_id_invalid'],
  ['missing_exp', {}, ['exp'], 'sacd_guard:token_expired'],
  ['malformed_sub', { sub: 'not-a-uuid' }, [], 'sacd_guard:subject_unreadable'],
];
for (const [name, overrides, drop, expected] of negatives) {
  const res = await listOwn(await mint(overrides, drop), {});
  const reason = guardReason(res.payload);
  record(`CT-5D_${name}`, res.status >= 400 && reason === expected, {
    status: res.status,
    guard: reason,
    gateway_message: reason ? undefined : String(res.payload?.message ?? '').slice(0, 120),
  });
}
// Variants the gateway itself refuses (recorded, not guard tests).
for (const [name, overrides] of [
  ['expired', { iat: now - 600, exp: now - 300 }],
  ['role_authenticated', { role: 'authenticated' }],
  ['role_anon', { role: 'anon' }],
  ['role_unknown', { role: 'no_such_role' }],
] as [string, Rec][]) {
  const res = await listOwn(await mint(overrides), {});
  record(`CT-5D_refused_before_guard_${name}`, res.status >= 400, {
    status: res.status,
    code: res.payload?.code ?? null,
    message: String(res.payload?.message ?? '').slice(0, 100),
  });
}

// ---------- CT-6 / CT-7: exhaustive denial through real routes ----------
const exposed = ['public', 'graphql_public', 'mcp_api'];
const rels = (
  await sql(
    `select n.nspname || '.' || c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname in ('public','graphql_public','mcp_api') and c.relkind in ('r','v','m','f','p') order by 1`,
  )
)
  .split('\n')
  .filter(Boolean);
const relResults: Rec[] = [];
for (const rel of rels) {
  const [schema, name] = rel.split('.');
  const sacd = await rest(tA2, 'GET', `${name}?select=*`, schema);
  const fp = await rest(alice, 'GET', `${name}?select=*`, schema);
  relResults.push({
    rel,
    sacd_status: sacd.status,
    sacd_code: sacd.payload?.code ?? null,
    first_party_status: fp.status,
    first_party_rows: Array.isArray(fp.payload) ? fp.payload.length : null,
  });
}
const privateRoute = await rest(tA2, 'GET', 'fixture?select=*', 'mcp_cap');
record(
  'CT-6_relations_denied',
  rels.length > 0 &&
    relResults.every((r) => (r.sacd_status as number) >= 400) &&
    relResults.some((r) => r.first_party_status === 200 && (r.first_party_rows as number) > 0) &&
    privateRoute.status >= 400,
  { relations: relResults, private_schema_route_status: privateRoute.status },
);
const fns = (
  await sql(
    `select n.nspname || '|' || p.proname from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname in ('public','graphql_public','mcp_api') order by 1`,
  )
)
  .split('\n')
  .filter(Boolean);
const fnResults: Rec[] = [];
for (const fn of fns) {
  const [schema, name] = fn.split('|');
  if (schema === 'mcp_api' && ['list_own_v1', 'proof_probe_v1', 'proof_lock_v1'].includes(name))
    continue;
  const sacd = await rest(tA2, 'POST', `rpc/${name}`, schema, {});
  const fp = await rest(alice, 'POST', `rpc/${name}`, schema, {});
  fnResults.push({
    fn: `${schema}.${name}`,
    sacd_status: sacd.status,
    sacd_code: sacd.payload?.code ?? null,
    first_party_status: fp.status,
  });
}
const guardRoute = await rest(tA2, 'POST', 'rpc/sacd_guard', 'mcp_cap', {});
const gql = await fetch(`${API}/graphql/v1`, {
  method: 'POST',
  headers: { apikey: ANON, authorization: `Bearer ${tA2}`, 'content-type': 'application/json' },
  body: JSON.stringify({ query: '{ __schema { queryType { name } } }' }),
});
const gqlBody = await json(gql);
record(
  'CT-7_functions_denied',
  fnResults.length > 0 &&
    fnResults.every((r) => r.sacd_code === '42501') &&
    fnResults.some((r) => r.first_party_status === 200) &&
    guardRoute.status >= 400 &&
    gql.status >= 400,
  {
    functions: fnResults,
    guard_route_status: guardRoute.status,
    graphql_status: gql.status,
    graphql_code: gqlBody?.code ?? null,
  },
);

// ---------- CT-14: bounds through real Data API requests ----------
const quick = await probe(tA2, 100);
record(
  'CT-14_role_timeouts_applied',
  quick.status === 200 &&
    quick.payload?.statement_timeout === '2s' &&
    quick.payload?.lock_timeout === '1s',
  { status: quick.status, settings: quick.payload },
);
const slowStart = performance.now();
const slow = await probe(tA2, 3000);
const slowMs = Math.round(performance.now() - slowStart);
record(
  'CT-14_statement_timeout',
  slow.status >= 400 && slow.payload?.code === '57014' && slowMs < 2800,
  { status: slow.status, code: slow.payload?.code ?? null, elapsed_ms: slowMs },
);
const holder = new Deno.Command('docker', {
  args: [
    'exec',
    '-i',
    DB,
    'psql',
    '-U',
    'postgres',
    '-d',
    'postgres',
    '-v',
    'ON_ERROR_STOP=1',
    '-c',
    'begin; lock table mcp_cap.fixture in access exclusive mode; select pg_sleep(4); commit;',
  ],
  stdout: 'null',
  stderr: 'null',
}).spawn();
await sleepMs(700);
const lockStart = performance.now();
const locked = await rest(tA2, 'POST', 'rpc/proof_lock_v1', 'mcp_api', {});
const lockMs = Math.round(performance.now() - lockStart);
await holder.status;
record(
  'CT-14_lock_timeout',
  locked.status >= 400 && locked.payload?.code === '55P03' && lockMs < 2500,
  { status: locked.status, code: locked.payload?.code ?? null, elapsed_ms: lockMs },
);

// ---------- CT-13: session expiry and configured session modes ----------
const s1 = await freshSacd(alice, clientA);
const s1ok = await listOwn(s1.access, {});
await sql(
  `update auth.sessions set not_after = now() - interval '1 second' where id = ${lit(s1.session)}::uuid`,
);
const s1exp = await listOwn(s1.access, {});
record(
  'CT-13_not_after',
  s1ok.status === 200 && guardReason(s1exp.payload) === 'sacd_guard:session_expired',
  { before: s1ok.status, after: s1exp.status, guard: guardReason(s1exp.payload) },
);
const s2 = await freshSacd(alice, clientA);
await sql(`update mcp_cap.session_policy set timebox = interval '3 seconds'`);
const s2ok = await listOwn(s2.access, {});
await sleepMs(3500);
const s2exp = await listOwn(s2.access, {});
await sql(`update mcp_cap.session_policy set timebox = null`);
record(
  'CT-13_timebox',
  s2ok.status === 200 && guardReason(s2exp.payload) === 'sacd_guard:session_timebox_expired',
  { before: s2ok.status, after: s2exp.status, guard: guardReason(s2exp.payload) },
);
const s3 = await freshSacd(alice, clientA);
await sql(`update mcp_cap.session_policy set inactivity_timeout = interval '3 seconds'`);
const s3ok = await listOwn(s3.access, {});
await sleepMs(3500);
const s3idle = await listOwn(s3.access, {});
const s3r = await refresh(clientA, s3.refresh);
const s3again = s3r.access ? await listOwn(s3r.access, {}) : null;
await sql(`update mcp_cap.session_policy set inactivity_timeout = null`);
record(
  'CT-13_inactivity',
  s3ok.status === 200 &&
    guardReason(s3idle.payload) === 'sacd_guard:session_inactive' &&
    s3again?.status === 200,
  {
    before: s3ok.status,
    idle: s3idle.status,
    guard: guardReason(s3idle.payload),
    after_refresh: s3again?.status ?? null,
    note: 'refresh updates refreshed_at; Auth-side inactivity enforcement is not configured locally',
  },
);

// ---------- CT-13: a missing session policy row must refuse, not disable limits ----------
const s4 = await freshSacd(alice, clientA);
const s4ok = await listOwn(s4.access, {});
await sql(`delete from mcp_cap.session_policy`);
const s4missing = await listOwn(s4.access, {});
await sql(`insert into mcp_cap.session_policy (singleton) values (true)`);
const s4restored = await listOwn(s4.access, {});
record(
  'CT-13_policy_row_missing',
  s4ok.status === 200 &&
    guardReason(s4missing.payload) === 'sacd_guard:session_policy_missing' &&
    s4restored.status === 200,
  {
    before: s4ok.status,
    missing: s4missing.status,
    guard: guardReason(s4missing.payload),
    restored: s4restored.status,
  },
);

// ---------- CT-14: serialized result byte budget with worst-case labels ----------
const BUDGET = 32768;
const carol = await signup(`sacd-carol-${RUN}@example.test`, `carol-synthetic-${RUN}`);
const carolSub = decodeJwt(carol).sub as string;
// Each label is 256 raw bytes of '"' and '\', both of which JSON escapes to two bytes.
await sql(
  `insert into mcp_cap.fixture(owner_sub, label) select ${lit(carolSub)}::uuid, repeat(E'"\\\\', 128) from generate_series(1, 100)`,
);
const cTok = (await freshSacd(carol, clientA)).access;
const wire = async (args: Rec, query = '') => {
  const res = await fetch(`${API}/rest/v1/rpc/list_own_v1${query}`, {
    method: 'POST',
    headers: {
      apikey: ANON,
      authorization: `Bearer ${cTok}`,
      'content-type': 'application/json',
      'content-profile': 'mcp_api',
    },
    body: JSON.stringify(args),
  });
  const bytes = new Uint8Array(await res.arrayBuffer());
  let payload: any = null;
  try {
    payload = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    payload = null;
  }
  return { status: res.status, bytes: bytes.byteLength, payload };
};
const worstAll = await wire({ max_rows: 100 });
const worstSome = await wire({ max_rows: 40 });
const worstSelect = await wire({ max_rows: 40 }, '?select=label');
const labelBytes =
  Array.isArray(worstSome.payload) && worstSome.payload.length > 0
    ? new TextEncoder().encode(worstSome.payload[0].label).length
    : null;
record(
  'CT-14_result_byte_budget',
  labelBytes === 256 &&
    worstAll.status >= 400 &&
    String(worstAll.payload?.message ?? '') === 'list_own_v1:result_budget_exceeded' &&
    worstSome.status === 200 &&
    Array.isArray(worstSome.payload) &&
    worstSome.payload.length === 40 &&
    worstSome.bytes <= BUDGET &&
    worstSelect.status === 200 &&
    worstSelect.bytes <= BUDGET,
  {
    budget_bytes: BUDGET,
    raw_label_bytes: labelBytes,
    max_rows_100: {
      status: worstAll.status,
      message: worstAll.payload?.message ?? null,
      wire_bytes: worstAll.bytes,
    },
    max_rows_40: {
      status: worstSome.status,
      rows: Array.isArray(worstSome.payload) ? worstSome.payload.length : null,
      wire_bytes: worstSome.bytes,
    },
    select_label: { status: worstSelect.status, wire_bytes: worstSelect.bytes },
  },
);

// ---------- CT-15: future functions in exposed schemas are not executable by the capability role ----------
const futureTxn = (
  await sql(`begin;
create function public.sacd_probe_future() returns integer language sql as 'select 1';
create function mcp_api.sacd_probe_future() returns integer language sql as 'select 1';
select has_function_privilege('mcp_ingress', 'public.sacd_probe_future()', 'EXECUTE')::text || ',' || has_function_privilege('mcp_ingress', 'mcp_api.sacd_probe_future()', 'EXECUTE')::text;
rollback;`)
)
  .split('\n')
  .filter((l) => l.includes(','))
  .pop();
await sql(`create function public.sacd_probe_api() returns integer language sql as 'select 1';
create function mcp_api.sacd_probe_api() returns integer language sql as 'select 1';
notify pgrst, 'reload schema';`);
for (let i = 0; i < 40; i++) {
  const p = await Promise.all([
    rest(null, 'POST', 'rpc/sacd_probe_api', 'public', {}),
    rest(null, 'POST', 'rpc/sacd_probe_api', 'mcp_api', {}),
  ]);
  if (p.every((x) => x.payload?.code !== 'PGRST202')) break;
  await sleepMs(250);
}
const futPublic = await rest(tA2, 'POST', 'rpc/sacd_probe_api', 'public', {});
const futApi = await rest(tA2, 'POST', 'rpc/sacd_probe_api', 'mcp_api', {});
await sql(
  `drop function public.sacd_probe_api(); drop function mcp_api.sacd_probe_api(); notify pgrst, 'reload schema';`,
);
record(
  'CT-15_future_function_defaults',
  futureTxn === 'false,false' &&
    futPublic.payload?.code === '42501' &&
    futApi.payload?.code === '42501',
  {
    transactional_probe: futureTxn,
    api_public: { status: futPublic.status, code: futPublic.payload?.code ?? null },
    api_mcp_api: { status: futApi.status, code: futApi.payload?.code ?? null },
  },
);

// ---------- CT-20: client removed from registry while session stays live ----------
await sql(`delete from mcp_cap.client_registry where client_id = ${lit(clientB)}`);
const removed = await listOwn(gB.access!, {});
const removedRefresh = await refresh(clientB, gB.refresh!);
record(
  'CT-20_registry_removal',
  removed.status >= 400 &&
    guardReason(removed.payload) === 'sacd_guard:client_not_approved' &&
    removedRefresh.access === null,
  {
    rpc_status: removed.status,
    guard: guardReason(removed.payload),
    refresh_status: removedRefresh.status,
    refresh_error: removedRefresh.error,
  },
);

// ---------- CT-12: grant revocation, already-issued token ----------
const beforeRevoke = await listOwn(tA2, {});
const revoke = await fetch(`${API}/auth/v1/user/oauth/grants?client_id=${clientA}`, {
  method: 'DELETE',
  headers: { apikey: ANON, authorization: `Bearer ${alice}` },
});
await revoke.body?.cancel();
const sessionLeft = await sql(
  `select count(*) from auth.sessions where id = ${lit(sessionA)}::uuid`,
);
const afterRevoke = await listOwn(tA2, {});
const tokenStillUnexpired = (decodeJwt(tA2).exp as number) > Math.floor(Date.now() / 1000);
record(
  'CT-12_revocation',
  beforeRevoke.status === 200 &&
    revoke.status < 300 &&
    tokenStillUnexpired &&
    afterRevoke.status >= 400 &&
    guardReason(afterRevoke.payload) === 'sacd_guard:session_not_live',
  {
    before_status: beforeRevoke.status,
    revoke_status: revoke.status,
    session_rows_after_revoke: Number(sessionLeft),
    token_unexpired: tokenStillUnexpired,
    after_status: afterRevoke.status,
    guard: guardReason(afterRevoke.payload),
  },
);

// ---------- CT-19: pooled connections, concurrency and refresh races ----------
const p1 = await freshSacd(alice, clientA);
const warm = await Promise.all(
  Array.from({ length: 30 }, () => listOwn(p1.access, { max_rows: 1 })),
);
const revokeP = await fetch(`${API}/auth/v1/user/oauth/grants?client_id=${clientA}`, {
  method: 'DELETE',
  headers: { apikey: ANON, authorization: `Bearer ${alice}` },
});
await revokeP.body?.cancel();
const cold = await Promise.all(
  Array.from({ length: 30 }, () => listOwn(p1.access, { max_rows: 1 })),
);
record(
  'CT-19_pooled_reuse_after_revoke',
  warm.every((x) => x.status === 200) &&
    cold.every((x) => guardReason(x.payload) === 'sacd_guard:session_not_live'),
  {
    warm_ok: warm.filter((x) => x.status === 200).length,
    after_refused: cold.filter((x) => guardReason(x.payload) === 'sacd_guard:session_not_live')
      .length,
    total: 30,
    postgrest_pool_size: 10,
  },
);
const p2 = await freshSacd(alice, clientA);
const t0 = performance.now();
let revokeDoneAt = Infinity;
const calls = Array.from({ length: 40 }, async (_, i) => {
  await sleepMs(i * 10);
  const startedAt = performance.now() - t0;
  const res = await listOwn(p2.access, { max_rows: 1 });
  return { startedAt, ok: res.status === 200, guard: guardReason(res.payload) };
});
const revoker = (async () => {
  await sleepMs(150);
  const res = await fetch(`${API}/auth/v1/user/oauth/grants?client_id=${clientA}`, {
    method: 'DELETE',
    headers: { apikey: ANON, authorization: `Bearer ${alice}` },
  });
  await res.body?.cancel();
  revokeDoneAt = performance.now() - t0;
  return res.status;
})();
const outcomes = await Promise.all(calls);
const revokeStatus = await revoker;
const afterCommit = outcomes.filter((o) => o.startedAt > revokeDoneAt);
record(
  'CT-19_concurrent_revoke',
  afterCommit.length > 0 &&
    afterCommit.every((o) => !o.ok && o.guard === 'sacd_guard:session_not_live') &&
    outcomes.some((o) => o.ok),
  {
    revoke_status: revokeStatus,
    revoke_done_ms: Math.round(revokeDoneAt),
    started_after_revoke: afterCommit.length,
    accepted_before_revoke: outcomes.filter((o) => o.ok).length,
    accepted_after_revoke: afterCommit.filter((o) => o.ok).length,
  },
);
const p3 = await freshSacd(alice, clientA);
const [raced, revRace] = await Promise.all([
  refresh(clientA, p3.refresh),
  fetch(`${API}/auth/v1/user/oauth/grants?client_id=${clientA}`, {
    method: 'DELETE',
    headers: { apikey: ANON, authorization: `Bearer ${alice}` },
  }).then(async (x) => {
    await x.body?.cancel();
    return x.status;
  }),
]);
const racedUse = raced.access ? await listOwn(raced.access, {}) : null;
const oldUse = await listOwn(p3.access, {});
record(
  'CT-19_refresh_revoke_race',
  (racedUse === null || guardReason(racedUse.payload) === 'sacd_guard:session_not_live') &&
    guardReason(oldUse.payload) === 'sacd_guard:session_not_live',
  {
    refresh_status: raced.status,
    refresh_issued_token: raced.access !== null,
    revoke_status: revRace,
    refreshed_token_guard: racedUse ? guardReason(racedUse.payload) : null,
    old_token_guard: guardReason(oldUse.payload),
  },
);

const p4 = await freshSacd(alice, clientA);
const p4r = await refresh(clientA, p4.refresh);
const p4new = p4r.access ? await listOwn(p4r.access, {}) : null;
const revoke4 = await fetch(`${API}/auth/v1/user/oauth/grants?client_id=${clientA}`, {
  method: 'DELETE',
  headers: { apikey: ANON, authorization: `Bearer ${alice}` },
});
await revoke4.body?.cancel();
const p4after = p4r.access ? await listOwn(p4r.access, {}) : null;
record(
  'CT-19_refresh_then_revoke',
  p4r.status === 200 &&
    p4new?.status === 200 &&
    revoke4.status < 300 &&
    guardReason(p4after?.payload) === 'sacd_guard:session_not_live',
  {
    refresh_status: p4r.status,
    new_token_before_revoke: p4new?.status ?? null,
    revoke_status: revoke4.status,
    new_token_after_revoke_guard: guardReason(p4after?.payload),
  },
);

// ---------- CT-15: catalog lint ----------
const lint = JSON.parse(
  await sql(`select json_build_object(
 'ingress_exec_in_exposed', (select coalesce(json_agg(p.oid::regprocedure::text order by 1), '[]') from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname in ('public','graphql_public','mcp_api') and has_function_privilege('mcp_ingress', p.oid, 'EXECUTE') and has_schema_privilege('mcp_ingress', n.oid, 'USAGE')),
 'ingress_exec_without_schema_usage', (select coalesce(json_agg(p.oid::regprocedure::text order by 1), '[]') from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname in ('public','graphql_public','mcp_api') and has_function_privilege('mcp_ingress', p.oid, 'EXECUTE') and not has_schema_privilege('mcp_ingress', n.oid, 'USAGE')),
 'ingress_relation_privs', (select coalesce(json_agg(n.nspname||'.'||c.relname order by 1), '[]') from pg_class c join pg_namespace n on n.oid=c.relnamespace where c.relkind in ('r','v','m','f','p','S') and n.nspname not in ('pg_catalog','information_schema') and has_schema_privilege('mcp_ingress', n.oid, 'USAGE') and (has_table_privilege('mcp_ingress', c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') or (c.relkind='S' and has_sequence_privilege('mcp_ingress', c.oid, 'USAGE,SELECT,UPDATE')))),
 'ingress_relations_without_schema_usage', (select coalesce(json_agg(n.nspname||'.'||c.relname order by 1), '[]') from pg_class c join pg_namespace n on n.oid=c.relnamespace where c.relkind in ('r','v','m','f','p') and n.nspname not in ('pg_catalog','information_schema') and not has_schema_privilege('mcp_ingress', n.oid, 'USAGE') and has_table_privilege('mcp_ingress', c.oid, 'SELECT')),
 'ingress_schema_usage', (select json_agg(nspname order by 1) from pg_namespace where nspname in ('public','graphql_public','mcp_api','mcp_cap','auth','extensions','storage','realtime') and has_schema_privilege('mcp_ingress', oid, 'USAGE')),
 'ingress_memberships', (select coalesce(json_agg(roleid::regrole::text), '[]') from pg_auth_members where member='mcp_ingress'::regrole),
 'ingress_members', (select coalesce(json_agg(member::regrole::text||':set='||set_option||':admin='||admin_option order by 1), '[]') from pg_auth_members where roleid='mcp_ingress'::regrole),
 'owner_members', (select coalesce(json_agg(member::regrole::text||':set='||set_option||':admin='||admin_option order by 1), '[]') from pg_auth_members where roleid='mcp_capability_owner'::regrole),
 'owner_relation_privs', (select coalesce(json_agg(n.nspname||'.'||c.relname order by 1), '[]') from pg_class c join pg_namespace n on n.oid=c.relnamespace where c.relkind in ('r','v','m','f','p') and n.nspname not in ('pg_catalog','information_schema') and has_schema_privilege('mcp_capability_owner', n.oid, 'USAGE') and has_table_privilege('mcp_capability_owner', c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')),
 'owner_schema_usage', (select json_agg(nspname order by 1) from pg_namespace where nspname in ('public','graphql_public','mcp_api','mcp_cap','auth','extensions','storage','realtime') and has_schema_privilege('mcp_capability_owner', oid, 'USAGE')),
 'roles', (select json_agg(json_build_object('role', rolname, 'super', rolsuper, 'bypassrls', rolbypassrls, 'login', rolcanlogin, 'inherit', rolinherit, 'config', rolconfig) order by rolname) from pg_roles where rolname in ('mcp_ingress','mcp_capability_owner')),
 'definers', (select json_agg(json_build_object('fn', p.oid::regprocedure::text, 'owner', p.proowner::regrole::text, 'secdef', p.prosecdef, 'config', p.proconfig) order by 1) from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname in ('mcp_cap','mcp_api')),
 'oracle_executors', (select coalesce(json_agg(r.rolname order by r.rolname), '[]') from pg_roles r where not r.rolsuper and r.rolname <> 'postgres' and has_function_privilege(r.oid, 'mcp_cap.session_status(uuid,uuid,text)', 'EXECUTE')),
 'global_function_default_revokes_public', (select exists (select 1 from pg_default_acl d where d.defaclrole = 'postgres'::regrole and d.defaclnamespace = 0 and d.defaclobjtype = 'f' and not exists (select 1 from aclexplode(d.defaclacl) a where a.grantee = 0))),
 'rls', (select json_agg(json_build_object('t', relname, 'enabled', relrowsecurity, 'forced', relforcerowsecurity) order by relname) from pg_class where relnamespace='mcp_cap'::regnamespace and relkind='r'),
 'public_exec_in_exposed', (select coalesce(json_agg(p.oid::regprocedure::text||' owner='||p.proowner::regrole::text), '[]') from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname in ('public','graphql_public','mcp_api') and (p.proacl is null or exists (select 1 from aclexplode(p.proacl) a where a.grantee=0 and a.privilege_type='EXECUTE'))),
 'default_function_acl', (select coalesce(json_agg(json_build_object('role', defaclrole::regrole::text, 'schema', coalesce(defaclnamespace::regnamespace::text,'*'), 'acl', defaclacl::text)), '[]') from pg_default_acl where defaclobjtype='f')
)`),
);
const lintPass =
  JSON.stringify([...lint.ingress_exec_in_exposed].sort()) ===
    JSON.stringify([
      'mcp_api.list_own_v1(integer,text)',
      'mcp_api.proof_lock_v1()',
      'mcp_api.proof_probe_v1(integer)',
    ]) &&
  lint.ingress_relation_privs.length === 0 &&
  lint.ingress_memberships.length === 0 &&
  JSON.stringify([...lint.ingress_members].sort()) ===
    JSON.stringify(['authenticator:set=true:admin=false', 'postgres:set=false:admin=true']) &&
  JSON.stringify(lint.owner_members) === JSON.stringify(['postgres:set=false:admin=true']) &&
  lint.global_function_default_revokes_public === true &&
  lint.public_exec_in_exposed.every(
    (f: string) => f.startsWith('graphql_public.') && f.endsWith('owner=supabase_admin'),
  ) &&
  !lint.ingress_schema_usage.includes('graphql_public') &&
  lint.roles.every((r: any) => !r.super && !r.bypassrls && !r.login) &&
  lint.definers
    .filter((d: any) => d.secdef)
    .every(
      (d: any) =>
        (d.owner === 'mcp_capability_owner' || d.fn === 'mcp_cap.session_status(uuid,uuid,text)') &&
        JSON.stringify(d.config) === JSON.stringify(['search_path=""']),
    ) &&
  lint.definers.find((d: any) => d.fn === 'mcp_cap.session_status(uuid,uuid,text)')?.owner ===
    'postgres' &&
  JSON.stringify(lint.oracle_executors) === JSON.stringify(['mcp_capability_owner']) &&
  lint.rls.every((t: any) => t.enabled && t.forced) &&
  JSON.stringify([...lint.owner_relation_privs].sort()) ===
    JSON.stringify(['mcp_cap.client_registry', 'mcp_cap.fixture']) &&
  !lint.owner_members.some((m: string) => m.includes(':set=true'));
record('CT-15_catalog_lint', lintPass, { lint });

// ---------- observation: PostgREST audience handling ----------
measurements.push({
  id: 'postgrest_audience',
  singleton_mcp_audience_accepted_by_postgrest: pos.status === 200,
  note: 'local PostgREST container has no PGRST_JWT_AUD; hosted behaviour unmeasured',
});

const EXPECTED = [
  'CT-2_issuance_claims',
  'CT-2_refresh_claims',
  'CT-9_positive_own_rows',
  'CT-9_row_cap_100',
  'CT-9_query_params_cannot_exceed_cap',
  'CT-9_input_cap',
  'CT-10_isolation',
  'CT-3_declared_non_mcp_unchanged_and_refused',
  'CT-3_first_party_refused',
  'CT-4_unknown_client_refused_by_hook',
  'CT-4_missing_client_refresh_not_downgraded',
  'CT-5D_minted_positive_control',
  'CT-5D_singleton_array_aud_accepted',
  ...negatives.map(([n]) => `CT-5D_${n}`),
  'CT-5D_refused_before_guard_expired',
  'CT-5D_refused_before_guard_role_authenticated',
  'CT-5D_refused_before_guard_role_anon',
  'CT-5D_refused_before_guard_role_unknown',
  'CT-6_relations_denied',
  'CT-7_functions_denied',
  'CT-14_role_timeouts_applied',
  'CT-14_statement_timeout',
  'CT-14_lock_timeout',
  'CT-13_not_after',
  'CT-13_timebox',
  'CT-13_inactivity',
  'CT-20_registry_removal',
  'CT-12_revocation',
  'CT-19_pooled_reuse_after_revoke',
  'CT-19_concurrent_revoke',
  'CT-19_refresh_revoke_race',
  'CT-15_catalog_lint',
  'CT-15_future_function_defaults',
  'CT-13_policy_row_missing',
  'CT-14_result_byte_budget',
  'CT-19_refresh_then_revoke',
];
const seenIds = new Set(results.map((x) => x.id as string));
const failed = [
  ...results.filter((x) => x.pass !== true).map((x) => x.id),
  ...EXPECTED.filter((id) => !seenIds.has(id)).map((id) => `missing:${id}`),
  ...[...seenIds].filter((id) => !EXPECTED.includes(id)).map((id) => `unexpected:${id}`),
];
console.log(
  JSON.stringify({ run: RUN, asserted: results.length, results, measurements, failed }, null, 1),
);
Deno.exit(failed.length === 0 ? 0 : 1);
