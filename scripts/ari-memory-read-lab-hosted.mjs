import { execFileSync } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer, request as httpsRequest } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { exportJWK, generateKeyPair, jwtVerify, SignJWT } from 'jose';

import {
  acquireControllerLock,
  BASELINE_ONLY_TOKEN,
  BASELINE_USER_ID,
  buildManifest,
  cleanup,
  DENIED_PRINCIPAL_ID,
  EXPIRED_CLIENT_ID,
  HOSTED_PROJECT_REF,
  HOSTILE_SENTINEL,
  installerSql,
  LAB_VERSION,
  LOCAL_B_CLIENT_ID,
  openLabDatabase,
  REVOKED_CLIENT_ID,
  retainedBaseline,
  SECOND_ONLY_TOKEN,
  SECOND_USER_ID,
  SECOND_USER_IDENTITY,
  SHARED_TOKEN,
  seed,
  sqlSha256,
} from './ari-memory-read-lab.mjs';

const A_CLIENT = 'external-a-client';
const AGENT = 'hook-only-agent';
const PUBLISHABLE = 'sb_publishable_memory_lab_not_a_secret';
const PASSWORD = 'synthetic-password-sentinel';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function coded(code) {
  return Object.assign(new Error(code), { code });
}

function git(args) {
  return execFileSync('git', args, { encoding: 'utf8', cwd: process.cwd() }).trim();
}

function withTimeout(promise, timeoutMs, signal) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(coded('orchestration_timeout')), timeoutMs);
  });
  const racers = [promise, timeout];
  if (signal?.aborted) racers.push(Promise.reject(coded('signal_received')));
  return Promise.race(racers).finally(() => clearTimeout(timer));
}

async function callBounded(timeoutMs, signal, work) {
  const controller = new AbortController();
  let reason = 'orchestration_timeout';
  let settled = false;
  const onAbort = () => {
    reason = 'signal_received';
    controller.abort();
  };
  signal?.addEventListener('abort', onAbort, { once: true });
  const attempt = (async () => {
    try {
      const value = await work(controller.signal);
      if (controller.signal.aborted) throw coded(reason);
      settled = true;
      return value;
    } catch (error) {
      if (controller.signal.aborted) throw coded(reason);
      throw error;
    }
  })();
  try {
    return await withTimeout(attempt, timeoutMs, signal);
  } finally {
    if (!settled) controller.abort();
    signal?.removeEventListener('abort', onAbort);
  }
}

function s256(verifier) {
  return createHash('sha256').update(verifier).digest('base64url');
}

function pkcePair() {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: s256(verifier) };
}

function headerRecord(headers) {
  const out = {};
  if (headers === undefined || headers === null) return out;
  if (typeof headers.forEach === 'function') {
    headers.forEach((value, key) => {
      out[key] = value;
    });
    return out;
  }
  return { ...headers };
}

function trustedFetch(ca) {
  return (input, init = {}) =>
    new Promise((resolve, reject) => {
      const raw =
        typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      const url = new URL(raw);
      const method =
        init.method ?? (typeof input === 'object' && input?.method ? input.method : 'GET');
      const headers = headerRecord(
        init.headers ?? (typeof input === 'object' ? input.headers : undefined),
      );
      let body = init.body;
      if (body === undefined && typeof input === 'object' && input?.body !== undefined)
        body = input.body;
      const payload =
        body === undefined || body === null
          ? undefined
          : typeof body === 'string'
            ? body
            : body instanceof URLSearchParams
              ? body.toString()
              : String(body);
      if (payload !== undefined && headers['content-length'] === undefined) {
        headers['content-length'] = String(Buffer.byteLength(payload));
      }
      const req = httpsRequest(
        {
          protocol: url.protocol,
          hostname: url.hostname,
          port: url.port,
          path: `${url.pathname}${url.search}`,
          method,
          headers,
          ca,
          signal: init.signal,
        },
        (res) => {
          const chunks = [];
          res.on('data', (chunk) => chunks.push(chunk));
          res.on('end', () => {
            const flat = {};
            for (const [key, value] of Object.entries(res.headers)) {
              if (value === undefined) continue;
              flat[key] = Array.isArray(value) ? value.join(', ') : value;
            }
            resolve(
              new Response(Buffer.concat(chunks), {
                status: res.statusCode ?? 500,
                headers: flat,
              }),
            );
          });
        },
      );
      req.on('error', reject);
      if (payload !== undefined) req.write(payload);
      req.end();
    });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function jsonValue(value) {
  if (typeof value === 'string') return JSON.parse(value);
  return value;
}

async function asVerified(db, claim, statement, params) {
  return db.transaction(async (tx) => {
    await tx.exec('set local role authenticated');
    await tx.query(`select set_config('request.jwt.claims', $1, true)`, [JSON.stringify(claim)]);
    const result = await tx.query(statement, params);
    return result.rows[0];
  });
}

function listen(server, host = '127.0.0.1') {
  return new Promise((resolve) => {
    server.listen(0, host, () => resolve(server.address().port));
  });
}

function closeServer(server) {
  server.closeAllConnections?.();
  return new Promise((resolve) => {
    server.close(() => resolve());
  });
}

async function startIssuer({ db, ca, cert, key, resource, bClientId, users }) {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  const jwks = { keys: [{ ...jwk, kid: 'g2-test', alg: 'ES256', use: 'sig' }] };
  const authorizations = new Map();
  const pending = new Map();
  const sessions = new Map();
  const sessionIds = [];
  const sourceBySub = new Map();
  const ledger = (id) => {
    sessionIds.push(id);
  };

  const server = createHttpsServer({ cert, key }, (req, res) => {
    const origin = `https://127.0.0.1:${server.address().port}`;
    const issuer = `${origin}/auth/v1`;
    const send = (status, body, type = 'application/json') => {
      if (res.writableEnded) return;
      const payload = typeof body === 'string' ? body : JSON.stringify(body);
      res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store' });
      res.end(payload);
    };
    const url = new URL(req.url ?? '/', origin);
    void (async () => {
      const bearer = async () => {
        const header = req.headers.authorization ?? '';
        const token = header.replace(/^Bearer\s+/u, '');
        if (token.length === 0) return undefined;
        try {
          const verified = await jwtVerify(token, publicKey, { issuer, algorithms: ['ES256'] });
          return { token, payload: verified.payload, meta: sessions.get(token) };
        } catch {
          return undefined;
        }
      };
      if (req.method === 'GET' && url.pathname === '/auth/v1/.well-known/jwks.json') {
        send(200, jwks);
        return;
      }
      if (req.method === 'GET' && url.pathname === '/auth/v1/oauth/authorize') {
        const challenge = url.searchParams.get('code_challenge') ?? '';
        if (url.searchParams.get('code_challenge_method') !== 'S256' || challenge.length < 20) {
          send(400, { error: 'invalid_request' });
          return;
        }
        const authorizationId = randomBytes(16).toString('base64url');
        authorizations.set(authorizationId, {
          clientId: url.searchParams.get('client_id') ?? '',
          challenge,
          redirect: url.searchParams.get('redirect_uri') ?? '',
          state: url.searchParams.get('state') ?? '',
          scope: url.searchParams.get('scope') ?? '',
          resource: url.searchParams.get('resource'),
        });
        res.writeHead(302, {
          location: `${origin}/oauth/consent?authorization_id=${authorizationId}`,
          'cache-control': 'no-store',
        });
        res.end();
        return;
      }
      const authorizationPath = url.pathname.match(
        /^\/auth\/v1\/oauth\/authorizations\/([^/]+)(\/consent)?$/u,
      );
      if (authorizationPath) {
        const authorizationId = decodeURIComponent(authorizationPath[1] ?? '');
        const record = authorizations.get(authorizationId);
        const user = await bearer();
        if (user?.meta === undefined) {
          send(401, { error: 'unauthorized' });
          return;
        }
        if (record === undefined) {
          send(404, { error: 'not_found' });
          return;
        }
        const issueCode = () => {
          const code = randomBytes(16).toString('base64url');
          pending.set(code, { ...record, sub: user.meta.sub });
          const redirectUrl = new URL(record.redirect);
          redirectUrl.searchParams.set('code', code);
          redirectUrl.searchParams.set('state', record.state);
          return redirectUrl.toString();
        };
        if (req.method === 'GET' && authorizationPath[2] === undefined) {
          send(200, { authorization_id: authorizationId });
          return;
        }
        if (req.method === 'POST' && authorizationPath[2] === '/consent') {
          await readBody(req);
          send(200, { redirect_url: issueCode() });
          return;
        }
      }
      if (
        req.method === 'POST' &&
        url.pathname === '/auth/v1/token' &&
        url.searchParams.get('grant_type') === 'password'
      ) {
        const raw = await readBody(req);
        let body = {};
        try {
          body = JSON.parse(raw);
        } catch {
          body = {};
        }
        const user = users.find(
          (item) => item.email === body.email && item.password === body.password,
        );
        if (user === undefined) {
          send(400, { error: 'invalid_grant' });
          return;
        }
        const sessionId = randomUUID();
        const token = await new SignJWT({ role: 'authenticated' })
          .setProtectedHeader({ alg: 'ES256', kid: 'g2-test', typ: 'JWT' })
          .setSubject(user.sub)
          .setIssuer(issuer)
          .setAudience('authenticated')
          .setIssuedAt()
          .setExpirationTime('5m')
          .sign(privateKey);
        sessions.set(token, { sub: user.sub, kind: 'password', sessionId });
        ledger(sessionId);
        send(200, { access_token: token, token_type: 'bearer' });
        return;
      }
      if (req.method === 'POST' && url.pathname === '/auth/v1/oauth/token') {
        const raw = await readBody(req);
        const form = new URLSearchParams(raw);
        const code = form.get('code') ?? '';
        const record = pending.get(code);
        pending.delete(code);
        if (record === undefined || s256(form.get('code_verifier') ?? '') !== record.challenge) {
          send(400, { error: 'invalid_grant' });
          return;
        }
        if (
          form.get('client_id') !== record.clientId ||
          form.get('redirect_uri') !== record.redirect
        ) {
          send(400, { error: 'invalid_grant' });
          return;
        }
        const sessionId = randomUUID();
        if (record.clientId === A_CLIENT) {
          const sourceSessionId = randomUUID();
          sourceBySub.set(record.sub, { sourceSessionId, aClientId: A_CLIENT });
          const token = await new SignJWT({
            role: 'mcp_ingress',
            client_id: A_CLIENT,
            session_id: sessionId,
            source_session_id: sourceSessionId,
            agent_id: AGENT,
          })
            .setProtectedHeader({ alg: 'ES256', kid: 'g2-test', typ: 'JWT' })
            .setSubject(record.sub)
            .setIssuer(issuer)
            .setAudience(record.resource ?? resource)
            .setIssuedAt()
            .setExpirationTime('5m')
            .sign(privateKey);
          sessions.set(token, {
            sub: record.sub,
            kind: 'a',
            sessionId,
            sourceSessionId,
            aClientId: A_CLIENT,
          });
          ledger(sessionId);
          ledger(sourceSessionId);
          send(200, { access_token: token, token_type: 'bearer' });
          return;
        }
        const linked = sourceBySub.get(record.sub);
        const token = await new SignJWT({
          role: 'authenticated',
          client_id: bClientId,
          agent_id: AGENT,
          session_id: sessionId,
        })
          .setProtectedHeader({ alg: 'ES256', kid: 'g2-test', typ: 'JWT' })
          .setSubject(record.sub)
          .setIssuer(issuer)
          .setAudience('authenticated')
          .setIssuedAt()
          .setExpirationTime('5m')
          .sign(privateKey);
        sessions.set(token, {
          sub: record.sub,
          kind: 'b',
          sessionId,
          sourceSessionId: linked?.sourceSessionId ?? null,
          aClientId: linked?.aClientId ?? null,
        });
        ledger(sessionId);
        send(200, { access_token: token, token_type: 'bearer' });
        return;
      }
      if (req.method === 'GET' && url.pathname === '/auth/v1/user') {
        const user = await bearer();
        if (user?.meta?.kind !== 'b' || !UUID.test(user.meta.sub)) {
          send(401, { error: 'unauthorized' });
          return;
        }
        send(200, { id: user.meta.sub, aud: 'authenticated' });
        return;
      }
      if (
        req.method === 'POST' &&
        url.pathname === '/rest/v1/rpc/ari_probe_source_session_live_v1'
      ) {
        const user = await bearer();
        const raw = await readBody(req);
        let body = {};
        try {
          body = JSON.parse(raw);
        } catch {
          body = {};
        }
        const live =
          user?.meta?.kind === 'b' &&
          user.meta.sourceSessionId === body.source_session_id &&
          user.meta.aClientId === body.a_client_id;
        send(200, live ? 'true' : 'false');
        return;
      }
      if (req.method === 'POST' && url.pathname.startsWith('/rest/v1/rpc/authorized_memory_')) {
        const user = await bearer();
        if (user?.meta?.kind !== 'b' || user.payload.role !== 'authenticated') {
          send(401, { error: 'unauthorized' });
          return;
        }
        if (user.payload.client_id !== bClientId) {
          send(401, { error: 'unauthorized' });
          return;
        }
        const raw = await readBody(req);
        let body = {};
        try {
          body = JSON.parse(raw);
        } catch {
          send(400, { message: 'invalid request', code: '22023' });
          return;
        }
        const claim = {
          sub: user.meta.sub,
          role: 'authenticated',
          aud: 'authenticated',
          client_id: user.payload.client_id,
        };
        try {
          const row = await dispatchRpc(db, url.pathname, claim, body);
          send(200, row);
        } catch (error) {
          const code = error !== null && typeof error === 'object' ? error.code : undefined;
          if (code === '22023') {
            send(400, { message: 'invalid cursor', code: '22023' });
            return;
          }
          send(500, { message: 'upstream' });
        }
        return;
      }
      send(404, { error: 'not_found' });
    })().catch(() => send(500, { message: 'upstream' }));
  });
  const port = await listen(server);
  const origin = `https://127.0.0.1:${port}`;
  return {
    origin,
    jwks,
    fetchImpl: trustedFetch(ca),
    sessionIds,
    clearSessions() {
      sessions.clear();
      pending.clear();
      authorizations.clear();
    },
    remainingSessions() {
      return sessions.size;
    },
    close: () => closeServer(server),
  };
}

async function dispatchRpc(db, pathname, claim, body) {
  if (pathname.endsWith('/authorized_memory_get_v1')) {
    const row = await asVerified(
      db,
      claim,
      `select memory.authorized_memory_get_v1($1::text) as result`,
      [body.id],
    );
    return jsonValue(row.result);
  }
  if (pathname.endsWith('/authorized_memory_list_recent_v1')) {
    const row = await asVerified(
      db,
      claim,
      `select memory.authorized_memory_list_recent_v1($1::jsonb, $2::int, $3::text) as result`,
      [JSON.stringify(body.filters ?? null), body.limit, body.cursor ?? null],
    );
    return jsonValue(row.result);
  }
  if (pathname.endsWith('/authorized_memory_search_v1')) {
    const row = await asVerified(
      db,
      claim,
      `select memory.authorized_memory_search_v1($1::text, $2::text, $3::jsonb, $4::int, $5::text) as result`,
      [
        body.query,
        body.mode ?? 'text',
        JSON.stringify(body.filters ?? null),
        body.limit,
        body.cursor ?? null,
      ],
    );
    return jsonValue(row.result);
  }
  throw coded('unknown_rpc');
}

function structuredContent(text) {
  const messages = [];
  try {
    messages.push(JSON.parse(text));
  } catch {
    // SSE frames are parsed below.
  }
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('data:')) continue;
    const payload = trimmed.slice(5).trim();
    if (payload.length === 0) continue;
    try {
      messages.push(JSON.parse(payload));
    } catch {
      // One bad frame does not invent a result.
    }
  }
  for (const message of messages) {
    const content = message?.result?.structuredContent;
    if (content !== null && typeof content === 'object') return content;
    if (typeof message?.error === 'string') return { error: message.error, statusError: true };
  }
  return null;
}

async function passwordGrant(fetchImpl, origin, user) {
  const response = await fetchImpl(`${origin}/auth/v1/token?grant_type=password`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ email: user.email, password: user.password }),
  });
  if (!response.ok) throw coded('password_grant_failed');
  const body = await response.json();
  if (typeof body.access_token !== 'string') throw coded('password_grant_failed');
  return body.access_token;
}

async function exchangeClient(fetchImpl, origin, userToken, profile) {
  const { verifier, challenge } = pkcePair();
  const state = randomUUID();
  const authorize = new URL('/auth/v1/oauth/authorize', origin);
  authorize.searchParams.set('response_type', 'code');
  authorize.searchParams.set('client_id', profile.clientId);
  authorize.searchParams.set('redirect_uri', profile.redirectUri);
  authorize.searchParams.set('scope', profile.scope);
  authorize.searchParams.set('state', state);
  authorize.searchParams.set('code_challenge', challenge);
  authorize.searchParams.set('code_challenge_method', 'S256');
  if (profile.resource !== undefined) authorize.searchParams.set('resource', profile.resource);
  const started = await fetchImpl(authorize, { redirect: 'manual' });
  const location = started.headers.get('location');
  if (location === null) throw coded('authorize_failed');
  const authorizationId = new URL(location).searchParams.get('authorization_id');
  if (authorizationId === null) throw coded('authorize_failed');
  const consent = await fetchImpl(
    new URL(`/auth/v1/oauth/authorizations/${authorizationId}/consent`, origin),
    {
      method: 'POST',
      headers: {
        authorization: `Bearer ${userToken}`,
        'content-type': 'application/json',
        accept: 'application/json',
      },
      body: '{}',
    },
  );
  if (!consent.ok) throw coded('consent_failed');
  const consented = await consent.json();
  const redirectUrl = new URL(consented.redirect_url);
  const code = redirectUrl.searchParams.get('code');
  if (code === null) throw coded('authorization_code_missing');
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: profile.clientId,
    redirect_uri: profile.redirectUri,
    code,
    code_verifier: verifier,
  });
  if (profile.resource !== undefined) body.set('resource', profile.resource);
  const exchanged = await fetchImpl(new URL('/auth/v1/oauth/token', origin), {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body,
  });
  if (!exchanged.ok) throw coded('exchange_failed');
  const token = await exchanged.json();
  if (typeof token.access_token !== 'string') throw coded('exchange_failed');
  return token.access_token;
}

async function consentHandlerUrl(fetchImpl, authorizationUrl, userToken) {
  const started = await fetchImpl(authorizationUrl, { redirect: 'manual' });
  const location = started.headers.get('location');
  if (location === null) throw coded('authorize_failed');
  const authorizationId = new URL(location).searchParams.get('authorization_id');
  if (authorizationId === null) throw coded('authorize_failed');
  const origin = new URL(authorizationUrl).origin;
  const consent = await fetchImpl(
    new URL(`/auth/v1/oauth/authorizations/${authorizationId}/consent`, origin),
    {
      method: 'POST',
      headers: {
        authorization: `Bearer ${userToken}`,
        'content-type': 'application/json',
        accept: 'application/json',
      },
      body: '{}',
    },
  );
  if (!consent.ok) throw coded('consent_failed');
  const consented = await consent.json();
  const redirectUrl = new URL(consented.redirect_url);
  return {
    code: redirectUrl.searchParams.get('code'),
    state: redirectUrl.searchParams.get('state'),
  };
}

function mcpRequest(url, token, body, signal) {
  return fetch(url, {
    method: 'POST',
    redirect: 'manual',
    signal,
    headers: {
      accept: 'application/json, text/event-stream',
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });
}

async function readResponse(response, signal) {
  try {
    return await response.text();
  } catch (error) {
    if (signal?.aborted) throw error;
    throw coded('unreadable');
  }
}

function assertUuid(value, code) {
  if (typeof value !== 'string' || !UUID.test(value)) throw coded(code);
  return value;
}

function manifestUsers(input) {
  const baselineUserId = input.baselineUserId ?? BASELINE_USER_ID;
  const secondUserId = input.secondUserId ?? SECOND_USER_ID;
  assertUuid(baselineUserId, 'baseline_user_invalid');
  assertUuid(secondUserId, 'second_user_invalid');
  if (baselineUserId === secondUserId) throw coded('users_not_distinct');
  const bClientId = input.bClientId ?? LOCAL_B_CLIENT_ID;
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(bClientId)
  ) {
    throw coded('b_client_invalid');
  }
  return {
    baselineUserId,
    secondUserId,
    bClientId,
    secondUserIdentity: input.secondUserIdentity ?? SECOND_USER_IDENTITY,
    users: [
      {
        sub: baselineUserId,
        email: 'ari-memory-lab-baseline@loopback.invalid',
        password: PASSWORD,
      },
      {
        sub: secondUserId,
        email: input.secondUserIdentity ?? SECOND_USER_IDENTITY,
        password: PASSWORD,
      },
    ],
  };
}

function refusesHosted(input, env) {
  const url = `${input.supabaseUrl ?? ''}${env.ARI_TEST_SUPABASE_URL ?? ''}${env.SUPABASE_URL ?? ''}`;
  return url.toLowerCase().includes(HOSTED_PROJECT_REF);
}

export async function runHostedController(input = {}, env = process.env) {
  const frozen = Object.freeze({ ...input });
  if (frozen.transport === 'retained-test') {
    if (env.ARI_MEMORY_LAB_EXECUTOR !== 'ariadne') throw coded('hosted_execution_refused');
    return driveRetained(frozen, env);
  }
  if (refusesHosted(frozen, env)) throw coded('hosted_execution_refused');
  return driveSynthetic(frozen);
}

async function driveRetained() {
  // Retained TEST contact stays refused in this writer process. Ariadne runs
  // the synthetic controller, which is the same native handler and Token B path.
  throw coded('hosted_execution_refused');
}

async function driveSynthetic(input) {
  const bound = manifestUsers(input);
  const runId = randomUUID();
  const manifest = buildManifest(runId, {
    baselineUserId: bound.baselineUserId,
    secondUserId: bound.secondUserId,
    bClientId: bound.bClientId,
    secondUserIdentity: bound.secondUserIdentity,
  });
  let release;
  if (input.acquireLock === true) release = acquireControllerLock();
  const dir = mkdtempSync(join(tmpdir(), 'ari-memory-hosted-'));
  const certPath = join(dir, 'cert.pem');
  const keyPath = join(dir, 'key.pem');
  execFileSync(
    'openssl',
    [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-keyout',
      keyPath,
      '-out',
      certPath,
      '-days',
      '1',
      '-nodes',
      '-subj',
      '/CN=127.0.0.1',
      '-addext',
      'subjectAltName=IP:127.0.0.1',
    ],
    { stdio: 'ignore' },
  );
  const cert = readFileSync(certPath);
  const key = readFileSync(keyPath);
  const db = await openLabDatabase();
  let issuer;
  let listener;
  const rows = [];
  let proofCode;
  let ownershipBefore = 0;
  const grantFacts = [];
  try {
    await seed(db, manifest);
    ownershipBefore = manifest.memoryIds.length;
    const probe = createHttpServer((_req, res) => {
      res.writeHead(404);
      res.end();
    });
    const mcpPort = await listen(probe);
    await closeServer(probe);
    const resource = `http://127.0.0.1:${mcpPort}/mcp`;
    issuer = await startIssuer({
      db,
      ca: cert,
      cert,
      key,
      resource,
      bClientId: bound.bClientId,
      users: bound.users,
    });
    listener = await startMcpListener({
      supabaseUrl: issuer.origin,
      publishableKey: PUBLISHABLE,
      jwks: issuer.jwks,
      aClientId: A_CLIENT,
      bClientId: bound.bClientId,
      agentId: AGENT,
      fetchImpl: issuer.fetchImpl,
      stall: input.stall ?? 'none',
      resourcePort: mcpPort,
      onGrantFact(fact) {
        grantFacts.push({
          event: fact.event,
          sessionId: fact.sessionId,
          sub: fact.sub,
          subjectMismatch: fact.subjectMismatch === true,
        });
      },
    });
    await proveHosted({
      issuer,
      listener,
      manifest,
      users: bound.users,
      rows,
      stall: input.stall ?? 'none',
      grantFacts,
    });
  } catch (error) {
    proofCode = typeof error?.code === 'string' ? error.code : 'child_failed';
  }
  const beforeCleanup = await authorizationSnapshot(db, manifest);
  let cleanupStatus = 'unresolved';
  let ownershipAfter = null;
  let baselineRetained = false;
  let schemasRemain = false;
  try {
    await cleanup(db, manifest);
    const after = await authorizationSnapshot(db, manifest);
    ownershipAfter = after.memories.length;
    baselineRetained = await retainedBaseline(db, manifest.principals);
    const names = await db.query(`
      select to_regnamespace('policy_lab') as policy_lab, to_regnamespace('memory') as memory
    `);
    schemasRemain = names.rows[0].policy_lab !== null && names.rows[0].memory !== null;
    const cleared = issuer === undefined ? 0 : issuer.remainingSessions();
    issuer?.clearSessions();
    cleanupStatus =
      ownershipAfter === 0 &&
      baselineRetained &&
      schemasRemain &&
      after.memberships.length === 0 &&
      after.grants.length === 0 &&
      after.transientClientIds.length === 0 &&
      after.deniedPrincipalId === null &&
      issuer?.remainingSessions() === 0 &&
      cleared >= 0
        ? 'confirmed'
        : 'unresolved';
  } catch {
    cleanupStatus = 'unresolved';
  }
  await listener?.close?.();
  await issuer?.close?.();
  await db.close();
  rmSync(dir, { recursive: true, force: true });
  release?.();
  const executed = rows.filter((item) => item.executed === true);
  const rowsPass =
    proofCode === undefined &&
    input.stall !== 'headers' &&
    input.stall !== 'body' &&
    executed.length > 0 &&
    executed.every((item) => item.pass === true) &&
    cleanupStatus === 'confirmed';
  const boundFacts = grantFacts.filter((fact) => fact.event === 'bound');
  return {
    type: 'receipt',
    packet: 'ari-memory-read-lab',
    version: LAB_VERSION,
    acceptance: false,
    hostedContact: false,
    executedByWriter: true,
    listenerCount: listener === undefined ? 0 : 1,
    listenerClosed: true,
    mode: 'hosted-synthetic',
    hostedProjectPinned: HOSTED_PROJECT_REF,
    hostedExecution: 'synthetic_loopback',
    provenanceLabel: 'mc1681:jesse_via_warden',
    d1: 'not_executed',
    d2: 'not_executed',
    hookBypass: 'excluded_from_first_hosted_batch',
    directTokenA: 'excluded_from_first_hosted_batch',
    adminCredentialUsed: false,
    issuanceStatus:
      proofCode === undefined ||
      proofCode === 'orchestration_timeout' ||
      proofCode === 'signal_received'
        ? 'resolved'
        : 'unresolved',
    runId,
    head: git(['rev-parse', 'HEAD']),
    tree: git(['rev-parse', 'HEAD^{tree}']),
    installerSha256: sqlSha256(installerSql()),
    expiresAt: manifest.expiresAt,
    subjectProvenance: {
      baselineUserId: bound.baselineUserId,
      secondUserId: bound.secondUserId,
      secondUserIdentity: bound.secondUserIdentity,
      bClientId: bound.bClientId,
      bClientBinding: 'local_synthetic_stand_in',
      sessionIds: issuer?.sessionIds ?? [],
    },
    grantFacts: boundFacts.map((fact) => ({
      event: fact.event,
      sessionId: fact.sessionId,
      sub: fact.sub,
    })),
    cleanup: {
      memoryIds: beforeCleanup.memories,
      memberships: beforeCleanup.memberships,
      grants: beforeCleanup.grants,
      transientClientIds: beforeCleanup.transientClientIds,
      deniedPrincipalId: beforeCleanup.deniedPrincipalId,
      sessionIds: issuer?.sessionIds ?? [],
      schemasRemain,
    },
    rowsPass,
    reason: rowsPass
      ? 'hosted_synthetic_proved'
      : input.stall === 'headers' || input.stall === 'body'
        ? (proofCode ?? 'orchestration_timeout')
        : (proofCode ?? 'cleanup_unconfirmed'),
    cleanupStatus,
    ownershipBefore,
    ownershipAfter,
    baselineRetained,
    positiveMemoryCount: manifest.memories.filter((item) => item.kind === 'positive').length,
    rows,
  };
}

async function authorizationSnapshot(db, manifest) {
  const memories = await db.query(
    `select memory_id from policy_lab.memories where memory_id = any($1::text[]) order by 1`,
    [manifest.memoryIds],
  );
  const memberships = await db.query(
    `select principal_id, client_id, workspace_id
     from policy_lab.memberships where workspace_id = any($1::text[])
     order by 1, 2, 3`,
    [manifest.workspaceIds],
  );
  const grants = await db.query(
    `select principal_id, client_id, workspace_id, capability
     from policy_lab.capability_grants where workspace_id = any($1::text[])
     order by 1, 2, 3, 4`,
    [manifest.workspaceIds],
  );
  const clients = await db.query(
    `select client_id from policy_lab.clients where client_id = any($1::text[]) order by 1`,
    [[REVOKED_CLIENT_ID, EXPIRED_CLIENT_ID]],
  );
  const denied = await db.query(
    `select principal_id from policy_lab.principals where principal_id = $1`,
    [DENIED_PRINCIPAL_ID],
  );
  return {
    memories: memories.rows.map((row) => row.memory_id),
    memberships: memberships.rows,
    grants: grants.rows,
    transientClientIds: clients.rows.map((row) => row.client_id),
    deniedPrincipalId: denied.rows[0]?.principal_id ?? null,
  };
}

async function startMcpListener(options) {
  const port = options.resourcePort;
  const resource = `http://127.0.0.1:${port}/mcp`;
  const redirect = `http://127.0.0.1:${port}/oauth/downstream/callback`;
  const { createNativeUserMcpReadHandler } = await import(
    '../packages/server/dist/native-user-mcp-read-handler.js'
  );
  const handler = createNativeUserMcpReadHandler({
    resourceServer: resource,
    supabaseUrl: options.supabaseUrl,
    expectedClientId: options.aClientId,
    expectedAgentId: options.agentId,
    ingressRole: 'mcp_ingress',
    publishableKey: options.publishableKey,
    jwks: options.jwks,
    downstreamClientId: options.bClientId,
    downstreamRedirectUri: redirect,
    fetch: options.fetchImpl,
    ...(options.onGrantFact === undefined ? {} : { onGrantFact: options.onGrantFact }),
  });
  const server = createHttpServer((req, res) => {
    const host = req.headers.host;
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const stalled = options.stall === 'headers' || options.stall === 'body';
      const toolCall = body.toString('utf8').includes('"tools/call"');
      if (stalled && toolCall) {
        if (options.stall === 'body') {
          res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
          res.write('{"jsonrpc":"2.0","id":1,"result":');
        }
        return;
      }
      const request = new Request(`http://${host}${req.url}`, {
        method: req.method,
        headers: req.headers,
        ...(body.length === 0 || req.method === 'GET' || req.method === 'HEAD' ? {} : { body }),
      });
      void handler(request).then(async (response) => {
        const headers = {};
        response.headers.forEach((value, key) => {
          headers[key] = value;
        });
        const payload = Buffer.from(await response.arrayBuffer());
        if (!res.headersSent) res.writeHead(response.status, headers);
        res.end(payload);
      });
    });
  });
  await new Promise((resolve) => {
    server.listen(port, '127.0.0.1', resolve);
  });
  return {
    resource,
    redirect,
    close: () => closeServer(server),
  };
}

async function proveHosted({ issuer, listener, manifest, users, rows, stall, grantFacts }) {
  const aRedirect = listener.redirect.replace('/oauth/downstream/callback', '/oauth/callback');
  const bindings = [];
  for (const user of users) {
    const userToken = await passwordGrant(issuer.fetchImpl, issuer.origin, user);
    const tokenA = await exchangeClient(issuer.fetchImpl, issuer.origin, userToken, {
      clientId: A_CLIENT,
      redirectUri: aRedirect,
      scope: 'openid',
      resource: listener.resource,
    });
    const opened = await mcpRequest(listener.resource, tokenA, {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'memory-lab', version: '0.0.0' },
      },
    });
    const openedText = await opened.text();
    const handshake = JSON.parse(openedText);
    if (opened.status !== 403 || typeof handshake.authorization_url !== 'string') {
      throw coded('handshake_missing');
    }
    const consented = await consentHandlerUrl(
      issuer.fetchImpl,
      handshake.authorization_url,
      userToken,
    );
    if (consented.code === null || consented.state === null)
      throw coded('authorization_code_missing');
    const callback = new URL(listener.redirect);
    callback.searchParams.set('code', consented.code);
    callback.searchParams.set('state', consented.state);
    const bound = await fetch(callback, { redirect: 'manual' });
    if (bound.status !== 200) throw coded('bind_failed');
    await bound.text();
    bindings.push({ sub: user.sub, tokenA });
  }
  const boundFacts = grantFacts.filter((fact) => fact.event === 'bound');
  const distinctSessions = new Set(boundFacts.map((fact) => fact.sessionId));
  const distinctSubs = new Set(boundFacts.map((fact) => fact.sub));
  if (boundFacts.length < 2 || distinctSessions.size < 2 || distinctSubs.size < 2) {
    throw coded('grants_not_coexistent');
  }
  if (stall === 'headers' || stall === 'body') {
    await callBounded(1200, undefined, async (signal) => {
      const response = await mcpRequest(
        listener.resource,
        bindings[0].tokenA,
        {
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: 'memory_get', arguments: { id: manifest.memories[0].id } },
        },
        signal,
      );
      await readResponse(response, signal);
      return true;
    });
    throw coded('stall_returned');
  }
  const memoryOf = (slot) => manifest.memories.find((row) => row.slot === slot);
  const tool = async (tokenA, name, args) => {
    const response = await callBounded(8000, undefined, async (signal) => {
      const upstream = await mcpRequest(
        listener.resource,
        tokenA,
        {
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name, arguments: args },
        },
        signal,
      );
      const text = await readResponse(upstream, signal);
      return { status: upstream.status, text };
    });
    return structuredContent(response.text);
  };
  const tag = manifest.positiveTag;
  const baseline = bindings[0];
  const second = bindings[1];
  const ownCases = [
    [baseline, 'a1', 'a2', 'a3', 'baseline'],
    [second, 'b1', 'b2', 'b3', 'second'],
  ];
  for (const [user, first, middle, last, label] of ownCases) {
    const record = await tool(user.tokenA, 'memory_get', { id: memoryOf(last).id });
    const getPass =
      record?.ok === true &&
      record.record?.id === memoryOf(last).id &&
      record.record.content === HOSTILE_SENTINEL;
    rows.push({
      id: `${label}_get`,
      executed: true,
      pass: getPass,
      reason: getPass ? 'own_record' : 'own_record_missed',
    });
    if (!getPass) throw coded('own_record_missed');
    const listed = await tool(user.tokenA, 'memory_list_recent', {
      filters: { tags: [tag] },
      limit: 25,
    });
    const ids = (listed?.items ?? []).map((item) => item.id);
    const expected = [last, middle, first].map((slot) => memoryOf(slot).id);
    const listPass = listed?.ok === true && ids.join() === expected.join();
    rows.push({
      id: `${label}_list`,
      executed: true,
      pass: listPass,
      reason: listPass ? 'own_only' : 'list_mismatch',
    });
    if (!listPass) throw coded('list_mismatch');
    const found = await tool(user.tokenA, 'memory_search', {
      query: SHARED_TOKEN,
      filters: { tags: [tag] },
      limit: 20,
    });
    const searchPass =
      found?.ok === true && found.items?.length === 1 && found.items[0].id === memoryOf(first).id;
    rows.push({
      id: `${label}_search`,
      executed: true,
      pass: searchPass,
      reason: searchPass ? 'own_match' : 'search_mismatch',
    });
    if (!searchPass) throw coded('search_mismatch');
  }
  const pages = [];
  let cursor;
  for (let index = 0; index < 3; index += 1) {
    const payload = await tool(baseline.tokenA, 'memory_list_recent', {
      filters: { tags: [tag] },
      limit: 1,
      ...(cursor === undefined ? {} : { cursor }),
    });
    if (payload?.ok !== true || payload.items?.length !== 1) throw coded('pagination_incomplete');
    pages.push(payload.items[0].id);
    cursor = payload.nextCursor;
    if (index < 2 && typeof cursor !== 'string') throw coded('pagination_incomplete');
  }
  const pagePass =
    cursor === undefined &&
    pages.join() === ['a3', 'a2', 'a1'].map((slot) => memoryOf(slot).id).join();
  rows.push({
    id: 'pagination_complete',
    executed: true,
    pass: pagePass,
    reason: pagePass ? 'complete' : 'pagination_incomplete',
  });
  if (!pagePass) throw coded('pagination_incomplete');
  const foreign = await tool(baseline.tokenA, 'memory_get', { id: memoryOf('b1').id });
  const foreignPass = foreign?.ok === false && foreign.error?.code === 'RESOURCE_UNAVAILABLE';
  rows.push({
    id: 'foreign_get_unavailable',
    executed: true,
    pass: foreignPass,
    reason: foreignPass ? 'unavailable' : 'foreign_visible',
  });
  if (!foreignPass) throw coded('foreign_visible');
  const ownBaseline = await tool(baseline.tokenA, 'memory_search', {
    query: BASELINE_ONLY_TOKEN,
    filters: { tags: [tag] },
    limit: 20,
  });
  const ownSecond = await tool(second.tokenA, 'memory_search', {
    query: SECOND_ONLY_TOKEN,
    filters: { tags: [tag] },
    limit: 20,
  });
  const positivePass =
    ownBaseline?.ok === true &&
    ownBaseline.items?.length === 1 &&
    ownBaseline.items[0].id === memoryOf('a2').id &&
    ownSecond?.ok === true &&
    ownSecond.items?.length === 1 &&
    ownSecond.items[0].id === memoryOf('b2').id;
  rows.push({
    id: 'foreign_only_token_positive',
    executed: true,
    pass: positivePass,
    reason: positivePass ? 'owner_found' : 'owner_missed',
  });
  if (!positivePass) throw coded('owner_missed');
  const emptyBaseline = await tool(baseline.tokenA, 'memory_search', {
    query: SECOND_ONLY_TOKEN,
    filters: { tags: [tag] },
    limit: 20,
  });
  const emptySecond = await tool(second.tokenA, 'memory_search', {
    query: BASELINE_ONLY_TOKEN,
    filters: { tags: [tag] },
    limit: 20,
  });
  const emptyPass =
    emptyBaseline?.ok === true &&
    emptyBaseline.items?.length === 0 &&
    emptySecond?.ok === true &&
    emptySecond.items?.length === 0;
  rows.push({
    id: 'foreign_only_search_empty',
    executed: true,
    pass: emptyPass,
    reason: emptyPass ? 'empty' : 'foreign_match',
  });
  if (!emptyPass) throw coded('foreign_match');
  const firstPage = await tool(baseline.tokenA, 'memory_list_recent', {
    filters: { tags: [tag] },
    limit: 1,
  });
  const refused = await tool(second.tokenA, 'memory_list_recent', {
    filters: { tags: [tag] },
    limit: 1,
    cursor: firstPage.nextCursor,
  });
  const cursorPass = refused?.ok === false && refused.error?.code === 'INVALID_REQUEST';
  rows.push({
    id: 'cross_user_cursor_refused',
    executed: true,
    pass: cursorPass,
    reason: cursorPass ? 'invalid_cursor' : 'cursor_accepted',
  });
  if (!cursorPass) throw coded('cursor_accepted');
  const [left, right] = await Promise.all([
    tool(baseline.tokenA, 'memory_get', { id: memoryOf('a1').id }),
    tool(second.tokenA, 'memory_get', { id: memoryOf('b1').id }),
  ]);
  const retry = await tool(baseline.tokenA, 'memory_get', { id: memoryOf('a1').id });
  const concurrentPass =
    left?.record?.id === memoryOf('a1').id &&
    right?.record?.id === memoryOf('b1').id &&
    retry?.record?.id === memoryOf('a1').id;
  rows.push({
    id: 'bounded_concurrent_retry',
    executed: true,
    pass: concurrentPass,
    reason: concurrentPass ? 'cross_user' : 'retry_mismatch',
  });
  if (!concurrentPass) throw coded('retry_mismatch');
  rows.push({
    id: 'same_user_different_b_client',
    executed: false,
    pass: false,
    label: 'not_executed',
    reason: 'not_executed',
  });
}
