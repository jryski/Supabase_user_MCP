import { execFileSync } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { exportJWK, generateKeyPair, jwtVerify, SignJWT } from 'jose';

import { trustedFetch } from './ari-memory-read-lab-hosted.mjs';

function digest(verifier) {
  return createHash('sha256').update(verifier).digest('base64url');
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function closeServer(server) {
  server.closeAllConnections?.();
  return new Promise((resolve) => {
    server.close(() => resolve());
  });
}

function memoryRow(memory) {
  return {
    id: memory.id,
    title: memory.title,
    content: memory.content,
    createdAt: memory.createdAt,
    provenanceSummary: 'retained-lab-fixture',
  };
}

function cursorFor(memory) {
  return `cur_${createHash('md5').update(`${memory.id}|${memory.createdAt}`).digest('hex')}`;
}

function tagsMatch(memory, filters) {
  const tags = filters?.tags;
  if (!Array.isArray(tags)) return true;
  return tags.every((tag) => Array.isArray(memory.tags) && memory.tags.includes(tag));
}

function scopeHasOpenId(scope) {
  return String(scope ?? '')
    .split(/\s+/u)
    .some((item) => item.toLowerCase() === 'openid');
}

export async function startRetainedTransportFixture({
  users,
  aClientId,
  bClientId,
  agentId,
  memories,
  publishableKey,
  alreadyConsented = [],
  tempRoot,
}) {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  const jwks = { keys: [{ ...jwk, kid: 'retained-fixture', alg: 'ES256', use: 'sig' }] };
  const authorizations = new Map();
  const pending = new Map();
  const sessions = new Map();
  const sourceBySub = new Map();
  const passwordBySub = new Map();
  const persisted = [];
  const decoys = [];
  const consented = new Set(alreadyConsented.map((item) => `${item.sub}:${item.clientId}`));
  const hits = [];
  const authorizeScopes = [];
  const consentFlows = [];
  let rejectedApiKey = 0;
  let openidRefusals = 0;
  const root = typeof tempRoot === 'string' && tempRoot.length > 0 ? tempRoot : tmpdir();
  const dir = mkdtempSync(join(root, 'ari-memory-retained-fixture-'));
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
  const server = createServer({ cert, key });
  const port = await listen(server);
  const origin = `https://127.0.0.1:${port}`;
  server.on('request', (req, res) => {
    const issuer = `${origin}/auth/v1`;
    const send = (status, body, type = 'application/json') => {
      if (res.writableEnded) return;
      const payload = typeof body === 'string' ? body : JSON.stringify(body);
      res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store' });
      res.end(payload);
    };
    const url = new URL(req.url ?? '/', origin);
    hits.push(`${req.method} ${url.pathname}${url.search}`);
    void (async () => {
      const bearer = async () => {
        const header = req.headers.authorization ?? '';
        const token = header.replace(/^Bearer\s+/u, '');
        if (token.length === 0) return undefined;
        try {
          const verified = await jwtVerify(token, publicKey, { issuer, algorithms: ['ES256'] });
          return { payload: verified.payload, meta: sessions.get(token) };
        } catch {
          return undefined;
        }
      };
      const requireApiKey = () => {
        if (req.headers.apikey === publishableKey) return true;
        rejectedApiKey += 1;
        send(401, { message: 'publishable_apikey_required' });
        return false;
      };
      const issueCode = (record, sub) => {
        const code = randomBytes(16).toString('base64url');
        pending.set(code, { ...record, sub });
        const redirectUrl = new URL(record.redirect);
        redirectUrl.searchParams.set('code', code);
        redirectUrl.searchParams.set('state', record.state);
        return redirectUrl.toString();
      };
      // Token B is the TEST-only public PKCE grant. exchangeLocalAuthorizationCode
      // omits apikey unless a publishable key is passed, and the handler does not
      // pass one. Every other Auth route, including password and Token A, must
      // present the publishable key.
      const publicPkceToken =
        req.method === 'POST' &&
        url.pathname === '/auth/v1/oauth/token' &&
        req.headers.apikey === undefined;
      if (url.pathname.startsWith('/auth/v1') && !publicPkceToken && !requireApiKey()) return;
      if (req.method === 'GET' && url.pathname === '/auth/v1/oauth/authorize') {
        const challenge = url.searchParams.get('code_challenge') ?? '';
        const scope = url.searchParams.get('scope') ?? '';
        authorizeScopes.push(scope);
        if (url.searchParams.get('code_challenge_method') !== 'S256' || challenge.length < 20) {
          send(400, { error: 'invalid_request' });
          return;
        }
        if (scopeHasOpenId(scope)) {
          openidRefusals += 1;
          send(400, { error: 'invalid_scope' });
          return;
        }
        const authorizationId = randomBytes(16).toString('base64url');
        authorizations.set(authorizationId, {
          clientId: url.searchParams.get('client_id') ?? '',
          challenge,
          redirect: url.searchParams.get('redirect_uri') ?? '',
          state: url.searchParams.get('state') ?? '',
          scope,
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
        const pair = `${user.meta.sub}:${record.clientId}`;
        if (req.method === 'GET' && authorizationPath[2] === undefined) {
          if (consented.has(pair)) {
            consentFlows.push('already_consented_get');
            send(200, { redirect_url: issueCode(record, user.meta.sub) });
            return;
          }
          send(200, { authorization_id: authorizationId });
          return;
        }
        if (req.method === 'POST' && authorizationPath[2] === '/consent') {
          await readBody(req);
          consented.add(pair);
          consentFlows.push('approval_post');
          send(200, { redirect_url: issueCode(record, user.meta.sub) });
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
        persisted.push(sessionId);
        passwordBySub.set(user.sub, sessionId);
        const token = await new SignJWT({ role: 'authenticated', session_id: sessionId })
          .setProtectedHeader({ alg: 'ES256', kid: 'retained-fixture', typ: 'JWT' })
          .setSubject(user.sub)
          .setIssuer(issuer)
          .setAudience('authenticated')
          .setIssuedAt()
          .setExpirationTime('5m')
          .sign(privateKey);
        sessions.set(token, { sub: user.sub, kind: 'password', sessionId });
        send(200, { access_token: token, token_type: 'bearer' });
        return;
      }
      if (req.method === 'POST' && url.pathname === '/auth/v1/oauth/token') {
        const raw = await readBody(req);
        const form = new URLSearchParams(raw);
        const code = form.get('code') ?? '';
        if (publicPkceToken && form.get('client_id') !== bClientId) {
          rejectedApiKey += 1;
          send(401, { message: 'publishable_apikey_required' });
          return;
        }
        const record = pending.get(code);
        pending.delete(code);
        if (record === undefined || digest(form.get('code_verifier') ?? '') !== record.challenge) {
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
        if (scopeHasOpenId(record.scope)) {
          openidRefusals += 1;
          send(403, { error: { http_code: 403, message: 'openid_scope_refused' } });
          return;
        }
        const sessionId = randomUUID();
        if (record.clientId === aClientId) {
          const sourceSessionId = randomUUID();
          const decoySessionId = randomUUID();
          persisted.push(sourceSessionId);
          decoys.push(decoySessionId);
          sourceBySub.set(record.sub, { sourceSessionId, aClientId });
          const token = await new SignJWT({
            role: 'mcp_ingress',
            client_id: aClientId,
            session_id: decoySessionId,
            source_session_id: sourceSessionId,
            agent_id: agentId,
          })
            .setProtectedHeader({ alg: 'ES256', kid: 'retained-fixture', typ: 'JWT' })
            .setSubject(record.sub)
            .setIssuer(issuer)
            .setAudience(record.resource)
            .setIssuedAt()
            .setExpirationTime('5m')
            .sign(privateKey);
          sessions.set(token, {
            sub: record.sub,
            kind: 'a',
            sessionId: decoySessionId,
            sourceSessionId,
          });
          send(200, { access_token: token, token_type: 'bearer' });
          return;
        }
        const linked = sourceBySub.get(record.sub);
        persisted.push(sessionId);
        const token = await new SignJWT({
          role: 'authenticated',
          client_id: bClientId,
          agent_id: agentId,
          session_id: sessionId,
        })
          .setProtectedHeader({ alg: 'ES256', kid: 'retained-fixture', typ: 'JWT' })
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
        send(200, { access_token: token, token_type: 'bearer' });
        return;
      }
      if (req.method === 'GET' && url.pathname === '/auth/v1/user') {
        const user = await bearer();
        if (user?.meta?.kind !== 'b') {
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
        if (user?.meta?.kind !== 'b' || user.payload.client_id !== bClientId) {
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
        const owned = memories
          .filter((memory) => memory.ownerId === user.meta.sub && tagsMatch(memory, body.filters))
          .slice()
          .sort((left, right) => {
            const created = right.createdAt.localeCompare(left.createdAt);
            if (created !== 0) return created;
            return right.id.localeCompare(left.id);
          });
        if (url.pathname.endsWith('/authorized_memory_get_v1')) {
          const memory = owned.find((item) => item.id === body.id);
          send(200, { record: memory === undefined ? null : memoryRow(memory) });
          return;
        }
        const pageOf = (ranked) => {
          let rows = ranked;
          if (typeof body.cursor === 'string' && body.cursor.length > 0) {
            const index = rows.findIndex((item) => item.cursor === body.cursor);
            if (index < 0) {
              send(400, { message: 'invalid cursor', code: '22023' });
              return null;
            }
            rows = rows.slice(index + 1);
          }
          const limit = Number(body.limit ?? rows.length);
          const page = rows.slice(0, limit);
          const payload = {
            rows: page.map((item) => {
              const row = memoryRow(item);
              return item.rank === undefined ? row : { ...row, rank: item.rank };
            }),
          };
          if (rows.length > page.length && page.length > 0) {
            payload.nextCursor = page[page.length - 1].cursor;
          }
          return payload;
        };
        if (url.pathname.endsWith('/authorized_memory_list_recent_v1')) {
          const ranked = owned.map((memory) => ({ ...memory, cursor: cursorFor(memory) }));
          const payload = pageOf(ranked);
          if (payload !== null) send(200, payload);
          return;
        }
        if (url.pathname.endsWith('/authorized_memory_search_v1')) {
          const query = String(body.query ?? '')
            .trim()
            .toLowerCase();
          const ranked = owned
            .filter(
              (memory) =>
                memory.title.toLowerCase().includes(query) ||
                memory.content.toLowerCase().includes(query),
            )
            .map((memory) => ({
              ...memory,
              rank: memory.title.toLowerCase().includes(query) ? 1 : 0.75,
              cursor: cursorFor(memory),
            }));
          const payload = pageOf(ranked);
          if (payload !== null) send(200, payload);
          return;
        }
      }
      send(404, { error: 'not_found' });
    })().catch(() => send(500, { message: 'upstream' }));
  });
  return {
    origin,
    jwks,
    fetchImpl: trustedFetch(cert),
    hits,
    authorizeScopes,
    consentFlows,
    persistedSessionIds: () => persisted.slice(),
    decoySessionIds: () => decoys.slice(),
    rejectedApiKey: () => rejectedApiKey,
    openidRefusals: () => openidRefusals,
    async close() {
      await closeServer(server);
      rmSync(dir, { recursive: true, force: true });
    },
  };
}
