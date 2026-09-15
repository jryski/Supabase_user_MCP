import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const fixtureDir = dirname(fileURLToPath(import.meta.url));
const root = resolve(fixtureDir, '../../..');
const mode = process.env.SYNTHETIC_STDIO_MODE ?? 'default';
const require = createRequire(resolve(root, 'package.json'));
const { serveStdio } = await import(
  pathToFileURL(require.resolve('@modelcontextprotocol/server/stdio').replace(/\.cjs$/, '.mjs'))
    .href
);
const { createReadOnlyServer } = await import(
  pathToFileURL(resolve(root, 'packages/server/dist/server.js')).href
);
const { createFixedSupabaseClient } = await import(
  pathToFileURL(resolve(root, 'packages/server/dist/fixed-supabase-client.js')).href
);

globalThis.fetch = async () => {
  throw new Error('Live network forbidden in synthetic stdio fixture');
};

const record = {
  id: 'mem_1234567890123456789012',
  title: 'Synthetic business address',
  content: 'TEST FIXTURE ONLY: 123 Example Street, Example City.',
  createdAt: '2026-09-15T00:00:00.000Z',
  provenanceSummary: 'Synthetic process test, not a real address',
};

const syntheticFetch = async (url, init) => {
  const path = new URL(String(url)).pathname;
  const json = (body) =>
    new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
  if (path === '/auth/v1/user') {
    return json({ id: '11111111-1111-4111-9111-111111111111', aud: 'authenticated' });
  }
  const body = JSON.parse(String(init?.body));
  if (mode === 'unavailable') return new Response('{}', { status: 503 });
  if (path.endsWith('authorized_memory_search_v1')) {
    if (body.query !== 'business address') return json({ rows: [] });
    if (mode === 'empty') return json({ rows: [] });
    if (mode === 'ambiguous') {
      return json({
        rows: [
          { ...record, rank: 0.9 },
          { ...record, id: 'mem_2234567890123456789012', rank: 0.8 },
        ],
      });
    }
    if (mode === 'partial') {
      return json({ rows: [{ ...record, rank: 0.9 }], nextCursor: 'cur_abcdefghijklmnop' });
    }
    return json({ rows: [{ ...record, rank: 0.9 }] });
  }
  if (path.endsWith('authorized_memory_get_v1')) return json({ record });
  throw new Error('Unexpected synthetic endpoint');
};

const handle = serveStdio(
  async () =>
    createReadOnlyServer({
      client: createFixedSupabaseClient({
        origin: 'https://synthetic.supabase.co',
        credentials: {
          projectPublishableKey: 'sb_publishable_synthetic',
          userAccessToken: 'header.payload.signature',
        },
        fetch: syntheticFetch,
      }),
      registerDraftTwoTools: mode !== 'default',
    }),
  { legacy: 'reject', onerror: (error) => console.error('SYNTHETIC_STDIO_ERROR', error.message) },
);

process.once('SIGTERM', () => void handle.close());
process.once('SIGINT', () => void handle.close());
