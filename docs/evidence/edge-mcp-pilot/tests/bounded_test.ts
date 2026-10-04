// Ingress bounds tests (ATLAS MC1810 item 6). Deadline must cover body ingestion, and
// expiry or client disconnect must abort the handler and its downstream work.
import { assert, assertEquals } from 'jsr:@std/assert@1';
import { createBounded, type Handler } from '../supabase/functions/mcp/bounded.ts';

const LIMITS = { maxBodyBytes: 1024, deadlineMs: 200 };
const URL_ = 'http://pilot.test/functions/v1/mcp';
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function slowBody(closeAfterMs: number, cancelled: { value: boolean }): ReadableStream<Uint8Array> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode('{"jsonrpc":'));
      timer = setTimeout(() => {
        try {
          controller.enqueue(new TextEncoder().encode('"2.0"}'));
          controller.close();
        } catch {
          /* already cancelled */
        }
      }, closeAfterMs);
    },
    cancel() {
      cancelled.value = true;
      clearTimeout(timer);
    },
  });
}

/** A handler that does abortable work for `workMs`, recording whether it saw an abort. */
function slowHandler(
  workMs: number,
  record: { called: boolean; observedAbort: boolean; settledAt: number },
): Handler {
  return (req) => {
    record.called = true;
    return new Promise<Response>((resolve, reject) => {
      const finish = (fn: () => void) => {
        record.settledAt = performance.now();
        fn();
      };
      if (req.signal.aborted) {
        record.observedAbort = true;
        return finish(() => reject(req.signal.reason));
      }
      const t = setTimeout(() => finish(() => resolve(new Response('late'))), workMs);
      req.signal.addEventListener(
        'abort',
        () => {
          clearTimeout(t);
          record.observedAbort = true;
          finish(() => reject(req.signal.reason));
        },
        { once: true },
      );
    });
  };
}

Deno.test('positive control: a small request passes through with its body and method', async () => {
  let seen = '';
  const bounded = createBounded(async (req) => {
    seen = `${req.method} ${await req.text()} ${req.headers.get('x-probe')}`;
    return new Response('ok');
  }, LIMITS);
  const res = await bounded(
    new Request(URL_, { method: 'POST', body: '{"a":1}', headers: { 'x-probe': 'p' } }),
  );
  assertEquals(res.status, 200);
  assertEquals(await res.text(), 'ok');
  assertEquals(seen, 'POST {"a":1} p');
});

Deno.test('deadline covers a slow request body and cancels the reader', async () => {
  const cancelled = { value: false };
  let handlerCalled = false;
  const bounded = createBounded(() => {
    handlerCalled = true;
    return Promise.resolve(new Response('ok'));
  }, LIMITS);
  const start = performance.now();
  const res = await bounded(
    new Request(URL_, {
      method: 'POST',
      body: slowBody(400, cancelled),
      duplex: 'half',
    } as RequestInit),
  );
  const elapsed = performance.now() - start;
  await res.body?.cancel();
  assertEquals(res.status, 504);
  assert(elapsed < 300, `responded after ${elapsed.toFixed(0)} ms`);
  assert(cancelled.value, 'body reader was not cancelled');
  assertEquals(handlerCalled, false);
});

Deno.test('deadline aborts a slow handler and the handler settles promptly', async () => {
  const record = { called: false, observedAbort: false, settledAt: 0 };
  const bounded = createBounded(slowHandler(400, record), LIMITS);
  const res = await bounded(new Request(URL_, { method: 'POST', body: '{}' }));
  const respondedAt = performance.now();
  await res.body?.cancel();
  assertEquals(res.status, 504);
  await sleep(20);
  assert(record.observedAbort, 'handler never observed the deadline abort');
  assert(
    record.settledAt > 0 && record.settledAt - respondedAt < 20,
    'handler did not settle with the response',
  );
});

Deno.test('an already-aborted client signal stops before the handler runs', async () => {
  const record = { called: false, observedAbort: false, settledAt: 0 };
  const bounded = createBounded(slowHandler(50, record), LIMITS);
  const ac = new AbortController();
  ac.abort();
  const res = await bounded(new Request(URL_, { method: 'POST', body: '{}', signal: ac.signal }));
  await res.body?.cancel();
  assertEquals(res.status, 499);
  assertEquals(record.called, false);
});

Deno.test('a client disconnect during handling aborts the handler', async () => {
  const record = { called: false, observedAbort: false, settledAt: 0 };
  const bounded = createBounded(slowHandler(400, record), LIMITS);
  const ac = new AbortController();
  setTimeout(() => ac.abort(), 50);
  const start = performance.now();
  const res = await bounded(new Request(URL_, { method: 'POST', body: '{}', signal: ac.signal }));
  const elapsed = performance.now() - start;
  await res.body?.cancel();
  assertEquals(res.status, 499);
  assert(elapsed < 150, `responded after ${elapsed.toFixed(0)} ms`);
  assert(record.observedAbort, 'handler never observed the disconnect');
});

Deno.test('oversized bodies are refused, declared or streamed, and the stream is cancelled', async () => {
  const bounded = createBounded(() => Promise.resolve(new Response('ok')), LIMITS);
  const declared = await bounded(
    new Request(URL_, {
      method: 'POST',
      body: 'x'.repeat(10),
      headers: { 'content-length': '5000' },
    }),
  );
  await declared.body?.cancel();
  assertEquals(declared.status, 413);
  let cancelled = false;
  const big = new ReadableStream<Uint8Array>({
    pull(controller) {
      controller.enqueue(new Uint8Array(600));
    },
    cancel() {
      cancelled = true;
    },
  });
  const streamed = await bounded(
    new Request(URL_, { method: 'POST', body: big, duplex: 'half' } as RequestInit),
  );
  await streamed.body?.cancel();
  assertEquals(streamed.status, 413);
  assert(cancelled, 'oversized stream was not cancelled');
});
