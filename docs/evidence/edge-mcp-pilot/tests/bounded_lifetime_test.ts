// Response-lifetime bounds (ATLAS MC1812 item 6). The request budget must cover the response
// body as well as the handler, and early refusals must not wait on body cancellation.
import { assert, assertEquals } from 'jsr:@std/assert@1';
import { createBounded } from '../supabase/functions/mcp/bounded.ts';

const LIMITS = { maxBodyBytes: 1024, deadlineMs: 200 };
const URL_ = 'http://pilot.test/functions/v1/mcp';
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

Deno.test('declared oversize returns at once even if body cancellation never settles', async () => {
  const bounded = createBounded(() => Promise.resolve(new Response('ok')), LIMITS);
  const stuck = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(10));
    },
    cancel() {
      return new Promise<void>(() => {});
    },
  });
  let guard: ReturnType<typeof setTimeout> | undefined;
  const start = performance.now();
  const res = await Promise.race([
    bounded(
      new Request(URL_, {
        method: 'POST',
        body: stuck,
        headers: { 'content-length': '5000' },
        duplex: 'half',
      } as RequestInit),
    ),
    new Promise<null>((r) => {
      guard = setTimeout(() => r(null), LIMITS.deadlineMs + 100);
    }),
  ]);
  clearTimeout(guard);
  const elapsed = performance.now() - start;
  assert(res !== null, 'declared-oversize response did not settle');
  await res.body?.cancel();
  assertEquals(res.status, 413);
  assert(elapsed < 50, `responded after ${elapsed.toFixed(0)} ms`);
});

Deno.test('deadline covers a streamed response body and aborts the work behind it', async () => {
  let workSignal: AbortSignal | null = null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const bounded = createBounded((req) => {
    workSignal = req.signal;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('data: first\n\n'));
        timer = setTimeout(() => {
          try {
            controller.enqueue(new TextEncoder().encode('data: late\n\n'));
            controller.close();
          } catch {
            /* stream already terminated */
          }
        }, 400);
      },
      cancel() {
        clearTimeout(timer);
      },
    });
    return Promise.resolve(
      new Response(body, { headers: { 'content-type': 'text/event-stream' } }),
    );
  }, LIMITS);
  const start = performance.now();
  const res = await bounded(new Request(URL_, { method: 'POST', body: '{}' }));
  assertEquals(res.status, 200);
  let text = '';
  let terminated = false;
  try {
    text = await res.text();
  } catch {
    terminated = true;
  }
  const elapsed = performance.now() - start;
  clearTimeout(timer);
  assert(elapsed < 300, `response body ran for ${elapsed.toFixed(0)} ms`);
  assert(!text.includes('late'), 'late data was delivered after the deadline');
  assert(
    terminated || text.includes('first'),
    'stream neither delivered early data nor terminated',
  );
  assert(
    (workSignal as AbortSignal | null)?.aborted === true,
    'work signal was not aborted at the deadline',
  );
});

Deno.test('client cancelling a streamed response aborts the work behind it', async () => {
  let workSignal: AbortSignal | null = null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const bounded = createBounded((req) => {
    workSignal = req.signal;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('data: first\n\n'));
        timer = setTimeout(() => controller.close(), 150);
      },
      cancel() {
        clearTimeout(timer);
      },
    });
    return Promise.resolve(new Response(body));
  }, LIMITS);
  const res = await bounded(new Request(URL_, { method: 'POST', body: '{}' }));
  const reader = res.body!.getReader();
  await reader.read();
  await reader.cancel('client went away');
  clearTimeout(timer);
  assert(
    (workSignal as AbortSignal | null)?.aborted === true,
    'work signal was not aborted on cancel',
  );
});

Deno.test('a streamed response that completes in time is delivered whole', async () => {
  const bounded = createBounded(() => {
    const body = new ReadableStream<Uint8Array>({
      async start(controller) {
        controller.enqueue(new TextEncoder().encode('a'));
        await sleep(30);
        controller.enqueue(new TextEncoder().encode('b'));
        controller.close();
      },
    });
    return Promise.resolve(new Response(body, { status: 201, headers: { 'x-probe': 'p' } }));
  }, LIMITS);
  const res = await bounded(new Request(URL_, { method: 'POST', body: '{}' }));
  assertEquals(res.status, 201);
  assertEquals(res.headers.get('x-probe'), 'p');
  assertEquals(await res.text(), 'ab');
});
