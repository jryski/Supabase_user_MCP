// Real MCP SDK cancellation (ATLAS MC1812): a delayed tool doing a downstream fetch, served
// through createBounded with SSE responses. Proves whether deadline and client disconnect reach
// the tool's downstream request.
import { assert, assertEquals } from 'jsr:@std/assert@1';
import { createMcpHandler, McpServer } from 'npm:@modelcontextprotocol/server@2.3.0';
import { z } from 'npm:zod@4.6.5';
import { createBounded } from '../supabase/functions/mcp/bounded.ts';

const LIMITS = { maxBodyBytes: 65_536, deadlineMs: 300 };

interface Downstream {
  url: string;
  started: Promise<void>;
  aborted: Promise<boolean>;
  close: () => Promise<void>;
}

/** A local downstream API that never answers and reports whether its caller went away. */
function slowDownstream(): Downstream {
  let markStarted: () => void = () => {};
  let markAborted: (v: boolean) => void = () => {};
  const started = new Promise<void>((r) => {
    markStarted = r;
  });
  const aborted = new Promise<boolean>((r) => {
    markAborted = r;
  });
  const server = Deno.serve({ hostname: '127.0.0.1', port: 0, onListen: () => {} }, (req) => {
    markStarted();
    return new Promise<Response>((resolve) => {
      const t = setTimeout(() => {
        markAborted(false);
        resolve(new Response('late'));
      }, 2_000);
      req.signal.addEventListener('abort', () => {
        clearTimeout(t);
        markAborted(true);
        resolve(new Response('aborted'));
      });
    });
  });
  const { port } = server.addr as Deno.NetAddr;
  return { url: `http://127.0.0.1:${port}/slow`, started, aborted, close: () => server.shutdown() };
}

function mcpFor(downstreamUrl: string) {
  return createBounded(
    (req) =>
      createMcpHandler(
        () => {
          const server = new McpServer({ name: 'cancel-probe', version: '0.0.1' });
          server.registerTool(
            'slow_fetch',
            { description: 'Delayed downstream fetch.', inputSchema: z.object({}) },
            async (_args, extra) => {
              const res = await fetch(downstreamUrl, { signal: extra.mcpReq.signal });
              return { content: [{ type: 'text', text: await res.text() }] };
            },
          );
          return server;
        },
        { onerror: () => {} },
      ).fetch(req),
    LIMITS,
  );
}

function toolCall(signal?: AbortSignal) {
  return new Request('http://pilot.test/functions/v1/mcp', {
    method: 'POST',
    signal,
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      'mcp-protocol-version': '2025-06-18',
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'slow_fetch', arguments: {} },
    }),
  });
}

async function drain(res: Response): Promise<{ ms: number; terminated: boolean; text: string }> {
  const start = performance.now();
  try {
    const text = await res.text();
    return { ms: performance.now() - start, terminated: false, text };
  } catch {
    return { ms: performance.now() - start, terminated: true, text: '' };
  }
}

Deno.test('SDK: deadline aborts a delayed tool and its downstream fetch', async () => {
  const down = slowDownstream();
  try {
    const start = performance.now();
    const res = await mcpFor(down.url)(toolCall());
    const body = await drain(res);
    const total = performance.now() - start;
    await down.started;
    const downstreamAborted = await Promise.race([
      down.aborted,
      new Promise<boolean>((r) => setTimeout(() => r(false), 500)),
    ]);
    console.log(
      JSON.stringify({
        case: 'deadline',
        status: res.status,
        content_type: res.headers.get('content-type'),
        total_ms: Math.round(total),
        stream_terminated: body.terminated,
        delivered_late_text: body.text.includes('late'),
        downstream_aborted: downstreamAborted,
      }),
    );
    assert(total < LIMITS.deadlineMs + 200, `request ran ${Math.round(total)} ms`);
    assert(!body.text.includes('late'), 'late tool result was delivered');
    assertEquals(downstreamAborted, true, 'downstream fetch was not aborted');
  } finally {
    await down.close();
  }
});

Deno.test('SDK: client disconnect aborts a delayed tool and its downstream fetch', async () => {
  const down = slowDownstream();
  try {
    const client = new AbortController();
    const resPromise = mcpFor(down.url)(toolCall(client.signal));
    await down.started;
    client.abort();
    const res = await resPromise;
    await drain(res);
    const downstreamAborted = await Promise.race([
      down.aborted,
      new Promise<boolean>((r) => setTimeout(() => r(false), 500)),
    ]);
    console.log(
      JSON.stringify({
        case: 'disconnect',
        status: res.status,
        downstream_aborted: downstreamAborted,
      }),
    );
    assertEquals(downstreamAborted, true, 'downstream fetch was not aborted');
  } finally {
    await down.close();
  }
});
