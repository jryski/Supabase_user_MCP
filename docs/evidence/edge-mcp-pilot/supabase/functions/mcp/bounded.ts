// Ingress bounds for the pilot MCP function: body size, request deadline and cancellation.
//
// One linked AbortSignal governs the whole request. It fires on the deadline or on client
// disconnect. The deadline starts before the body is read. On abort, the body reader is
// cancelled, and the signal is passed to the handler through the rebuilt Request so that
// handler and downstream work can stop. The response is never held open waiting for
// work that ignores the signal.

export type Handler = (req: Request) => Promise<Response>;

export interface Limits {
  maxBodyBytes: number;
  deadlineMs: number;
}

export function jsonError(status: number, code: string): Response {
  return Response.json({ error: code }, { status, headers: { 'cache-control': 'no-store' } });
}

class DeadlineExceeded extends Error {
  constructor() {
    super('deadline_exceeded');
    this.name = 'DeadlineExceeded';
  }
}

const TOO_LARGE = Symbol('too_large');

async function readBounded(
  body: ReadableStream<Uint8Array>,
  maxBytes: number,
  signal: AbortSignal,
): Promise<Uint8Array<ArrayBuffer> | typeof TOO_LARGE> {
  const reader = body.getReader();
  const onAbort = () => {
    reader.cancel(signal.reason).catch(() => {});
  };
  signal.addEventListener('abort', onAbort, { once: true });
  try {
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      if (signal.aborted) throw signal.reason;
      const { done, value } = await reader.read();
      if (signal.aborted) throw signal.reason;
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        reader.cancel().catch(() => {});
        return TOO_LARGE;
      }
      chunks.push(value);
    }
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      out.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return out;
  } finally {
    signal.removeEventListener('abort', onAbort);
  }
}

export function createBounded(handler: Handler, limits: Limits): Handler {
  return async function bounded(req: Request): Promise<Response> {
    const controller = new AbortController();
    const signal = controller.signal;
    const timer = setTimeout(() => controller.abort(new DeadlineExceeded()), limits.deadlineMs);
    const relay = () => controller.abort(req.signal.reason);
    if (req.signal.aborted) relay();
    else req.signal.addEventListener('abort', relay, { once: true });

    let rejectOnAbort: (reason: unknown) => void = () => {};
    const aborted = new Promise<never>((_, reject) => {
      rejectOnAbort = reject;
    });
    aborted.catch(() => {});
    const onSignal = () => rejectOnAbort(signal.reason);
    if (signal.aborted) onSignal();
    else signal.addEventListener('abort', onSignal, { once: true });

    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      clearTimeout(timer);
      req.signal.removeEventListener('abort', relay);
      signal.removeEventListener('abort', onSignal);
    };
    // When a streamed response is returned, the budget stays active until that body ends.
    let handedOff = false;

    try {
      if (signal.aborted) throw signal.reason;
      const declared = Number(req.headers.get('content-length') ?? '0');
      if (Number.isFinite(declared) && declared > limits.maxBodyBytes) {
        // Refuse at once; do not wait for the client stream to acknowledge cancellation.
        req.body?.cancel().catch(() => {});
        return jsonError(413, 'body_too_large');
      }
      let body: Uint8Array<ArrayBuffer> | undefined;
      if (req.body !== null) {
        const read = await Promise.race([
          readBounded(req.body, limits.maxBodyBytes, signal),
          aborted,
        ]);
        if (read === TOO_LARGE) return jsonError(413, 'body_too_large');
        body = read;
      }
      if (signal.aborted) throw signal.reason;
      const inner = new Request(req.url, {
        method: req.method,
        headers: req.headers,
        body,
        signal,
      });
      const response = await Promise.race([handler(inner), aborted]);
      if (response.body === null) return response;
      handedOff = true;
      return new Response(boundedBody(response.body, controller, release), {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      });
    } catch (error) {
      if (signal.reason instanceof DeadlineExceeded) return jsonError(504, 'deadline_exceeded');
      if (signal.aborted) return jsonError(499, 'client_closed_request');
      throw error;
    } finally {
      if (!handedOff) release();
    }
  };
}

/**
 * Relays a handler's response body under the request budget. The deadline or a client
 * disconnect terminates the stream and cancels its source. A consumer cancel aborts the
 * work signal. The budget is released only when the body finishes.
 */
function boundedBody(
  source: ReadableStream<Uint8Array>,
  controller: AbortController,
  release: () => void,
): ReadableStream<Uint8Array> {
  const signal = controller.signal;
  const reader = source.getReader();
  let onAbort: (() => void) | undefined;
  const finish = () => {
    if (onAbort) signal.removeEventListener('abort', onAbort);
    release();
  };
  return new ReadableStream<Uint8Array>({
    start(out) {
      onAbort = () => {
        reader.cancel(signal.reason).catch(() => {});
        try {
          out.error(signal.reason);
        } catch {
          /* already closed */
        }
        finish();
      };
      if (signal.aborted) onAbort();
      else signal.addEventListener('abort', onAbort, { once: true });
    },
    async pull(out) {
      try {
        const { done, value } = await reader.read();
        if (signal.aborted) return;
        if (done) {
          out.close();
          finish();
        } else {
          out.enqueue(value);
        }
      } catch (error) {
        try {
          out.error(error);
        } catch {
          /* already errored */
        }
        finish();
      }
    },
    cancel(reason) {
      controller.abort(reason ?? new Error('client_closed_response'));
      reader.cancel(reason).catch(() => {});
      finish();
    },
  });
}
