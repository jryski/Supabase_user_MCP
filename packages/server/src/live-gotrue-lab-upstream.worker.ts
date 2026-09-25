import { parentPort, type MessagePort } from 'node:worker_threads';

import { LabDualGrantError } from './lab-dual-grant-broker.js';
import {
  performLiveUpstreamOperation,
  type LiveUpstreamOperation,
} from './live-gotrue-lab-upstream.js';

interface WorkerRequest {
  readonly operation: LiveUpstreamOperation;
  readonly sab: SharedArrayBuffer;
  readonly port: MessagePort;
}

function errorCode(error: unknown): string {
  if (error instanceof LabDualGrantError) return error.code;
  if (error instanceof Error && /:\s\d{3}$/.test(error.message) && !error.message.includes('eyJ')) {
    return error.message;
  }
  return 'live_upstream_failed';
}

parentPort?.on('message', (message: WorkerRequest) => {
  void (async () => {
    let body: { ok: boolean; result?: unknown; error?: string };
    try {
      body = { ok: true, result: await performLiveUpstreamOperation(message.operation) };
    } catch (error) {
      body = { ok: false, error: errorCode(error) };
    }
    try {
      message.port.postMessage(body);
    } catch {
      // The parent treats a missing result as failure. Do not include request material.
    }
    const flag = new Int32Array(message.sab);
    Atomics.store(flag, 0, 1);
    Atomics.notify(flag, 0);
  })();
});
