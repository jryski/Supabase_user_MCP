import { MAX_TOOL_EXECUTION_MS } from '@supabase-user-mcp/contracts';
import { exportJWK, generateKeyPair } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createNativeUserMcpHandler, MCP_INGRESS_ROLE } from './native-user-mcp.js';

async function handler() {
  const { publicKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  return createNativeUserMcpHandler({
    resourceServer: 'https://mcp.example.invalid/mcp',
    supabaseUrl: 'https://project.example.invalid',
    expectedClientId: 'synthetic-ingress-client',
    ingressRole: MCP_INGRESS_ROLE,
    publishableKey: 'sb_publishable_synthetic_ingress',
    jwks: { keys: [{ ...jwk, kid: 'synthetic', alg: 'ES256' }] },
  });
}

function stalledRequest(signal?: AbortSignal) {
  const cancelled = vi.fn(() => new Promise<void>(() => undefined));
  const body = new ReadableStream<Uint8Array>({
    pull: () => new Promise<void>(() => undefined),
    cancel: cancelled,
  });
  const request = new Request('https://mcp.example.invalid/mcp', {
    method: 'POST',
    body,
    duplex: 'half',
    ...(signal === undefined ? {} : { signal }),
  } as RequestInit & { duplex: 'half' });
  return { request, cancelled };
}

afterEach(() => vi.useRealTimers());

describe('native MCP ingress lifetime', () => {
  it('returns on its fixed deadline even when body read and cancellation never settle', async () => {
    const run = await handler();
    vi.useFakeTimers();
    const { request, cancelled } = stalledRequest();
    const pending = run(request);
    await vi.advanceTimersByTimeAsync(MAX_TOOL_EXECUTION_MS + 1);
    const response = await pending;
    expect(response.status).toBe(408);
    expect(await response.json()).toEqual({ error: 'deadline_exceeded' });
    expect(cancelled).toHaveBeenCalledOnce();
  });

  it('honors caller abort while the body is stalled without waiting for cancellation', async () => {
    const run = await handler();
    const controller = new AbortController();
    const { request, cancelled } = stalledRequest(controller.signal);
    const pending = run(request);
    controller.abort();
    expect((await pending).status).toBe(408);
    expect(cancelled).toHaveBeenCalledOnce();
  });
});
