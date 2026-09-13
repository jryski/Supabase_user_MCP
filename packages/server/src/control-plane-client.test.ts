import { describe, expect, it, vi } from 'vitest';

import { CreateWorkItemInputSchema } from '@supabase-user-mcp/contracts';

import { createControlPlaneClient } from './control-plane-client.js';

const origin = 'https://synthetic.supabase.co';
const serviceRoleKey = 's'.repeat(64);
const agentId = 'synthetic-ariadne';
const workItemId = '11111111-1111-4111-9111-111111111111';
const messageId = '22222222-2222-4222-9222-222222222222';

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function createInput(idempotencyKey = 'synthetic-create-001') {
  return CreateWorkItemInputSchema.parse({
    boardSlug: 'synthetic-board',
    title: 'Synthetic work item',
    idempotencyKey,
  });
}

describe('fixed control-plane client', () => {
  it('calls only the two fixed RPC paths and injects configured agent attribution', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async (url, init) => {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      if (String(url).endsWith('/rpc/create_work_item')) {
        expect(init?.method).toBe('POST');
        expect(init?.headers).toMatchObject({
          'Accept-Profile': 'planning',
          'Content-Profile': 'planning',
          Authorization: `Bearer ${serviceRoleKey}`,
          apikey: serviceRoleKey,
        });
        expect(body).toMatchObject({
          p_board_slug: 'synthetic-board',
          p_title: 'Synthetic work item',
          p_created_by_agent: agentId,
          p_source_agent: agentId,
          p_idempotency_key: 'synthetic-create-001',
        });
        expect(body).not.toHaveProperty('sql');
        expect(body).not.toHaveProperty('table');
        return jsonResponse({
          item_id: workItemId,
          item_number: 41,
          board_slug: 'synthetic-board',
          created: true,
          idempotency_key: 'synthetic-create-001',
        });
      }
      expect(String(url)).toBe(`${origin}/rest/v1/rpc/post_model_message`);
      expect(init?.headers).toMatchObject({
        'Accept-Profile': 'public',
        'Content-Profile': 'public',
      });
      expect(body).toEqual({
        p_from_agent: agentId,
        p_to_agent: 'synthetic-warden',
        p_subject: 'Synthetic subject',
        p_body: 'Synthetic body',
        p_re_seq: null,
      });
      return jsonResponse({ id: messageId, seq: 81 });
    });
    const client = createControlPlaneClient({ origin, serviceRoleKey, agentId, fetch });

    await expect(client.createWorkItem(createInput())).resolves.toMatchObject({
      ok: true,
      receipt: { id: workItemId, itemNumber: 41, created: true },
    });
    await expect(
      client.postModelMessage({
        toAgent: 'synthetic-warden',
        subject: 'Synthetic subject',
        body: 'Synthetic body',
      }),
    ).resolves.toMatchObject({ ok: true, receipt: { id: messageId, seq: 81 } });

    expect(fetch.mock.calls.map(([url]) => String(url))).toEqual([
      `${origin}/rest/v1/rpc/create_work_item`,
      `${origin}/rest/v1/rpc/post_model_message`,
    ]);
    expect(fetch.mock.calls.every(([, init]) => init?.method === 'POST')).toBe(true);
  });

  it('preserves board-scoped idempotency under concurrent duplicate requests', async () => {
    const receipts = new Map<string, unknown>();
    let nextNumber = 100;
    const fetch = vi.fn<typeof globalThis.fetch>(async (_url, init) => {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      const key = `${body.p_board_slug}:${body.p_idempotency_key}`;
      await Promise.resolve();
      const existing = receipts.get(key);
      if (existing !== undefined) return jsonResponse({ ...existing, created: false });
      const receipt = {
        id: workItemId,
        item_number: nextNumber++,
        board_slug: body.p_board_slug,
        idempotency_key: body.p_idempotency_key,
      };
      receipts.set(key, receipt);
      return jsonResponse({ ...receipt, created: true });
    });
    const client = createControlPlaneClient({ origin, serviceRoleKey, agentId, fetch });

    const [first, second] = await Promise.all([
      client.createWorkItem(createInput('same-key')),
      client.createWorkItem(createInput('same-key')),
    ]);

    expect(first.ok && first.receipt.id).toBe(workItemId);
    expect(second.ok && second.receipt.id).toBe(workItemId);
    expect(first.ok && first.receipt.itemNumber).toBe(100);
    expect(second.ok && second.receipt.itemNumber).toBe(100);
    expect(first.ok && first.receipt.created).toBe(true);
    expect(second.ok && second.receipt.created).toBe(false);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('does not invent a creation outcome when the RPC omits it', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async () =>
      jsonResponse({
        id: workItemId,
        item_number: 41,
        board_slug: 'synthetic-board',
        idempotency_key: 'synthetic-create-001',
      }),
    );
    const client = createControlPlaneClient({ origin, serviceRoleKey, agentId, fetch });

    await expect(client.createWorkItem(createInput())).resolves.toEqual({
      ok: true,
      receipt: {
        id: workItemId,
        itemNumber: 41,
        boardSlug: 'synthetic-board',
        idempotencyKey: 'synthetic-create-001',
      },
    });
  });

  it('keeps concurrent allocations distinct and does not serialize client requests', async () => {
    let inFlight = 0;
    let maximumInFlight = 0;
    let nextItem = 200;
    let nextMessage = 300;
    const fetch = vi.fn<typeof globalThis.fetch>(async (url, init) => {
      inFlight += 1;
      maximumInFlight = Math.max(maximumInFlight, inFlight);
      await new Promise((resolve) => setTimeout(resolve, 5));
      inFlight -= 1;
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      if (String(url).endsWith('/rpc/create_work_item')) {
        const itemNumber = nextItem++;
        return jsonResponse({
          id: itemNumber === 200 ? workItemId : '33333333-3333-4333-9333-333333333333',
          item_number: itemNumber,
          board_slug: body.p_board_slug,
          idempotency_key: body.p_idempotency_key,
          created: true,
        });
      }
      const seq = nextMessage++;
      return jsonResponse({
        id: seq === 300 ? messageId : '44444444-4444-4444-9444-444444444444',
        seq,
      });
    });
    const client = createControlPlaneClient({ origin, serviceRoleKey, agentId, fetch });

    const [firstItem, secondItem, firstMessage, secondMessage] = await Promise.all([
      client.createWorkItem(createInput('concurrent-a')),
      client.createWorkItem(createInput('concurrent-b')),
      client.postModelMessage({ toAgent: 'a', subject: 'A', body: 'A' }),
      client.postModelMessage({ toAgent: 'b', subject: 'B', body: 'B' }),
    ]);

    expect(maximumInFlight).toBeGreaterThan(1);
    expect(
      [firstItem, secondItem].map((result) => result.ok && result.receipt.itemNumber).toSorted(),
    ).toEqual([200, 201]);
    expect(
      [firstMessage, secondMessage].map((result) => result.ok && result.receipt.seq).toSorted(),
    ).toEqual([300, 301]);
  });

  it.each([
    [
      'createWorkItem',
      { code: 'P0001', message: 'board does not exist' },
      'CONTROL_PLANE_BOARD_UNAVAILABLE',
    ],
    [
      'postModelMessage',
      { code: 'P0001', message: 're_seq does not reference a message' },
      'CONTROL_PLANE_REPLY_UNAVAILABLE',
    ],
  ] as const)('maps invalid references deterministically for %s', async (method, error, code) => {
    const fetch = vi.fn<typeof globalThis.fetch>(async () => jsonResponse(error, 400));
    const client = createControlPlaneClient({ origin, serviceRoleKey, agentId, fetch });
    const operation =
      method === 'createWorkItem'
        ? client.createWorkItem(createInput())
        : client.postModelMessage({
            toAgent: 'synthetic-warden',
            subject: 'Synthetic reply',
            body: 'Synthetic body',
            reSeq: 999,
          });
    await expect(operation).rejects.toMatchObject({ code });
    expect(fetch).toHaveBeenCalledOnce();
  });
});
