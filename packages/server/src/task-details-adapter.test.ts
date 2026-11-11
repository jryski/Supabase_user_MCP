import { type JSONRPCMessage, McpServer, type Transport } from '@modelcontextprotocol/server';
import * as contractsIndex from '@supabase-user-mcp/contracts';
import { MAX_TOOL_EXECUTION_MS } from '@supabase-user-mcp/contracts';
import { describe, expect, it, vi } from 'vitest';

import {
  createTaskDetailsRefusal,
  createTaskDetailsV2McpResult,
  decodeEventListV2,
  MAX_PAGE_SIZE,
  MAX_PROVIDER_RESPONSE_BYTES,
  MAX_TASK_DETAILS_REQUEST_BYTES,
  MAX_TASK_DETAILS_TIMEOUT_MS,
  ReadEventsV2InputSchema,
  segmentWindow,
  TASK_DETAILS_UNTRUSTED_TEXT_PREFIX,
  TASK_DETAILS_V2_BUDGET_REQUEST_ID,
  type TaskDetailV2,
  taskDetailsV2WireFrameByteLength,
} from '../../contracts/src/task-details-v2.js';
import * as serverIndex from './index.js';
import {
  createTaskDetailsAdapter,
  type TaskDetailsPort,
  type TaskPortResult,
} from './task-details-adapter.js';

const TASK = '00000000-0000-4000-8000-000000000001';
const HUMAN = '00000000-0000-4000-8000-0000000000a1';
const AGENT = '00000000-0000-4000-8000-0000000000b1';
const CLIENT = '00000000-0000-4000-8000-0000000000c1';
const WORKSTREAM = '00000000-0000-4000-8000-0000000000d1';
const RECEIPT = '00000000-0000-4000-8000-0000000000e1';
const IDEM = '00000000-0000-4000-8000-0000000000f1';
const VERSION = 'ab'.repeat(32);
const VERSION_B = 'cd'.repeat(32);
const TIME = '2026-01-01T00:00:00.000Z';

function seg(text = 'synthetic') {
  return segmentWindow(text, 80);
}

function detail(): TaskDetailV2 {
  return {
    readVersion: 2,
    view: 'task',
    task: {
      taskId: TASK,
      title: seg('Synthetic title'),
      status: 'open',
      version: VERSION,
      body: seg('Synthetic body'),
      assignedPrincipal: { kind: 'agent', id: AGENT },
      workstreamId: WORKSTREAM,
      citation: seg(''),
    },
  };
}

function readInput() {
  return { readVersion: 2 as const, view: 'task' as const, taskId: TASK, expectedVersion: VERSION };
}

function ok<T>(value: T): TaskPortResult {
  return { ok: true, value };
}

function port(overrides: Partial<TaskDetailsPort> = {}): TaskDetailsPort {
  return {
    readTask: vi.fn(async () => ok(detail())),
    readTasks: vi.fn(async () =>
      ok({
        readVersion: 2,
        view: 'tasks',
        limit: 1,
        afterTaskId: null,
        nextAfterTaskId: null,
        tasks: [],
      }),
    ),
    readAssignmentTargets: vi.fn(async () =>
      ok({
        readVersion: 2,
        view: 'assignment_targets',
        limit: 1,
        afterPrincipalId: null,
        nextAfterPrincipalId: null,
        targets: [],
        coverage: { completeLibrary: false, eligibleTargetsGrantAuthority: false },
      }),
    ),
    readCoordinationTargets: vi.fn(async () =>
      ok({
        readVersion: 2,
        view: 'coordination_targets',
        limit: 1,
        after: null,
        nextAfter: null,
        targets: [],
        coverage: { completeLibrary: false, eligibleTargetsGrantAuthority: false },
      }),
    ),
    readEvents: vi.fn(async () =>
      ok({
        readVersion: 2,
        view: 'events',
        taskId: TASK,
        limit: 1,
        after: null,
        nextAfter: null,
        events: [],
        coverage: {
          completeHistory: false,
          actualStoredAttributionOnly: true,
          approvalInferred: false,
        },
      }),
    ),
    appendNote: vi.fn(async () =>
      ok({
        readVersion: 2,
        command: 'note',
        receiptId: RECEIPT,
        taskId: TASK,
        occurredAt: TIME,
        taskVersion: VERSION,
        receiptVersion: VERSION_B,
        actor: { kind: 'human', id: HUMAN },
        clientId: CLIENT,
      }),
    ),
    assignTask: vi.fn(async () =>
      ok({
        readVersion: 2,
        command: 'assign',
        receiptId: RECEIPT,
        taskId: TASK,
        occurredAt: TIME,
        taskVersion: VERSION,
        receiptVersion: VERSION_B,
        actor: { kind: 'human', id: HUMAN },
        clientId: CLIENT,
      }),
    ),
    ...overrides,
  };
}

class ProbeTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;
  readonly sent: JSONRPCMessage[] = [];
  async start(): Promise<void> {}
  async send(message: JSONRPCMessage): Promise<void> {
    this.sent.push(message);
  }
  async close(): Promise<void> {
    this.onclose?.();
  }
  emit(message: JSONRPCMessage): void {
    this.onmessage?.(message);
  }
}

async function sdkFrame(output: unknown, requestId: string | number): Promise<string> {
  const server = new McpServer({ name: 'synthetic-frame-probe', version: '0.0.0' });
  server.registerTool(
    'synthetic_frame_probe',
    { description: 'Synthetic frame probe.' },
    async () => createTaskDetailsV2McpResult(output),
  );
  const transport = new ProbeTransport();
  await server.connect(transport);
  try {
    transport.emit({
      jsonrpc: '2.0',
      id: 'init-synthetic',
      method: 'initialize',
      params: {
        protocolVersion: '2026-07-28',
        capabilities: {},
        clientInfo: { name: 'synthetic-frame-probe', version: '0.0.0' },
      },
    });
    transport.emit({ jsonrpc: '2.0', method: 'notifications/initialized' });
    transport.emit({
      jsonrpc: '2.0',
      id: requestId,
      method: 'tools/call',
      params: { name: 'synthetic_frame_probe', arguments: {} },
    });
    for (let attempt = 0; attempt < 50; attempt += 1) {
      const response = transport.sent.find(
        (message) => 'id' in message && message.id === requestId,
      );
      if (response !== undefined) return `${JSON.stringify(response)}\n`;
      await new Promise((resolve) => setTimeout(resolve, 1));
    }
    throw new Error('no probe response');
  } finally {
    await server.close();
  }
}

describe('synthetic: negotiation, version conflict and registration', () => {
  it('refuses an over-2048-byte event request before calling the port', async () => {
    const injected = port();
    const occurredAt = `2026-01-01T00:00:00.${'1'.repeat(3000)}Z`;
    const input = {
      readVersion: 2 as const,
      view: 'events' as const,
      taskId: TASK,
      limit: 1,
      after: { occurredAt, receiptId: RECEIPT },
    };
    expect(ReadEventsV2InputSchema.safeParse(input).success).toBe(false);
    expect(Buffer.byteLength(JSON.stringify(input))).toBeGreaterThan(
      MAX_TASK_DETAILS_REQUEST_BYTES,
    );
    const result = await createTaskDetailsAdapter({ port: injected }).readEvents(input);
    expect(result).toEqual(createTaskDetailsRefusal('INVALID_REQUEST'));
    expect(Object.isFrozen(result)).toBe(true);
    expect(injected.readEvents).not.toHaveBeenCalled();
  });

  it('checks readVersion before the 2048-byte bound', async () => {
    const injected = port();
    const input = {
      readVersion: 3 as const,
      view: 'events' as const,
      taskId: TASK,
      limit: 1,
      after: { occurredAt: `2026-01-01T00:00:00.${'1'.repeat(3000)}Z`, receiptId: RECEIPT },
    };
    expect(Buffer.byteLength(JSON.stringify(input))).toBeGreaterThan(
      MAX_TASK_DETAILS_REQUEST_BYTES,
    );
    const result = await createTaskDetailsAdapter({ port: injected }).readEvents(input);
    expect(result).toEqual(createTaskDetailsRefusal('UNSUPPORTED_REPRESENTATION'));
    expect(injected.readEvents).not.toHaveBeenCalled();
  });

  it('refuses an in-budget event cursor the decoder would refuse before calling the port', async () => {
    const fraction13 = {
      readVersion: 2 as const,
      view: 'events' as const,
      taskId: TASK,
      limit: 1,
      after: { occurredAt: `2026-01-01T00:00:00.${'1'.repeat(13)}Z`, receiptId: RECEIPT },
    };
    const preEpoch = {
      ...fraction13,
      after: { occurredAt: '1969-12-31T23:59:59Z', receiptId: RECEIPT },
    };
    for (const input of [fraction13, preEpoch]) {
      const injected = port();
      expect(ReadEventsV2InputSchema.safeParse(input).success).toBe(false);
      expect(Buffer.byteLength(JSON.stringify(input))).toBeLessThanOrEqual(
        MAX_TASK_DETAILS_REQUEST_BYTES,
      );
      const result = await createTaskDetailsAdapter({ port: injected }).readEvents(input);
      expect(result).toEqual(createTaskDetailsRefusal('INVALID_REQUEST'));
      expect(injected.readEvents).not.toHaveBeenCalled();
    }
    const after = { occurredAt: '2026-01-01T00:00:00.5Z', receiptId: RECEIPT };
    const accepted = port({
      readEvents: vi.fn(async () =>
        ok({
          readVersion: 2,
          view: 'events',
          taskId: TASK,
          limit: 1,
          after,
          nextAfter: null,
          events: [],
          coverage: {
            completeHistory: false,
            actualStoredAttributionOnly: true,
            approvalInferred: false,
          },
        }),
      ),
    });
    const result = await createTaskDetailsAdapter({ port: accepted }).readEvents({
      readVersion: 2,
      view: 'events',
      taskId: TASK,
      limit: 1,
      after,
    });
    expect(result.ok).toBe(true);
    expect(
      ReadEventsV2InputSchema.safeParse({
        readVersion: 2,
        view: 'events',
        taskId: TASK,
        limit: 1,
        after,
      }).success,
    ).toBe(true);
    expect(accepted.readEvents).toHaveBeenCalledTimes(1);
  });

  it('reads readVersion from the snapshot, not from a later or inherited value', async () => {
    let reads = 0;
    const flipping = port();
    const flipped = await createTaskDetailsAdapter({ port: flipping }).readTask({
      view: 'task',
      taskId: TASK,
      expectedVersion: VERSION,
      get readVersion() {
        reads += 1;
        return reads === 1 ? 2 : 3;
      },
    });
    expect(flipped.ok).toBe(true);
    expect(reads).toBe(1);
    expect(flipping.readTask).toHaveBeenCalledTimes(1);

    const inherited = port();
    const hidden = await createTaskDetailsAdapter({ port: inherited }).readTask(
      Object.assign(Object.create({ readVersion: 2 }), {
        view: 'task',
        taskId: TASK,
        expectedVersion: VERSION,
      }),
    );
    expect(hidden).toEqual(createTaskDetailsRefusal('UNSUPPORTED_REPRESENTATION'));
    expect(inherited.readTask).not.toHaveBeenCalled();
  });

  it('refuses a snapshot that is not a plain object', async () => {
    for (const input of [{ toJSON: () => null }, { toJSON: () => 5 }]) {
      const injected = port();
      const result = await createTaskDetailsAdapter({ port: injected }).readTask(input);
      expect(result).toEqual(createTaskDetailsRefusal('INVALID_REQUEST'));
      expect(result).toMatchObject({ refusal: { retryable: false } });
      expect(Object.isFrozen(result)).toBe(true);
      expect(Object.isFrozen((result as { refusal: object }).refusal)).toBe(true);
      expect(injected.readTask).not.toHaveBeenCalled();
    }
  });

  it('maps a throwing readVersion getter on the caller input to INVALID_REQUEST', async () => {
    const secret = 'synthetic-readversion-must-not-leak';
    const injected = port();
    const input = {
      view: 'task' as const,
      taskId: TASK,
      expectedVersion: VERSION,
      get readVersion(): number {
        throw new Error(secret);
      },
    };
    const result = await createTaskDetailsAdapter({ port: injected }).readTask(input);
    expect(result).toEqual(createTaskDetailsRefusal('INVALID_REQUEST'));
    expect(result).toMatchObject({ refusal: { retryable: false } });
    expect(JSON.stringify(result)).not.toContain(secret);
    expect(Object.isFrozen(result)).toBe(true);
    expect(injected.readTask).not.toHaveBeenCalled();
  });

  it('accepts a shared actor object on an event page from the port', async () => {
    const actor = { kind: 'human' as const, id: HUMAN };
    const first = {
      command: 'create' as const,
      receiptId: '00000000-0000-4000-8000-000000000002',
      occurredAt: '2026-01-01T00:00:00Z',
      taskVersion: VERSION,
      receiptVersion: VERSION,
      actor,
      clientId: CLIENT,
    };
    const second = {
      ...first,
      receiptId: '00000000-0000-4000-8000-000000000003',
      occurredAt: '2026-01-01T00:00:01Z',
      actor,
    };
    const value = {
      readVersion: 2 as const,
      view: 'events' as const,
      taskId: TASK,
      limit: 2,
      after: null,
      nextAfter: { occurredAt: second.occurredAt, receiptId: second.receiptId },
      events: [first, second],
      coverage: {
        completeHistory: false as const,
        actualStoredAttributionOnly: true as const,
        approvalInferred: false as const,
      },
    };
    expect(value.events[0]?.actor).toBe(value.events[1]?.actor);
    const injected = port({ readEvents: vi.fn(async () => ok(value)) });
    const result = await createTaskDetailsAdapter({ port: injected }).readEvents({
      readVersion: 2,
      view: 'events',
      taskId: TASK,
      limit: 2,
      after: null,
    });
    expect(result).toEqual({
      ok: true,
      value: decodeEventListV2(JSON.parse(JSON.stringify(value))),
    });
    expect(injected.readEvents).toHaveBeenCalledTimes(1);
  });

  it('refuses a deep shared diamond from the port before the deadline', async () => {
    let reads = 0;
    let node: object = { leaf: 1 };
    for (let level = 0; level < 40; level += 1) {
      const child = node;
      const layer: { l?: object; r?: object } = {};
      Object.defineProperty(layer, 'l', {
        enumerable: true,
        get() {
          reads += 1;
          return child;
        },
      });
      Object.defineProperty(layer, 'r', {
        enumerable: true,
        get() {
          reads += 1;
          return child;
        },
      });
      node = layer;
    }
    const injected = port({
      readEvents: vi.fn(async () => ok({ readVersion: 2, view: 'events', junk: node } as never)),
    });
    const started = performance.now();
    const result = await createTaskDetailsAdapter({ port: injected }).readEvents({
      readVersion: 2,
      view: 'events',
      taskId: TASK,
      limit: 1,
      after: null,
    });
    expect(result).toEqual(createTaskDetailsRefusal('RESPONSE_LIMIT_EXCEEDED'));
    expect(result).toMatchObject({ refusal: { retryable: false } });
    expect(reads).toBeLessThanOrEqual(MAX_PROVIDER_RESPONSE_BYTES);
    expect(performance.now() - started).toBeLessThan(250);
    expect(injected.readEvents).toHaveBeenCalledTimes(1);
  });

  it('keeps the adapter and contract unregistered', () => {
    expect(Object.keys(contractsIndex)).not.toContain('decodeTaskDetailV2');
    expect(Object.keys(serverIndex)).not.toContain('createTaskDetailsAdapter');
  });

  it('refuses a read that does not negotiate readVersion 2 and does not call the port', async () => {
    const injected = port();
    const adapter = createTaskDetailsAdapter({ port: injected });
    for (const input of [
      null,
      [],
      { taskId: TASK },
      { readVersion: 1, view: 'task', taskId: TASK, expectedVersion: VERSION },
    ]) {
      const result = await adapter.readTask(input);
      expect(result.ok).toBe(false);
    }
    expect(injected.readTask).not.toHaveBeenCalled();
  });

  it('requires the returned version to match and returns no data on version_conflict', async () => {
    const conflict = port({
      readTask: vi.fn(async () => ({ ok: false as const, denial: 'version_conflict' as const })),
    });
    const refused = await createTaskDetailsAdapter({ port: conflict }).readTask(readInput());
    expect(refused).toEqual(createTaskDetailsRefusal('VERSION_CONFLICT'));
    expect(refused).not.toHaveProperty('value');
    expect(JSON.stringify(refused)).not.toContain(TASK);

    const mismatch = port({
      readTask: vi.fn(async () =>
        ok({ ...detail(), task: { ...detail().task, version: VERSION_B } }),
      ),
    });
    const malformed = await createTaskDetailsAdapter({ port: mismatch }).readTask(readInput());
    expect(malformed).toEqual(createTaskDetailsRefusal('MALFORMED_REPRESENTATION'));
    expect(malformed).not.toHaveProperty('value');
  });

  it('forwards detail parameters without readVersion', async () => {
    const injected = port();
    await createTaskDetailsAdapter({ port: injected }).readTask(readInput());
    expect(injected.readTask).toHaveBeenCalledWith(
      { view: 'task', taskId: TASK, expectedVersion: VERSION },
      expect.any(AbortSignal),
    );
  });

  it('accepts a page of 10 and rejects 11 without calling the port', async () => {
    const injected = port({
      readTasks: vi.fn(async () =>
        ok({
          readVersion: 2,
          view: 'tasks',
          limit: MAX_PAGE_SIZE,
          afterTaskId: null,
          nextAfterTaskId: null,
          tasks: [],
        }),
      ),
    });
    const adapter = createTaskDetailsAdapter({ port: injected });
    const input = { readVersion: 2, view: 'tasks', limit: MAX_PAGE_SIZE, afterTaskId: null };
    expect((await adapter.readTasks(input)).ok).toBe(true);
    expect((await adapter.readTasks({ ...input, limit: MAX_PAGE_SIZE + 1 })).ok).toBe(false);
    expect(injected.readTasks).toHaveBeenCalledTimes(1);
  });
});

describe('synthetic: denials, throws, deadline and bounds', () => {
  it('maps every port denial and rejects prototype-named denials', async () => {
    const expected: Record<string, string> = {
      not_found: 'NOT_AVAILABLE',
      wrong_workstream: 'NOT_AVAILABLE',
      wrong_client: 'NOT_AVAILABLE',
      wrong_session: 'NOT_AVAILABLE',
      version_conflict: 'VERSION_CONFLICT',
      idempotency_conflict: 'IDEMPOTENCY_CONFLICT',
      target_unknown: 'TARGET_UNAVAILABLE',
      target_withdrawn: 'TARGET_UNAVAILABLE',
      unavailable: 'UPSTREAM_UNAVAILABLE',
      toString: 'INTERNAL_ERROR',
      constructor: 'INTERNAL_ERROR',
      __proto__: 'INTERNAL_ERROR',
      hasOwnProperty: 'INTERNAL_ERROR',
    };
    for (const [denial, code] of Object.entries(expected)) {
      const adapter = createTaskDetailsAdapter({
        port: port({ readTask: async () => ({ ok: false, denial }) as never }),
      });
      const result = await adapter.readTask(readInput());
      expect(result).toMatchObject({ ok: false, refusal: { code } });
      expect(Object.isFrozen(result)).toBe(true);
    }
  });

  it('maps a throwing getter or Proxy trap to the fixed refusal with no thrown text', async () => {
    const secret = 'synthetic-secret-text-must-not-leak';
    const throwingGetter = () =>
      Object.defineProperty({}, 'ok', {
        enumerable: true,
        get() {
          throw new Error(secret);
        },
      });
    const throwingHas = () =>
      new Proxy({} as Record<string, unknown>, {
        get: (_target, key) => (key === 'ok' ? true : undefined),
        has: () => {
          throw new Error(secret);
        },
      });
    for (const make of [throwingGetter, throwingHas]) {
      const adapter = createTaskDetailsAdapter({
        port: port({ readTask: async () => make() as never }),
      });
      const result = await adapter.readTask(readInput());
      expect(result).toEqual(createTaskDetailsRefusal('UPSTREAM_UNAVAILABLE'));
      expect(JSON.stringify(result)).not.toContain(secret);
      expect(Object.isFrozen(result)).toBe(true);
    }
    let reads = 0;
    const input = new Proxy(readInput(), {
      get(target, key) {
        if (key === 'expectedVersion') {
          reads += 1;
          if (reads > 1) throw new Error(secret);
        }
        return Reflect.get(target, key);
      },
    });
    const trapped = await createTaskDetailsAdapter({ port: port() }).readTask(input);
    expect(trapped.ok).toBe(true);
    expect(reads).toBe(1);
    expect(JSON.stringify(trapped)).not.toContain(secret);

    const throwingValue = {
      readVersion: 2,
      view: 'task',
      get taskId() {
        throw new Error(secret);
      },
    };
    const internal = await createTaskDetailsAdapter({
      port: port({ readTask: async () => ({ ok: true, value: throwingValue }) as never }),
    }).readTask(readInput());
    expect(internal).toEqual(createTaskDetailsRefusal('INTERNAL_ERROR'));
    expect(internal).toMatchObject({ refusal: { retryable: false } });
    expect(JSON.stringify(internal)).not.toContain(secret);
    expect(Object.isFrozen(internal)).toBe(true);
  });

  it('aborts the port on deadline, mid-flight cancel, and a pre-aborted signal', async () => {
    const signals: AbortSignal[] = [];
    const slow = port({
      readTask: vi.fn(
        (_params, signal): Promise<TaskPortResult> =>
          new Promise(() => {
            signals.push(signal);
          }),
      ),
    });
    const timed = await createTaskDetailsAdapter({ port: slow, timeoutMs: 15 }).readTask(
      readInput(),
    );
    expect(timed).toEqual(createTaskDetailsRefusal('DEADLINE_EXCEEDED'));
    expect(signals[0]?.aborted).toBe(true);

    const caller = new AbortController();
    const pending = createTaskDetailsAdapter({
      port: slow,
      timeoutMs: MAX_TOOL_EXECUTION_MS,
    }).readTask(readInput(), caller.signal);
    caller.abort();
    expect(await pending).toEqual(createTaskDetailsRefusal('REQUEST_CANCELLED'));

    const already = new AbortController();
    already.abort();
    const calls = port();
    const pre = await createTaskDetailsAdapter({ port: calls }).readTask(
      readInput(),
      already.signal,
    );
    expect(pre).toEqual(createTaskDetailsRefusal('REQUEST_CANCELLED'));
    expect(calls.readTask).not.toHaveBeenCalled();
  });

  it('accepts the governor timeout and refuses a timeout above the packet or the governor', () => {
    expect(MAX_TOOL_EXECUTION_MS).toBeLessThanOrEqual(MAX_TASK_DETAILS_TIMEOUT_MS);
    expect(() =>
      createTaskDetailsAdapter({ port: port(), timeoutMs: MAX_TOOL_EXECUTION_MS }),
    ).not.toThrow();
    expect(() =>
      createTaskDetailsAdapter({ port: port(), timeoutMs: MAX_TOOL_EXECUTION_MS + 1 }),
    ).toThrow(RangeError);
    expect(() =>
      createTaskDetailsAdapter({ port: port(), timeoutMs: MAX_TASK_DETAILS_TIMEOUT_MS }),
    ).toThrow(RangeError);
    expect(() => createTaskDetailsAdapter({ port: port(), timeoutMs: 0 })).toThrow(RangeError);
  });

  it('returns a note or assign receipt and refuses an oversized request before the port', async () => {
    const injected = port();
    const adapter = createTaskDetailsAdapter({ port: injected });
    const note = await adapter.appendNote({
      readVersion: 2,
      taskId: TASK,
      expectedVersion: VERSION,
      idempotencyKey: IDEM,
      text: 'Synthetic note',
    });
    expect(note).toMatchObject({ ok: true, receipt: { command: 'note', taskId: TASK } });
    const assigned = await adapter.assignTask({
      readVersion: 2,
      taskId: TASK,
      expectedVersion: VERSION,
      idempotencyKey: IDEM,
      target: { kind: 'human', id: HUMAN },
    });
    expect(assigned).toMatchObject({ ok: true, receipt: { command: 'assign' } });
    const huge = { ...readInput(), taskId: 'a'.repeat(3_000) };
    expect((await adapter.readTask(huge)).ok).toBe(false);
    expect(injected.readTask).not.toHaveBeenCalled();
  });

  it('matches the in-test SDK frame and keeps the untrusted label', async () => {
    const output = { ok: true as const, value: detail() };
    const frame = await sdkFrame(output, TASK_DETAILS_V2_BUDGET_REQUEST_ID);
    expect(Buffer.byteLength(frame)).toBe(
      taskDetailsV2WireFrameByteLength(TASK_DETAILS_V2_BUDGET_REQUEST_ID, output),
    );
    expect(frame.endsWith('\n')).toBe(true);
    const parsed = JSON.parse(frame) as {
      result: { content: { text: string }[]; structuredContent: unknown };
    };
    expect(parsed.result.content[0]?.text.startsWith(TASK_DETAILS_UNTRUSTED_TEXT_PREFIX)).toBe(
      true,
    );
    expect(parsed.result.structuredContent).toEqual(output);
  });
});

describe('synthetic: adapter cross-checks, cancel and listener', () => {
  it('pins malformed arrays and an unsupported read version', async () => {
    const injected = port();
    const adapter = createTaskDetailsAdapter({ port: injected });
    const tagged = await adapter.readTask(Object.assign([], { readVersion: 1 }));
    expect(tagged).toEqual(createTaskDetailsRefusal('MALFORMED_REPRESENTATION'));
    const other = await adapter.readTask({
      readVersion: 1,
      view: 'task',
      taskId: TASK,
      expectedVersion: VERSION,
    });
    expect(other).toEqual(createTaskDetailsRefusal('UNSUPPORTED_REPRESENTATION'));
    expect(injected.readTask).not.toHaveBeenCalled();
  });

  it('refuses a detail whose task id does not match the request', async () => {
    const injected = port({
      readTask: vi.fn(async () =>
        ok({
          ...detail(),
          task: { ...detail().task, taskId: '00000000-0000-4000-8000-000000000099' },
        }),
      ),
    });
    const result = await createTaskDetailsAdapter({ port: injected }).readTask(readInput());
    expect(result).toEqual(createTaskDetailsRefusal('MALFORMED_REPRESENTATION'));
  });

  it('refuses a task page whose cursor or limit does not match the request', async () => {
    const page = {
      readVersion: 2,
      view: 'tasks',
      limit: 1,
      afterTaskId: TASK,
      nextAfterTaskId: null,
      tasks: [],
    };
    const injected = port({ readTasks: vi.fn(async () => ok(page)) });
    const adapter = createTaskDetailsAdapter({ port: injected });
    const input = { readVersion: 2, view: 'tasks', limit: 1, afterTaskId: null };
    expect(await adapter.readTasks(input)).toEqual(
      createTaskDetailsRefusal('MALFORMED_REPRESENTATION'),
    );
    const limitOnly = port({
      readTasks: vi.fn(async () =>
        ok({
          readVersion: 2,
          view: 'tasks',
          limit: 1,
          afterTaskId: null,
          nextAfterTaskId: null,
          tasks: [],
        }),
      ),
    });
    expect(
      await createTaskDetailsAdapter({ port: limitOnly }).readTasks({
        readVersion: 2,
        view: 'tasks',
        limit: 2,
        afterTaskId: null,
      }),
    ).toEqual(createTaskDetailsRefusal('MALFORMED_REPRESENTATION'));
  });

  it('refuses target and event pages that ignore the requested cursor or task', async () => {
    const targets = port({
      readAssignmentTargets: vi.fn(async () =>
        ok({
          readVersion: 2,
          view: 'assignment_targets',
          limit: 1,
          afterPrincipalId: HUMAN,
          nextAfterPrincipalId: null,
          targets: [],
          coverage: { completeLibrary: false, eligibleTargetsGrantAuthority: false },
        }),
      ),
      readCoordinationTargets: vi.fn(async () =>
        ok({
          readVersion: 2,
          view: 'coordination_targets',
          limit: 1,
          after: { principalId: HUMAN, clientId: CLIENT },
          nextAfter: null,
          targets: [],
          coverage: { completeLibrary: false, eligibleTargetsGrantAuthority: false },
        }),
      ),
      readEvents: vi.fn(async () =>
        ok({
          readVersion: 2,
          view: 'events',
          taskId: '00000000-0000-4000-8000-000000000099',
          limit: 1,
          after: { occurredAt: TIME, receiptId: RECEIPT },
          nextAfter: null,
          events: [],
          coverage: {
            completeHistory: false,
            actualStoredAttributionOnly: true,
            approvalInferred: false,
          },
        }),
      ),
    });
    const adapter = createTaskDetailsAdapter({ port: targets });
    expect(
      await adapter.readAssignmentTargets({
        readVersion: 2,
        view: 'assignment_targets',
        limit: 1,
        afterPrincipalId: null,
      }),
    ).toEqual(createTaskDetailsRefusal('MALFORMED_REPRESENTATION'));
    expect(
      await adapter.readCoordinationTargets({
        readVersion: 2,
        view: 'coordination_targets',
        limit: 1,
        after: null,
      }),
    ).toEqual(createTaskDetailsRefusal('MALFORMED_REPRESENTATION'));
    expect(
      await adapter.readEvents({
        readVersion: 2,
        view: 'events',
        taskId: TASK,
        limit: 1,
        after: null,
      }),
    ).toEqual(createTaskDetailsRefusal('MALFORMED_REPRESENTATION'));
    const wrongTask = port({
      readEvents: vi.fn(async () =>
        ok({
          readVersion: 2,
          view: 'events',
          taskId: '00000000-0000-4000-8000-000000000099',
          limit: 1,
          after: null,
          nextAfter: null,
          events: [],
          coverage: {
            completeHistory: false,
            actualStoredAttributionOnly: true,
            approvalInferred: false,
          },
        }),
      ),
    });
    expect(
      await createTaskDetailsAdapter({ port: wrongTask }).readEvents({
        readVersion: 2,
        view: 'events',
        taskId: TASK,
        limit: 1,
        after: null,
      }),
    ).toEqual(createTaskDetailsRefusal('MALFORMED_REPRESENTATION'));
    const wrongCursor = port({
      readEvents: vi.fn(async () =>
        ok({
          readVersion: 2,
          view: 'events',
          taskId: TASK,
          limit: 1,
          after: { occurredAt: TIME, receiptId: RECEIPT },
          nextAfter: null,
          events: [],
          coverage: {
            completeHistory: false,
            actualStoredAttributionOnly: true,
            approvalInferred: false,
          },
        }),
      ),
    });
    expect(
      await createTaskDetailsAdapter({ port: wrongCursor }).readEvents({
        readVersion: 2,
        view: 'events',
        taskId: TASK,
        limit: 1,
        after: null,
      }),
    ).toEqual(createTaskDetailsRefusal('MALFORMED_REPRESENTATION'));
  });

  it('refuses a note or assignment receipt that does not match the request', async () => {
    const injected = port({
      appendNote: vi.fn(async () =>
        ok({
          readVersion: 2,
          command: 'note',
          receiptId: RECEIPT,
          taskId: '00000000-0000-4000-8000-000000000099',
          occurredAt: TIME,
          taskVersion: VERSION,
          receiptVersion: VERSION_B,
          actor: { kind: 'human', id: HUMAN },
          clientId: CLIENT,
        }),
      ),
      assignTask: vi.fn(async () =>
        ok({
          readVersion: 2,
          command: 'note',
          receiptId: RECEIPT,
          taskId: TASK,
          occurredAt: TIME,
          taskVersion: VERSION,
          receiptVersion: VERSION_B,
          actor: { kind: 'human', id: HUMAN },
          clientId: CLIENT,
        }),
      ),
    });
    const adapter = createTaskDetailsAdapter({ port: injected });
    const note = {
      readVersion: 2,
      taskId: TASK,
      expectedVersion: VERSION,
      idempotencyKey: IDEM,
      text: 'Synthetic note',
    };
    expect(await adapter.appendNote(note)).toEqual(
      createTaskDetailsRefusal('MALFORMED_REPRESENTATION'),
    );
    const wrongVersion = port({
      appendNote: vi.fn(async () =>
        ok({
          readVersion: 2,
          command: 'note',
          receiptId: RECEIPT,
          taskId: TASK,
          occurredAt: TIME,
          taskVersion: VERSION_B,
          receiptVersion: VERSION_B,
          actor: { kind: 'human', id: HUMAN },
          clientId: CLIENT,
        }),
      ),
    });
    expect(await createTaskDetailsAdapter({ port: wrongVersion }).appendNote(note)).toEqual(
      createTaskDetailsRefusal('MALFORMED_REPRESENTATION'),
    );
    expect(
      await adapter.assignTask({
        readVersion: 2,
        taskId: TASK,
        expectedVersion: VERSION,
        idempotencyKey: IDEM,
        target: { kind: 'human', id: HUMAN },
      }),
    ).toEqual(createTaskDetailsRefusal('MALFORMED_REPRESENTATION'));
  });

  it('aborts the port signal on mid-flight cancel and drops the listener afterwards', async () => {
    const signals: AbortSignal[] = [];
    const slow = port({
      readTask: vi.fn(
        (_params, signal): Promise<TaskPortResult> =>
          new Promise((resolve) => {
            signals.push(signal);
            signal.addEventListener('abort', () => resolve(ok(detail())));
          }),
      ),
    });
    const caller = new AbortController();
    const pending = createTaskDetailsAdapter({
      port: slow,
      timeoutMs: MAX_TOOL_EXECUTION_MS,
    }).readTask(readInput(), caller.signal);
    caller.abort();
    expect(await pending).toEqual(createTaskDetailsRefusal('REQUEST_CANCELLED'));
    expect(signals[0]?.aborted).toBe(true);

    const unhandled: unknown[] = [];
    const onUnhandled = (error: unknown) => {
      unhandled.push(error);
    };
    process.on('unhandledRejection', onUnhandled);
    const caller2 = new AbortController();
    const done = await createTaskDetailsAdapter({ port: port() }).readTask(
      readInput(),
      caller2.signal,
    );
    expect(done.ok).toBe(true);
    caller2.abort();
    await new Promise((resolve) => setTimeout(resolve, 10));
    process.off('unhandledRejection', onUnhandled);
    expect(unhandled).toEqual([]);

    const signalsAfter: AbortSignal[] = [];
    const caller3 = new AbortController();
    const quick = port({
      readTask: vi.fn((_params, signal): Promise<TaskPortResult> => {
        signalsAfter.push(signal);
        return Promise.resolve(ok(detail()));
      }),
    });
    const settled = await createTaskDetailsAdapter({ port: quick, timeoutMs: 40 }).readTask(
      readInput(),
      caller3.signal,
    );
    expect(settled.ok).toBe(true);
    caller3.abort();
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(signalsAfter[0]?.aborted).toBe(false);
  });
});
