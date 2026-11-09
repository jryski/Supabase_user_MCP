import { describe, expect, it } from 'vitest';

import { MAX_REQUEST_ID_BYTES, MAX_TOOL_EXECUTION_MS } from './read-tools.js';
import {
  AppendTaskNoteV2InputSchema,
  AssignmentTargetListV2Schema,
  AssignTaskV2InputSchema,
  CONSUMER_V1_COMPATIBILITY_GATE,
  CoordinationTargetListV2Schema,
  clipChars,
  codePointLength,
  completeWithinPacketLimit,
  createTaskDetailsRefusal,
  createTaskDetailsV2McpResult,
  DETAIL_BODY_MAX_CHARS,
  decodeAssignmentTargetListV2,
  decodeCoordinationTargetListV2,
  decodeEventListV2,
  decodeTaskDetailV2,
  decodeTaskListV2,
  decodeTaskMutationReceiptV2,
  EVENT_COMMAND_V2_VALUES,
  EventListV2Schema,
  LIST_SEGMENT_MAX_CHARS,
  MAX_COMPLETE_RESULT_BYTES,
  MAX_PAGE_SIZE,
  MAX_PROVIDER_RESPONSE_BYTES,
  MAX_STRUCTURED_CONTENT_BYTES,
  MAX_TASK_DETAILS_REQUEST_BYTES,
  MAX_TASK_DETAILS_TIMEOUT_MS,
  providerWithinPacketLimit,
  ReadTaskDetailV2InputSchema,
  ReadTaskListV2InputSchema,
  requestWithinPacketLimit,
  segmentWindow,
  structuredWithinPacketLimit,
  TASK_DETAILS_READ_VERSION,
  TASK_DETAILS_UNTRUSTED_TEXT_PREFIX,
  TASK_DETAILS_V2_BUDGET_REQUEST_ID,
  TASK_STATUS_V2_VALUES,
  TaskDetailsDecodeError,
  type TaskDetailV2,
  taskDetailsV2WireFrameByteLength,
  timeoutWithinPacketLimit,
} from './task-details-v2.js';

const TASK = '00000000-0000-4000-8000-000000000001';
const TASK_B = '00000000-0000-4000-8000-000000000002';
const HUMAN = '00000000-0000-4000-8000-0000000000a1';
const AGENT = '00000000-0000-4000-8000-0000000000b1';
const CLIENT = '00000000-0000-4000-8000-0000000000c1';
const WORKSTREAM = '00000000-0000-4000-8000-0000000000d1';
const RECEIPT = '00000000-0000-4000-8000-0000000000e1';
const VERSION = 'ab'.repeat(32);
const VERSION_B = 'cd'.repeat(32);
const TIME = '2026-01-01T00:00:00.000Z';

function segment(text: string, maxChars: number) {
  return segmentWindow(text, maxChars);
}

function detail(overrides: Partial<TaskDetailV2['task']> = {}): TaskDetailV2 {
  return {
    readVersion: 2,
    view: 'task',
    task: {
      taskId: TASK,
      title: segment('Synthetic title', DETAIL_BODY_MAX_CHARS),
      status: 'in_progress',
      version: VERSION,
      body: segment('Synthetic body', DETAIL_BODY_MAX_CHARS),
      assignedPrincipal: { kind: 'agent', id: AGENT },
      workstreamId: WORKSTREAM,
      citation: segment('', DETAIL_BODY_MAX_CHARS),
      ...overrides,
    },
  };
}

describe('synthetic: packet vocabulary and negotiation', () => {
  it('names the consumer v1 gap and does not invent a v1 fixture', () => {
    expect(CONSUMER_V1_COMPATIBILITY_GATE).toBe(
      'NAMED MISSING-CONTRACT GATE: consumer v1 compatibility',
    );
    expect(TASK_DETAILS_READ_VERSION).toBe(2);
    expect(TASK_STATUS_V2_VALUES).toEqual(['open', 'in_progress', 'blocked', 'done', 'cancelled']);
    expect(EVENT_COMMAND_V2_VALUES).toEqual([
      'create',
      'update',
      'assign',
      'transition',
      'note',
      'submit',
      'review',
    ]);
  });

  it('accepts the five statuses and fails closed on any other status', () => {
    for (const status of TASK_STATUS_V2_VALUES) {
      expect(decodeTaskDetailV2(detail({ status })).task.status).toBe(status);
    }
    for (const status of ['inbox', 'backlog', 'ready', 'review', 'archived', 'OPEN']) {
      expect(() => decodeTaskDetailV2(detail({ status: status as 'open' }))).toThrow(
        TaskDetailsDecodeError,
      );
    }
  });

  it('requires readVersion 2 and rejects other versions before accepting a shape', () => {
    expect(() => decodeTaskDetailV2({ ...detail(), readVersion: 1 })).toThrow(
      expect.objectContaining({ code: 'UNSUPPORTED_REPRESENTATION' }),
    );
    expect(() => decodeTaskDetailV2({ view: 'task' })).toThrow(
      expect.objectContaining({ code: 'MALFORMED_REPRESENTATION' }),
    );
    const tagged = Object.assign([], { readVersion: 2 });
    expect(() => decodeTaskDetailV2(tagged)).toThrow(
      expect.objectContaining({ code: 'MALFORMED_REPRESENTATION' }),
    );
  });

  it('requires canonical lower-case UUIDs and 64-character lower-case hex versions', () => {
    expect(decodeTaskDetailV2(detail()).task.taskId).toBe(TASK);
    expect(() =>
      decodeTaskDetailV2(detail({ taskId: '00000000-0000-4000-8000-00000000000A' })),
    ).toThrow(TaskDetailsDecodeError);
    expect(() => decodeTaskDetailV2(detail({ taskId: 'task-synthetic-001' }))).toThrow(
      TaskDetailsDecodeError,
    );
    expect(() => decodeTaskDetailV2(detail({ version: VERSION.toUpperCase() }))).toThrow(
      TaskDetailsDecodeError,
    );
    expect(() => decodeTaskDetailV2(detail({ version: 'ab'.repeat(31) }))).toThrow(
      TaskDetailsDecodeError,
    );
    expect(
      ReadTaskDetailV2InputSchema.safeParse({
        readVersion: 2,
        view: 'task',
        taskId: TASK,
        expectedVersion: VERSION,
      }).success,
    ).toBe(true);
  });
});

describe('synthetic: segments, views, events and coverage', () => {
  it('clips on code-point boundaries and records offset, total, next and complete', () => {
    expect(codePointLength('é')).toBe(1);
    const clipped = segmentWindow('abcdef', 3);
    expect(clipped).toEqual({
      text: 'abc',
      offset: 3 - 3,
      totalChars: 6,
      nextOffset: 3,
      complete: false,
    });
    const rest = segmentWindow('abcdef', 3, 3);
    expect(rest).toMatchObject({ text: 'def', offset: 3, nextOffset: 6, complete: true });
    expect(() => clipChars('abc', Number.NaN)).toThrow(RangeError);
    expect(() => clipChars('abc', -1)).toThrow(RangeError);
    expect(() => clipChars('a\uD800', 2)).toThrow(RangeError);
    expect(LIST_SEGMENT_MAX_CHARS).toBeLessThan(DETAIL_BODY_MAX_CHARS);
  });

  it('rejects an inconsistent segment and a list segment above the tighter cap', () => {
    const broken = detail();
    broken.task.body = { ...broken.task.body, complete: true, totalChars: 99 };
    expect(() => decodeTaskDetailV2(broken)).toThrow(TaskDetailsDecodeError);
    const page = {
      readVersion: 2,
      view: 'tasks' as const,
      limit: 1,
      afterTaskId: null,
      nextAfterTaskId: null,
      tasks: [
        {
          ...detail().task,
          title: segmentWindow('x'.repeat(LIST_SEGMENT_MAX_CHARS + 1), LIST_SEGMENT_MAX_CHARS + 1),
          body: segment('', LIST_SEGMENT_MAX_CHARS),
          citation: segment('', LIST_SEGMENT_MAX_CHARS),
        },
      ],
    };
    expect(() => decodeTaskListV2(page)).toThrow(TaskDetailsDecodeError);
  });

  it('accepts a task keyset page and rejects an out-of-order or oversized page', () => {
    const page = {
      readVersion: 2,
      view: 'tasks' as const,
      limit: 2,
      afterTaskId: null,
      nextAfterTaskId: TASK_B,
      tasks: [detail().task, { ...detail().task, taskId: TASK_B }].map((task) => ({
        ...task,
        title: segment('t', LIST_SEGMENT_MAX_CHARS),
        body: segment('b', LIST_SEGMENT_MAX_CHARS),
        citation: segment('', LIST_SEGMENT_MAX_CHARS),
      })),
    };
    expect(decodeTaskListV2(page).tasks).toHaveLength(2);
    expect(() => decodeTaskListV2({ ...page, tasks: [...page.tasks].reverse() })).toThrow(
      TaskDetailsDecodeError,
    );
    expect(() => decodeTaskListV2({ ...page, limit: MAX_PAGE_SIZE + 1 })).toThrow(
      TaskDetailsDecodeError,
    );
  });

  it('declares target coverage flags and a distinct coordination client', () => {
    const coverage = {
      completeLibrary: false as const,
      eligibleTargetsGrantAuthority: false as const,
    };
    const assignment = {
      readVersion: 2 as const,
      view: 'assignment_targets' as const,
      limit: 1,
      afterPrincipalId: null,
      nextAfterPrincipalId: null,
      targets: [{ principal: { kind: 'human' as const, id: HUMAN } }],
      coverage,
    };
    expect(decodeAssignmentTargetListV2(assignment).coverage).toEqual(coverage);
    expect(() =>
      AssignmentTargetListV2Schema.parse({
        ...assignment,
        coverage: { ...coverage, eligibleTargetsGrantAuthority: true },
      }),
    ).toThrow();
    const coordination = {
      readVersion: 2 as const,
      view: 'coordination_targets' as const,
      limit: 1,
      after: null,
      nextAfter: null,
      targets: [{ principal: { kind: 'agent' as const, id: AGENT }, clientId: CLIENT }],
      coverage,
    };
    expect(decodeCoordinationTargetListV2(coordination).targets[0]?.clientId).toBe(CLIENT);
    expect(CoordinationTargetListV2Schema.safeParse(coordination).success).toBe(true);
  });

  it('accepts the event command vocabulary and evidence only on note and submit', () => {
    const coverage = {
      completeHistory: false as const,
      actualStoredAttributionOnly: true as const,
      approvalInferred: false as const,
    };
    const baseEvent = {
      receiptId: RECEIPT,
      occurredAt: TIME,
      taskVersion: VERSION,
      receiptVersion: VERSION_B,
      actor: { kind: 'human' as const, id: HUMAN },
      clientId: CLIENT,
    };
    for (const command of EVENT_COMMAND_V2_VALUES) {
      const event =
        command === 'note' || command === 'submit'
          ? { ...baseEvent, command, evidence: segment('synthetic evidence', 400) }
          : { ...baseEvent, command };
      const page = {
        readVersion: 2 as const,
        view: 'events' as const,
        taskId: TASK,
        limit: 1,
        after: null,
        nextAfter: null,
        events: [event],
        coverage,
      };
      expect(decodeEventListV2(page).events[0]?.command).toBe(command);
    }
    expect(() =>
      EventListV2Schema.parse({
        readVersion: 2,
        view: 'events',
        taskId: TASK,
        limit: 1,
        after: null,
        nextAfter: null,
        events: [{ ...baseEvent, command: 'create', evidence: segment('no', 20) }],
        coverage,
      }),
    ).toThrow();
    expect(() =>
      EventListV2Schema.parse({
        readVersion: 2,
        view: 'events',
        taskId: TASK,
        limit: 1,
        after: null,
        nextAfter: null,
        events: [{ ...baseEvent, command: 'create' }],
        coverage: { ...coverage, approvalInferred: true },
      }),
    ).toThrow();
  });
});

describe('synthetic: packet byte bounds', () => {
  it('pins the packet numbers rather than only the exported names', () => {
    expect(requestWithinPacketLimit(2048)).toBe(true);
    expect(requestWithinPacketLimit(2049)).toBe(false);
    expect(providerWithinPacketLimit(60_000)).toBe(true);
    expect(providerWithinPacketLimit(60_001)).toBe(false);
    expect(structuredWithinPacketLimit(27_000)).toBe(true);
    expect(structuredWithinPacketLimit(27_001)).toBe(false);
    expect(completeWithinPacketLimit(60_000)).toBe(true);
    expect(completeWithinPacketLimit(60_001)).toBe(false);
    expect(timeoutWithinPacketLimit(5_000)).toBe(true);
    expect(timeoutWithinPacketLimit(5_001)).toBe(false);
    expect(MAX_PAGE_SIZE).toBe(10);
  });

  it('pins the request, provider, structured, complete and timeout ceilings', () => {
    expect(requestWithinPacketLimit(MAX_TASK_DETAILS_REQUEST_BYTES)).toBe(true);
    expect(requestWithinPacketLimit(MAX_TASK_DETAILS_REQUEST_BYTES + 1)).toBe(false);
    expect(providerWithinPacketLimit(MAX_PROVIDER_RESPONSE_BYTES)).toBe(true);
    expect(providerWithinPacketLimit(MAX_PROVIDER_RESPONSE_BYTES + 1)).toBe(false);
    expect(structuredWithinPacketLimit(MAX_STRUCTURED_CONTENT_BYTES)).toBe(true);
    expect(structuredWithinPacketLimit(MAX_STRUCTURED_CONTENT_BYTES + 1)).toBe(false);
    expect(completeWithinPacketLimit(MAX_COMPLETE_RESULT_BYTES)).toBe(true);
    expect(completeWithinPacketLimit(MAX_COMPLETE_RESULT_BYTES + 1)).toBe(false);
    expect(timeoutWithinPacketLimit(MAX_TASK_DETAILS_TIMEOUT_MS)).toBe(true);
    expect(timeoutWithinPacketLimit(MAX_TASK_DETAILS_TIMEOUT_MS + 1)).toBe(false);
    expect(timeoutWithinPacketLimit(0)).toBe(false);
    expect(MAX_PAGE_SIZE).toBe(10);
    expect(MAX_TOOL_EXECUTION_MS).toBeLessThanOrEqual(MAX_TASK_DETAILS_TIMEOUT_MS);
    expect(TASK_DETAILS_V2_BUDGET_REQUEST_ID.length + 2).toBe(MAX_REQUEST_ID_BYTES);
  });

  it('refuses a provider payload above 60000 bytes before accepting it as a task', () => {
    const prefix = '{"readVersion":2,"pad":"';
    const suffix = '"}';
    const fit = 'a'.repeat(MAX_PROVIDER_RESPONSE_BYTES - prefix.length - suffix.length);
    const atLimit = JSON.parse(`${prefix}${fit}${suffix}`) as unknown;
    const over = JSON.parse(`${prefix}${fit}a${suffix}`) as unknown;
    expect(() => decodeTaskDetailV2(atLimit)).toThrow(
      expect.objectContaining({ code: 'MALFORMED_REPRESENTATION' }),
    );
    expect(() => decodeTaskDetailV2(over)).toThrow(
      expect.objectContaining({ code: 'RESPONSE_LIMIT_EXCEEDED' }),
    );
  });

  it('refuses structured content above 27000 bytes and labels stored text', () => {
    const oversized = {
      ok: true as const,
      value: { pad: 'x'.repeat(MAX_STRUCTURED_CONTENT_BYTES) },
    };
    expect(() => createTaskDetailsV2McpResult(oversized)).toThrow(
      expect.objectContaining({ code: 'RESPONSE_LIMIT_EXCEEDED' }),
    );
    const accepted = detail();
    const result = createTaskDetailsV2McpResult(accepted);
    expect(result.content[0]?.text.startsWith(TASK_DETAILS_UNTRUSTED_TEXT_PREFIX)).toBe(true);
    expect(result.structuredContent).toEqual({ ok: true, value: accepted });
    expect(JSON.stringify(result).length).toBeLessThanOrEqual(MAX_COMPLETE_RESULT_BYTES);
    const frame = taskDetailsV2WireFrameByteLength(TASK_DETAILS_V2_BUDGET_REQUEST_ID, {
      ok: true,
      value: accepted,
    });
    expect(frame).toBeGreaterThan(JSON.stringify(result).length);
    const emoji = '😀';
    const under = detail({ body: segment(emoji.repeat(6600), DETAIL_BODY_MAX_CHARS) });
    const seam = detail({ body: segment(emoji.repeat(6601), DETAIL_BODY_MAX_CHARS) });
    const underWrapped = { ok: true as const, value: under };
    const seamWrapped = { ok: true as const, value: seam };
    expect(Buffer.byteLength(JSON.stringify(under))).toBeLessThanOrEqual(27_000);
    expect(Buffer.byteLength(JSON.stringify(underWrapped))).toBeLessThanOrEqual(27_000);
    expect(Buffer.byteLength(JSON.stringify(seam))).toBeLessThanOrEqual(27_000);
    expect(Buffer.byteLength(JSON.stringify(seamWrapped))).toBeGreaterThan(27_000);
    expect(() => decodeTaskDetailV2(under)).not.toThrow();
    expect(() => createTaskDetailsV2McpResult(underWrapped)).not.toThrow();
    expect(() => decodeTaskDetailV2(seam)).toThrow(
      expect.objectContaining({ code: 'RESPONSE_LIMIT_EXCEEDED' }),
    );
    const refusal = createTaskDetailsRefusal('NOT_AVAILABLE');
    const refusalResult = createTaskDetailsV2McpResult(refusal);
    expect(refusalResult.structuredContent).toEqual(refusal);
    expect((refusalResult.structuredContent as { ok: boolean }).ok).toBe(false);
    const receipt = {
      ok: true as const,
      receipt: {
        readVersion: 2 as const,
        command: 'note' as const,
        receiptId: RECEIPT,
        taskId: TASK,
        occurredAt: TIME,
        taskVersion: VERSION,
        receiptVersion: VERSION_B,
        actor: { kind: 'human' as const, id: HUMAN },
        clientId: CLIENT,
      },
    };
    const receiptResult = createTaskDetailsV2McpResult(receipt);
    expect(receiptResult.structuredContent).toEqual(receipt);
    const text = receiptResult.content[0]?.text.slice(TASK_DETAILS_UNTRUSTED_TEXT_PREFIX.length);
    expect(JSON.parse(text ?? '')).toEqual(receipt);
  });

  it('fails closed on forbidden text and a non-plain prototype', () => {
    expect(() => decodeTaskDetailV2(detail({ title: segment('bad\u0000text', 20) }))).toThrow(
      TaskDetailsDecodeError,
    );
    const foreign = Object.assign(Object.create({}), detail()) as TaskDetailV2;
    expect(() => decodeTaskDetailV2(foreign)).toThrow(
      expect.objectContaining({ code: 'MALFORMED_REPRESENTATION' }),
    );
  });

  it('decodes a note receipt and rejects evidence on an assignment receipt', () => {
    const note = {
      readVersion: 2,
      command: 'note',
      receiptId: RECEIPT,
      taskId: TASK,
      occurredAt: TIME,
      taskVersion: VERSION,
      receiptVersion: VERSION_B,
      actor: { kind: 'agent', id: AGENT },
      clientId: CLIENT,
      evidence: segment('synthetic note', 400),
    };
    expect(decodeTaskMutationReceiptV2(note).command).toBe('note');
    expect(() => decodeTaskMutationReceiptV2({ ...note, occurredAt: 'not-a-timestamp' })).toThrow(
      expect.objectContaining({ code: 'MALFORMED_REPRESENTATION' }),
    );
    expect(() => decodeTaskMutationReceiptV2({ ...note, command: 'assign' })).toThrow(
      TaskDetailsDecodeError,
    );
    expect(
      AppendTaskNoteV2InputSchema.safeParse({
        readVersion: 2,
        taskId: TASK,
        expectedVersion: VERSION,
        idempotencyKey: RECEIPT,
        text: ' synthetic ',
      }).success,
    ).toBe(false);
    expect(
      AssignTaskV2InputSchema.safeParse({
        readVersion: 2,
        taskId: TASK,
        expectedVersion: VERSION,
        idempotencyKey: RECEIPT,
        target: { kind: 'human', id: HUMAN },
      }).success,
    ).toBe(true);
  });

  it('builds a frozen refusal that carries no task data', () => {
    const refusal = createTaskDetailsRefusal('VERSION_CONFLICT');
    expect(refusal).toEqual({
      ok: false,
      refusal: {
        code: 'VERSION_CONFLICT',
        message: 'Task version has changed.',
        retryable: false,
      },
    });
    expect(Object.isFrozen(refusal)).toBe(true);
    expect(Object.isFrozen(refusal.refusal)).toBe(true);
    expect(JSON.stringify(refusal)).not.toContain('task');
    expect(createTaskDetailsRefusal('DEADLINE_EXCEEDED').refusal.retryable).toBe(true);
    expect(createTaskDetailsRefusal('UPSTREAM_UNAVAILABLE').refusal.retryable).toBe(true);
    expect(createTaskDetailsRefusal('REQUEST_CANCELLED').refusal.retryable).toBe(true);
    expect(createTaskDetailsRefusal('NOT_AVAILABLE').refusal.retryable).toBe(false);
  });
});

describe('synthetic: keyset order, coverage flags, arrays and text', () => {
  const coverage = {
    completeHistory: false as const,
    actualStoredAttributionOnly: true as const,
    approvalInferred: false as const,
  };
  const targetCoverage = {
    completeLibrary: false as const,
    eligibleTargetsGrantAuthority: false as const,
  };

  function eventRow(occurredAt: string, n: number) {
    return {
      command: 'create' as const,
      receiptId: `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`,
      occurredAt,
      taskVersion: VERSION,
      receiptVersion: VERSION,
      actor: { kind: 'human' as const, id: HUMAN },
      clientId: CLIENT,
    };
  }

  function eventPage(
    events: ReturnType<typeof eventRow>[],
    after: { occurredAt: string; receiptId: string } | null = null,
  ) {
    const last = events.at(-1);
    return {
      readVersion: 2 as const,
      view: 'events' as const,
      taskId: TASK,
      limit: 10,
      after,
      nextAfter:
        last === undefined ? null : { occurredAt: last.occurredAt, receiptId: last.receiptId },
      events,
      coverage,
    };
  }

  it('orders events by parsed instant, not by the raw timestamp string', () => {
    const correct = eventPage([
      eventRow('2026-01-01T00:00:00Z', 2),
      eventRow('2026-01-01T00:00:00.500Z', 3),
    ]);
    expect(decodeEventListV2(correct).events).toHaveLength(2);
    expect(() =>
      decodeEventListV2(
        eventPage([eventRow('2026-01-01T00:00:00.500Z', 2), eventRow('2026-01-01T00:00:00Z', 3)]),
      ),
    ).toThrow(expect.objectContaining({ code: 'MALFORMED_REPRESENTATION' }));
    expect(() =>
      decodeEventListV2(
        eventPage([eventRow('2026-01-01T01:00:00Z', 2), eventRow('2026-01-01T05:00:00+05:00', 3)]),
      ),
    ).toThrow(expect.objectContaining({ code: 'MALFORMED_REPRESENTATION' }));
    const later = [
      eventRow('2026-01-01T00:00:00Z', 2),
      eventRow('2026-01-01T00:00:00.500Z', 3),
      eventRow('2026-01-01T00:00:01Z', 4),
    ];
    expect(() => decodeEventListV2({ ...eventPage(later), limit: 2 })).toThrow(
      TaskDetailsDecodeError,
    );
    const early = eventPage([eventRow('2026-01-01T00:00:00Z', 2)], {
      occurredAt: '2026-01-01T00:00:03Z',
      receiptId: eventRow('2026-01-01T00:00:03Z', 4).receiptId,
    });
    expect(() => decodeEventListV2(early)).toThrow(TaskDetailsDecodeError);
    const sameMillisecond = eventPage([
      eventRow('2026-01-01T00:00:00.000100Z', 3),
      eventRow('2026-01-01T00:00:00.000200Z', 2),
    ]);
    expect(decodeEventListV2(sameMillisecond).events).toHaveLength(2);
    expect(() =>
      decodeEventListV2(
        eventPage([
          eventRow('2026-01-01T00:00:00.000200Z', 2),
          eventRow('2026-01-01T00:00:00.000100Z', 3),
        ]),
      ),
    ).toThrow(TaskDetailsDecodeError);
    const nextPage = eventPage([eventRow('2026-01-01T00:00:00.000200Z', 2)], {
      occurredAt: '2026-01-01T00:00:00.000100Z',
      receiptId: eventRow('2026-01-01T00:00:00.000100Z', 3).receiptId,
    });
    expect(decodeEventListV2(nextPage).events).toHaveLength(1);
    expect(() => decodeEventListV2(eventPage([eventRow('1969-12-31T23:59:59Z', 2)]))).toThrow(
      TaskDetailsDecodeError,
    );
    expect(() =>
      decodeEventListV2(
        eventPage([eventRow('1969-12-31T23:59:58Z', 2), eventRow('1969-12-31T23:59:59Z', 3)]),
      ),
    ).toThrow(TaskDetailsDecodeError);
    expect(
      decodeEventListV2(
        eventPage([eventRow('1970-01-01T00:00:00.999Z', 2), eventRow('1970-01-01T00:00:01Z', 3)]),
      ).events,
    ).toHaveLength(2);
    expect(
      decodeEventListV2(
        eventPage([eventRow('1970-01-01T00:00:09Z', 2), eventRow('1970-01-01T00:00:10Z', 3)]),
      ).events,
    ).toHaveLength(2);
    expect(() =>
      decodeEventListV2(
        eventPage([eventRow('1970-01-01T00:00:10Z', 2), eventRow('1970-01-01T00:00:09Z', 3)]),
      ),
    ).toThrow(TaskDetailsDecodeError);
    expect(
      decodeEventListV2(
        eventPage([eventRow('2026-01-01T00:00:00.25Z', 2), eventRow('2026-01-01T00:00:00.5Z', 3)]),
      ).events,
    ).toHaveLength(2);
    expect(() =>
      decodeEventListV2(
        eventPage([eventRow('2026-01-01T00:00:00.5Z', 2), eventRow('2026-01-01T00:00:00.25Z', 3)]),
      ),
    ).toThrow(TaskDetailsDecodeError);
    expect(
      decodeEventListV2(
        eventPage([
          eventRow('2026-01-01T00:00:00.5Z', 2),
          eventRow('2026-01-01T00:00:00.500000Z', 3),
        ]),
      ).events,
    ).toHaveLength(2);
    expect(() =>
      decodeEventListV2(
        eventPage([
          eventRow('2026-01-01T00:00:00.5Z', 3),
          eventRow('2026-01-01T00:00:00.500000Z', 2),
        ]),
      ),
    ).toThrow(TaskDetailsDecodeError);
    expect(
      decodeEventListV2(
        eventPage([eventRow('2026-01-01T05:29:00+05:30', 2), eventRow('2026-01-01T00:00:00Z', 3)]),
      ).events,
    ).toHaveLength(2);
    expect(() =>
      decodeEventListV2(
        eventPage([eventRow('2026-01-01T00:00:00Z', 2), eventRow('2026-01-01T05:29:00+05:30', 3)]),
      ),
    ).toThrow(TaskDetailsDecodeError);
    const fraction12 = `2026-01-01T00:00:00.${'1'.repeat(12)}Z`;
    const fraction13 = `2026-01-01T00:00:00.${'1'.repeat(13)}Z`;
    expect(decodeEventListV2(eventPage([eventRow(fraction12, 2)])).events).toHaveLength(1);
    expect(() => decodeEventListV2(eventPage([eventRow(fraction13, 2)]))).toThrow(
      TaskDetailsDecodeError,
    );
    expect(() =>
      decodeEventListV2({
        ...eventPage([]),
        after: {
          occurredAt: '1969-12-31T23:59:59Z',
          receiptId: eventRow('1969-12-31T23:59:59Z', 2).receiptId,
        },
      }),
    ).toThrow(TaskDetailsDecodeError);
    expect(DETAIL_BODY_MAX_CHARS).toBe(8000);
  });

  it('rejects a v1-tagged array and an oversized array as malformed', () => {
    expect(() => decodeTaskDetailV2(Object.assign([], { readVersion: 1 }))).toThrow(
      expect.objectContaining({ code: 'MALFORMED_REPRESENTATION' }),
    );
    const oversized = Object.assign(
      Array.from({ length: 70_000 }, () => 'x'),
      { readVersion: 2 },
    );
    expect(() => decodeTaskDetailV2(oversized)).toThrow(
      expect.objectContaining({ code: 'MALFORMED_REPRESENTATION' }),
    );
  });

  it('rejects DEL, a lone surrogate, a cycle, a bad timestamp and an unknown actor kind', () => {
    expect(() =>
      decodeTaskDetailV2(detail({ body: segment('a\u007fb', DETAIL_BODY_MAX_CHARS) })),
    ).toThrow(TaskDetailsDecodeError);
    expect(() =>
      decodeTaskDetailV2(
        detail({
          body: { text: 'a\ud800', offset: 0, totalChars: 2, nextOffset: 2, complete: true },
        }),
      ),
    ).toThrow(TaskDetailsDecodeError);
    const cycle: Record<string, unknown> = { readVersion: 2 };
    cycle.self = cycle;
    expect(() => decodeTaskDetailV2(cycle)).toThrow(
      expect.objectContaining({ code: 'MALFORMED_REPRESENTATION' }),
    );
    expect(() => decodeEventListV2(eventPage([eventRow('not-a-timestamp', 2)]))).toThrow(
      TaskDetailsDecodeError,
    );
    expect(() =>
      decodeTaskDetailV2(detail({ assignedPrincipal: { kind: 'service' as 'human', id: HUMAN } })),
    ).toThrow(TaskDetailsDecodeError);
  });

  it('rejects each coverage flag when it is not the required literal', () => {
    const targets = {
      readVersion: 2 as const,
      view: 'assignment_targets' as const,
      limit: 1,
      afterPrincipalId: null,
      nextAfterPrincipalId: null,
      targets: [{ principal: { kind: 'human' as const, id: HUMAN } }],
      coverage: targetCoverage,
    };
    expect(() =>
      decodeAssignmentTargetListV2({
        ...targets,
        coverage: { ...targetCoverage, completeLibrary: true },
      }),
    ).toThrow(TaskDetailsDecodeError);
    expect(() =>
      decodeEventListV2({
        ...eventPage([eventRow(TIME, 2)]),
        coverage: { ...coverage, completeHistory: true },
      }),
    ).toThrow(TaskDetailsDecodeError);
    expect(() =>
      decodeEventListV2({
        ...eventPage([eventRow(TIME, 2)]),
        coverage: { ...coverage, actualStoredAttributionOnly: false },
      }),
    ).toThrow(TaskDetailsDecodeError);
  });

  it('rejects inconsistent task, target and event keyset pages', () => {
    const item = (id: string) => ({
      taskId: id,
      title: segment('t', LIST_SEGMENT_MAX_CHARS),
      status: 'open' as const,
      version: VERSION,
      body: segment('b', LIST_SEGMENT_MAX_CHARS),
      assignedPrincipal: null,
      workstreamId: WORKSTREAM,
      citation: segment('', LIST_SEGMENT_MAX_CHARS),
    });
    const tasks = {
      readVersion: 2 as const,
      view: 'tasks' as const,
      limit: 2,
      afterTaskId: TASK,
      nextAfterTaskId: TASK_B,
      tasks: [item(TASK), item(TASK_B)],
    };
    expect(() => decodeTaskListV2(tasks)).toThrow(TaskDetailsDecodeError);
    expect(() =>
      decodeTaskListV2({
        ...tasks,
        afterTaskId: null,
        tasks: [item(TASK)],
        limit: 1,
        nextAfterTaskId: null,
      }),
    ).not.toThrow();
    expect(() =>
      decodeTaskListV2({
        ...tasks,
        afterTaskId: null,
        limit: 2,
        tasks: [item(TASK), item(TASK_B)],
        nextAfterTaskId: TASK,
      }),
    ).toThrow(TaskDetailsDecodeError);
    expect(() =>
      decodeTaskListV2({
        ...tasks,
        afterTaskId: null,
        limit: 1,
        tasks: [item(TASK), item(TASK_B)],
        nextAfterTaskId: TASK_B,
      }),
    ).toThrow(TaskDetailsDecodeError);
    expect(() =>
      ReadTaskListV2InputSchema.parse({
        readVersion: 2,
        view: 'tasks',
        limit: 0,
        afterTaskId: null,
      }),
    ).toThrow();

    const unorderedTargets = {
      readVersion: 2 as const,
      view: 'assignment_targets' as const,
      limit: 2,
      afterPrincipalId: null,
      nextAfterPrincipalId: HUMAN,
      targets: [
        { principal: { kind: 'agent' as const, id: AGENT } },
        { principal: { kind: 'human' as const, id: HUMAN } },
      ],
      coverage: targetCoverage,
    };
    expect(() => decodeAssignmentTargetListV2(unorderedTargets)).toThrow(TaskDetailsDecodeError);
    expect(() =>
      decodeAssignmentTargetListV2({
        ...unorderedTargets,
        targets: [{ principal: { kind: 'human' as const, id: HUMAN } }],
        limit: 1,
        nextAfterPrincipalId: AGENT,
      }),
    ).toThrow(TaskDetailsDecodeError);

    const ordered = {
      readVersion: 2 as const,
      view: 'coordination_targets' as const,
      limit: 2,
      after: null,
      nextAfter: { principalId: AGENT, clientId: CLIENT },
      targets: [
        { principal: { kind: 'human' as const, id: HUMAN }, clientId: CLIENT },
        { principal: { kind: 'agent' as const, id: AGENT }, clientId: CLIENT },
      ],
      coverage: targetCoverage,
    };
    expect(decodeCoordinationTargetListV2(ordered).targets).toHaveLength(2);
    expect(() =>
      decodeCoordinationTargetListV2({
        ...ordered,
        targets: [...ordered.targets].reverse(),
        nextAfter: { principalId: HUMAN, clientId: CLIENT },
      }),
    ).toThrow(TaskDetailsDecodeError);
    const coord = {
      readVersion: 2 as const,
      view: 'coordination_targets' as const,
      limit: 1,
      after: { principalId: HUMAN, clientId: CLIENT },
      nextAfter: null,
      targets: [{ principal: { kind: 'human' as const, id: HUMAN }, clientId: CLIENT }],
      coverage: targetCoverage,
    };
    expect(() => decodeCoordinationTargetListV2(coord)).toThrow(TaskDetailsDecodeError);

    const broken = segment('ab', 10);
    expect(() =>
      decodeTaskDetailV2(
        detail({
          body: {
            ...broken,
            offset: 5,
            nextOffset: broken.nextOffset,
            totalChars: broken.totalChars,
            complete: broken.complete,
          },
        }),
      ),
    ).toThrow(TaskDetailsDecodeError);
  });

  it('wraps the largest legal detail without throwing and rejects one extra body character', () => {
    const largest = detail({
      body: segment('b'.repeat(DETAIL_BODY_MAX_CHARS), DETAIL_BODY_MAX_CHARS),
    });
    expect(decodeTaskDetailV2(largest).task.body.text).toHaveLength(DETAIL_BODY_MAX_CHARS);
    expect(() => createTaskDetailsV2McpResult({ ok: true, value: largest })).not.toThrow();
    expect(() =>
      decodeTaskDetailV2(
        detail({
          body: segment('b'.repeat(DETAIL_BODY_MAX_CHARS + 1), DETAIL_BODY_MAX_CHARS + 1),
        }),
      ),
    ).toThrow(TaskDetailsDecodeError);
  });

  it('rejects an acting-identity field on a detail read', () => {
    expect(
      ReadTaskDetailV2InputSchema.safeParse({
        readVersion: 2,
        view: 'task',
        taskId: TASK,
        expectedVersion: VERSION,
        actingIdentity: HUMAN,
      }).success,
    ).toBe(false);
  });
});
