import { describe, expect, it } from 'vitest';

import { MAX_REQUEST_ID_BYTES, MAX_RESPONSE_BYTES } from './read-tools.js';
import {
  AppendTaskNoteV2InputSchema,
  AssignTaskV2InputSchema,
  clipUtf8,
  createTaskDetailsRefusal,
  createTaskDetailsV2McpResult,
  decodeTaskDetailsV2,
  decodeTaskMutationReceiptV2,
  MAX_ACTIVITY_ENTRIES,
  MAX_ACTIVITY_TEXT_BYTES,
  MAX_ASSIGNMENT_TARGETS,
  MAX_TASK_BODY_BYTES,
  MAX_TASK_DETAILS_V2_FRAME_BYTES,
  ReadTaskDetailsV2InputSchema,
  TASK_DETAILS_UNTRUSTED_TEXT_PREFIX,
  TASK_DETAILS_V1_LABEL,
  TASK_DETAILS_V2_BUDGET_REQUEST_ID,
  TASK_DETAILS_V2_REPRESENTATION,
  TaskDetailsDecodeError,
  type TaskDetailsRefusalCode,
  type TaskDetailsV2,
  taskDetailsV2WireFrameByteLength,
} from './task-details-v2.js';

/** Synthetic idempotency values are built, not written as literals, so they never read as keys. */
const syntheticIdempotencyKey = (suffix: string): string => `idem-synthetic-${suffix}`;

const SYNTHETIC_TIME = '2026-01-01T00:00:00.000Z';

// Synthetic fixture mirroring #71 receipt outputs @5ffd0974. These bytes are written here by hand;
// nothing is imported from #71. They are not a consumer v1 compatibility fixture.
const SYNTHETIC_71_CREATE_RECEIPT_BYTES =
  '{"ok":true,"receipt":{"id":"00000000-0000-4000-8000-000000000001","itemNumber":1,"boardSlug":"synthetic-board","created":true,"idempotencyKey":"synthetic-item-001"}}';
const SYNTHETIC_71_POST_RECEIPT_BYTES =
  '{"ok":true,"receipt":{"id":"00000000-0000-4000-8000-000000000002","seq":7,"posted":true}}';
const SYNTHETIC_71_ERROR_BYTES =
  '{"ok":false,"error":{"code":"IDEMPOTENCY_CONFLICT","message":"Idempotency key conflicts with an existing request.","retryable":false}}';

function provenance(actorKind: 'human' | 'agent', actorId: string, clientId: string) {
  return { actorKind, actorId, clientId, occurredAt: SYNTHETIC_TIME };
}

function syntheticDetails(): TaskDetailsV2 {
  return {
    representation: 'task-details.v2',
    task: {
      taskId: 'task-synthetic-001',
      workstreamId: 'workstream-synthetic-a',
      title: 'Synthetic task title',
      status: 'in_progress',
      body: clipUtf8('Synthetic task body.', MAX_TASK_BODY_BYTES),
      version: 'ver-synthetic-0002',
      createdBy: provenance('human', 'human-synthetic-a', 'client-synthetic-a'),
      lastChangedBy: provenance('agent', 'agent-synthetic-a', 'client-synthetic-a'),
      assignee: { kind: 'agent', id: 'agent-synthetic-a' },
    },
    assignmentTargets: {
      targets: [
        { kind: 'human', id: 'human-synthetic-a', status: 'active' },
        { kind: 'agent', id: 'agent-synthetic-a', status: 'active' },
        { kind: 'agent', id: 'agent-synthetic-b', status: 'withdrawn' },
      ],
      coverage: { returnedCount: 3, totalCount: 3, clipped: false },
    },
    activity: {
      entries: [
        {
          entryKind: 'note',
          receiptId: 'receipt-synthetic-001',
          recordedBy: provenance('agent', 'agent-synthetic-a', 'client-synthetic-a'),
          text: clipUtf8('Synthetic note without a stored citation.', MAX_ACTIVITY_TEXT_BYTES),
        },
        {
          entryKind: 'note',
          receiptId: 'receipt-synthetic-002',
          recordedBy: provenance('human', 'human-synthetic-a', 'client-synthetic-a'),
          text: clipUtf8('Synthetic note with a stored citation.', MAX_ACTIVITY_TEXT_BYTES),
          citation: { sourceRef: 'synthetic://source/001' },
        },
        {
          entryKind: 'assignment',
          receiptId: 'receipt-synthetic-003',
          recordedBy: provenance('human', 'human-synthetic-a', 'client-synthetic-a'),
          assignee: { kind: 'agent', id: 'agent-synthetic-a' },
        },
      ],
      coverage: { returnedCount: 3, totalCount: 3, clipped: false },
    },
  };
}

/** Synthetic details sized by a count of full notes and the ASCII body length. */
function sizedDetails(noteCount: number, bodyBytes: number): TaskDetailsV2 {
  const base = syntheticDetails();
  const entries = Array.from({ length: noteCount }, (_, index) => ({
    entryKind: 'note' as const,
    receiptId: `receipt-synthetic-size-${index}`,
    recordedBy: provenance('agent', 'agent-synthetic-a', 'client-synthetic-a'),
    text: clipUtf8('n'.repeat(MAX_ACTIVITY_TEXT_BYTES), MAX_ACTIVITY_TEXT_BYTES),
  }));
  return {
    ...base,
    task: { ...base.task, body: clipUtf8('b'.repeat(bodyBytes), MAX_TASK_BODY_BYTES) },
    activity: {
      entries,
      coverage: { returnedCount: noteCount, totalCount: noteCount, clipped: false },
    },
  };
}

const budgetFrame = (details: TaskDetailsV2) =>
  taskDetailsV2WireFrameByteLength(TASK_DETAILS_V2_BUDGET_REQUEST_ID, { ok: true, details });

/**
 * Finds sizing whose budget frame is exactly the ceiling. Body lengths stay within 1000..8191 so
 * each extra ASCII byte adds exactly one frame byte.
 */
function exactCeilingDetails(): { details: TaskDetailsV2; noteCount: number; bodyBytes: number } {
  for (let noteCount = 1; noteCount <= MAX_ACTIVITY_ENTRIES; noteCount += 1) {
    const delta = MAX_TASK_DETAILS_V2_FRAME_BYTES - budgetFrame(sizedDetails(noteCount, 1_000));
    if (delta >= 1 && delta < MAX_TASK_BODY_BYTES - 1_000) {
      const bodyBytes = 1_000 + delta;
      return { details: sizedDetails(noteCount, bodyBytes), noteCount, bodyBytes };
    }
  }
  throw new Error('no exact-ceiling sizing found');
}

/** Every field and count at its schema maximum, with worst-case JSON escaping. */
function allFieldsAtMaximum(): TaskDetailsV2 {
  const quote = (bytes: number) => clipUtf8('"'.repeat(bytes), bytes);
  const id = (prefix: string, index: number) => `${prefix}-${index}`.padEnd(128, 'x');
  const who = (index: number) => ({
    actorKind: 'agent' as const,
    actorId: id('agent', index),
    clientId: id('client', index),
    occurredAt: SYNTHETIC_TIME,
  });
  return {
    representation: 'task-details.v2',
    task: {
      taskId: id('task', 0),
      workstreamId: id('workstream', 0),
      title: '"'.repeat(256),
      status: 'in_progress',
      body: quote(MAX_TASK_BODY_BYTES),
      version: '!'.repeat(128),
      createdBy: who(0),
      lastChangedBy: who(1),
      assignee: { kind: 'agent', id: id('agent', 0) },
    },
    assignmentTargets: {
      targets: Array.from({ length: MAX_ASSIGNMENT_TARGETS }, (_, index) => ({
        kind: 'agent' as const,
        id: id('agent', index),
        status: 'active' as const,
      })),
      coverage: {
        returnedCount: MAX_ASSIGNMENT_TARGETS,
        totalCount: MAX_ASSIGNMENT_TARGETS,
        clipped: false,
      },
    },
    activity: {
      entries: Array.from({ length: MAX_ACTIVITY_ENTRIES }, (_, index) => ({
        entryKind: 'note' as const,
        receiptId: id('receipt', index),
        recordedBy: who(index),
        text: quote(MAX_ACTIVITY_TEXT_BYTES),
        citation: { sourceRef: `s${'"'.repeat(510)}s` },
      })),
      coverage: {
        returnedCount: MAX_ACTIVITY_ENTRIES,
        totalCount: MAX_ACTIVITY_ENTRIES,
        clipped: false,
      },
    },
  };
}

function decodeErrorCode(decode: () => unknown): string {
  try {
    decode();
  } catch (error) {
    if (error instanceof TaskDetailsDecodeError) return error.code;
    throw error;
  }
  return 'decoded';
}

function expectDecodeError(raw: unknown, code: TaskDetailsDecodeError['code']) {
  expect(decodeErrorCode(() => decodeTaskDetailsV2(raw))).toBe(code);
}

describe('synthetic: v1 label names the #71 write receipts; there is no v1 task-details read', () => {
  it('labels v1 as the #71 write receipt outputs, not a task-details read shape', () => {
    expect(TASK_DETAILS_V1_LABEL).toBe(
      '#71 create_work_item / post_model_message receipt outputs @5ffd0974',
    );
    expect(TASK_DETAILS_V2_REPRESENTATION).toBe('task-details.v2');
  });

  it('never decodes the synthetic #71-mirroring receipt or error bytes as v2', () => {
    for (const bytes of [
      SYNTHETIC_71_CREATE_RECEIPT_BYTES,
      SYNTHETIC_71_POST_RECEIPT_BYTES,
      SYNTHETIC_71_ERROR_BYTES,
    ]) {
      expectDecodeError(JSON.parse(bytes), 'MALFORMED_REPRESENTATION');
      expect(decodeErrorCode(() => decodeTaskMutationReceiptV2(JSON.parse(bytes)))).toBe(
        'MALFORMED_REPRESENTATION',
      );
    }
  });
});

describe('synthetic: v2 decoder', () => {
  it('round-trips a valid v2 representation byte for byte', () => {
    const value = syntheticDetails();
    const bytes = JSON.stringify(value);
    const decoded = decodeTaskDetailsV2(JSON.parse(bytes));
    expect(decoded).toEqual(value);
    expect(JSON.stringify(decoded)).toBe(bytes);
    expect(decoded.activity.entries[0]).not.toHaveProperty('citation');
    expect(decoded.activity.entries[1]).toHaveProperty('citation', {
      sourceRef: 'synthetic://source/001',
    });
  });

  it('refuses unknown representation versions', () => {
    for (const representation of ['task-details.v1', 'task-details.v3', 'task-details', 'V2']) {
      expectDecodeError({ ...syntheticDetails(), representation }, 'UNSUPPORTED_REPRESENTATION');
    }
  });

  it('refuses malformed representations, extra keys and wrong types', () => {
    const base = syntheticDetails();
    const malformed: unknown[] = [
      null,
      'task-details.v2',
      [],
      { ...base, representation: 2 },
      (({ representation: _r, ...rest }) => rest)(base),
      { ...base, extra: true },
      { ...base, task: { ...base.task, actingAgent: 'agent-synthetic-z' } },
      { ...base, task: { ...base.task, version: '' } },
      { ...base, task: { ...base.task, version: 'has space' } },
      { ...base, task: { ...base.task, status: 'in-progress' } },
      { ...base, task: { ...base.task, createdBy: { ...base.task.createdBy, occurredAt: 'x' } } },
      { ...base, task: { ...base.task, assignee: { kind: 'robot', id: 'x' } } },
      { ...base, task: { ...base.task, body: { ...base.task.body, returnedBytes: 1 } } },
      { ...base, task: { ...base.task, body: { ...base.task.body, clipped: true } } },
      {
        ...base,
        activity: {
          ...base.activity,
          entries: [{ ...base.activity.entries[0], citation: null }],
          coverage: { returnedCount: 1, totalCount: 1, clipped: false },
        },
      },
      {
        ...base,
        activity: {
          ...base.activity,
          entries: [{ ...base.activity.entries[0], payload: { command: 'synthetic' } }],
          coverage: { returnedCount: 1, totalCount: 1, clipped: false },
        },
      },
      {
        ...base,
        activity: {
          ...base.activity,
          coverage: { returnedCount: 2, totalCount: 3, clipped: true },
        },
      },
      {
        ...base,
        activity: {
          ...base.activity,
          coverage: { returnedCount: 3, totalCount: 9, clipped: false },
        },
      },
      {
        ...base,
        assignmentTargets: {
          ...base.assignmentTargets,
          targets: [{ kind: 'agent', id: 'agent-synthetic-a', status: 'retired' }],
          coverage: { returnedCount: 1, totalCount: 1, clipped: false },
        },
      },
      {
        ...base,
        activity: {
          entries: [base.activity.entries[0], base.activity.entries[0]],
          coverage: { returnedCount: 2, totalCount: 2, clipped: false },
        },
      },
    ];
    for (const raw of malformed) expectDecodeError(raw, 'MALFORMED_REPRESENTATION');
  });

  it('refuses identifiers outside the bounded grammar', () => {
    const base = syntheticDetails();
    for (const taskId of ['-task', 'task synthetic', 'task\u00e9', 'x'.repeat(129)]) {
      expectDecodeError({ ...base, task: { ...base.task, taskId } }, 'MALFORMED_REPRESENTATION');
    }
  });

  it('refuses bounded text whose byte count disagrees with its text', () => {
    const base = syntheticDetails();
    expectDecodeError(
      {
        ...base,
        task: {
          ...base.task,
          body: { text: 'abc', clipped: true, totalBytes: 3, returnedBytes: 2 },
        },
      },
      'MALFORMED_REPRESENTATION',
    );
    expectDecodeError(
      {
        ...base,
        task: {
          ...base.task,
          body: { text: 'abc', clipped: false, totalBytes: 2, returnedBytes: 3 },
        },
      },
      'MALFORMED_REPRESENTATION',
    );
  });

  it('refuses coverage that returns more than the total', () => {
    const base = syntheticDetails();
    expectDecodeError(
      {
        ...base,
        activity: {
          ...base.activity,
          coverage: { returnedCount: 3, totalCount: 2, clipped: false },
        },
      },
      'MALFORMED_REPRESENTATION',
    );
  });

  it('refuses extra provenance keys and padded citations', () => {
    const base = syntheticDetails();
    expectDecodeError(
      {
        ...base,
        task: { ...base.task, createdBy: { ...base.task.createdBy, sessionId: 'session-x' } },
      },
      'MALFORMED_REPRESENTATION',
    );
    expectDecodeError(
      {
        ...base,
        activity: {
          entries: [{ ...base.activity.entries[1], citation: { sourceRef: ' synthetic://a' } }],
          coverage: { returnedCount: 1, totalCount: 1, clipped: false },
        },
      },
      'MALFORMED_REPRESENTATION',
    );
  });

  it('accepts the title and citation ceilings and refuses one unit over', () => {
    const base = syntheticDetails();
    const withTitle = (title: string) => ({ ...base, task: { ...base.task, title } });
    const withCitation = (sourceRef: string) => ({
      ...base,
      activity: {
        entries: [{ ...base.activity.entries[1], citation: { sourceRef } }],
        coverage: { returnedCount: 1, totalCount: 1, clipped: false },
      },
    });
    expect(decodeTaskDetailsV2(withTitle('t'.repeat(256))).task.title).toHaveLength(256);
    expectDecodeError(withTitle('t'.repeat(257)), 'MALFORMED_REPRESENTATION');
    expect(decodeTaskDetailsV2(withCitation('c'.repeat(512))).activity.entries).toHaveLength(1);
    expectDecodeError(withCitation('c'.repeat(513)), 'MALFORMED_REPRESENTATION');
  });

  it('refuses duplicate, miscounted or too many assignment targets', () => {
    const base = syntheticDetails();
    const target = { kind: 'agent', id: 'agent-synthetic-a', status: 'active' } as const;
    const targets = (list: readonly unknown[], returnedCount = list.length) => ({
      ...base,
      assignmentTargets: {
        targets: list,
        coverage: {
          returnedCount,
          totalCount: Math.max(returnedCount, list.length),
          clipped: false,
        },
      },
    });
    expectDecodeError(targets([target, target]), 'MALFORMED_REPRESENTATION');
    expectDecodeError(
      {
        ...base,
        assignmentTargets: {
          targets: [target],
          coverage: { returnedCount: 2, totalCount: 2, clipped: false },
        },
      },
      'MALFORMED_REPRESENTATION',
    );
    const many = Array.from({ length: MAX_ASSIGNMENT_TARGETS + 1 }, (_, index) => ({
      ...target,
      id: `agent-synthetic-${index}`,
    }));
    expectDecodeError(targets(many), 'MALFORMED_REPRESENTATION');
    expect(decodeTaskDetailsV2(targets(many.slice(0, MAX_ASSIGNMENT_TARGETS)))).toBeDefined();
  });

  it('refuses more than the maximum activity entries', () => {
    const base = syntheticDetails();
    const entry = base.activity.entries[2];
    const entries = (count: number) => ({
      ...base,
      activity: {
        entries: Array.from({ length: count }, (_, index) => ({
          ...entry,
          receiptId: `receipt-synthetic-many-${index}`,
        })),
        coverage: { returnedCount: count, totalCount: count, clipped: false },
      },
    });
    expectDecodeError(entries(MAX_ACTIVITY_ENTRIES + 1), 'MALFORMED_REPRESENTATION');
    expect(decodeTaskDetailsV2(entries(MAX_ACTIVITY_ENTRIES)).activity.entries).toHaveLength(
      MAX_ACTIVITY_ENTRIES,
    );
  });

  it('refuses oversized fields and approval semantics', () => {
    const base = syntheticDetails();
    expectDecodeError(
      { ...base, task: { ...base.task, approved: true } },
      'MALFORMED_REPRESENTATION',
    );
    const huge = 'x'.repeat(MAX_TASK_BODY_BYTES + 1);
    expectDecodeError(
      {
        ...base,
        task: {
          ...base.task,
          body: { text: huge, clipped: false, totalBytes: huge.length, returnedBytes: huge.length },
        },
      },
      'MALFORMED_REPRESENTATION',
    );
  });

  it('decodes mutation receipts strictly', () => {
    const receipt = {
      representation: 'task-details.v2',
      receiptId: 'receipt-synthetic-010',
      taskId: 'task-synthetic-001',
      version: 'ver-synthetic-0003',
      recordedBy: provenance('agent', 'agent-synthetic-a', 'client-synthetic-a'),
      replayed: false,
    };
    expect(decodeTaskMutationReceiptV2(receipt)).toEqual(receipt);
    expect(() =>
      decodeTaskMutationReceiptV2({ ...receipt, representation: 'task-details.v9' }),
    ).toThrow(TaskDetailsDecodeError);
    expect(() => decodeTaskMutationReceiptV2({ ...receipt, sql: 'select 1' })).toThrow(
      TaskDetailsDecodeError,
    );
  });
});

describe('synthetic: one whole-frame size policy', () => {
  it('emits the payload once, as labelled text, with no structured duplicate', () => {
    const output = { ok: true, details: syntheticDetails() };
    const result = createTaskDetailsV2McpResult(output);
    expect(Object.keys(result).toSorted()).toEqual(['content', 'isError']);
    expect(result.content).toEqual([
      { type: 'text', text: `${TASK_DETAILS_UNTRUSTED_TEXT_PREFIX}${JSON.stringify(output)}` },
    ]);
  });

  it('measures the complete JSON-RPC frame including envelope, escaping and newline', () => {
    const output = { ok: true, details: syntheticDetails() };
    const frame = `${JSON.stringify({
      jsonrpc: '2.0',
      id: 7,
      result: createTaskDetailsV2McpResult(output),
    })}\n`;
    expect(taskDetailsV2WireFrameByteLength(7, output)).toBe(
      new TextEncoder().encode(frame).byteLength,
    );
    expect(
      new TextEncoder().encode(JSON.stringify(TASK_DETAILS_V2_BUDGET_REQUEST_ID)).byteLength,
    ).toBe(MAX_REQUEST_ID_BYTES);
    expect(MAX_TASK_DETAILS_V2_FRAME_BYTES).toBe(MAX_RESPONSE_BYTES);
  });

  it('refuses the all-fields-at-maximum result with RESPONSE_LIMIT_EXCEEDED', () => {
    const maximum = allFieldsAtMaximum();
    expect(budgetFrame(maximum)).toBeGreaterThan(MAX_TASK_DETAILS_V2_FRAME_BYTES);
    expectDecodeError(maximum, 'RESPONSE_LIMIT_EXCEEDED');
    const refusal = createTaskDetailsRefusal('RESPONSE_LIMIT_EXCEEDED');
    expect(refusal.refusal.retryable).toBe(false);
    expect(
      taskDetailsV2WireFrameByteLength(TASK_DETAILS_V2_BUDGET_REQUEST_ID, refusal),
    ).toBeLessThanOrEqual(MAX_TASK_DETAILS_V2_FRAME_BYTES);
  });

  it('accepts a frame of exactly 65536 bytes and refuses 65537', () => {
    const { details, noteCount, bodyBytes } = exactCeilingDetails();
    expect(budgetFrame(details)).toBe(MAX_TASK_DETAILS_V2_FRAME_BYTES);
    expect(decodeTaskDetailsV2(details)).toEqual(details);
    const over = sizedDetails(noteCount, bodyBytes + 1);
    expect(budgetFrame(over)).toBe(MAX_TASK_DETAILS_V2_FRAME_BYTES + 1);
    expectDecodeError(over, 'RESPONSE_LIMIT_EXCEEDED');
    const under = sizedDetails(noteCount, bodyBytes - 1);
    expect(budgetFrame(under)).toBe(MAX_TASK_DETAILS_V2_FRAME_BYTES - 1);
    expect(decodeTaskDetailsV2(under)).toEqual(under);
  });

  it('keeps every accepted frame within the ceiling for every legal request id', () => {
    const { details } = exactCeilingDetails();
    for (const id of [null, 0, Number.MAX_SAFE_INTEGER, 'r', TASK_DETAILS_V2_BUDGET_REQUEST_ID]) {
      expect(taskDetailsV2WireFrameByteLength(id, { ok: true, details })).toBeLessThanOrEqual(
        MAX_RESPONSE_BYTES,
      );
    }
  });

  it('refuses an oversized raw payload before schema parsing', () => {
    const base = syntheticDetails();
    const huge = 'x'.repeat(MAX_RESPONSE_BYTES);
    expectDecodeError(
      { ...base, task: { ...base.task, body: { ...base.task.body, text: huge } } },
      'RESPONSE_LIMIT_EXCEEDED',
    );
  });

  it('fits the largest legal mutation receipt frame', () => {
    const receipt = {
      representation: 'task-details.v2',
      receiptId: 'r'.repeat(128),
      taskId: 't'.repeat(128),
      version: '"'.repeat(128),
      recordedBy: {
        actorKind: 'agent',
        actorId: 'a'.repeat(128),
        clientId: 'c'.repeat(128),
        occurredAt: '2026-01-01T00:00:00.000000000+14:00',
      },
      replayed: true,
    };
    expect(decodeTaskMutationReceiptV2(receipt)).toEqual(receipt);
    expect(
      taskDetailsV2WireFrameByteLength(TASK_DETAILS_V2_BUDGET_REQUEST_ID, { ok: true, receipt }),
    ).toBeLessThanOrEqual(MAX_RESPONSE_BYTES);
  });
});

describe('synthetic: bounded and clipped text', () => {
  it('clips UTF-8 on code point boundaries and reports coverage', () => {
    const text = `${'a'.repeat(5)}\u00e9\u20ac\u{1f600}`;
    expect(clipUtf8(text, 64)).toEqual({ text, clipped: false, totalBytes: 14, returnedBytes: 14 });
    expect(clipUtf8(text, 6)).toEqual({
      text: 'aaaaa',
      clipped: true,
      totalBytes: 14,
      returnedBytes: 5,
    });
    expect(clipUtf8(text, 7)).toEqual({
      text: 'aaaaa\u00e9',
      clipped: true,
      totalBytes: 14,
      returnedBytes: 7,
    });
    expect(clipUtf8(text, 12)).toEqual({
      text: 'aaaaa\u00e9\u20ac',
      clipped: true,
      totalBytes: 14,
      returnedBytes: 10,
    });
    expect(clipUtf8(text, 0)).toEqual({
      text: '',
      clipped: true,
      totalBytes: 14,
      returnedBytes: 0,
    });
  });

  it('fails closed on a NaN, infinite, negative or fractional byte limit', () => {
    for (const limit of [Number.NaN, Number.POSITIVE_INFINITY, -1, 1.5, 2 ** 53]) {
      expect(() => clipUtf8('synthetic', limit)).toThrow(RangeError);
    }
  });

  it('fails closed on lone surrogates and keeps paired surrogates', () => {
    expect(() => clipUtf8('a\ud800b', 64)).toThrow(RangeError);
    expect(() => clipUtf8('a\udc00', 64)).toThrow(RangeError);
    expect(clipUtf8('\u{1f600}', 64).returnedBytes).toBe(4);
  });

  it('keeps a clipped body and clipped notes visible after decode', () => {
    const base = syntheticDetails();
    const longBody = '\u00e9'.repeat(MAX_TASK_BODY_BYTES);
    const longNote = '\u20ac'.repeat(MAX_ACTIVITY_TEXT_BYTES);
    const decoded = decodeTaskDetailsV2({
      ...base,
      task: { ...base.task, body: clipUtf8(longBody, MAX_TASK_BODY_BYTES) },
      activity: {
        entries: [
          {
            entryKind: 'note',
            receiptId: 'receipt-synthetic-020',
            recordedBy: provenance('agent', 'agent-synthetic-a', 'client-synthetic-a'),
            text: clipUtf8(longNote, MAX_ACTIVITY_TEXT_BYTES),
          },
        ],
        coverage: { returnedCount: 1, totalCount: 40, clipped: true },
      },
    });
    expect(decoded.task.body).toMatchObject({
      clipped: true,
      totalBytes: MAX_TASK_BODY_BYTES * 2,
      returnedBytes: MAX_TASK_BODY_BYTES,
    });
    const note = decoded.activity.entries[0];
    expect(note?.entryKind).toBe('note');
    if (note?.entryKind !== 'note') throw new Error('expected note');
    expect(note.text.clipped).toBe(true);
    expect(note.text.totalBytes).toBe(MAX_ACTIVITY_TEXT_BYTES * 3);
    expect(note.text.returnedBytes).toBe(MAX_ACTIVITY_TEXT_BYTES - (MAX_ACTIVITY_TEXT_BYTES % 3));
    expect(decoded.activity.coverage).toEqual({ returnedCount: 1, totalCount: 40, clipped: true });
  });

  it('rejects NUL, control characters and lone surrogates in stored text', () => {
    const base = syntheticDetails();
    const bounded = (text: string) => ({
      text,
      clipped: false,
      totalBytes: new TextEncoder().encode(text).byteLength,
      returnedBytes: new TextEncoder().encode(text).byteLength,
    });
    const note = base.activity.entries[1];
    for (const bad of ['a\u0000b', 'a\u0007b', 'a\u001bb', 'a\u007fb', 'a\ud800b', 'a\udfffb']) {
      expectDecodeError(
        { ...base, task: { ...base.task, body: bounded(bad) } },
        'MALFORMED_REPRESENTATION',
      );
      expectDecodeError(
        { ...base, task: { ...base.task, title: bad } },
        'MALFORMED_REPRESENTATION',
      );
      expectDecodeError(
        {
          ...base,
          activity: {
            entries: [{ ...note, text: bounded(bad), citation: { sourceRef: 'synthetic://a' } }],
            coverage: { returnedCount: 1, totalCount: 1, clipped: false },
          },
        },
        'MALFORMED_REPRESENTATION',
      );
      expectDecodeError(
        {
          ...base,
          activity: {
            entries: [{ ...note, citation: { sourceRef: bad } }],
            coverage: { returnedCount: 1, totalCount: 1, clipped: false },
          },
        },
        'MALFORMED_REPRESENTATION',
      );
    }
    const allowed = 'line one\n\tline two\r\nline \u{1f600}';
    const decoded = decodeTaskDetailsV2({
      ...base,
      task: { ...base.task, body: bounded(allowed) },
    });
    expect(decoded.task.body.text).toBe(allowed);
  });

  it('marks stored text as untrusted data in MCP results', () => {
    const value = syntheticDetails();
    const result = createTaskDetailsV2McpResult({ ok: true, details: value });
    expect(result.content[0]?.text.startsWith(TASK_DETAILS_UNTRUSTED_TEXT_PREFIX)).toBe(true);
    expect(result.isError).toBe(false);
    expect(createTaskDetailsV2McpResult(createTaskDetailsRefusal('NOT_AVAILABLE')).isError).toBe(
      true,
    );
  });
});

describe('synthetic: typed refusals', () => {
  it('marks only deadline, cancellation and upstream refusals retryable', () => {
    const codes: readonly TaskDetailsRefusalCode[] = [
      'INVALID_REQUEST',
      'UNSUPPORTED_REPRESENTATION',
      'MALFORMED_REPRESENTATION',
      'RESPONSE_LIMIT_EXCEEDED',
      'NOT_AVAILABLE',
      'VERSION_CONFLICT',
      'IDEMPOTENCY_CONFLICT',
      'TARGET_UNAVAILABLE',
      'DEADLINE_EXCEEDED',
      'REQUEST_CANCELLED',
      'UPSTREAM_UNAVAILABLE',
      'INTERNAL_ERROR',
    ];
    const retryable = codes.filter((code) => createTaskDetailsRefusal(code).refusal.retryable);
    expect(retryable).toEqual(['DEADLINE_EXCEEDED', 'REQUEST_CANCELLED', 'UPSTREAM_UNAVAILABLE']);
    for (const code of codes) {
      expect(createTaskDetailsRefusal(code)).toMatchObject({ ok: false, refusal: { code } });
    }
  });
});

describe('synthetic: typed assignment targets', () => {
  it('keeps human and agent kinds and withdrawn status distinct', () => {
    const decoded = decodeTaskDetailsV2(syntheticDetails());
    expect(decoded.assignmentTargets.targets).toEqual([
      { kind: 'human', id: 'human-synthetic-a', status: 'active' },
      { kind: 'agent', id: 'agent-synthetic-a', status: 'active' },
      { kind: 'agent', id: 'agent-synthetic-b', status: 'withdrawn' },
    ]);
  });
});

describe('synthetic: input schemas reject caller identity and generic controls', () => {
  const read = { representation: 'task-details.v2', taskId: 'task-synthetic-001' };
  const note = {
    representation: 'task-details.v2',
    taskId: 'task-synthetic-001',
    expectedVersion: 'ver-synthetic-0001',
    idempotencyKey: syntheticIdempotencyKey('001'),
    text: 'Synthetic note.',
  };
  const assign = {
    representation: 'task-details.v2',
    taskId: 'task-synthetic-001',
    expectedVersion: 'ver-synthetic-0001',
    idempotencyKey: syntheticIdempotencyKey('002'),
    target: { kind: 'agent', id: 'agent-synthetic-a' },
  };

  it('accepts only finite parameters', () => {
    expect(ReadTaskDetailsV2InputSchema.parse(read)).toEqual({ ...read, activityLimit: 20 });
    expect(AppendTaskNoteV2InputSchema.safeParse(note).success).toBe(true);
    expect(
      AppendTaskNoteV2InputSchema.safeParse({ ...note, citation: { sourceRef: 'synthetic://a' } })
        .success,
    ).toBe(true);
    expect(AssignTaskV2InputSchema.safeParse(assign).success).toBe(true);
  });

  it('bounds activityLimit to 1..50 integers', () => {
    for (const activityLimit of [0, -1, 51, 1.5, Number.NaN, '5']) {
      expect(ReadTaskDetailsV2InputSchema.safeParse({ ...read, activityLimit }).success).toBe(
        false,
      );
    }
    for (const activityLimit of [1, MAX_ACTIVITY_ENTRIES]) {
      expect(ReadTaskDetailsV2InputSchema.parse({ ...read, activityLimit }).activityLimit).toBe(
        activityLimit,
      );
    }
  });

  it('requires explicit v2 negotiation', () => {
    expect(ReadTaskDetailsV2InputSchema.safeParse({ taskId: 'task-synthetic-001' }).success).toBe(
      false,
    );
    expect(ReadTaskDetailsV2InputSchema.safeParse({ ...read, representation: 'v1' }).success).toBe(
      false,
    );
  });

  it('rejects caller-supplied identity, authority and database controls', () => {
    const forbidden = [
      'actingAgent',
      'actorId',
      'authorId',
      'clientId',
      'sessionId',
      'userId',
      'role',
      'workstreamId',
      'sql',
      'schema',
      'relation',
      'url',
      'credential',
      'approved',
      'payload',
    ];
    for (const key of forbidden) {
      expect(ReadTaskDetailsV2InputSchema.safeParse({ ...read, [key]: 'x' }).success).toBe(false);
      expect(AppendTaskNoteV2InputSchema.safeParse({ ...note, [key]: 'x' }).success).toBe(false);
      expect(AssignTaskV2InputSchema.safeParse({ ...assign, [key]: 'x' }).success).toBe(false);
    }
    expect(
      AssignTaskV2InputSchema.safeParse({
        ...assign,
        target: { ...assign.target, status: 'active' },
      }).success,
    ).toBe(false);
  });

  it('refuses empty, oversized or padded note text instead of clipping writes', () => {
    expect(
      AppendTaskNoteV2InputSchema.safeParse({
        ...note,
        text: '\u20ac'.repeat(Math.floor(MAX_ACTIVITY_TEXT_BYTES / 3) + 1),
      }).success,
    ).toBe(false);
    expect(AppendTaskNoteV2InputSchema.safeParse({ ...note, text: ' padded ' }).success).toBe(
      false,
    );
    expect(AppendTaskNoteV2InputSchema.safeParse({ ...note, text: '' }).success).toBe(false);
    expect(
      AppendTaskNoteV2InputSchema.safeParse({ ...note, text: 'n'.repeat(MAX_ACTIVITY_TEXT_BYTES) })
        .success,
    ).toBe(true);
  });

  it('rejects NUL, control characters and lone surrogates in written notes', () => {
    for (const bad of ['a\u0000b', 'a\u0007b', 'a\u007fb', 'a\ud800b', 'a\udc00b']) {
      expect(AppendTaskNoteV2InputSchema.safeParse({ ...note, text: bad }).success).toBe(false);
      expect(
        AppendTaskNoteV2InputSchema.safeParse({ ...note, citation: { sourceRef: bad } }).success,
      ).toBe(false);
    }
    expect(
      AppendTaskNoteV2InputSchema.safeParse({ ...note, text: 'line one\n\tline two\r\nend' })
        .success,
    ).toBe(true);
  });
});
