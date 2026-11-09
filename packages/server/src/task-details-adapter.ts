import { MAX_TOOL_EXECUTION_MS } from '@supabase-user-mcp/contracts';

// Relative import of the built contract on purpose: the v2 contract is not exported from the
// contracts index, so this path needs `npm run build` of the contracts package first. Replacing it
// with an index export is remaining integration work. The same relative path resolves from both
// src/ and dist/. This adapter is not registered with any MCP server.
import {
  type AppendTaskNoteV2Input,
  AppendTaskNoteV2InputSchema,
  type AssignmentTargetListV2,
  type AssignTaskV2Input,
  AssignTaskV2InputSchema,
  adapterTimeoutIsLegal,
  type CoordinationTargetListV2,
  createTaskDetailsRefusal,
  decodeAssignmentTargetListV2,
  decodeCoordinationTargetListV2,
  decodeEventListV2,
  decodeTaskDetailV2,
  decodeTaskListV2,
  decodeTaskMutationReceiptV2,
  type EventListV2,
  type ReadAssignmentTargetsV2Input,
  ReadAssignmentTargetsV2InputSchema,
  type ReadCoordinationTargetsV2Input,
  ReadCoordinationTargetsV2InputSchema,
  type ReadEventsV2Input,
  ReadEventsV2InputSchema,
  type ReadTaskDetailV2Input,
  ReadTaskDetailV2InputSchema,
  type ReadTaskListV2Input,
  ReadTaskListV2InputSchema,
  requestWithinPacketLimit,
  TaskDetailsDecodeError,
  type TaskDetailsRefusal,
  type TaskDetailsRefusalCode,
  type TaskDetailV2,
  type TaskListV2,
  type TaskMutationReceiptV2,
  taskDetailsRequestByteLength,
} from '../../contracts/dist/task-details-v2.js';

/** Finite port parameters. There is no acting identity, credential, SQL, or relation. */
export type TaskDetailParams = Omit<ReadTaskDetailV2Input, 'readVersion'>;
export type TaskListParams = Omit<ReadTaskListV2Input, 'readVersion'>;
export type AssignmentTargetParams = Omit<ReadAssignmentTargetsV2Input, 'readVersion'>;
export type CoordinationTargetParams = Omit<ReadCoordinationTargetsV2Input, 'readVersion'>;
export type EventListParams = Omit<ReadEventsV2Input, 'readVersion'>;
export type TaskNoteParams = Omit<AppendTaskNoteV2Input, 'readVersion'>;
export type TaskAssignParams = Omit<AssignTaskV2Input, 'readVersion'>;

/** Denials a database-owned port may report. Identity and authorization live behind the port. */
export type TaskPortDenial =
  | 'not_found'
  | 'wrong_workstream'
  | 'wrong_client'
  | 'wrong_session'
  | 'version_conflict'
  | 'idempotency_conflict'
  | 'target_unknown'
  | 'target_withdrawn'
  | 'unavailable';

export type TaskPortResult =
  | { readonly ok: true; readonly value: unknown }
  | { readonly ok: false; readonly denial: TaskPortDenial };

export interface TaskDetailsPort {
  readonly readTask: (params: TaskDetailParams, signal: AbortSignal) => Promise<TaskPortResult>;
  readonly readTasks: (params: TaskListParams, signal: AbortSignal) => Promise<TaskPortResult>;
  readonly readAssignmentTargets: (
    params: AssignmentTargetParams,
    signal: AbortSignal,
  ) => Promise<TaskPortResult>;
  readonly readCoordinationTargets: (
    params: CoordinationTargetParams,
    signal: AbortSignal,
  ) => Promise<TaskPortResult>;
  readonly readEvents: (params: EventListParams, signal: AbortSignal) => Promise<TaskPortResult>;
  readonly appendNote: (params: TaskNoteParams, signal: AbortSignal) => Promise<TaskPortResult>;
  readonly assignTask: (params: TaskAssignParams, signal: AbortSignal) => Promise<TaskPortResult>;
}

export type TaskReadOutput<T> = { readonly ok: true; readonly value: T } | TaskDetailsRefusal;

export type TaskMutationOutput =
  | { readonly ok: true; readonly receipt: TaskMutationReceiptV2 }
  | TaskDetailsRefusal;

export interface TaskDetailsAdapterOptions {
  readonly port: TaskDetailsPort;
  readonly timeoutMs?: number;
}

export interface TaskDetailsAdapter {
  readonly readTask: (
    unsafeInput: unknown,
    signal?: AbortSignal,
  ) => Promise<TaskReadOutput<TaskDetailV2>>;
  readonly readTasks: (
    unsafeInput: unknown,
    signal?: AbortSignal,
  ) => Promise<TaskReadOutput<TaskListV2>>;
  readonly readAssignmentTargets: (
    unsafeInput: unknown,
    signal?: AbortSignal,
  ) => Promise<TaskReadOutput<AssignmentTargetListV2>>;
  readonly readCoordinationTargets: (
    unsafeInput: unknown,
    signal?: AbortSignal,
  ) => Promise<TaskReadOutput<CoordinationTargetListV2>>;
  readonly readEvents: (
    unsafeInput: unknown,
    signal?: AbortSignal,
  ) => Promise<TaskReadOutput<EventListV2>>;
  readonly appendNote: (unsafeInput: unknown, signal?: AbortSignal) => Promise<TaskMutationOutput>;
  readonly assignTask: (unsafeInput: unknown, signal?: AbortSignal) => Promise<TaskMutationOutput>;
}

class AdapterRefusal extends Error {
  constructor(readonly code: TaskDetailsRefusalCode) {
    super(code);
  }
}

const DENIAL_CODES: Readonly<Record<TaskPortDenial, TaskDetailsRefusalCode>> = Object.freeze({
  not_found: 'NOT_AVAILABLE',
  wrong_workstream: 'NOT_AVAILABLE',
  wrong_client: 'NOT_AVAILABLE',
  wrong_session: 'NOT_AVAILABLE',
  version_conflict: 'VERSION_CONFLICT',
  idempotency_conflict: 'IDEMPOTENCY_CONFLICT',
  target_unknown: 'TARGET_UNAVAILABLE',
  target_withdrawn: 'TARGET_UNAVAILABLE',
  unavailable: 'UPSTREAM_UNAVAILABLE',
});

function negotiate<T extends { readVersion: number }>(
  schema: { safeParse: (value: unknown) => { success: true; data: T } | { success: false } },
  unsafeInput: unknown,
): T {
  if (typeof unsafeInput !== 'object' || unsafeInput === null || Array.isArray(unsafeInput)) {
    throw new AdapterRefusal('MALFORMED_REPRESENTATION');
  }
  if ((unsafeInput as Record<string, unknown>).readVersion !== 2) {
    throw new AdapterRefusal('UNSUPPORTED_REPRESENTATION');
  }
  let bytes: number;
  try {
    bytes = taskDetailsRequestByteLength(unsafeInput);
  } catch {
    throw new AdapterRefusal('INVALID_REQUEST');
  }
  if (!requestWithinPacketLimit(bytes)) throw new AdapterRefusal('INVALID_REQUEST');
  const parsed = schema.safeParse(unsafeInput);
  if (!parsed.success) throw new AdapterRefusal('INVALID_REQUEST');
  return parsed.data;
}

function unwrapPortResult(result: unknown): unknown {
  if (typeof result !== 'object' || result === null) {
    throw new AdapterRefusal('MALFORMED_REPRESENTATION');
  }
  const record = result as Record<string, unknown>;
  if (record.ok === true && 'value' in record) return record.value;
  if (record.ok === false) {
    const denial = record.denial;
    if (typeof denial === 'string' && Object.hasOwn(DENIAL_CODES, denial)) {
      throw new AdapterRefusal(DENIAL_CODES[denial as TaskPortDenial]);
    }
    throw new AdapterRefusal('INTERNAL_ERROR');
  }
  throw new AdapterRefusal('MALFORMED_REPRESENTATION');
}

function decodeOrRefuse<T>(decode: (raw: unknown) => T, raw: unknown): T {
  try {
    return decode(raw);
  } catch (error) {
    if (error instanceof TaskDetailsDecodeError) throw new AdapterRefusal(error.code);
    throw new AdapterRefusal('INTERNAL_ERROR');
  }
}

function withoutReadVersion<T extends { readVersion: number }>(input: T): Omit<T, 'readVersion'> {
  const { readVersion: _readVersion, ...params } = input;
  return params;
}

/**
 * Unregistered task-details v2 adapter over an injected, database-owned port.
 * Detail reads require an exact expected version. A version conflict returns a refusal and no data.
 */
export function createTaskDetailsAdapter(options: TaskDetailsAdapterOptions): TaskDetailsAdapter {
  const timeoutMs = options.timeoutMs ?? MAX_TOOL_EXECUTION_MS;
  if (!adapterTimeoutIsLegal(timeoutMs, MAX_TOOL_EXECUTION_MS)) {
    throw new RangeError('Invalid task-details adapter timeout.');
  }

  const run = async <T>(
    callerSignal: AbortSignal | undefined,
    body: (signal: AbortSignal) => Promise<T>,
  ): Promise<T | TaskDetailsRefusal> => {
    if (callerSignal?.aborted) return createTaskDetailsRefusal('REQUEST_CANCELLED');
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let onCallerAbort: (() => void) | undefined;
    const stop = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new AdapterRefusal('DEADLINE_EXCEEDED'));
      }, timeoutMs);
      onCallerAbort = () => {
        controller.abort();
        reject(new AdapterRefusal('REQUEST_CANCELLED'));
      };
      callerSignal?.addEventListener('abort', onCallerAbort, { once: true });
    });
    try {
      return await Promise.race([body(controller.signal), stop]);
    } catch (error) {
      if (error instanceof AdapterRefusal) return createTaskDetailsRefusal(error.code);
      return createTaskDetailsRefusal('UPSTREAM_UNAVAILABLE');
    } finally {
      clearTimeout(timer);
      if (onCallerAbort !== undefined) callerSignal?.removeEventListener('abort', onCallerAbort);
    }
  };

  const callPort = async (invoke: () => Promise<TaskPortResult>): Promise<unknown> => {
    try {
      return unwrapPortResult(await invoke());
    } catch (error) {
      if (error instanceof AdapterRefusal) throw error;
      throw new AdapterRefusal('UPSTREAM_UNAVAILABLE');
    }
  };

  const readValue = async <T>(
    decode: (raw: unknown) => T,
    invoke: () => Promise<TaskPortResult>,
  ): Promise<TaskReadOutput<T>> => {
    const value = decodeOrRefuse(decode, await callPort(invoke));
    return Object.freeze({ ok: true as const, value });
  };

  return Object.freeze({
    readTask: (unsafeInput: unknown, signal?: AbortSignal) =>
      run(signal, async (portSignal) => {
        const input = negotiate(ReadTaskDetailV2InputSchema, unsafeInput);
        const value = decodeOrRefuse(
          decodeTaskDetailV2,
          await callPort(() => options.port.readTask(withoutReadVersion(input), portSignal)),
        );
        if (value.task.taskId !== input.taskId || value.task.version !== input.expectedVersion) {
          throw new AdapterRefusal('MALFORMED_REPRESENTATION');
        }
        return Object.freeze({ ok: true as const, value });
      }),
    readTasks: (unsafeInput: unknown, signal?: AbortSignal) =>
      run(signal, async (portSignal) => {
        const input = negotiate(ReadTaskListV2InputSchema, unsafeInput);
        const page = await readValue(decodeTaskListV2, () =>
          options.port.readTasks(withoutReadVersion(input), portSignal),
        );
        if (
          page.ok &&
          (page.value.limit !== input.limit || page.value.afterTaskId !== input.afterTaskId)
        ) {
          throw new AdapterRefusal('MALFORMED_REPRESENTATION');
        }
        return page;
      }),
    readAssignmentTargets: (unsafeInput: unknown, signal?: AbortSignal) =>
      run(signal, async (portSignal) => {
        const input = negotiate(ReadAssignmentTargetsV2InputSchema, unsafeInput);
        const page = await readValue(decodeAssignmentTargetListV2, () =>
          options.port.readAssignmentTargets(withoutReadVersion(input), portSignal),
        );
        if (
          page.ok &&
          (page.value.limit !== input.limit ||
            page.value.afterPrincipalId !== input.afterPrincipalId)
        ) {
          throw new AdapterRefusal('MALFORMED_REPRESENTATION');
        }
        return page;
      }),
    readCoordinationTargets: (unsafeInput: unknown, signal?: AbortSignal) =>
      run(signal, async (portSignal) => {
        const input = negotiate(ReadCoordinationTargetsV2InputSchema, unsafeInput);
        const page = await readValue(decodeCoordinationTargetListV2, () =>
          options.port.readCoordinationTargets(withoutReadVersion(input), portSignal),
        );
        if (
          page.ok &&
          (page.value.limit !== input.limit || !sameCursor(page.value.after, input.after))
        ) {
          throw new AdapterRefusal('MALFORMED_REPRESENTATION');
        }
        return page;
      }),
    readEvents: (unsafeInput: unknown, signal?: AbortSignal) =>
      run(signal, async (portSignal) => {
        const input = negotiate(ReadEventsV2InputSchema, unsafeInput);
        const page = await readValue(decodeEventListV2, () =>
          options.port.readEvents(withoutReadVersion(input), portSignal),
        );
        if (
          page.ok &&
          (page.value.taskId !== input.taskId ||
            page.value.limit !== input.limit ||
            !sameEventCursor(page.value.after, input.after))
        ) {
          throw new AdapterRefusal('MALFORMED_REPRESENTATION');
        }
        return page;
      }),
    appendNote: (unsafeInput: unknown, signal?: AbortSignal) =>
      run(signal, async (portSignal) => {
        const input = negotiate(AppendTaskNoteV2InputSchema, unsafeInput);
        const receipt = decodeOrRefuse(
          decodeTaskMutationReceiptV2,
          await callPort(() => options.port.appendNote(withoutReadVersion(input), portSignal)),
        );
        if (
          receipt.taskId !== input.taskId ||
          receipt.command !== 'note' ||
          receipt.taskVersion !== input.expectedVersion
        ) {
          throw new AdapterRefusal('MALFORMED_REPRESENTATION');
        }
        return Object.freeze({ ok: true as const, receipt });
      }),
    assignTask: (unsafeInput: unknown, signal?: AbortSignal) =>
      run(signal, async (portSignal) => {
        const input = negotiate(AssignTaskV2InputSchema, unsafeInput);
        const receipt = decodeOrRefuse(
          decodeTaskMutationReceiptV2,
          await callPort(() => options.port.assignTask(withoutReadVersion(input), portSignal)),
        );
        if (
          receipt.taskId !== input.taskId ||
          receipt.command !== 'assign' ||
          receipt.taskVersion !== input.expectedVersion
        ) {
          throw new AdapterRefusal('MALFORMED_REPRESENTATION');
        }
        return Object.freeze({ ok: true as const, receipt });
      }),
  });
}

function sameCursor(
  left: { readonly principalId: string; readonly clientId: string } | null,
  right: { readonly principalId: string; readonly clientId: string } | null,
): boolean {
  if (left === null || right === null) return left === right;
  return left.principalId === right.principalId && left.clientId === right.clientId;
}

function sameEventCursor(
  left: { readonly occurredAt: string; readonly receiptId: string } | null,
  right: { readonly occurredAt: string; readonly receiptId: string } | null,
): boolean {
  if (left === null || right === null) return left === right;
  return left.occurredAt === right.occurredAt && left.receiptId === right.receiptId;
}
