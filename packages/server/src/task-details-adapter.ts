import { MAX_TOOL_EXECUTION_MS } from '@supabase-user-mcp/contracts';

// Relative import of the built contract on purpose: the v2 contract is not exported from the
// contracts index, so this path needs `npm run build` of the contracts package first. Replacing it
// with an index export is remaining integration work. The same relative path resolves from both
// src/ and dist/. This adapter is not registered with any MCP server.
import {
  type AppendTaskNoteV2Input,
  AppendTaskNoteV2InputSchema,
  type AssignTaskV2Input,
  AssignTaskV2InputSchema,
  createTaskDetailsRefusal,
  decodeTaskDetailsV2,
  decodeTaskMutationReceiptV2,
  type ReadTaskDetailsV2Input,
  ReadTaskDetailsV2InputSchema,
  TASK_DETAILS_V2_REPRESENTATION,
  TaskDetailsDecodeError,
  type TaskDetailsRefusal,
  type TaskDetailsRefusalCode,
  type TaskDetailsV2,
  type TaskMutationReceiptV2,
} from '../../contracts/dist/task-details-v2.js';

/** Finite port parameters. There is no acting identity, credential, SQL, or relation. */
export type TaskReadParams = Omit<ReadTaskDetailsV2Input, 'representation'>;
export type TaskNoteParams = Omit<AppendTaskNoteV2Input, 'representation'>;
export type TaskAssignParams = Omit<AssignTaskV2Input, 'representation'>;

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
  readonly readTaskDetails: (
    params: TaskReadParams,
    signal: AbortSignal,
  ) => Promise<TaskPortResult>;
  readonly appendNote: (params: TaskNoteParams, signal: AbortSignal) => Promise<TaskPortResult>;
  readonly assignTask: (params: TaskAssignParams, signal: AbortSignal) => Promise<TaskPortResult>;
}

export type TaskDetailsReadOutput =
  | { readonly ok: true; readonly details: TaskDetailsV2 }
  | TaskDetailsRefusal;

export type TaskMutationOutput =
  | { readonly ok: true; readonly receipt: TaskMutationReceiptV2 }
  | TaskDetailsRefusal;

export interface TaskDetailsAdapterOptions {
  readonly port: TaskDetailsPort;
  readonly timeoutMs?: number;
}

export interface TaskDetailsAdapter {
  readonly readTaskDetails: (
    unsafeInput: unknown,
    signal?: AbortSignal,
  ) => Promise<TaskDetailsReadOutput>;
  readonly appendNote: (unsafeInput: unknown, signal?: AbortSignal) => Promise<TaskMutationOutput>;
  readonly assignTask: (unsafeInput: unknown, signal?: AbortSignal) => Promise<TaskMutationOutput>;
}

class AdapterRefusal extends Error {
  constructor(readonly code: TaskDetailsRefusalCode) {
    super(code);
  }
}

const DENIAL_CODES: Readonly<Record<TaskPortDenial, TaskDetailsRefusalCode>> = Object.freeze({
  // Authorization denials are deliberately indistinguishable from a missing task.
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

function negotiate<T>(
  schema: { safeParse: (value: unknown) => { success: true; data: T } | { success: false } },
  unsafeInput: unknown,
): T {
  if (
    typeof unsafeInput !== 'object' ||
    unsafeInput === null ||
    (unsafeInput as Record<string, unknown>).representation !== TASK_DETAILS_V2_REPRESENTATION
  ) {
    throw new AdapterRefusal('UNSUPPORTED_REPRESENTATION');
  }
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

function withoutRepresentation<T extends { representation: string }>(
  input: T,
): Omit<T, 'representation'> {
  const { representation: _representation, ...params } = input;
  return params;
}

/**
 * Creates an unregistered task-details.v2 adapter over an injected, database-owned port.
 * Every input is negotiated explicitly; every port result is decoded strictly.
 */
export function createTaskDetailsAdapter(options: TaskDetailsAdapterOptions): TaskDetailsAdapter {
  const timeoutMs = options.timeoutMs ?? MAX_TOOL_EXECUTION_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TOOL_EXECUTION_MS) {
    throw new RangeError('Invalid task-details adapter timeout.');
  }

  const run = async <T>(
    callerSignal: AbortSignal | undefined,
    body: (signal: AbortSignal) => Promise<T>,
  ): Promise<T | TaskDetailsRefusal> => {
    // An already-cancelled caller never reaches the port.
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
    let result: TaskPortResult;
    try {
      result = await invoke();
    } catch {
      throw new AdapterRefusal('UPSTREAM_UNAVAILABLE');
    }
    return unwrapPortResult(result);
  };

  const mutation = async (
    taskId: string,
    invoke: () => Promise<TaskPortResult>,
  ): Promise<TaskMutationOutput> => {
    const receipt = decodeOrRefuse(decodeTaskMutationReceiptV2, await callPort(invoke));
    if (receipt.taskId !== taskId) throw new AdapterRefusal('MALFORMED_REPRESENTATION');
    return Object.freeze({ ok: true as const, receipt });
  };

  return Object.freeze({
    readTaskDetails: (unsafeInput: unknown, signal?: AbortSignal) =>
      run(signal, async (portSignal): Promise<TaskDetailsReadOutput> => {
        const input = negotiate(ReadTaskDetailsV2InputSchema, unsafeInput);
        const params = withoutRepresentation(input);
        const raw = await callPort(() => options.port.readTaskDetails(params, portSignal));
        const details = decodeOrRefuse(decodeTaskDetailsV2, raw);
        if (
          details.task.taskId !== input.taskId ||
          details.activity.entries.length > input.activityLimit
        ) {
          throw new AdapterRefusal('MALFORMED_REPRESENTATION');
        }
        return Object.freeze({ ok: true as const, details });
      }),
    appendNote: (unsafeInput: unknown, signal?: AbortSignal) =>
      run(signal, async (portSignal) => {
        const input = negotiate(AppendTaskNoteV2InputSchema, unsafeInput);
        const params = withoutRepresentation(input);
        return mutation(input.taskId, () => options.port.appendNote(params, portSignal));
      }),
    assignTask: (unsafeInput: unknown, signal?: AbortSignal) =>
      run(signal, async (portSignal) => {
        const input = negotiate(AssignTaskV2InputSchema, unsafeInput);
        const params = withoutRepresentation(input);
        return mutation(input.taskId, () => options.port.assignTask(params, portSignal));
      }),
  });
}
