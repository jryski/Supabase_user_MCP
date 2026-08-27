import { createHash } from 'node:crypto';

import type * as z from 'zod/v4';

import {
  createReadToolError,
  type ReadToolErrorCode,
  readToolWireResponseByteLength,
} from '@supabase-user-mcp/contracts';

interface ReadToolLimiterState {
  active: number;
  requestTimestamps: number[];
  lastTouchedAt: number;
}

interface ReadToolDescriptor<TInput extends z.ZodTypeAny, TOutput extends z.ZodTypeAny> {
  readonly operation: string;
  readonly inputSchema: TInput;
  readonly outputSchema: TOutput;
  readonly limits: {
    readonly maxRows: number;
    readonly maxResponseBytes: number;
    readonly maxExecutionMs: number;
  };
  readonly errorMapping: {
    readonly validation: ReadToolErrorCode;
    readonly unavailable: ReadToolErrorCode;
    readonly responseLimit: ReadToolErrorCode;
    readonly timeout: ReadToolErrorCode;
    readonly unexpected: ReadToolErrorCode;
  };
}

export interface ReadToolGovernancePolicy {
  readonly maxConcurrentExecutions?: number;
  readonly maxRequestsPerWindow?: number;
  readonly requestWindowMs?: number;
}

export interface ReadToolOperationalEvent {
  readonly requestId: string | number | null;
  readonly operation: string;
  readonly scope: string;
  readonly normalizedArgumentDigest: string;
  readonly timestamp: string;
  readonly durationMs: number;
  readonly rowCount: number;
  readonly outcome: 'success' | 'blocked';
  readonly denialClass?: ReadToolErrorCode;
  readonly principalId?: string;
  readonly clientId?: string;
}

export interface ReadToolExecutionContext {
  readonly requestId?: string | number | null;
  readonly principalId?: string;
  readonly clientId?: string;
  readonly signal?: AbortSignal;
  readonly now?: () => number;
  readonly emitOperationalEvent?: (event: ReadToolOperationalEvent) => void;
}

const DEFAULT_RATE_LIMIT = {
  maxConcurrentExecutions: 4,
  maxRequestsPerWindow: 30,
  requestWindowMs: 60_000,
} as const;
const MAX_TRACKED_SCOPES = 1_024;

// Process-global by design: rebuilding a tool executor must not reset a warm process's budget.
const limiterStates = new Map<string, ReadToolLimiterState>();

function deriveLimiterScope(
  descriptor: ReadToolDescriptor<z.ZodTypeAny, z.ZodTypeAny>,
  context: ReadToolExecutionContext,
): string {
  if (context.principalId !== undefined) return `principal:${context.principalId}`;
  if (context.clientId !== undefined) return `client:${context.clientId}`;
  return `operation:${descriptor.operation}`;
}

function createDefaultState(now: number): ReadToolLimiterState {
  return {
    active: 0,
    requestTimestamps: [],
    lastTouchedAt: now,
  };
}

function getLimiterState(scope: string, now: number): ReadToolLimiterState | undefined {
  const existing = limiterStates.get(scope);
  if (existing !== undefined) {
    existing.lastTouchedAt = now;
    return existing;
  }
  if (limiterStates.size >= MAX_TRACKED_SCOPES) {
    const evictable = [...limiterStates.entries()]
      .filter(([, state]) => state.active === 0)
      .toSorted((left, right) => left[1].lastTouchedAt - right[1].lastTouchedAt)[0];
    if (evictable === undefined) return undefined;
    limiterStates.delete(evictable[0]);
  }
  const state = createDefaultState(now);
  limiterStates.set(scope, state);
  return state;
}

function normalizeValueForDigest(value: unknown, seen = new WeakSet<object>()): unknown {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : String(value);
  if (typeof value === 'bigint' || typeof value === 'symbol' || typeof value === 'function') {
    return `[${typeof value}]`;
  }
  if (value === undefined) return '[undefined]';
  if (typeof value !== 'object') return '[unknown]';
  if (seen.has(value)) return '[circular]';
  seen.add(value);
  if (Array.isArray(value)) {
    return value.map((entry) => normalizeValueForDigest(entry, seen));
  }
  const normalized: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort()) {
    try {
      normalized[key] = normalizeValueForDigest((value as Record<string, unknown>)[key], seen);
    } catch {
      normalized[key] = '[unreadable]';
    }
  }
  return normalized;
}

function hashedArgumentDigest(value: unknown): string {
  const stableValue = JSON.stringify(normalizeValueForDigest(value));
  return createHash('sha256').update(stableValue).digest('hex').slice(0, 24);
}

function stableNow(now: () => number): number {
  return Math.max(0, Math.floor(now()));
}

function countRows(output: unknown): number {
  if (typeof output !== 'object' || output === null || 'ok' in output === false) {
    return 0;
  }

  const value = output as Record<string, unknown>;
  if (value.ok === true && Array.isArray(value.items)) {
    return value.items.length;
  }

  if (value.ok === true && value.record !== undefined) {
    return value.record === null ? 0 : 1;
  }

  return 0;
}

function causeToFailureCode(error: unknown): ReadToolErrorCode | undefined {
  if (!(typeof error === 'object' && error !== null && 'code' in error)) {
    return undefined;
  }

  const code = (error as { code: unknown }).code;
  if (code === 'FIXED_CLIENT_TIMEOUT' || code === 'DEADLINE_EXCEEDED') {
    return 'DEADLINE_EXCEEDED';
  }
  if (code === 'FIXED_CLIENT_RESPONSE_TOO_LARGE') {
    return 'RESPONSE_LIMIT_EXCEEDED';
  }
  if (code === 'FIXED_CLIENT_INVALID_CREDENTIAL' || code === 'FIXED_CLIENT_INVALID_REQUEST') {
    return 'INVALID_REQUEST';
  }

  return undefined;
}

function enforceWindow(
  state: ReadToolLimiterState,
  now: number,
  policy: Required<ReadToolGovernancePolicy>,
): boolean {
  state.lastTouchedAt = now;
  const windowStart = now - policy.requestWindowMs;
  state.requestTimestamps = state.requestTimestamps.filter((timestamp) => timestamp > windowStart);
  if (state.requestTimestamps.length >= policy.maxRequestsPerWindow) {
    return false;
  }

  state.requestTimestamps.push(now);
  return true;
}

function releaseConcurrency(state: ReadToolLimiterState): void {
  if (state.active > 0) {
    state.active -= 1;
  }
}

export function createReadToolExecutor<TInput extends z.ZodTypeAny, TOutput extends z.ZodTypeAny>(
  descriptor: ReadToolDescriptor<TInput, TOutput>,
  execute: (input: z.infer<TInput>, signal: AbortSignal) => Promise<unknown>,
  policy: ReadToolGovernancePolicy = {},
) {
  const fullPolicy: Required<ReadToolGovernancePolicy> = { ...DEFAULT_RATE_LIMIT, ...policy };
  if (
    !Number.isSafeInteger(fullPolicy.maxConcurrentExecutions) ||
    fullPolicy.maxConcurrentExecutions <= 0 ||
    !Number.isSafeInteger(fullPolicy.maxRequestsPerWindow) ||
    fullPolicy.maxRequestsPerWindow <= 0 ||
    !Number.isSafeInteger(fullPolicy.requestWindowMs) ||
    fullPolicy.requestWindowMs <= 0
  ) {
    throw new TypeError('Invalid read-tool governance policy.');
  }
  const emitNoop = () => undefined;

  return async (
    unsafeInput: unknown,
    context: ReadToolExecutionContext = {},
  ): Promise<z.infer<TOutput>> => {
    const scope = deriveLimiterScope(descriptor, context);
    const requestId = context.requestId ?? null;
    const now = context.now ?? (() => Date.now());
    const emitOperationalEvent = context.emitOperationalEvent ?? emitNoop;
    const eventTimestamp = new Date(stableNow(now)).toISOString();
    const startedAt = stableNow(now);
    let state: ReadToolLimiterState | undefined;
    let releaseConcurrencySlot = false;
    let rowCount = 0;
    let outcome: 'success' | 'blocked' = 'blocked';
    let denialClass: ReadToolErrorCode | undefined;
    const input = descriptor.inputSchema.safeParse(unsafeInput);
    const normalizedArgumentDigest = hashedArgumentDigest(input.success ? input.data : unsafeInput);
    const emit = () => {
      const event: Omit<ReadToolOperationalEvent, 'denialClass' | 'principalId' | 'clientId'> = {
        requestId,
        operation: descriptor.operation,
        scope,
        normalizedArgumentDigest,
        timestamp: eventTimestamp,
        durationMs: Math.max(0, stableNow(now) - startedAt),
        rowCount,
        outcome,
      };

      const eventWithOptionalContext: ReadToolOperationalEvent =
        context.principalId === undefined && context.clientId === undefined
          ? event
          : {
              ...event,
              ...(context.principalId === undefined ? {} : { principalId: context.principalId }),
              ...(context.clientId === undefined ? {} : { clientId: context.clientId }),
            };

      try {
        emitOperationalEvent(
          denialClass === undefined
            ? eventWithOptionalContext
            : Object.freeze({ ...eventWithOptionalContext, denialClass }),
        );
      } catch {
        // Operational event emission must never affect tool execution.
      }
    };

    if (!input.success) {
      denialClass = descriptor.errorMapping.validation;
      emit();
      return Promise.resolve(
        createReadToolError(descriptor.errorMapping.validation) as z.infer<TOutput>,
      );
    }

    state = getLimiterState(scope, stableNow(now));
    if (state === undefined || !enforceWindow(state, stableNow(now), fullPolicy)) {
      denialClass = descriptor.errorMapping.unavailable;
      emit();
      return Promise.resolve(
        createReadToolError(descriptor.errorMapping.unavailable) as z.infer<TOutput>,
      );
    }

    if (state.active >= fullPolicy.maxConcurrentExecutions) {
      denialClass = descriptor.errorMapping.unavailable;
      emit();
      return Promise.resolve(
        createReadToolError(descriptor.errorMapping.unavailable) as z.infer<TOutput>,
      );
    }

    state.active += 1;
    releaseConcurrencySlot = true;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), descriptor.limits.maxExecutionMs);
    const onCallerAbort = () => {
      controller.abort();
    };
    context.signal?.addEventListener('abort', onCallerAbort, { once: true });
    if (context.signal?.aborted) {
      controller.abort();
    }

    try {
      const result = await execute(input.data, controller.signal);
      const parsedResult = descriptor.outputSchema.safeParse(result);
      if (!parsedResult.success) {
        denialClass = descriptor.errorMapping.unexpected;
        return createReadToolError(denialClass) as z.infer<TOutput>;
      }

      if (
        typeof parsedResult.data === 'object' &&
        parsedResult.data !== null &&
        'ok' in parsedResult.data &&
        parsedResult.data.ok === false &&
        'error' in parsedResult.data &&
        typeof parsedResult.data.error === 'object' &&
        parsedResult.data.error !== null &&
        'code' in parsedResult.data.error
      ) {
        denialClass = parsedResult.data.error.code as ReadToolErrorCode;
        return parsedResult.data;
      }

      rowCount = countRows(parsedResult.data);
      if (rowCount > descriptor.limits.maxRows) {
        denialClass = descriptor.errorMapping.responseLimit;
        return createReadToolError(denialClass) as z.infer<TOutput>;
      }

      const estimatedBytes = readToolWireResponseByteLength(requestId, parsedResult.data);
      if (estimatedBytes > descriptor.limits.maxResponseBytes) {
        denialClass = descriptor.errorMapping.responseLimit;
        return createReadToolError(denialClass) as z.infer<TOutput>;
      }

      outcome = 'success';
      return parsedResult.data;
    } catch (error) {
      const mapped = causeToFailureCode(error);
      if (controller.signal.aborted) {
        denialClass = descriptor.errorMapping.timeout;
      } else if (mapped === 'INVALID_REQUEST') {
        denialClass = descriptor.errorMapping.validation;
      } else if (mapped === 'RESPONSE_LIMIT_EXCEEDED') {
        denialClass = descriptor.errorMapping.responseLimit;
      } else {
        denialClass = descriptor.errorMapping.unexpected;
      }
      return createReadToolError(denialClass) as z.infer<TOutput>;
    } finally {
      clearTimeout(timeout);
      context.signal?.removeEventListener('abort', onCallerAbort);
      if (releaseConcurrencySlot) {
        releaseConcurrency(state);
      }
      emit();
    }
  };
}

export type ReadToolInvocationContext = ReadToolExecutionContext | AbortSignal;

export function normalizeReadToolExecutionContext(
  context: ReadToolInvocationContext | undefined,
): ReadToolExecutionContext {
  return context instanceof AbortSignal ? { signal: context } : (context ?? {});
}
