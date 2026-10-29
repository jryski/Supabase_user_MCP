import {
  createControlPlaneToolError,
  type ControlPlaneToolErrorCode,
} from '@supabase-user-mcp/contracts';
import type * as z from 'zod/v4';

import { ControlPlaneClientError } from './control-plane-client.js';

export interface ControlPlaneToolExecutionContext {
  readonly requestId: string | number;
  readonly signal?: AbortSignal;
  readonly emitOperationalEvent?: (event: ControlPlaneOperationalEvent) => void;
}

export interface ControlPlaneOperationalEvent {
  readonly operation: string;
  readonly requestId: string | number;
  readonly outcome: 'succeeded' | 'blocked' | 'failed';
  readonly errorCode?: ControlPlaneToolErrorCode;
  readonly durationMs: number;
}

interface ControlPlaneToolDescriptor<TInput extends z.ZodType, TOutput extends z.ZodType> {
  readonly operation: string;
  readonly inputSchema: TInput;
  readonly outputSchema: TOutput;
  readonly limits: {
    readonly maxExecutionMs: number;
    readonly maxResponseBytes: number;
  };
}

function mapClientError(error: unknown): ControlPlaneToolErrorCode {
  if (!(error instanceof ControlPlaneClientError)) return 'INTERNAL_ERROR';
  switch (error.code) {
    case 'CONTROL_PLANE_INVALID_CONFIGURATION':
    case 'CONTROL_PLANE_MALFORMED_RESPONSE':
      return 'INTERNAL_ERROR';
    case 'CONTROL_PLANE_INVALID_REQUEST':
      return 'INVALID_REQUEST';
    case 'CONTROL_PLANE_BOARD_UNAVAILABLE':
      return 'BOARD_UNAVAILABLE';
    case 'CONTROL_PLANE_REPLY_UNAVAILABLE':
      return 'REPLY_UNAVAILABLE';
    case 'CONTROL_PLANE_IDEMPOTENCY_CONFLICT':
      return 'IDEMPOTENCY_CONFLICT';
    case 'CONTROL_PLANE_TIMEOUT':
      return 'DEADLINE_EXCEEDED';
    case 'CONTROL_PLANE_RESPONSE_TOO_LARGE':
      return 'RESPONSE_LIMIT_EXCEEDED';
    case 'CONTROL_PLANE_NETWORK_FAILURE':
    case 'CONTROL_PLANE_UPSTREAM_STATUS':
      return 'UPSTREAM_UNAVAILABLE';
  }
}

function byteLength(value: unknown): number {
  try {
    return new TextEncoder().encode(JSON.stringify(value)).byteLength;
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}

export function createControlPlaneToolExecutor<TInput extends z.ZodType, TOutput extends z.ZodType>(
  descriptor: ControlPlaneToolDescriptor<TInput, TOutput>,
  invoke: (input: z.infer<TInput>, signal: AbortSignal) => Promise<z.infer<TOutput>>,
) {
  return async (
    unsafeInput: unknown,
    context: ControlPlaneToolExecutionContext,
  ): Promise<z.infer<TOutput>> => {
    const startedAt = Date.now();
    let outcome: ControlPlaneOperationalEvent['outcome'] = 'failed';
    let errorCode: ControlPlaneToolErrorCode | undefined;
    const emit = () =>
      context.emitOperationalEvent?.({
        operation: descriptor.operation,
        requestId: context.requestId,
        outcome,
        ...(errorCode === undefined ? {} : { errorCode }),
        durationMs: Math.max(0, Date.now() - startedAt),
      });

    const parsedInput = descriptor.inputSchema.safeParse(unsafeInput);
    if (!parsedInput.success) {
      outcome = 'blocked';
      errorCode = 'INVALID_REQUEST';
      emit();
      return createControlPlaneToolError(errorCode) as z.infer<TOutput>;
    }

    const controller = new AbortController();
    const abort = () => controller.abort();
    context.signal?.addEventListener('abort', abort, { once: true });
    if (context.signal?.aborted) controller.abort();
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<never>((_resolve, reject) => {
      timeout = setTimeout(() => {
        controller.abort();
        reject(new ControlPlaneClientError('CONTROL_PLANE_TIMEOUT'));
      }, descriptor.limits.maxExecutionMs);
    });

    try {
      const rawOutput = await Promise.race([invoke(parsedInput.data, controller.signal), deadline]);
      const parsedOutput = descriptor.outputSchema.safeParse(rawOutput);
      if (!parsedOutput.success) throw new TypeError('Invalid control-plane output.');
      if (byteLength(parsedOutput.data) > descriptor.limits.maxResponseBytes) {
        errorCode = 'RESPONSE_LIMIT_EXCEEDED';
        outcome = 'blocked';
        return createControlPlaneToolError(errorCode) as z.infer<TOutput>;
      }
      outcome = 'succeeded';
      return parsedOutput.data;
    } catch (error) {
      errorCode = mapClientError(error);
      outcome = errorCode === 'INTERNAL_ERROR' ? 'failed' : 'blocked';
      return createControlPlaneToolError(errorCode) as z.infer<TOutput>;
    } finally {
      if (timeout !== undefined) clearTimeout(timeout);
      context.signal?.removeEventListener('abort', abort);
      emit();
    }
  };
}
