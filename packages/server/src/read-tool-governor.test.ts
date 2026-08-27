import { describe, expect, it, vi } from 'vitest';
import { createReadToolError, MEMORY_SEARCH_TOOL } from '@supabase-user-mcp/contracts';
import { createHash } from 'node:crypto';

import {
  createReadToolExecutor,
  type ReadToolExecutionContext,
  type ReadToolOperationalEvent,
} from './read-tool-governor.js';

const validQuery = {
  query: 'synthetic search',
  limit: 2,
};

const sampleRow = {
  id: `mem_${'A'.repeat(23)}`,
  title: 'Synthetic title',
  content: 'Synthetic content',
  contentTrust: 'untrusted' as const,
  createdAt: '2026-08-20T00:00:00.000Z',
  provenanceSummary: 'synthetic fixture',
};

describe('createReadToolExecutor', () => {
  it('validates read arguments before execution and emits a redacted denied event', async () => {
    const events: ReadToolOperationalEvent[] = [];
    const handler = vi.fn();
    const execute = createReadToolExecutor(MEMORY_SEARCH_TOOL, handler);

    const result = await execute(
      { query: '' },
      {
        requestId: 'req_invalid',
        emitOperationalEvent: (event) => {
          events.push(event);
        },
      },
    );

    expect(result).toEqual({
      ok: false,
      error: {
        code: MEMORY_SEARCH_TOOL.errorMapping.validation,
        message: 'Request is invalid.',
        retryable: false,
      },
    });
    expect(handler).not.toHaveBeenCalled();
    expect(events).toEqual([
      {
        requestId: 'req_invalid',
        operation: 'authorized_memory_search_v1',
        scope: 'operation:authorized_memory_search_v1',
        normalizedArgumentDigest: createHash('sha256')
          .update(JSON.stringify({ query: '' }))
          .digest('hex')
          .slice(0, 24),
        timestamp: expect.any(String),
        durationMs: expect.any(Number),
        rowCount: 0,
        outcome: 'blocked',
        denialClass: MEMORY_SEARCH_TOOL.errorMapping.validation,
      },
    ]);
  });

  it('enforces row ceilings before returning oversized success responses', async () => {
    const tool = {
      ...MEMORY_SEARCH_TOOL,
      limits: {
        ...MEMORY_SEARCH_TOOL.limits,
        maxRows: 1,
      },
    };
    const execute = createReadToolExecutor(tool, () =>
      Promise.resolve({
        ok: true as const,
        items: [
          {
            ...sampleRow,
            rank: 0.91,
            content: 'first',
          },
          {
            ...sampleRow,
            id: `mem_${'B'.repeat(23)}`,
            rank: 0.82,
            content: 'second',
          },
        ],
      }),
    );

    const result = await execute(validQuery, { principalId: 'principal-rows' });

    expect(result).toEqual({
      ok: false,
      error: {
        code: MEMORY_SEARCH_TOOL.errorMapping.responseLimit,
        message: 'Response limit exceeded.',
        retryable: false,
      },
    });
  });

  it('enforces wire byte ceilings after output validation', async () => {
    const tool = {
      ...MEMORY_SEARCH_TOOL,
      limits: {
        ...MEMORY_SEARCH_TOOL.limits,
        maxResponseBytes: 96,
      },
    };
    const execute = createReadToolExecutor(tool, () =>
      Promise.resolve({
        ok: true as const,
        items: [
          {
            ...sampleRow,
            rank: 0.5,
            content: 'x'.repeat(256),
          },
        ],
      }),
    );

    const result = await execute(validQuery, { principalId: 'principal-bytes' });

    expect(result).toEqual({
      ok: false,
      error: {
        code: MEMORY_SEARCH_TOOL.errorMapping.responseLimit,
        message: 'Response limit exceeded.',
        retryable: false,
      },
    });
  });

  it('rejects excess concurrency and excess rate with non-enumerating denial events', async () => {
    const concurrencyTool = {
      ...MEMORY_SEARCH_TOOL,
      limits: {
        ...MEMORY_SEARCH_TOOL.limits,
        maxExecutionMs: 30,
      },
    };
    let release: () => void = () => undefined;
    const blocked = new Promise<unknown>((resolve) => {
      release = () => resolve({ ok: true as const, items: [] });
    });
    const execute = createReadToolExecutor(concurrencyTool, () => blocked, {
      maxConcurrentExecutions: 1,
    });

    const first = execute(validQuery, { principalId: 'principal-concurrency' });
    const second = execute(validQuery, { principalId: 'principal-concurrency' });

    expect(await second).toEqual({
      ok: false,
      error: {
        code: MEMORY_SEARCH_TOOL.errorMapping.unavailable,
        message: 'Record is unavailable.',
        retryable: false,
      },
    });
    release();
    expect(await first).toEqual({ ok: true, items: [] });

    const rateTool = {
      ...MEMORY_SEARCH_TOOL,
      limits: {
        ...MEMORY_SEARCH_TOOL.limits,
        maxExecutionMs: 1,
      },
    };
    const executeRate = createReadToolExecutor(
      rateTool,
      () => Promise.resolve({ ok: true as const, items: [] }),
      {
        maxRequestsPerWindow: 1,
        requestWindowMs: 60_000,
        maxConcurrentExecutions: 4,
      },
    );

    await expect(
      executeRate(validQuery, { principalId: 'principal-rate', requestId: 'rate-1' }),
    ).resolves.toEqual({ ok: true, items: [] });
    await expect(
      executeRate(validQuery, { principalId: 'principal-rate', requestId: 'rate-2' }),
    ).resolves.toMatchObject({
      ok: false,
      error: {
        code: MEMORY_SEARCH_TOOL.errorMapping.unavailable,
      },
    });
  });

  it('maps caller or internal cancellation to deadline errors', async () => {
    vi.useFakeTimers();
    const execute = createReadToolExecutor(
      {
        ...MEMORY_SEARCH_TOOL,
        limits: {
          ...MEMORY_SEARCH_TOOL.limits,
          maxExecutionMs: 25,
        },
      },
      (_input, signal) =>
        new Promise((_resolve, reject) => {
          signal.addEventListener('abort', () => {
            reject(new Error('cancelled'));
          });
        }),
    );

    const result = execute(validQuery, {
      principalId: 'principal-timeout',
      requestId: 'timeout',
    });
    await vi.advanceTimersByTimeAsync(30);
    await expect(result).resolves.toEqual({
      ok: false,
      error: {
        code: MEMORY_SEARCH_TOOL.errorMapping.timeout,
        message: 'Request deadline exceeded.',
        retryable: false,
      },
    });
    vi.useRealTimers();
  });

  it('emits redacted, structured operational events for successful calls', async () => {
    const events: ReadToolOperationalEvent[] = [];
    const execute = createReadToolExecutor(MEMORY_SEARCH_TOOL, () =>
      Promise.resolve({
        ok: true as const,
        items: [
          {
            ...sampleRow,
            rank: 0.75,
          },
        ],
      }),
    );

    await expect(
      execute(
        { query: 'sensitive-query', filters: { tags: ['x'] } },
        {
          requestId: 'evt-ok',
          principalId: 'principal-1',
          emitOperationalEvent: (event) => {
            events.push(event);
          },
        },
      ),
    ).resolves.toEqual({
      ok: true,
      items: [
        {
          ...sampleRow,
          rank: 0.75,
        },
      ],
    });

    expect(events).toHaveLength(1);
    const event = events[0];
    if (event === undefined) {
      throw new Error('Expected one operational event.');
    }
    expect(event).toMatchObject({
      requestId: 'evt-ok',
      operation: 'authorized_memory_search_v1',
      scope: 'principal:principal-1',
      principalId: 'principal-1',
      outcome: 'success',
      rowCount: 1,
      timestamp: expect.any(String),
      durationMs: expect.any(Number),
    });
    expect(event.normalizedArgumentDigest).not.toContain('sensitive-query');
    expect(event.normalizedArgumentDigest).toHaveLength(24);
  });

  it('normalizes cyclic invalid input instead of throwing during digest creation', async () => {
    const events: ReadToolOperationalEvent[] = [];
    const cyclic: Record<string, unknown> = { query: '' };
    cyclic.self = cyclic;
    const execute = createReadToolExecutor(MEMORY_SEARCH_TOOL, vi.fn());

    await expect(
      execute(cyclic, {
        principalId: 'principal-cyclic',
        emitOperationalEvent: (event) => events.push(event),
      }),
    ).resolves.toEqual(createReadToolError('INVALID_REQUEST'));
    expect(events).toHaveLength(1);
    expect(events[0]?.outcome).toBe('blocked');
  });

  it('records valid error outputs as blocked operational events', async () => {
    const events: ReadToolOperationalEvent[] = [];
    const execute = createReadToolExecutor(MEMORY_SEARCH_TOOL, () =>
      Promise.resolve(createReadToolError('RESOURCE_UNAVAILABLE')),
    );

    await expect(
      execute(validQuery, {
        principalId: 'principal-error-output',
        emitOperationalEvent: (event) => events.push(event),
      }),
    ).resolves.toEqual(createReadToolError('RESOURCE_UNAVAILABLE'));
    expect(events[0]).toMatchObject({
      outcome: 'blocked',
      denialClass: 'RESOURCE_UNAVAILABLE',
    });
  });

  it('rejects invalid limiter policies at construction time', () => {
    expect(() =>
      createReadToolExecutor(MEMORY_SEARCH_TOOL, vi.fn(), {
        maxConcurrentExecutions: 0,
      }),
    ).toThrow('Invalid read-tool governance policy.');
  });

  it('ignores caller-reachable scope churn when applying a verified principal budget', async () => {
    const events: ReadToolOperationalEvent[] = [];
    const execute = createReadToolExecutor(
      MEMORY_SEARCH_TOOL,
      () => Promise.resolve({ ok: true as const, items: [] }),
      { maxRequestsPerWindow: 1 },
    );
    const hostileContext = (scope: string) =>
      ({
        principalId: 'verified-principal-scope-churn',
        scope,
        emitOperationalEvent: (event: ReadToolOperationalEvent) => events.push(event),
      }) as unknown as ReadToolExecutionContext;

    await expect(execute(validQuery, hostileContext('attacker-scope-one'))).resolves.toEqual({
      ok: true,
      items: [],
    });
    await expect(execute(validQuery, hostileContext('attacker-scope-two'))).resolves.toMatchObject({
      ok: false,
      error: { code: MEMORY_SEARCH_TOOL.errorMapping.unavailable },
    });
    expect(events.map((event) => event.scope)).toEqual([
      'principal:verified-principal-scope-churn',
      'principal:verified-principal-scope-churn',
    ]);
  });

  it('does not let a hostile scope collision consume another principal budget', async () => {
    const execute = createReadToolExecutor(
      MEMORY_SEARCH_TOOL,
      () => Promise.resolve({ ok: true as const, items: [] }),
      { maxRequestsPerWindow: 1 },
    );
    const hostileAttackerContext = {
      principalId: 'verified-attacker-principal',
      scope: 'verified-victim-principal',
    } as unknown as ReadToolExecutionContext;

    await expect(execute(validQuery, hostileAttackerContext)).resolves.toEqual({
      ok: true,
      items: [],
    });
    await expect(
      execute(validQuery, { principalId: 'verified-victim-principal' }),
    ).resolves.toEqual({ ok: true, items: [] });
  });
});
