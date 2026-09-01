import { describe, expect, it, vi } from 'vitest';

import {
  createIdempotentShutdown,
  runReadOnlyStdioCli,
  STDIO_READY_MESSAGE,
  STDIO_SHUTDOWN_FAILURE_MESSAGE,
  STDIO_STARTUP_FAILURE_MESSAGE,
  STDIO_TRANSPORT_FAILURE_MESSAGE,
  startReadOnlyStdioFromEnvironment,
  type StdioStartupDependencies,
} from './stdio-startup.js';
import type { VerifiedFixedSupabaseClient } from './fixed-supabase-client.js';
import type { ReadOnlyServer } from './server.js';

describe('read-only stdio startup', () => {
  it('rejects every command argument before loading credentials', async () => {
    const loadCredentials = vi.fn();

    await expect(
      startReadOnlyStdioFromEnvironment({
        argv: ['--token', 'forbidden'],
        env: {
          SUPABASE_USER_MCP_ORIGIN: 'https://project.supabase.co',
          SUPABASE_USER_MCP_CREDENTIAL_FILE: '/tmp/credentials.json',
        },
        dependencies: {
          loadCredentials,
          createClient: vi.fn(),
          createServer: vi.fn(),
          serveStdio: vi.fn(),
        },
      }),
    ).rejects.toThrowError('STDIO_STARTUP_INVALID_CONFIGURATION');
    expect(loadCredentials).not.toHaveBeenCalled();
  });

  it('coalesces repeated shutdown signals into one close operation', async () => {
    const close = vi.fn(async () => undefined);
    const onFailure = vi.fn();
    const shutdown = createIdempotentShutdown(close, onFailure);

    await Promise.all([shutdown('SIGINT'), shutdown('SIGTERM')]);

    expect(close).toHaveBeenCalledOnce();
    expect(onFailure).not.toHaveBeenCalled();
  });

  it('assembles the exact fixed client and verifies the server before starting stdio', async () => {
    const order: string[] = [];
    const credentials = Object.freeze({
      projectPublishableKey: 'synthetic-publishable-key',
      userAccessToken: 'header.payload.signature',
    });
    const client: VerifiedFixedSupabaseClient = {
      verifyUserIdentity: async () => ({ principalId: '11111111-1111-4111-9111-111111111111' }),
      listMemoryRows: async () => [],
      searchMemoryRows: async () => ({ rows: [] }),
      getMemoryRow: async () => null,
      listRecentMemoryRows: async () => ({ rows: [] }),
    };
    const server: ReadOnlyServer = {
      connect: async () => undefined,
      close: async () => undefined,
    };
    let capturedFactory: (() => ReadOnlyServer | Promise<ReadOnlyServer>) | undefined;
    const handle = { close: vi.fn(async () => undefined) };
    const dependencies: StdioStartupDependencies = {
      loadCredentials: vi.fn(async () => {
        order.push('credentials');
        return credentials;
      }),
      createClient: vi.fn(() => {
        order.push('client');
        return client;
      }),
      createServer: vi.fn(async () => {
        order.push('verified-server');
        return server;
      }),
      serveStdio: vi.fn((factory, options) => {
        order.push('stdio');
        capturedFactory = factory;
        expect(options).toMatchObject({ legacy: 'reject' });
        return handle;
      }),
    };

    await expect(
      startReadOnlyStdioFromEnvironment({
        argv: [],
        env: {
          SUPABASE_USER_MCP_ORIGIN: 'https://project.supabase.co',
          SUPABASE_USER_MCP_CREDENTIAL_FILE: '/tmp/credentials.json',
        },
        dependencies,
      }),
    ).resolves.toBe(handle);

    expect(order).toEqual(['credentials', 'client', 'verified-server', 'stdio']);
    expect(dependencies.loadCredentials).toHaveBeenCalledWith('/tmp/credentials.json');
    expect(dependencies.createClient).toHaveBeenCalledWith({
      origin: 'https://project.supabase.co',
      credentials,
    });
    if (!capturedFactory) throw new TypeError('Expected stdio factory.');
    await expect(capturedFactory()).resolves.toBe(server);
  });

  it('reports startup failures generically without registering signal handlers', async () => {
    const stderr = vi.fn();
    const setExitCode = vi.fn();
    const onceSignal = vi.fn();

    await runReadOnlyStdioCli({
      runtime: { argv: [], env: {}, stderr, setExitCode, onceSignal },
      start: async () => {
        throw new Error('secret path /private/credentials.json token=never-log');
      },
    });

    expect(stderr).toHaveBeenCalledWith(STDIO_STARTUP_FAILURE_MESSAGE);
    expect(stderr.mock.calls.flat().join(' ')).not.toMatch(/secret|private|token/iu);
    expect(setExitCode).toHaveBeenCalledWith(1);
    expect(onceSignal).not.toHaveBeenCalled();
  });

  it('announces readiness and registers both shutdown signals', async () => {
    const stderr = vi.fn();
    const setExitCode = vi.fn();
    const listeners = new Map<string, () => void>();
    const close = vi.fn(async () => undefined);

    await runReadOnlyStdioCli({
      runtime: {
        argv: [],
        env: {},
        stderr,
        setExitCode,
        onceSignal: (signal, listener) => listeners.set(signal, listener),
      },
      start: async () => ({ close }),
    });

    expect(stderr).toHaveBeenCalledWith(STDIO_READY_MESSAGE);
    expect(Array.from(listeners.keys()).toSorted()).toEqual(['SIGINT', 'SIGTERM']);
    listeners.get('SIGINT')?.();
    listeners.get('SIGTERM')?.();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(close).toHaveBeenCalledOnce();
    expect(setExitCode).not.toHaveBeenCalled();
  });

  it('closes the verified server when stdio setup throws', async () => {
    const close = vi.fn(async () => undefined);
    const client: VerifiedFixedSupabaseClient = {
      verifyUserIdentity: async () => ({ principalId: '11111111-1111-4111-9111-111111111111' }),
      listMemoryRows: async () => [],
      searchMemoryRows: async () => ({ rows: [] }),
      getMemoryRow: async () => null,
      listRecentMemoryRows: async () => ({ rows: [] }),
    };
    const dependencies: StdioStartupDependencies = {
      loadCredentials: async () => ({
        projectPublishableKey: 'synthetic-publishable-key',
        userAccessToken: 'header.payload.signature',
      }),
      createClient: () => client,
      createServer: async () => ({ connect: async () => undefined, close }),
      serveStdio: () => {
        throw new Error('secret transport detail');
      },
    };

    await expect(
      startReadOnlyStdioFromEnvironment({
        argv: [],
        env: {
          SUPABASE_USER_MCP_ORIGIN: 'https://project.supabase.co',
          SUPABASE_USER_MCP_CREDENTIAL_FILE: '/tmp/credentials.json',
        },
        dependencies,
      }),
    ).rejects.toThrowError('secret transport detail');
    expect(close).toHaveBeenCalledOnce();
  });

  it('reports transport and shutdown failures with stable generic messages', async () => {
    const stderr = vi.fn();
    const setExitCode = vi.fn();
    const listeners = new Map<string, () => void>();

    await runReadOnlyStdioCli({
      runtime: {
        argv: [],
        env: {},
        stderr,
        setExitCode,
        onceSignal: (signal, listener) => listeners.set(signal, listener),
      },
      start: async (options) => {
        options.onTransportError?.(new Error('secret upstream transport detail'));
        return {
          close: async () => {
            throw new Error('secret close detail');
          },
        };
      },
    });

    listeners.get('SIGTERM')?.();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(stderr.mock.calls.flat()).toEqual([
      STDIO_TRANSPORT_FAILURE_MESSAGE,
      STDIO_READY_MESSAGE,
      STDIO_SHUTDOWN_FAILURE_MESSAGE,
    ]);
    expect(stderr.mock.calls.flat().join(' ')).not.toMatch(/secret|upstream|detail/iu);
    expect(setExitCode).toHaveBeenCalledWith(1);
  });
});
