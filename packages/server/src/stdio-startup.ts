import {
  serveStdio as serveSdkStdio,
  type ServeStdioOptions,
  type StdioServerHandle,
} from '@modelcontextprotocol/server/stdio';

import {
  createFixedSupabaseClient,
  type FixedSupabaseClientConfig,
  type VerifiedFixedSupabaseClient,
} from './fixed-supabase-client.js';
import { loadLocalCredentials, type LocalCredentials } from './local-credential-loader.js';
import { createReadOnlyServer, type ReadOnlyServer, type ReadOnlyServerOptions } from './server.js';

export const STDIO_STARTUP_ERROR = 'STDIO_STARTUP_INVALID_CONFIGURATION';
export const SUPABASE_ORIGIN_ENV = 'SUPABASE_USER_MCP_ORIGIN';
export const CREDENTIAL_FILE_ENV = 'SUPABASE_USER_MCP_CREDENTIAL_FILE';
export const STDIO_STARTUP_FAILURE_MESSAGE = 'Supabase User MCP failed to start.';
export const STDIO_TRANSPORT_FAILURE_MESSAGE = 'Supabase User MCP stdio transport failed.';
export const STDIO_SHUTDOWN_FAILURE_MESSAGE = 'Supabase User MCP failed to close cleanly.';
export const STDIO_READY_MESSAGE = 'Supabase User MCP read-only stdio server ready.';

export class StdioStartupError extends Error {
  constructor() {
    super(STDIO_STARTUP_ERROR);
    this.name = 'StdioStartupError';
  }
}

export interface StdioStartupDependencies {
  readonly loadCredentials: (path: string) => Promise<LocalCredentials>;
  readonly createClient: (config: FixedSupabaseClientConfig) => VerifiedFixedSupabaseClient;
  readonly createServer: (options: ReadOnlyServerOptions) => Promise<ReadOnlyServer>;
  readonly serveStdio: (
    factory: () => ReadOnlyServer | Promise<ReadOnlyServer>,
    options: ServeStdioOptions,
  ) => StdioServerHandle;
}

export interface StdioStartupOptions {
  readonly argv?: readonly string[];
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly onTransportError?: (error: Error) => void;
  readonly dependencies?: StdioStartupDependencies;
}

export interface StdioCliRuntime {
  readonly argv: readonly string[];
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly stderr: (message: string) => void;
  readonly setExitCode: (code: number) => void;
  readonly onceSignal: (signal: 'SIGINT' | 'SIGTERM', listener: () => void) => void;
}

export interface ReadOnlyStdioCliOptions {
  readonly runtime?: StdioCliRuntime;
  readonly start?: (options: StdioStartupOptions) => Promise<StdioServerHandle>;
}

const defaultDependencies: StdioStartupDependencies = Object.freeze({
  loadCredentials: loadLocalCredentials,
  createClient: createFixedSupabaseClient,
  createServer: createReadOnlyServer,
  serveStdio: (
    factory: () => ReadOnlyServer | Promise<ReadOnlyServer>,
    options: ServeStdioOptions,
  ): StdioServerHandle =>
    // The pinned SDK factory type names its concrete server classes, while serveStdio uses only
    // connect() and close(). ReadOnlyServer deliberately exposes exactly that guarded runtime seam.
    serveSdkStdio(factory as unknown as Parameters<typeof serveSdkStdio>[0], options),
});

function invalidConfiguration(): never {
  throw new StdioStartupError();
}

export function createIdempotentShutdown(
  close: () => Promise<void>,
  onFailure: () => void,
): (signal: NodeJS.Signals) => Promise<void> {
  let shutdown: Promise<void> | undefined;
  return (_signal) => {
    shutdown ??= close().catch(() => {
      onFailure();
    });
    return shutdown;
  };
}

const defaultCliRuntime: StdioCliRuntime = Object.freeze({
  argv: process.argv.slice(2),
  env: process.env,
  stderr: (message: string) => console.error(message),
  setExitCode: (code: number) => {
    process.exitCode = code;
  },
  onceSignal: (signal: 'SIGINT' | 'SIGTERM', listener: () => void) => {
    process.once(signal, listener);
  },
});

export async function runReadOnlyStdioCli(options: ReadOnlyStdioCliOptions = {}): Promise<void> {
  const runtime = options.runtime ?? defaultCliRuntime;
  const start = options.start ?? startReadOnlyStdioFromEnvironment;
  let handle: StdioServerHandle;
  try {
    handle = await start({
      argv: runtime.argv,
      env: runtime.env,
      onTransportError: () => runtime.stderr(STDIO_TRANSPORT_FAILURE_MESSAGE),
    });
  } catch {
    runtime.stderr(STDIO_STARTUP_FAILURE_MESSAGE);
    runtime.setExitCode(1);
    return;
  }

  runtime.stderr(STDIO_READY_MESSAGE);
  const shutdown = createIdempotentShutdown(
    () => handle.close(),
    () => {
      runtime.stderr(STDIO_SHUTDOWN_FAILURE_MESSAGE);
      runtime.setExitCode(1);
    },
  );
  runtime.onceSignal('SIGINT', () => {
    void shutdown('SIGINT');
  });
  runtime.onceSignal('SIGTERM', () => {
    void shutdown('SIGTERM');
  });
}

export async function startReadOnlyStdioFromEnvironment(
  options: StdioStartupOptions = {},
): Promise<StdioServerHandle> {
  const argv = options.argv ?? process.argv.slice(2);
  if (argv.length !== 0) invalidConfiguration();

  const env = options.env ?? process.env;
  const origin = env[SUPABASE_ORIGIN_ENV];
  const credentialFile = env[CREDENTIAL_FILE_ENV];
  if (
    typeof origin !== 'string' ||
    origin.trim().length === 0 ||
    typeof credentialFile !== 'string' ||
    credentialFile.trim().length === 0
  ) {
    invalidConfiguration();
  }

  const dependencies = options.dependencies ?? defaultDependencies;
  const credentials = await dependencies.loadCredentials(credentialFile);
  const client = dependencies.createClient({ origin, credentials });
  const server = await dependencies.createServer({ client });
  try {
    const stdioOptions: ServeStdioOptions = {
      legacy: 'reject',
      ...(options.onTransportError === undefined ? {} : { onerror: options.onTransportError }),
    };
    return dependencies.serveStdio(async () => server, stdioOptions);
  } catch (error) {
    await server.close().catch(() => undefined);
    throw error;
  }
}
