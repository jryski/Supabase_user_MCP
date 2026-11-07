import { McpServer, type JSONRPCMessage, type Transport } from '@modelcontextprotocol/server';
import {
  CREATE_WORK_ITEM_TOOL,
  createControlPlaneToolMcpResult,
  MAX_REQUEST_ID_BYTES,
  MAX_RESPONSE_BYTES,
  POST_MODEL_MESSAGE_TOOL,
} from '@supabase-user-mcp/contracts';

import type { ControlPlaneClient } from './control-plane-client.js';
import {
  createControlPlaneToolExecutor,
  type ControlPlaneOperationalEvent,
} from './control-plane-tool-governor.js';
import { SERVER_VERSION } from './server.js';

export const CONTROL_PLANE_SERVER_NAME = 'supabase-user-mcp-control-plane';

export interface ControlPlaneServerOptions {
  readonly client: ControlPlaneClient;
  readonly emitOperationalEvent?: (event: ControlPlaneOperationalEvent) => void;
}

export interface ControlPlaneServer {
  connect(transport: Transport): Promise<void>;
  close(): Promise<void>;
}

function frameByteLength(message: JSONRPCMessage): number {
  try {
    return new TextEncoder().encode(`${JSON.stringify(message)}\n`).byteLength;
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}

function requestIdByteLength(message: JSONRPCMessage): number {
  if (!('id' in message)) return 0;
  try {
    return new TextEncoder().encode(JSON.stringify(message.id)).byteLength;
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}

class BoundedControlPlaneTransport implements Transport {
  onclose?: Transport['onclose'];
  onerror?: Transport['onerror'];
  onmessage?: Transport['onmessage'];
  readonly hasPerRequestStream: boolean;

  constructor(private readonly inner: Transport) {
    this.hasPerRequestStream = inner.hasPerRequestStream ?? false;
  }

  setProtocolVersion(version: string): void {
    this.inner.setProtocolVersion?.(version);
  }

  setSupportedProtocolVersions(versions: string[]): void {
    this.inner.setSupportedProtocolVersions?.(versions);
  }

  async start(): Promise<void> {
    this.inner.onclose = () => this.onclose?.();
    this.inner.onerror = (error) => this.onerror?.(error);
    this.inner.onmessage = (message, extra) => {
      if (
        frameByteLength(message) > MAX_RESPONSE_BYTES ||
        requestIdByteLength(message) > MAX_REQUEST_ID_BYTES
      ) {
        void this.inner.close().catch((error: unknown) => {
          this.onerror?.(error instanceof Error ? error : new Error('Transport close failed.'));
        });
        return;
      }
      this.onmessage?.(message, extra);
    };
    await this.inner.start();
  }

  async send(message: JSONRPCMessage, options?: Parameters<Transport['send']>[1]): Promise<void> {
    if (frameByteLength(message) > MAX_RESPONSE_BYTES) {
      await this.inner.close();
      throw new RangeError(`MCP frame must not exceed ${MAX_RESPONSE_BYTES} UTF-8 bytes.`);
    }
    await this.inner.send(message, options);
  }

  async close(): Promise<void> {
    await this.inner.close();
  }
}

const CREATE_WORK_ITEM_ANNOTATIONS = Object.freeze({
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
});

const POST_MODEL_MESSAGE_ANNOTATIONS = Object.freeze({
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: false,
});

export function createControlPlaneServer(options: ControlPlaneServerOptions): ControlPlaneServer {
  const server = new McpServer(
    { name: CONTROL_PLANE_SERVER_NAME, version: SERVER_VERSION },
    {
      instructions:
        'Privileged deployment control-plane profile. It exposes two fixed RPC-backed tools and never accepts SQL, relation, schema, URL, role, credential, or caller identity arguments.',
    },
  );
  const createWorkItem = createControlPlaneToolExecutor(
    CREATE_WORK_ITEM_TOOL,
    options.client.createWorkItem,
  );
  const postModelMessage = createControlPlaneToolExecutor(
    POST_MODEL_MESSAGE_TOOL,
    options.client.postModelMessage,
  );
  const context = (requestId: string | number, signal: AbortSignal) => ({
    requestId,
    signal,
    ...(options.emitOperationalEvent === undefined
      ? {}
      : { emitOperationalEvent: options.emitOperationalEvent }),
  });

  server.registerTool(
    CREATE_WORK_ITEM_TOOL.name,
    {
      title: 'Create work item',
      description: 'Creates one bounded planning work item through the fixed deployment RPC.',
      inputSchema: CREATE_WORK_ITEM_TOOL.inputSchema,
      outputSchema: CREATE_WORK_ITEM_TOOL.outputSchema,
      annotations: CREATE_WORK_ITEM_ANNOTATIONS,
    },
    async (input, request) =>
      createControlPlaneToolMcpResult(
        await createWorkItem(input, context(request.mcpReq.id, request.mcpReq.signal)),
      ),
  );

  server.registerTool(
    POST_MODEL_MESSAGE_TOOL.name,
    {
      title: 'Post model message',
      description: 'Posts one bounded model-channel message through the fixed deployment RPC.',
      inputSchema: POST_MODEL_MESSAGE_TOOL.inputSchema,
      outputSchema: POST_MODEL_MESSAGE_TOOL.outputSchema,
      annotations: POST_MODEL_MESSAGE_ANNOTATIONS,
    },
    async (input, request) =>
      createControlPlaneToolMcpResult(
        await postModelMessage(input, context(request.mcpReq.id, request.mcpReq.signal)),
      ),
  );

  return Object.freeze({
    connect: async (transport: Transport) =>
      server.connect(new BoundedControlPlaneTransport(transport)),
    close: async () => server.close(),
  });
}
