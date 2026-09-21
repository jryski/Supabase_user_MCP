import {
  CreateWorkItemInputSchema,
  type CreateWorkItemInput,
  type CreateWorkItemOutput,
  PostModelMessageInputSchema,
  type PostModelMessageInput,
  type PostModelMessageOutput,
} from '@supabase-user-mcp/contracts';

const CREATE_WORK_ITEM_PATH = '/rest/v1/rpc/create_work_item';
const POST_MODEL_MESSAGE_PATH = '/rest/v1/rpc/post_model_message';
const DEFAULT_TIMEOUT_MS = 2_000;
const MAX_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_RESPONSE_BYTES = 65_536;
const MAX_RESPONSE_BYTES = 65_536;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const AGENT_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]*$/u;

export type ControlPlaneClientErrorCode =
  | 'CONTROL_PLANE_INVALID_CONFIGURATION'
  | 'CONTROL_PLANE_INVALID_REQUEST'
  | 'CONTROL_PLANE_BOARD_UNAVAILABLE'
  | 'CONTROL_PLANE_REPLY_UNAVAILABLE'
  | 'CONTROL_PLANE_IDEMPOTENCY_CONFLICT'
  | 'CONTROL_PLANE_TIMEOUT'
  | 'CONTROL_PLANE_NETWORK_FAILURE'
  | 'CONTROL_PLANE_MALFORMED_RESPONSE'
  | 'CONTROL_PLANE_UPSTREAM_STATUS'
  | 'CONTROL_PLANE_RESPONSE_TOO_LARGE';

export class ControlPlaneClientError extends Error {
  readonly code: ControlPlaneClientErrorCode;

  constructor(code: ControlPlaneClientErrorCode) {
    super(code);
    this.name = 'ControlPlaneClientError';
    this.code = code;
  }
}

export interface ControlPlaneClientConfig {
  readonly origin: string;
  readonly serviceRoleKey: string;
  readonly agentId: string;
  readonly fetch?: typeof globalThis.fetch;
  readonly timeoutMs?: number;
  readonly maxResponseBytes?: number;
}

export interface ControlPlaneClient {
  readonly agentId: string;
  readonly createWorkItem: (
    input: CreateWorkItemInput,
    signal?: AbortSignal,
  ) => Promise<CreateWorkItemOutput>;
  readonly postModelMessage: (
    input: PostModelMessageInput,
    signal?: AbortSignal,
  ) => Promise<PostModelMessageOutput>;
}

function fail(code: ControlPlaneClientErrorCode): never {
  throw new ControlPlaneClientError(code);
}

function boundedInteger(value: number, maximum: number): boolean {
  return Number.isSafeInteger(value) && value > 0 && value <= maximum;
}

async function readBoundedBody(response: Response, maximum: number): Promise<string> {
  if (response.body === null) return '';
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  while (true) {
    const result = await reader.read();
    if (result.done) break;
    length += result.value.byteLength;
    if (length > maximum) {
      await reader.cancel();
      fail('CONTROL_PLANE_RESPONSE_TOO_LARGE');
    }
    chunks.push(result.value);
  }
  return Buffer.concat(chunks, length).toString('utf8');
}

function record(value: unknown): Readonly<Record<string, unknown>> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    fail('CONTROL_PLANE_MALFORMED_RESPONSE');
  }
  return value as Readonly<Record<string, unknown>>;
}

function requiredUuid(value: unknown): string {
  if (typeof value !== 'string' || !UUID.test(value)) {
    fail('CONTROL_PLANE_MALFORMED_RESPONSE');
  }
  return value;
}

function requiredSafeInteger(value: unknown): number {
  const parsed = typeof value === 'string' && /^\d+$/u.test(value) ? Number(value) : value;
  if (typeof parsed !== 'number' || !Number.isSafeInteger(parsed) || parsed <= 0) {
    fail('CONTROL_PLANE_MALFORMED_RESPONSE');
  }
  return parsed;
}

function parseWorkItemReceipt(value: unknown, input: CreateWorkItemInput): CreateWorkItemOutput {
  const payload = record(value);
  const id = requiredUuid(payload.id ?? payload.item_id ?? payload.work_item_id);
  const itemNumber = requiredSafeInteger(payload.item_number ?? payload.itemNumber);
  const boardSlug = payload.board_slug ?? payload.boardSlug ?? input.boardSlug;
  const idempotencyKey = payload.idempotency_key ?? payload.idempotencyKey ?? input.idempotencyKey;
  const created = payload.created;
  if (
    typeof boardSlug !== 'string' ||
    boardSlug !== input.boardSlug ||
    typeof idempotencyKey !== 'string' ||
    idempotencyKey !== input.idempotencyKey ||
    (created !== undefined && typeof created !== 'boolean')
  ) {
    fail('CONTROL_PLANE_MALFORMED_RESPONSE');
  }
  return Object.freeze({
    ok: true as const,
    receipt: Object.freeze({
      id,
      itemNumber,
      boardSlug,
      ...(created === undefined ? {} : { created }),
      idempotencyKey,
    }),
  });
}

function parseModelMessageReceipt(value: unknown): PostModelMessageOutput {
  const payload = record(value);
  const id = requiredUuid(payload.id ?? payload.message_id);
  const seq = requiredSafeInteger(payload.seq);
  return Object.freeze({
    ok: true as const,
    receipt: Object.freeze({ id, seq, posted: true as const }),
  });
}

function classifyUpstreamError(
  operation: 'create_work_item' | 'post_model_message',
  status: number,
  body: string,
): never {
  let code = '';
  let message = '';
  try {
    const payload = record(JSON.parse(body));
    code = typeof payload.code === 'string' ? payload.code : '';
    message = typeof payload.message === 'string' ? payload.message.toLowerCase() : '';
  } catch (error) {
    if (error instanceof ControlPlaneClientError) {
      code = '';
      message = '';
    } else {
      throw error;
    }
  }

  if (operation === 'create_work_item' && /board/u.test(message)) {
    fail('CONTROL_PLANE_BOARD_UNAVAILABLE');
  }
  if (operation === 'post_model_message' && /re[_ ]?seq|reply/u.test(message)) {
    fail('CONTROL_PLANE_REPLY_UNAVAILABLE');
  }
  if (/idempot/u.test(message) || code === '23505') {
    fail('CONTROL_PLANE_IDEMPOTENCY_CONFLICT');
  }
  if (status === 400 || status === 404 || code === '22P02' || code === '23514') {
    fail('CONTROL_PLANE_INVALID_REQUEST');
  }
  fail('CONTROL_PLANE_UPSTREAM_STATUS');
}

function createWorkItemArguments(input: CreateWorkItemInput, agentId: string) {
  return {
    p_board_slug: input.boardSlug,
    p_item_kind: input.itemKind,
    p_title: input.title,
    p_description: input.description ?? null,
    p_priority: input.priority,
    p_status: input.status,
    p_workstream: input.workstream ?? null,
    p_repository: input.repository ?? null,
    p_labels: input.labels,
    p_acceptance_criteria: input.acceptanceCriteria ?? null,
    p_deliverable: input.deliverable ?? null,
    p_execution_mode: input.executionMode,
    p_authority_required: input.authorityRequired,
    p_review_required: input.reviewRequired,
    p_assigned_to_agent: input.assignedToAgent ?? null,
    p_created_by_agent: agentId,
    p_source_agent: agentId,
    p_source_ref: input.sourceRef ?? null,
    p_idempotency_key: input.idempotencyKey,
    p_metadata: input.metadata,
  };
}

function postModelMessageArguments(input: PostModelMessageInput, agentId: string) {
  return {
    p_from_agent: agentId,
    p_to_agent: input.toAgent,
    p_subject: input.subject,
    p_body: input.body,
    p_re_seq: input.reSeq ?? null,
  };
}

export function createControlPlaneClient(config: ControlPlaneClientConfig): ControlPlaneClient {
  let origin: URL;
  try {
    origin = new URL(config.origin);
  } catch {
    fail('CONTROL_PLANE_INVALID_CONFIGURATION');
  }
  const key = config.serviceRoleKey.trim();
  const agentId = config.agentId.trim();
  if (
    origin.protocol !== 'https:' ||
    origin.origin !== config.origin ||
    origin.username !== '' ||
    origin.password !== '' ||
    key.length < 32 ||
    key.length > 4_096 ||
    agentId.length < 1 ||
    agentId.length > 128 ||
    agentId !== config.agentId ||
    !AGENT_ID.test(agentId)
  ) {
    fail('CONTROL_PLANE_INVALID_CONFIGURATION');
  }
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxResponseBytes = config.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  if (
    !boundedInteger(timeoutMs, MAX_TIMEOUT_MS) ||
    !boundedInteger(maxResponseBytes, MAX_RESPONSE_BYTES)
  ) {
    fail('CONTROL_PLANE_INVALID_CONFIGURATION');
  }

  const fetchImplementation = config.fetch ?? globalThis.fetch;
  const request = async (
    schema: 'planning' | 'public',
    path: string,
    operation: 'create_work_item' | 'post_model_message',
    body: Readonly<Record<string, unknown>>,
    callerSignal?: AbortSignal,
  ): Promise<unknown> => {
    const controller = new AbortController();
    const cancel = () => controller.abort();
    callerSignal?.addEventListener('abort', cancel, { once: true });
    if (callerSignal?.aborted) controller.abort();
    const timer = setTimeout(cancel, timeoutMs);
    const expectedUrl = `${origin.origin}${path}`;
    try {
      const response = await fetchImplementation(expectedUrl, {
        method: 'POST',
        redirect: 'error',
        headers: {
          Accept: 'application/json',
          'Accept-Profile': schema,
          Authorization: `Bearer ${key}`,
          apikey: key,
          'Content-Type': 'application/json',
          'Content-Profile': schema,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      if (response.redirected || (response.url !== '' && response.url !== expectedUrl)) {
        fail('CONTROL_PLANE_UPSTREAM_STATUS');
      }
      const advertisedLength = response.headers.get('content-length');
      if (advertisedLength !== null && Number(advertisedLength) > maxResponseBytes) {
        fail('CONTROL_PLANE_RESPONSE_TOO_LARGE');
      }
      const responseBody = await readBoundedBody(response, maxResponseBytes);
      if (!response.ok) classifyUpstreamError(operation, response.status, responseBody);
      try {
        return JSON.parse(responseBody);
      } catch {
        fail('CONTROL_PLANE_MALFORMED_RESPONSE');
      }
    } catch (error) {
      if (error instanceof ControlPlaneClientError) throw error;
      if (controller.signal.aborted) fail('CONTROL_PLANE_TIMEOUT');
      fail('CONTROL_PLANE_NETWORK_FAILURE');
    } finally {
      clearTimeout(timer);
      callerSignal?.removeEventListener('abort', cancel);
    }
  };

  return Object.freeze({
    agentId,
    createWorkItem: async (unsafeInput: CreateWorkItemInput, signal?: AbortSignal) => {
      const input = CreateWorkItemInputSchema.safeParse(unsafeInput);
      if (!input.success) fail('CONTROL_PLANE_INVALID_REQUEST');
      const payload = await request(
        'planning',
        CREATE_WORK_ITEM_PATH,
        'create_work_item',
        createWorkItemArguments(input.data, agentId),
        signal,
      );
      return parseWorkItemReceipt(payload, input.data);
    },
    postModelMessage: async (unsafeInput: PostModelMessageInput, signal?: AbortSignal) => {
      const input = PostModelMessageInputSchema.safeParse(unsafeInput);
      if (!input.success) fail('CONTROL_PLANE_INVALID_REQUEST');
      const payload = await request(
        'public',
        POST_MODEL_MESSAGE_PATH,
        'post_model_message',
        postModelMessageArguments(input.data, agentId),
        signal,
      );
      return parseModelMessageReceipt(payload);
    },
  });
}
