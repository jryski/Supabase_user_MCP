import * as z from 'zod/v4';

import {
  MAX_RESPONSE_BYTES,
  MAX_TOOL_EXECUTION_MS,
  ReadToolErrorOutputSchema,
  readToolWireResponseByteLength,
} from './read-tools.js';
import {
  STORAGE_ALLOWED_MIME_TYPES,
  STORAGE_MAX_INLINE_BYTES,
  STORAGE_MAX_LIST_ITEMS,
  STORAGE_MAX_OBJECT_BYTES,
  STORAGE_SIGNED_URL_TTL_SECONDS,
  StorageListPrefixSchema,
  StorageMimeTypeSchema,
  StorageRelativeKeySchema,
} from './storage-bounds.js';

/**
 * Issue #123 S2: read-side storage tool contracts.
 *
 * Storage capabilities are separate from the memory `CAPABILITIES` set so the
 * existing memory access matrix and policy-lab constraint are unchanged.
 * Tool input never carries a bucket, a principal, a token, or an absolute
 * key; keys are S1-bounded relative keys under the session's principal scope.
 */

export const STORAGE_CAPABILITIES = Object.freeze(['storage:read', 'storage:write'] as const);
export const StorageCapabilitySchema = z.enum(STORAGE_CAPABILITIES);
export type StorageCapability = z.infer<typeof StorageCapabilitySchema>;

export const STORAGE_READ_TOOL_NAMES = Object.freeze([
  'storage_capabilities',
  'storage_list',
  'storage_get',
] as const);

const StorageCursorSchema = z
  .string()
  .min(20)
  .max(256)
  .regex(/^cur_[A-Za-z0-9_-]+$/, 'Expected an opaque cursor.');

const IsoDateTimeSchema = z.iso.datetime({ offset: true });

function withinWireLimit(value: unknown): boolean {
  return readToolWireResponseByteLength(null, value) <= MAX_RESPONSE_BYTES;
}

// storage_capabilities -------------------------------------------------------

export const StorageCapabilitiesInputSchema = z.object({}).strict();

const StorageCapabilitiesSuccessSchema = z
  .object({
    ok: z.literal(true),
    capabilities: z.array(StorageCapabilitySchema).max(STORAGE_CAPABILITIES.length),
    tools: z.array(z.string().regex(/^storage_[a-z_]+$/)).max(8),
    limits: z
      .object({
        maxInlineBytes: z.literal(STORAGE_MAX_INLINE_BYTES),
        maxObjectBytes: z.literal(STORAGE_MAX_OBJECT_BYTES),
        maxListItems: z.literal(STORAGE_MAX_LIST_ITEMS),
        signedUrlTtlSeconds: z.literal(STORAGE_SIGNED_URL_TTL_SECONDS),
        allowedMimeTypes: z.array(StorageMimeTypeSchema).max(STORAGE_ALLOWED_MIME_TYPES.length),
      })
      .strict(),
  })
  .strict();

export const StorageCapabilitiesOutputSchema = z.union([
  StorageCapabilitiesSuccessSchema,
  ReadToolErrorOutputSchema,
]);
export type StorageCapabilitiesOutput = z.infer<typeof StorageCapabilitiesOutputSchema>;

// storage_list ---------------------------------------------------------------

export const StorageListInputSchema = z
  .object({
    prefix: StorageListPrefixSchema.default(''),
    limit: z.number().int().min(1).max(STORAGE_MAX_LIST_ITEMS).default(STORAGE_MAX_LIST_ITEMS),
    cursor: StorageCursorSchema.optional(),
  })
  .strict();
export type StorageListInput = z.infer<typeof StorageListInputSchema>;

const StorageListObjectSchema = z
  .object({
    kind: z.literal('object'),
    key: StorageRelativeKeySchema,
    size: z.number().int().min(0).max(STORAGE_MAX_OBJECT_BYTES),
    mimeType: StorageMimeTypeSchema,
    updatedAt: IsoDateTimeSchema,
  })
  .strict();

const StorageListFolderSchema = z
  .object({
    kind: z.literal('folder'),
    key: StorageListPrefixSchema.refine((value) => value.length > 0),
  })
  .strict();

export const StorageListItemSchema = z.discriminatedUnion('kind', [
  StorageListObjectSchema,
  StorageListFolderSchema,
]);
export type StorageListItem = z.infer<typeof StorageListItemSchema>;

const StorageListSuccessSchema = z
  .object({
    ok: z.literal(true),
    items: z.array(StorageListItemSchema).max(STORAGE_MAX_LIST_ITEMS),
    nextCursor: StorageCursorSchema.optional(),
  })
  .strict();

export const StorageListOutputSchema = z
  .union([StorageListSuccessSchema, ReadToolErrorOutputSchema])
  .refine(withinWireLimit, `Wire response must not exceed ${MAX_RESPONSE_BYTES} UTF-8 bytes.`);
export type StorageListOutput = z.infer<typeof StorageListOutputSchema>;

// storage_get ----------------------------------------------------------------

export const StorageGetInputSchema = z
  .object({
    key: StorageRelativeKeySchema,
    delivery: z.enum(['auto', 'inline', 'signed_url']).default('auto'),
  })
  .strict();
export type StorageGetInput = z.infer<typeof StorageGetInputSchema>;

const StorageObjectMetadataFields = {
  key: StorageRelativeKeySchema,
  size: z.number().int().min(0).max(STORAGE_MAX_OBJECT_BYTES),
  mimeType: StorageMimeTypeSchema,
  updatedAt: IsoDateTimeSchema,
};

const StorageGetInlineRecordSchema = z
  .object({
    ...StorageObjectMetadataFields,
    delivery: z.literal('inline'),
    contentTrust: z.literal('untrusted'),
    contentBase64: z.base64().max(Math.ceil(STORAGE_MAX_INLINE_BYTES / 3) * 4),
  })
  .strict();

const StorageGetSignedRecordSchema = z
  .object({
    ...StorageObjectMetadataFields,
    delivery: z.literal('signed_url'),
    contentTrust: z.literal('untrusted'),
    signedUrl: z.url({ protocol: /^https$/ }).max(2048),
    expiresAt: IsoDateTimeSchema,
  })
  .strict();

const StorageGetSuccessSchema = z
  .object({
    ok: z.literal(true),
    record: z.discriminatedUnion('delivery', [
      StorageGetInlineRecordSchema,
      StorageGetSignedRecordSchema,
    ]),
  })
  .strict();

export const StorageGetOutputSchema = z
  .union([StorageGetSuccessSchema, ReadToolErrorOutputSchema])
  .refine(withinWireLimit, `Wire response must not exceed ${MAX_RESPONSE_BYTES} UTF-8 bytes.`);
export type StorageGetOutput = z.infer<typeof StorageGetOutputSchema>;

// descriptors ----------------------------------------------------------------

const STORAGE_SHARED_LIMITS = Object.freeze({
  maxResponseBytes: MAX_RESPONSE_BYTES,
  maxResponseBytesUnit: 'utf8_jsonrpc_mcp_wire_response' as const,
  maxExecutionMs: MAX_TOOL_EXECUTION_MS,
});

const STORAGE_READ_BEHAVIOR = Object.freeze({
  retry: Object.freeze({ maxAttempts: 1, policy: 'none' as const }),
  idempotency: 'idempotent' as const,
  concurrency: 'parallel_safe' as const,
  approval: 'not_required' as const,
  audit: 'read_access' as const,
  errorMapping: Object.freeze({
    validation: 'INVALID_REQUEST' as const,
    unavailable: 'RESOURCE_UNAVAILABLE' as const,
    responseLimit: 'RESPONSE_LIMIT_EXCEEDED' as const,
    timeout: 'DEADLINE_EXCEEDED' as const,
    unexpected: 'INTERNAL_ERROR' as const,
  }),
});

export const STORAGE_CAPABILITIES_TOOL = Object.freeze({
  name: 'storage_capabilities' as const,
  capability: 'storage:read' as const,
  operation: 'storage_capabilities_v1',
  inputSchema: StorageCapabilitiesInputSchema,
  outputSchema: StorageCapabilitiesOutputSchema,
  ...STORAGE_READ_BEHAVIOR,
  limits: Object.freeze({ maxRows: 0, ...STORAGE_SHARED_LIMITS }),
});

export const STORAGE_LIST_TOOL = Object.freeze({
  name: 'storage_list' as const,
  capability: 'storage:read' as const,
  operation: 'storage_list_v1',
  inputSchema: StorageListInputSchema,
  outputSchema: StorageListOutputSchema,
  ...STORAGE_READ_BEHAVIOR,
  limits: Object.freeze({ maxRows: STORAGE_MAX_LIST_ITEMS, ...STORAGE_SHARED_LIMITS }),
});

export const STORAGE_GET_TOOL = Object.freeze({
  name: 'storage_get' as const,
  capability: 'storage:read' as const,
  operation: 'storage_get_v1',
  inputSchema: StorageGetInputSchema,
  outputSchema: StorageGetOutputSchema,
  ...STORAGE_READ_BEHAVIOR,
  limits: Object.freeze({ maxRows: 1, ...STORAGE_SHARED_LIMITS }),
});

export const STORAGE_READ_TOOLS = Object.freeze([
  STORAGE_CAPABILITIES_TOOL,
  STORAGE_LIST_TOOL,
  STORAGE_GET_TOOL,
] as const);
