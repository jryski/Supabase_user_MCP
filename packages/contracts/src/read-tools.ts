import * as z from 'zod/v4';

export const MAX_QUERY_LENGTH = 512;
export const MAX_FILTERS = 5;
export const MAX_SEARCH_ROWS = 20;
export const MAX_RESPONSE_BYTES = 65_536;
export const MAX_TOOL_EXECUTION_MS = 2_000;

const OpaqueCursorSchema = z
  .string()
  .min(20)
  .max(1024)
  .regex(/^cur_[A-Za-z0-9_-]+$/, 'Expected an opaque cursor.');

const SearchFiltersSchema = z
  .object({
    tags: z.array(z.string().trim().min(1).max(64)).max(MAX_FILTERS).optional(),
    createdAfter: z.iso.datetime({ offset: true }).optional(),
    createdBefore: z.iso.datetime({ offset: true }).optional(),
  })
  .strict()
  .refine(
    (filters) =>
      (filters.tags?.length ?? 0) +
        Number(filters.createdAfter !== undefined) +
        Number(filters.createdBefore !== undefined) <=
      MAX_FILTERS,
    `At most ${MAX_FILTERS} filters are allowed.`,
  );

export const MemorySearchInputSchema = z
  .object({
    query: z.string().trim().min(1).max(MAX_QUERY_LENGTH),
    mode: z.enum(['text', 'semantic']).default('text'),
    filters: SearchFiltersSchema.optional(),
    limit: z.number().int().min(1).max(MAX_SEARCH_ROWS).default(MAX_SEARCH_ROWS),
    cursor: OpaqueCursorSchema.optional(),
  })
  .strict();

export type MemorySearchInput = z.infer<typeof MemorySearchInputSchema>;

const OpaqueMemoryIdSchema = z
  .string()
  .min(26)
  .max(132)
  .regex(/^mem_[A-Za-z0-9_-]+$/, 'Expected an opaque memory identifier.');

const SearchResultSchema = z
  .object({
    id: OpaqueMemoryIdSchema,
    title: z.string().max(256),
    content: z.string().max(8192),
    contentTrust: z.literal('untrusted'),
    createdAt: z.iso.datetime({ offset: true }),
    provenanceSummary: z.string().max(512),
    rank: z.number().min(0).max(1),
  })
  .strict();

const ReadToolErrorSchema = z.discriminatedUnion('code', [
  z
    .object({
      code: z.literal('INVALID_REQUEST'),
      message: z.literal('Request is invalid.'),
      retryable: z.literal(false),
    })
    .strict(),
  z
    .object({
      code: z.literal('RESOURCE_UNAVAILABLE'),
      message: z.literal('Record is unavailable.'),
      retryable: z.literal(false),
    })
    .strict(),
  z
    .object({
      code: z.literal('RESPONSE_LIMIT_EXCEEDED'),
      message: z.literal('Response limit exceeded.'),
      retryable: z.literal(false),
    })
    .strict(),
  z
    .object({
      code: z.literal('DEADLINE_EXCEEDED'),
      message: z.literal('Request deadline exceeded.'),
      retryable: z.literal(false),
    })
    .strict(),
  z
    .object({
      code: z.literal('INTERNAL_ERROR'),
      message: z.literal('Request could not be completed.'),
      retryable: z.literal(false),
    })
    .strict(),
]);

const ReadToolErrorOutputSchema = z
  .object({
    ok: z.literal(false),
    error: ReadToolErrorSchema,
  })
  .strict();

function withinResponseByteLimit(value: unknown): boolean {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength <= MAX_RESPONSE_BYTES;
}

const MemorySearchSuccessSchema = z
  .object({
    ok: z.literal(true),
    items: z.array(SearchResultSchema).max(MAX_SEARCH_ROWS),
    nextCursor: OpaqueCursorSchema.optional(),
  })
  .strict();

export const MemorySearchOutputSchema = z
  .union([MemorySearchSuccessSchema, ReadToolErrorOutputSchema])
  .refine(withinResponseByteLimit, `Response must not exceed ${MAX_RESPONSE_BYTES} bytes.`);

export type MemorySearchOutput = z.infer<typeof MemorySearchOutputSchema>;

export const MemoryGetInputSchema = z.object({ id: OpaqueMemoryIdSchema }).strict();

const MemoryRecordSchema = z
  .object({
    id: OpaqueMemoryIdSchema,
    title: z.string().max(256),
    content: z.string().max(8192),
    contentTrust: z.literal('untrusted'),
    createdAt: z.iso.datetime({ offset: true }),
    provenanceSummary: z.string().max(512),
  })
  .strict();

const MemoryGetSuccessSchema = z
  .object({
    ok: z.literal(true),
    record: MemoryRecordSchema,
  })
  .strict();

export const MemoryGetOutputSchema = z
  .union([MemoryGetSuccessSchema, ReadToolErrorOutputSchema])
  .refine(withinResponseByteLimit, `Response must not exceed ${MAX_RESPONSE_BYTES} bytes.`);

export type MemoryGetInput = z.infer<typeof MemoryGetInputSchema>;
export type MemoryGetOutput = z.infer<typeof MemoryGetOutputSchema>;

export const MAX_RECENT_ROWS = 25;

const RecentFiltersSchema = z
  .object({
    tags: z.array(z.string().trim().min(1).max(64)).max(MAX_FILTERS).optional(),
  })
  .strict();

export const MemoryListRecentInputSchema = z
  .object({
    filters: RecentFiltersSchema.optional(),
    limit: z.number().int().min(1).max(MAX_RECENT_ROWS).default(MAX_RECENT_ROWS),
    cursor: OpaqueCursorSchema.optional(),
  })
  .strict();

const MemoryListRecentSuccessSchema = z
  .object({
    ok: z.literal(true),
    items: z.array(MemoryRecordSchema).max(MAX_RECENT_ROWS),
    nextCursor: OpaqueCursorSchema.optional(),
  })
  .strict();

export const MemoryListRecentOutputSchema = z
  .union([MemoryListRecentSuccessSchema, ReadToolErrorOutputSchema])
  .refine(withinResponseByteLimit, `Response must not exceed ${MAX_RESPONSE_BYTES} bytes.`);

export type MemoryListRecentInput = z.infer<typeof MemoryListRecentInputSchema>;
export type MemoryListRecentOutput = z.infer<typeof MemoryListRecentOutputSchema>;

const SHARED_LIMITS = Object.freeze({
  maxResponseBytes: MAX_RESPONSE_BYTES,
  maxExecutionMs: MAX_TOOL_EXECUTION_MS,
});

export const MEMORY_SEARCH_TOOL = Object.freeze({
  name: 'memory_search',
  capability: 'memory:search',
  operation: 'authorized_memory_search_v1',
  inputSchema: MemorySearchInputSchema,
  outputSchema: MemorySearchOutputSchema,
  limits: Object.freeze({
    maxFilters: MAX_FILTERS,
    maxRows: MAX_SEARCH_ROWS,
    ...SHARED_LIMITS,
  }),
});

export const MEMORY_GET_TOOL = Object.freeze({
  name: 'memory_get',
  capability: 'memory:read',
  operation: 'authorized_memory_get_v1',
  inputSchema: MemoryGetInputSchema,
  outputSchema: MemoryGetOutputSchema,
  limits: Object.freeze({ maxFilters: 0, maxRows: 1, ...SHARED_LIMITS }),
});

export const MEMORY_LIST_RECENT_TOOL = Object.freeze({
  name: 'memory_list_recent',
  capability: 'memory:read',
  operation: 'authorized_memory_list_recent_v1',
  ordering: 'created_at_desc_id_desc',
  inputSchema: MemoryListRecentInputSchema,
  outputSchema: MemoryListRecentOutputSchema,
  limits: Object.freeze({
    maxFilters: MAX_FILTERS,
    maxRows: MAX_RECENT_ROWS,
    ...SHARED_LIMITS,
  }),
});
