import { createHash } from 'node:crypto';
import { z } from 'zod';

import { MAX_RESPONSE_BYTES, MAX_TOOL_EXECUTION_MS } from './read-tools.js';

/**
 * PROPOSED contract for issue #122 (ADR-0005). Types, schema and a pure validator
 * only. Nothing here is imported by the server, exported from the package index,
 * or wired into runtime tool registration. An empty registry is the default.
 */

export const CAPABILITY_DESCRIPTOR_VERSION = 'supabase-user-mcp.capability-descriptor.v1';
export const CAPABILITY_REGISTRY_VERSION = 'supabase-user-mcp.capability-registry.v1';

/** Finite upper bound on registered application capabilities. */
export const MAX_REGISTERED_CAPABILITIES = 16;
export const MAX_CAPABILITY_ARGUMENTS = 16;
export const MAX_CAPABILITY_STRING_ARGUMENT_LENGTH = 1_024;
export const MAX_CAPABILITY_DESCRIPTION_LENGTH = 512;

/** Names owned by the fixed server. Application capabilities may never take them. */
export const RESERVED_TOOL_NAMES = Object.freeze([
  'memory_search',
  'memory_get',
  'memory_list_recent',
  'memory_retrieve',
  'session_capabilities_get',
  'system_compatibility_probe',
  'artifact_stat',
  'artifact_read_range',
  'artifact_read_lines',
  'artifact_read_heading',
  'artifact_search_exact',
] as const);

/** Every application capability lives in its own prefix, so it cannot shadow a fixed tool. */
export const APPLICATION_TOOL_PREFIX = 'app_';

/** Database schemas a descriptor may never route to. */
export const FORBIDDEN_RPC_SCHEMAS = Object.freeze([
  'auth',
  'storage',
  'vault',
  'realtime',
  'graphql',
  'graphql_public',
  'extensions',
  'net',
  'cron',
  'pgsodium',
  'pgbouncer',
  'information_schema',
  'pg_catalog',
  'pg_toast',
] as const);

/**
 * Argument names a model could use to forge routing, identity or authority.
 * Descriptors may not declare them; the server supplies routing and identity itself.
 */
export const FORBIDDEN_ARGUMENT_NAMES = Object.freeze([
  'schema',
  'rpc',
  'function',
  'fn',
  'url',
  'endpoint',
  'method',
  'sql',
  'query_sql',
  'relation',
  'table',
  'view',
  'select',
  'headers',
  'authorization',
  'apikey',
  'api_key',
  'token',
  'access_token',
  'refresh_token',
  'jwt',
  'role',
  'user_id',
  'uid',
  'sub',
  'actor',
  'actor_id',
  'principal',
  'owner',
  'owner_id',
  'tenant_id',
  'approved',
  'approval',
  'approver',
] as const);

/**
 * Only these kinds exist. "read" is allowed in the read-only composition;
 * "proposal" only in an explicit application composition. There is no
 * approval, admin or write kind, by construction.
 */
export const CapabilityKindSchema = z.enum(['read', 'proposal']);
export type CapabilityKind = z.infer<typeof CapabilityKindSchema>;

export const CapabilityCompositionSchema = z.enum(['read-only', 'application']);
export type CapabilityComposition = z.infer<typeof CapabilityCompositionSchema>;

const identifierPattern = /^[a-z_][a-z0-9_]{0,62}$/;
const toolNamePattern = /^app_[a-z][a-z0-9_]{2,47}$/;
const argumentNamePattern = /^[a-z][a-z0-9_]{0,31}$/;
const sha256Pattern = /^[0-9a-f]{64}$/;

const forbiddenSchemas = new Set<string>(FORBIDDEN_RPC_SCHEMAS);
const forbiddenArguments = new Set<string>(FORBIDDEN_ARGUMENT_NAMES);
const reservedNames = new Set<string>(RESERVED_TOOL_NAMES);

const boundedText = (max: number) =>
  z
    .string()
    .min(1)
    .max(max)
    .refine(
      (value) =>
        ![...value].some((ch) => {
          const code = ch.codePointAt(0) ?? 0;
          return code < 0x20 || code === 0x7f;
        }),
      'control characters',
    );

const StringArgumentSchema = z.strictObject({
  type: z.literal('string'),
  minLength: z.number().int().min(0).max(MAX_CAPABILITY_STRING_ARGUMENT_LENGTH).optional(),
  maxLength: z.number().int().min(1).max(MAX_CAPABILITY_STRING_ARGUMENT_LENGTH),
  pattern: z
    .string()
    .min(1)
    .max(256)
    .refine((pattern) => {
      try {
        new RegExp(pattern, 'u');
        return true;
      } catch {
        return false;
      }
    }, 'pattern does not compile')
    .optional(),
  enum: z.array(z.string().min(1).max(128)).min(1).max(32).optional(),
});

const IntegerArgumentSchema = z
  .strictObject({
    type: z.literal('integer'),
    minimum: z.number().int().safe(),
    maximum: z.number().int().safe(),
  })
  .refine((value) => value.minimum <= value.maximum, 'minimum exceeds maximum');

const BooleanArgumentSchema = z.strictObject({ type: z.literal('boolean') });

export const CapabilityArgumentSchema = z.union([
  StringArgumentSchema,
  IntegerArgumentSchema,
  BooleanArgumentSchema,
]);

/** Closed JSON-object envelope: flat scalars only, no additional properties. */
export const CapabilityInputSchemaSchema = z
  .strictObject({
    type: z.literal('object'),
    additionalProperties: z.literal(false),
    required: z.array(z.string()).max(MAX_CAPABILITY_ARGUMENTS),
    properties: z.record(z.string(), CapabilityArgumentSchema),
  })
  .superRefine((value, ctx) => {
    const names = Object.keys(value.properties);
    if (names.length > MAX_CAPABILITY_ARGUMENTS) {
      ctx.addIssue({ code: 'custom', message: 'too many arguments' });
    }
    for (const name of names) {
      if (!argumentNamePattern.test(name)) {
        ctx.addIssue({ code: 'custom', message: 'invalid argument name' });
      }
      if (forbiddenArguments.has(name)) {
        ctx.addIssue({ code: 'custom', message: 'forbidden routing or identity argument' });
      }
    }
    if (new Set(value.required).size !== value.required.length) {
      ctx.addIssue({ code: 'custom', message: 'duplicate required argument' });
    }
    for (const name of value.required) {
      if (!Object.hasOwn(value.properties, name)) {
        ctx.addIssue({ code: 'custom', message: 'required argument is not declared' });
      }
    }
  });

/** The descriptor body that a reviewer approves; its digest is pinned in the review record. */
export const CapabilityDescriptorBodySchema = z.strictObject({
  descriptorVersion: z.literal(CAPABILITY_DESCRIPTOR_VERSION),
  name: z
    .string()
    .regex(toolNamePattern)
    .refine((name) => !reservedNames.has(name), 'reserved tool name'),
  title: boundedText(80),
  description: boundedText(MAX_CAPABILITY_DESCRIPTION_LENGTH),
  kind: CapabilityKindSchema,
  rpc: z.strictObject({
    schema: z
      .string()
      .regex(identifierPattern)
      .refine(
        (schema) =>
          !forbiddenSchemas.has(schema) &&
          !schema.startsWith('pg_') &&
          !schema.startsWith('supabase_'),
        'forbidden schema',
      ),
    function: z.string().regex(identifierPattern),
  }),
  inputSchema: CapabilityInputSchemaSchema,
  limits: z.strictObject({
    maxResponseBytes: z.number().int().min(1).max(MAX_RESPONSE_BYTES),
    timeoutMs: z.number().int().min(1).max(MAX_TOOL_EXECUTION_MS),
  }),
});
export type CapabilityDescriptorBody = z.infer<typeof CapabilityDescriptorBodySchema>;

export const CapabilityReviewRecordSchema = z.strictObject({
  /** The accepted ADR (or later superseding ADR) under which this descriptor was reviewed. */
  adr: z.string().regex(/^ADR-\d{4}$/),
  /** sha256 of the canonical descriptor body the reviewers approved. */
  approvedBodySha256: z.string().regex(sha256Pattern),
});

export const CapabilityDescriptorSchema = z.strictObject({
  body: CapabilityDescriptorBodySchema,
  review: CapabilityReviewRecordSchema,
});
export type CapabilityDescriptor = z.infer<typeof CapabilityDescriptorSchema>;

export const CapabilityRegistryInputSchema = z.strictObject({
  registryVersion: z.literal(CAPABILITY_REGISTRY_VERSION),
  composition: CapabilityCompositionSchema,
  descriptors: z.array(z.unknown()).max(MAX_REGISTERED_CAPABILITIES),
});

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const entries = Object.keys(value)
      .sort()
      .map(
        (key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`,
      );
    return `{${entries.join(',')}}`;
  }
  return JSON.stringify(value);
}

/** Stable digest of a descriptor body (sorted keys, no whitespace). */
export function capabilityBodySha256(body: CapabilityDescriptorBody): string {
  return createHash('sha256').update(canonicalJson(body), 'utf8').digest('hex');
}

export type CapabilityRegistrationErrorCode =
  | 'registry_invalid'
  | 'registry_too_large'
  | 'descriptor_invalid'
  | 'descriptor_not_reviewed'
  | 'name_collision'
  | 'rpc_collision'
  | 'kind_denied_in_composition';

export interface CapabilityRegistry {
  readonly registryVersion: typeof CAPABILITY_REGISTRY_VERSION;
  readonly composition: CapabilityComposition;
  readonly names: readonly string[];
  /** Deny-by-default lookup: anything not listed resolves to undefined. */
  resolve(name: string): Readonly<CapabilityDescriptorBody> | undefined;
}

export type CapabilityRegistrationResult =
  | { readonly ok: true; readonly registry: CapabilityRegistry }
  | { readonly ok: false; readonly code: CapabilityRegistrationErrorCode; readonly index?: number };

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    for (const key of Object.keys(value)) deepFreeze((value as Record<string, unknown>)[key]);
    Object.freeze(value);
  }
  return value;
}

/**
 * Registration contract. Validates the whole registry atomically: one bad
 * descriptor rejects everything, and the server would then start with only its
 * fixed tools. Returns a frozen, finite registry; it never reads the database.
 */
export function validateCapabilityRegistry(input: unknown): CapabilityRegistrationResult {
  if (
    input !== null &&
    typeof input === 'object' &&
    Array.isArray((input as { descriptors?: unknown }).descriptors) &&
    (input as { descriptors: unknown[] }).descriptors.length > MAX_REGISTERED_CAPABILITIES
  ) {
    return { ok: false, code: 'registry_too_large' };
  }
  const parsed = CapabilityRegistryInputSchema.safeParse(input);
  if (!parsed.success) return { ok: false, code: 'registry_invalid' };

  const { composition } = parsed.data;
  const entries = new Map<string, CapabilityDescriptorBody>();
  const targets = new Set<string>();

  for (const [index, raw] of parsed.data.descriptors.entries()) {
    const descriptor = CapabilityDescriptorSchema.safeParse(raw);
    if (!descriptor.success) return { ok: false, code: 'descriptor_invalid', index };
    const { body, review } = descriptor.data;
    if (capabilityBodySha256(body) !== review.approvedBodySha256) {
      return { ok: false, code: 'descriptor_not_reviewed', index };
    }
    if (composition === 'read-only' && body.kind !== 'read') {
      return { ok: false, code: 'kind_denied_in_composition', index };
    }
    if (entries.has(body.name)) return { ok: false, code: 'name_collision', index };
    const target = `${body.rpc.schema}.${body.rpc.function}`;
    if (targets.has(target)) return { ok: false, code: 'rpc_collision', index };
    entries.set(body.name, deepFreeze(structuredClone(body)));
    targets.add(target);
  }

  const names = Object.freeze([...entries.keys()].sort());
  const registry: CapabilityRegistry = Object.freeze({
    registryVersion: CAPABILITY_REGISTRY_VERSION,
    composition,
    names,
    resolve(name: string) {
      return typeof name === 'string' ? entries.get(name) : undefined;
    },
  });
  return { ok: true, registry };
}

/**
 * Call-time argument check for a registered descriptor: a closed object with
 * exactly the declared scalar arguments. Extra keys (including forged routing
 * or identity fields) are rejected, never stripped. Pure; performs no call.
 */
export function validateCapabilityArguments(
  body: Readonly<CapabilityDescriptorBody>,
  args: unknown,
):
  | { readonly ok: true; readonly value: Readonly<Record<string, string | number | boolean>> }
  | { readonly ok: false } {
  if (args === null || typeof args !== 'object' || Array.isArray(args)) return { ok: false };
  const record = args as Record<string, unknown>;
  const declared = body.inputSchema.properties;
  for (const key of Object.keys(record)) {
    if (!Object.hasOwn(declared, key)) return { ok: false };
  }
  for (const key of body.inputSchema.required) {
    if (!Object.hasOwn(record, key)) return { ok: false };
  }
  const value: Record<string, string | number | boolean> = {};
  for (const [key, spec] of Object.entries(declared)) {
    if (!Object.hasOwn(record, key)) continue;
    const item = record[key];
    if (spec.type === 'string') {
      if (typeof item !== 'string') return { ok: false };
      if (item.length > spec.maxLength || item.length < (spec.minLength ?? 0)) return { ok: false };
      if (spec.enum !== undefined && !spec.enum.includes(item)) return { ok: false };
      if (spec.pattern !== undefined && !new RegExp(spec.pattern, 'u').test(item))
        return { ok: false };
    } else if (spec.type === 'integer') {
      if (typeof item !== 'number' || !Number.isSafeInteger(item)) return { ok: false };
      if (item < spec.minimum || item > spec.maximum) return { ok: false };
    } else if (typeof item !== 'boolean') {
      return { ok: false };
    }
    value[key] = item;
  }
  return { ok: true, value: Object.freeze(value) };
}
