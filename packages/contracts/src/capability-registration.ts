import { createHash } from 'node:crypto';
import { z } from 'zod';

import { MAX_RESPONSE_BYTES, MAX_TOOL_EXECUTION_MS } from './read-tools.js';

/**
 * PROPOSED contract for issue #122 (ADR-0005). Types, schemas and pure validators
 * only. Nothing here is imported by the server, exported from the package index,
 * or wired into runtime tool registration. An empty registry is the default.
 *
 * Authority split (ADR-0005):
 * - The adopter's descriptor file proposes capabilities. It cannot choose its own
 *   composition, approve itself, or name a schema the server did not allow.
 * - The server supplies a CapabilityServerPolicy: the composition, the adopter
 *   schema allowlist, and the release-shipped approval allowlist.
 */

export const CAPABILITY_DESCRIPTOR_VERSION = 'supabase-user-mcp.capability-descriptor.v1';
export const CAPABILITY_REGISTRY_VERSION = 'supabase-user-mcp.capability-registry.v1';
export const CAPABILITY_APPROVAL_ALLOWLIST_VERSION = 'supabase-user-mcp.capability-approvals.v1';

/** Finite upper bound on registered application capabilities. */
export const MAX_REGISTERED_CAPABILITIES = 16;
export const MAX_CAPABILITY_ARGUMENTS = 16;
export const MAX_CAPABILITY_STRING_ARGUMENT_LENGTH = 1_024;
export const MAX_CAPABILITY_DESCRIPTION_LENGTH = 512;
export const MAX_ADOPTER_SCHEMAS = 8;
/** Bound on object nesting inspected by the own-__proto__ pre-pass. */
const MAX_INSPECTED_DEPTH = 16;

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

/**
 * Schemas that can never be an adopter schema, even if a server policy lists them.
 * Defence in depth behind the positive allowlist; the database stays authoritative.
 */
export const FORBIDDEN_RPC_SCHEMAS = Object.freeze([
  'public',
  'auth',
  'storage',
  'vault',
  'realtime',
  'extensions',
  'net',
  'cron',
  'pgbouncer',
  'information_schema',
] as const);
/** Prefixes covering platform families (graphql*, pg*, pgsodium*, pgmq*, pgtle, supabase_*). */
export const FORBIDDEN_RPC_SCHEMA_PREFIXES = Object.freeze(['graphql', 'pg', 'supabase_'] as const);

/**
 * Argument-name tokens (split on "_") that could forge routing, identity,
 * credentials or approval. Any token match rejects the argument name.
 * Tokens starting with "approv" are also rejected.
 */
export const FORBIDDEN_ARGUMENT_TOKENS = Object.freeze([
  'schema',
  'rpc',
  'function',
  'fn',
  'url',
  'uri',
  'endpoint',
  'method',
  'sql',
  'relation',
  'table',
  'view',
  'select',
  'header',
  'headers',
  'authorization',
  'auth',
  'apikey',
  'key',
  'token',
  'jwt',
  'secret',
  'password',
  'credential',
  'credentials',
  'session',
  'service',
  'role',
  'user',
  'userid',
  'uid',
  'sub',
  'actor',
  'principal',
  'owner',
  'tenant',
  'admin',
] as const);
const forbiddenTokens = new Set<string>(FORBIDDEN_ARGUMENT_TOKENS);

export function isForbiddenArgumentName(name: string): boolean {
  return name.split('_').some((token) => forbiddenTokens.has(token) || token.startsWith('approv'));
}

export function isForbiddenSchemaName(schema: string): boolean {
  return (
    (FORBIDDEN_RPC_SCHEMAS as readonly string[]).includes(schema) ||
    FORBIDDEN_RPC_SCHEMA_PREFIXES.some((prefix) => schema.startsWith(prefix)) ||
    schema.startsWith('_')
  );
}

/**
 * Only these kinds exist. "read" is allowed in the read-only composition;
 * "proposal" only when the server itself selects the application composition.
 * There is no approval, admin or write kind, by construction.
 */
export const CapabilityKindSchema = z.enum(['read', 'proposal']);
export type CapabilityKind = z.infer<typeof CapabilityKindSchema>;

export const CapabilityCompositionSchema = z.enum(['read-only', 'application']);
export type CapabilityComposition = z.infer<typeof CapabilityCompositionSchema>;

const schemaNamePattern = /^[a-z][a-z0-9_]{0,62}$/;
const functionNamePattern = /^[a-z][a-z0-9_]{0,62}$/;
const toolNamePattern = /^app_[a-z][a-z0-9_]{2,47}$/;
const argumentNamePattern = /^[a-z][a-z0-9_]{0,31}$/;
const sha256Pattern = /^[0-9a-f]{64}$/;
const adrPattern = /^ADR-\d{4}$/;
/** Unicode Cc, Cf, Zl and Zp: control, format (incl. bidi and zero-width) and separators. */
const unreviewableCharacters = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;

const reservedNames = new Set<string>(RESERVED_TOOL_NAMES);

function isReviewableText(value: string, max: number): boolean {
  // Length is checked first so oversized input never reaches the character scan.
  return value.length <= max && !unreviewableCharacters.test(value);
}

const boundedText = (max: number) =>
  z
    .string()
    .min(1)
    .max(max)
    .refine((value) => value.length > max || isReviewableText(value, max), 'unreviewable text');

/** v1 strings: bounded length and optional enum. No regex `pattern` (ADR-0005, M4). */
const StringArgumentSchema = z
  .strictObject({
    type: z.literal('string'),
    minLength: z.number().int().min(0).max(MAX_CAPABILITY_STRING_ARGUMENT_LENGTH).optional(),
    maxLength: z.number().int().min(1).max(MAX_CAPABILITY_STRING_ARGUMENT_LENGTH),
    enum: z.array(boundedText(128)).min(1).max(32).optional(),
  })
  .superRefine((value, ctx) => {
    const min = value.minLength ?? 0;
    if (min > value.maxLength)
      ctx.addIssue({ code: 'custom', message: 'minLength exceeds maxLength' });
    if (value.enum !== undefined) {
      if (new Set(value.enum).size !== value.enum.length) {
        ctx.addIssue({ code: 'custom', message: 'duplicate enum value' });
      }
      if (value.enum.some((item) => item.length < min || item.length > value.maxLength)) {
        ctx.addIssue({ code: 'custom', message: 'enum value outside length bounds' });
      }
    }
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
      if (isForbiddenArgumentName(name)) {
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

/** The descriptor body that reviewers approve; its digest must be in the release allowlist. */
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
      .regex(schemaNamePattern)
      .refine((schema) => !isForbiddenSchemaName(schema), 'forbidden schema'),
    function: z.string().regex(functionNamePattern),
  }),
  inputSchema: CapabilityInputSchemaSchema,
  limits: z.strictObject({
    maxResponseBytes: z.number().int().min(1).max(MAX_RESPONSE_BYTES),
    timeoutMs: z.number().int().min(1).max(MAX_TOOL_EXECUTION_MS),
  }),
});
export type CapabilityDescriptorBody = z.infer<typeof CapabilityDescriptorBodySchema>;

/**
 * In-config link to the external approval record. This is an integrity
 * reference only: it is never proof of review on its own.
 */
export const CapabilityApprovalReferenceSchema = z.strictObject({
  adr: z.string().regex(adrPattern),
  bodySha256: z.string().regex(sha256Pattern),
});

export const CapabilityDescriptorSchema = z.strictObject({
  body: CapabilityDescriptorBodySchema,
  approval: CapabilityApprovalReferenceSchema,
});
export type CapabilityDescriptor = z.infer<typeof CapabilityDescriptorSchema>;

/** Adopter-supplied registry file. It has no composition or approval fields. */
export const CapabilityRegistryInputSchema = z.strictObject({
  registryVersion: z.literal(CAPABILITY_REGISTRY_VERSION),
  descriptors: z.array(z.unknown()).max(MAX_REGISTERED_CAPABILITIES),
});

/**
 * Release-shipped approval allowlist (ADR-0005 option 1). It is installed with
 * the server release in a location the running agent cannot write, and is
 * loaded by server code, never from the adopter's descriptor file.
 */
export const CapabilityApprovalAllowlistSchema = z.strictObject({
  allowlistVersion: z.literal(CAPABILITY_APPROVAL_ALLOWLIST_VERSION),
  approvals: z
    .array(
      z.strictObject({
        adr: z.string().regex(adrPattern),
        bodySha256: z.string().regex(sha256Pattern),
      }),
    )
    .max(MAX_REGISTERED_CAPABILITIES),
});
export type CapabilityApprovalAllowlist = z.infer<typeof CapabilityApprovalAllowlistSchema>;

/** Server-owned inputs. Never read from the adopter's registry file. */
export interface CapabilityServerPolicy {
  readonly composition: CapabilityComposition;
  /** Adopter schemas this server may route to. `public` and platform schemas are always refused. */
  readonly adopterSchemas: readonly string[];
  /** Parsed release-shipped allowlist; see {@link parseCapabilityApprovalAllowlist}. */
  readonly approvals: CapabilityApprovalAllowlist;
}

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

/** Rejects any own `__proto__` key (zod would otherwise drop it silently). */
function hasOwnProtoKey(value: unknown, depth = 0): boolean {
  if (value === null || typeof value !== 'object') return false;
  if (depth > MAX_INSPECTED_DEPTH) return true;
  if (Object.hasOwn(value, '__proto__')) return true;
  return Object.values(value).some((child) => hasOwnProtoKey(child, depth + 1));
}

/** Snapshot untrusted input once: getters run once, functions and symbols are refused. */
function snapshot(input: unknown): { ok: true; value: unknown } | { ok: false } {
  try {
    const value = structuredClone(input);
    return hasOwnProtoKey(value) ? { ok: false } : { ok: true, value };
  } catch {
    return { ok: false };
  }
}

export function parseCapabilityApprovalAllowlist(
  input: unknown,
): { readonly ok: true; readonly allowlist: CapabilityApprovalAllowlist } | { readonly ok: false } {
  const copy = snapshot(input);
  if (!copy.ok) return { ok: false };
  const parsed = CapabilityApprovalAllowlistSchema.safeParse(copy.value);
  return parsed.success ? { ok: true, allowlist: deepFreeze(parsed.data) } : { ok: false };
}

export type CapabilityRegistrationErrorCode =
  | 'policy_invalid'
  | 'registry_invalid'
  | 'registry_too_large'
  | 'descriptor_invalid'
  | 'descriptor_digest_mismatch'
  | 'descriptor_not_approved'
  | 'schema_not_allowed'
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
  | {
      readonly ok: false;
      readonly code: CapabilityRegistrationErrorCode;
      readonly index?: number;
    };

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    for (const key of Object.keys(value)) deepFreeze((value as Record<string, unknown>)[key]);
    Object.freeze(value);
  }
  return value;
}

function validatePolicy(policy: CapabilityServerPolicy): ReadonlySet<string> | undefined {
  if (!CapabilityCompositionSchema.safeParse(policy?.composition).success) return undefined;
  const schemas = policy.adopterSchemas;
  if (!Array.isArray(schemas) || schemas.length > MAX_ADOPTER_SCHEMAS) return undefined;
  for (const schema of schemas) {
    if (typeof schema !== 'string' || !schemaNamePattern.test(schema)) return undefined;
    if (isForbiddenSchemaName(schema)) return undefined;
  }
  if (!CapabilityApprovalAllowlistSchema.safeParse(policy.approvals).success) return undefined;
  return new Set(schemas);
}

/**
 * Registration contract. Validates the whole registry atomically against a
 * server-owned policy: one bad descriptor rejects everything, and the server
 * would then start with only its fixed tools. Returns a frozen, finite
 * registry; it never reads files, the network or the database.
 */
export function validateCapabilityRegistry(
  input: unknown,
  policy: CapabilityServerPolicy,
): CapabilityRegistrationResult {
  const allowedSchemas = validatePolicy(policy);
  if (allowedSchemas === undefined) return { ok: false, code: 'policy_invalid' };
  const approved = new Set(
    policy.approvals.approvals.map((entry) => `${entry.adr}:${entry.bodySha256}`),
  );

  const copy = snapshot(input);
  if (!copy.ok) return { ok: false, code: 'registry_invalid' };
  const data = copy.value;
  if (
    data !== null &&
    typeof data === 'object' &&
    Array.isArray((data as { descriptors?: unknown }).descriptors) &&
    (data as { descriptors: unknown[] }).descriptors.length > MAX_REGISTERED_CAPABILITIES
  ) {
    return { ok: false, code: 'registry_too_large' };
  }
  const parsed = CapabilityRegistryInputSchema.safeParse(data);
  if (!parsed.success) return { ok: false, code: 'registry_invalid' };

  const { composition } = policy;
  const entries = new Map<string, CapabilityDescriptorBody>();
  const targets = new Set<string>();

  for (const [index, raw] of parsed.data.descriptors.entries()) {
    const descriptor = CapabilityDescriptorSchema.safeParse(raw);
    if (!descriptor.success) return { ok: false, code: 'descriptor_invalid', index };
    const { body, approval } = descriptor.data;
    if (capabilityBodySha256(body) !== approval.bodySha256) {
      return { ok: false, code: 'descriptor_digest_mismatch', index };
    }
    if (!approved.has(`${approval.adr}:${approval.bodySha256}`)) {
      return { ok: false, code: 'descriptor_not_approved', index };
    }
    if (!allowedSchemas.has(body.rpc.schema)) {
      return { ok: false, code: 'schema_not_allowed', index };
    }
    if (composition === 'read-only' && body.kind !== 'read') {
      return { ok: false, code: 'kind_denied_in_composition', index };
    }
    if (entries.has(body.name)) return { ok: false, code: 'name_collision', index };
    const target = `${body.rpc.schema}.${body.rpc.function}`;
    if (targets.has(target)) return { ok: false, code: 'rpc_collision', index };
    entries.set(body.name, deepFreeze(body));
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
 * or identity fields) are rejected, never stripped. Linear time; no regex on
 * model input. Pure; performs no call.
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
