import { createHash } from 'node:crypto';

import {
  type ArtifactInspectionReceipt,
  ArtifactInspectionReceiptSchema,
  AuthorizationIdentifierSchema,
} from '@supabase-user-mcp/contracts';
import * as z from 'zod/v4';

const CANONICAL_RECEIPT_ERROR = 'Artifact inspection receipt is not canonical.';

export const ARTIFACT_RECEIPT_JOURNAL_PROFILE_VERSION = 'artifact-receipt-journal/0.1' as const;

function rejectNoncanonical(): never {
  throw new TypeError(CANONICAL_RECEIPT_ERROR);
}

function assertCanonicalJsonGraph(value: unknown, seen = new WeakSet<object>()): void {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) rejectNoncanonical();
    return;
  }
  if (typeof value !== 'object') rejectNoncanonical();
  if (seen.has(value)) rejectNoncanonical();
  seen.add(value);

  const prototype = Object.getPrototypeOf(value);
  if (Array.isArray(value)) {
    if (prototype !== Array.prototype) rejectNoncanonical();
    const keys = Reflect.ownKeys(value);
    if (
      keys.some((key) => typeof key !== 'string') ||
      keys.length !== value.length + 1 ||
      keys[keys.length - 1] !== 'length'
    ) {
      rejectNoncanonical();
    }
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (descriptor === undefined || !('value' in descriptor) || !descriptor.enumerable) {
        rejectNoncanonical();
      }
      assertCanonicalJsonGraph(descriptor.value, seen);
    }
    return;
  }

  if (prototype !== Object.prototype && prototype !== null) rejectNoncanonical();
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') rejectNoncanonical();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor) || !descriptor.enumerable) {
      rejectNoncanonical();
    }
    if (key === 'toJSON') rejectNoncanonical();
    assertCanonicalJsonGraph(descriptor.value, seen);
  }
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .toSorted()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(',')}}`;
}

export function canonicalArtifactInspectionReceiptBytes(receipt: unknown): Uint8Array {
  try {
    assertCanonicalJsonGraph(receipt);
    const parsed = ArtifactInspectionReceiptSchema.safeParse(receipt);
    if (!parsed.success) rejectNoncanonical();
    return new TextEncoder().encode(canonicalJson(parsed.data));
  } catch {
    return rejectNoncanonical();
  }
}

export function artifactInspectionReceiptSha256(receipt: unknown): string {
  return createHash('sha256')
    .update(Buffer.from(canonicalArtifactInspectionReceiptBytes(receipt)))
    .digest('hex');
}

export const ARTIFACT_RECEIPT_JOURNAL_ACK_SCHEMA_VERSION =
  'artifact-receipt-journal-ack/0.1' as const;

const LowercaseSha256Schema = z.string().regex(/^[0-9a-f]{64}$/);

export const ArtifactReceiptJournalAcknowledgementSchema = z
  .object({
    schemaVersion: z.literal(ARTIFACT_RECEIPT_JOURNAL_ACK_SCHEMA_VERSION),
    receiptSha256: LowercaseSha256Schema,
    journalRef: AuthorizationIdentifierSchema,
  })
  .strict();
export type ArtifactReceiptJournalAcknowledgement = z.infer<
  typeof ArtifactReceiptJournalAcknowledgementSchema
>;

export interface ArtifactReceiptJournal {
  append(receipt: ArtifactInspectionReceipt, expectedReceiptSha256: string): Promise<unknown>;
}

export class ArtifactReceiptJournalError extends Error {
  readonly code = 'JOURNAL_APPEND_FAILED' as const;

  constructor() {
    super('Artifact receipt journal acknowledgement failed.');
    this.name = 'ArtifactReceiptJournalError';
  }
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const key of Reflect.ownKeys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor !== undefined && 'value' in descriptor) deepFreeze(descriptor.value);
    }
  }
  return value;
}

export async function appendArtifactInspectionReceipt(
  journal: ArtifactReceiptJournal,
  receipt: unknown,
  expectedReceiptSha256: string,
): Promise<ArtifactReceiptJournalAcknowledgement> {
  try {
    assertCanonicalJsonGraph(receipt);
    const parsedReceipt = ArtifactInspectionReceiptSchema.safeParse(receipt);
    if (!parsedReceipt.success || !LowercaseSha256Schema.safeParse(expectedReceiptSha256).success) {
      throw new ArtifactReceiptJournalError();
    }
    const safeReceipt = deepFreeze(parsedReceipt.data);
    if (artifactInspectionReceiptSha256(safeReceipt) !== expectedReceiptSha256) {
      throw new ArtifactReceiptJournalError();
    }

    const rawAcknowledgement = await journal.append(safeReceipt, expectedReceiptSha256);
    const parsedAcknowledgement =
      ArtifactReceiptJournalAcknowledgementSchema.safeParse(rawAcknowledgement);
    if (
      !parsedAcknowledgement.success ||
      parsedAcknowledgement.data.receiptSha256 !== expectedReceiptSha256
    ) {
      throw new ArtifactReceiptJournalError();
    }
    return deepFreeze(parsedAcknowledgement.data);
  } catch {
    throw new ArtifactReceiptJournalError();
  }
}
