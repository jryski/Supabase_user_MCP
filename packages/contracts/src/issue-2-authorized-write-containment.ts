import * as z from 'zod/v4';

const Issue2IdentifierSchema = z
  .string()
  .min(1)
  .refine((value) => value.trim() === value, 'Identifiers must not have surrounding whitespace.');

const Issue2ReaderClosureSchema = z
  .object({
    principalId: Issue2IdentifierSchema,
    readClosure: z.array(Issue2IdentifierSchema),
  })
  .strict()
  .superRefine(({ readClosure }, context) => {
    if (new Set(readClosure).size !== readClosure.length) {
      context.addIssue({ code: 'custom', message: 'Read closures must not contain duplicates.' });
    }
  });

const Issue2WritableTargetSchema = z
  .object({
    targetId: Issue2IdentifierSchema,
    readers: z.array(Issue2ReaderClosureSchema),
  })
  .strict()
  .superRefine(({ readers }, context) => {
    const principalIds = readers.map(({ principalId }) => principalId);
    if (new Set(principalIds).size !== principalIds.length) {
      context.addIssue({ code: 'custom', message: 'Target readers must be unambiguous.' });
    }
  });

export const Issue2AuthorizedWriteContainmentInputSchema = z
  .object({
    writer: Issue2ReaderClosureSchema,
    writableTargets: z.array(Issue2WritableTargetSchema),
  })
  .strict()
  .superRefine(({ writableTargets }, context) => {
    const targetIds = writableTargets.map(({ targetId }) => targetId);
    if (new Set(targetIds).size !== targetIds.length) {
      context.addIssue({ code: 'custom', message: 'Writable targets must be unambiguous.' });
    }
  });

export interface Issue2ReaderClosure {
  principalId: string;
  readClosure: readonly string[];
}

export interface Issue2WritableTarget {
  targetId: string;
  readers: readonly Issue2ReaderClosure[];
}

export interface Issue2AuthorizedWriteContainmentInput {
  writer: Issue2ReaderClosure;
  writableTargets: readonly Issue2WritableTarget[];
}

export interface Issue2UnsafeFlow {
  targetId: string;
  readerPrincipalId: string;
  missingFromReaderClosure: readonly string[];
}

export type Issue2AuthorizedWriteContainmentDecision =
  | { allowed: true; reason: 'contained'; unsafeFlows: readonly [] }
  | {
      allowed: false;
      reason: 'unsafe-flow';
      unsafeFlows: readonly Issue2UnsafeFlow[];
    }
  | { allowed: false; reason: 'invalid-input'; unsafeFlows: readonly [] };

export function evaluateIssue2AuthorizedWriteContainment(
  input: unknown,
): Issue2AuthorizedWriteContainmentDecision {
  const parsed = Issue2AuthorizedWriteContainmentInputSchema.safeParse(input);
  if (!parsed.success) {
    return { allowed: false, reason: 'invalid-input', unsafeFlows: [] };
  }

  const policy = parsed.data;
  const unsafeFlows: Issue2UnsafeFlow[] = [];

  for (const target of policy.writableTargets) {
    for (const reader of target.readers) {
      const readerClosure = new Set(reader.readClosure);
      const missingFromReaderClosure = policy.writer.readClosure.filter(
        (resource) => !readerClosure.has(resource),
      );

      if (missingFromReaderClosure.length > 0) {
        unsafeFlows.push({
          targetId: target.targetId,
          readerPrincipalId: reader.principalId,
          missingFromReaderClosure,
        });
      }
    }
  }

  return unsafeFlows.length === 0
    ? { allowed: true, reason: 'contained', unsafeFlows: [] }
    : { allowed: false, reason: 'unsafe-flow', unsafeFlows };
}
