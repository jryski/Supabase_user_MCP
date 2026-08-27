import * as z from 'zod/v4';

export const ISSUE_2_AUTHORIZED_WRITE_LIMITS = {
  identifierLength: 256,
  closureMembers: 100,
  writableTargets: 100,
  readersPerTarget: 100,
  unsafeFlowDiagnostics: 100,
  missingMembersPerDiagnostic: 25,
} as const;

const Issue2IdentifierSchema = z
  .string()
  .min(1)
  .max(ISSUE_2_AUTHORIZED_WRITE_LIMITS.identifierLength)
  .refine((value) => value.trim() === value, 'Identifiers must not have surrounding whitespace.');

const Issue2ReaderClosureSchema = z
  .object({
    principalId: Issue2IdentifierSchema,
    readClosure: z
      .array(Issue2IdentifierSchema)
      .max(ISSUE_2_AUTHORIZED_WRITE_LIMITS.closureMembers),
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
    readerAudienceComplete: z.literal(true),
    readers: z
      .array(Issue2ReaderClosureSchema)
      .max(ISSUE_2_AUTHORIZED_WRITE_LIMITS.readersPerTarget),
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
    writableTargets: z
      .array(Issue2WritableTargetSchema)
      .max(ISSUE_2_AUTHORIZED_WRITE_LIMITS.writableTargets),
  })
  .strict()
  .superRefine(({ writableTargets }, context) => {
    const targetIds = writableTargets.map(({ targetId }) => targetId);
    if (new Set(targetIds).size !== targetIds.length) {
      context.addIssue({ code: 'custom', message: 'Writable targets must be unambiguous.' });
    }
  });

export type Issue2ReaderClosure = z.infer<typeof Issue2ReaderClosureSchema>;
export type Issue2WritableTarget = z.infer<typeof Issue2WritableTargetSchema>;
export type Issue2AuthorizedWriteContainmentInput = z.infer<
  typeof Issue2AuthorizedWriteContainmentInputSchema
>;

export interface Issue2UnsafeFlow {
  targetId: string;
  readerPrincipalId: string;
  missingFromReaderClosure: readonly string[];
  omittedMissingMemberCount: number;
}

export type Issue2AuthorizedWriteContainmentDecision =
  | { allowed: true; reason: 'contained'; unsafeFlows: readonly [] }
  | {
      allowed: false;
      reason: 'unsafe-flow';
      unsafeFlows: readonly Issue2UnsafeFlow[];
      omittedUnsafeFlowCount: number;
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
  let unsafeFlowCount = 0;

  for (const target of policy.writableTargets) {
    for (const reader of target.readers) {
      const readerClosure = new Set(reader.readClosure);
      const missingFromReaderClosure: string[] = [];
      let missingMemberCount = 0;

      for (const resource of policy.writer.readClosure) {
        if (!readerClosure.has(resource)) {
          missingMemberCount += 1;
          if (
            missingFromReaderClosure.length <
            ISSUE_2_AUTHORIZED_WRITE_LIMITS.missingMembersPerDiagnostic
          ) {
            missingFromReaderClosure.push(resource);
          }
        }
      }

      if (missingMemberCount > 0) {
        unsafeFlowCount += 1;
        if (unsafeFlows.length < ISSUE_2_AUTHORIZED_WRITE_LIMITS.unsafeFlowDiagnostics) {
          unsafeFlows.push({
            targetId: target.targetId,
            readerPrincipalId: reader.principalId,
            missingFromReaderClosure,
            omittedMissingMemberCount: missingMemberCount - missingFromReaderClosure.length,
          });
        }
      }
    }
  }

  return unsafeFlows.length === 0
    ? { allowed: true, reason: 'contained', unsafeFlows: [] }
    : {
        allowed: false,
        reason: 'unsafe-flow',
        unsafeFlows,
        omittedUnsafeFlowCount: unsafeFlowCount - unsafeFlows.length,
      };
}
