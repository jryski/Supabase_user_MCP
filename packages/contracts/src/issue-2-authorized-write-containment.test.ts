import { describe, expect, it } from 'vitest';

import {
  type Issue2AuthorizedWriteContainmentDecision,
  evaluateIssue2AuthorizedWriteContainment,
} from './issue-2-authorized-write-containment.js';

const unsafeAuthorizedWrite = {
  writer: {
    principalId: 'agent-a',
    readClosure: ['workspace/shared', 'workspace/secret'],
  },
  writableTargets: [
    {
      targetId: 'shared-queue',
      readerAudienceComplete: true,
      readers: [
        {
          principalId: 'lower-trust-consumer',
          readClosure: ['workspace/shared'],
        },
      ],
    },
  ],
} as const;

type ContainmentControl = (input: unknown) => Issue2AuthorizedWriteContainmentDecision;

const LIMITS = {
  identifierLength: 256,
  closureMembers: 100,
  writableTargets: 100,
  readersPerTarget: 100,
} as const;

const validWriter = { principalId: 'agent-a', readClosure: [] } as const;

function expectInvalid(input: unknown): void {
  expect(evaluateIssue2AuthorizedWriteContainment(input)).toEqual({
    allowed: false,
    reason: 'invalid-input',
    unsafeFlows: [],
  });
}

function expectUnsafeAuthorizedWriteDenied(control: ContainmentControl): void {
  expect(control(unsafeAuthorizedWrite)).toEqual({
    allowed: false,
    reason: 'unsafe-flow',
    omittedUnsafeFlowCount: 0,
    unsafeFlows: [
      {
        targetId: 'shared-queue',
        readerPrincipalId: 'lower-trust-consumer',
        missingFromReaderClosure: ['workspace/secret'],
        omittedMissingMemberCount: 0,
      },
    ],
  });
}

describe('issue #2 authorized-write containment contract', () => {
  it('denies an authorized write when a target reader lacks part of the writer read closure', () => {
    expectUnsafeAuthorizedWriteDenied(evaluateIssue2AuthorizedWriteContainment);
  });

  it('allows a write when every target reader read closure contains the writer read closure', () => {
    expect(
      evaluateIssue2AuthorizedWriteContainment({
        writer: {
          principalId: 'agent-a',
          readClosure: ['workspace/shared', 'workspace/secret'],
        },
        writableTargets: [
          {
            targetId: 'contained-queue',
            readerAudienceComplete: true,
            readers: [
              {
                principalId: 'same-scope-consumer',
                readClosure: ['workspace/shared', 'workspace/secret'],
              },
              {
                principalId: 'broader-scope-consumer',
                readClosure: ['workspace/shared', 'workspace/secret', 'workspace/archive'],
              },
            ],
          },
        ],
      }),
    ).toEqual({
      allowed: true,
      reason: 'contained',
      unsafeFlows: [],
    });
  });

  it('proves the unsafe-flow oracle rejects a deliberate fail-open control mutant', () => {
    const failOpenMutant: ContainmentControl = () => ({
      allowed: true,
      reason: 'contained',
      unsafeFlows: [],
    });

    expect(() => expectUnsafeAuthorizedWriteDenied(failOpenMutant)).toThrow();
  });

  it('distinguishes a verified empty audience from an unknown or omitted audience', () => {
    const base = {
      writer: { principalId: 'agent-a', readClosure: ['workspace/secret'] },
      writableTargets: [{ targetId: 'private-draft', readers: [] }],
    };

    expectInvalid(base);
    expectInvalid({
      ...base,
      writableTargets: [{ ...base.writableTargets[0], readerAudienceComplete: false }],
    });
    expect(
      evaluateIssue2AuthorizedWriteContainment({
        ...base,
        writableTargets: [{ ...base.writableTargets[0], readerAudienceComplete: true }],
      }),
    ).toEqual({ allowed: true, reason: 'contained', unsafeFlows: [] });
  });

  it('accepts identifiers at the limit and rejects identifiers one character over', () => {
    const atLimit = 'a'.repeat(LIMITS.identifierLength);
    expect(
      evaluateIssue2AuthorizedWriteContainment({
        writer: { principalId: atLimit, readClosure: [] },
        writableTargets: [],
      }),
    ).toEqual({ allowed: true, reason: 'contained', unsafeFlows: [] });
    expectInvalid({
      writer: { principalId: `${atLimit}a`, readClosure: [] },
      writableTargets: [],
    });
  });

  it('accepts each collection at its cardinality limit', () => {
    const closure = Array.from({ length: LIMITS.closureMembers }, (_, index) => `r-${index}`);
    const readers = Array.from({ length: LIMITS.readersPerTarget }, (_, index) => ({
      principalId: `reader-${index}`,
      readClosure: closure,
    }));
    const writableTargets = Array.from({ length: LIMITS.writableTargets }, (_, index) => ({
      targetId: `target-${index}`,
      readerAudienceComplete: true,
      readers,
    }));

    expect(
      evaluateIssue2AuthorizedWriteContainment({
        writer: { principalId: 'agent-a', readClosure: closure },
        writableTargets,
      }),
    ).toEqual({ allowed: true, reason: 'contained', unsafeFlows: [] });
  });

  it.each([
    [
      'writer closure',
      {
        writer: {
          principalId: 'agent-a',
          readClosure: Array.from(
            { length: LIMITS.closureMembers + 1 },
            (_, index) => `r-${index}`,
          ),
        },
        writableTargets: [],
      },
    ],
    [
      'writable targets',
      {
        writer: validWriter,
        writableTargets: Array.from({ length: LIMITS.writableTargets + 1 }, (_, index) => ({
          targetId: `target-${index}`,
          readerAudienceComplete: true,
          readers: [],
        })),
      },
    ],
    [
      'target readers',
      {
        writer: validWriter,
        writableTargets: [
          {
            targetId: 'target',
            readerAudienceComplete: true,
            readers: Array.from({ length: LIMITS.readersPerTarget + 1 }, (_, index) => ({
              principalId: `reader-${index}`,
              readClosure: [],
            })),
          },
        ],
      },
    ],
  ])('rejects %s one over the cardinality limit', (_case, input) => {
    expectInvalid(input);
  });

  it.each([
    [10, 100, 0],
    [11, 100, 10],
  ])(
    'bounds diagnostics for %i unsafe targets across multiple readers at %i with %i omitted',
    (targetCount, expectedVisible, expectedOmitted) => {
      const writableTargets = Array.from({ length: targetCount }, (_, targetIndex) => ({
        targetId: `target-${targetIndex}`,
        readerAudienceComplete: true,
        readers: Array.from({ length: 10 }, (_, readerIndex) => ({
          principalId: `reader-${readerIndex}`,
          readClosure: [],
        })),
      }));
      const decision = evaluateIssue2AuthorizedWriteContainment({
        writer: { principalId: 'agent-a', readClosure: ['workspace/secret'] },
        writableTargets,
      });

      expect(decision.allowed).toBe(false);
      if (decision.reason !== 'unsafe-flow') throw new Error('expected unsafe-flow decision');
      expect(decision.unsafeFlows).toHaveLength(expectedVisible);
      expect(decision.omittedUnsafeFlowCount).toBe(expectedOmitted);
      expect(decision.unsafeFlows[0]).toEqual({
        targetId: 'target-0',
        readerPrincipalId: 'reader-0',
        missingFromReaderClosure: ['workspace/secret'],
        omittedMissingMemberCount: 0,
      });
    },
  );

  it.each([
    [25, 25, 0],
    [26, 25, 1],
  ])(
    'bounds %i missing closure members to %i with omitted count %i',
    (memberCount, expectedVisible, expectedOmitted) => {
      const decision = evaluateIssue2AuthorizedWriteContainment({
        writer: {
          principalId: 'agent-a',
          readClosure: Array.from({ length: memberCount }, (_, index) => `secret-${index}`),
        },
        writableTargets: [
          {
            targetId: 'target',
            readerAudienceComplete: true,
            readers: [{ principalId: 'reader', readClosure: [] }],
          },
        ],
      });

      expect(decision.allowed).toBe(false);
      if (decision.reason !== 'unsafe-flow') throw new Error('expected unsafe-flow decision');
      expect(decision.unsafeFlows[0]?.missingFromReaderClosure).toHaveLength(expectedVisible);
      expect(decision.unsafeFlows[0]?.omittedMissingMemberCount).toBe(expectedOmitted);
    },
  );

  it.each([
    ['malformed', { writer: { principalId: 'agent-a' }, writableTargets: [] }],
    [
      'duplicate writer closure member',
      {
        writer: {
          principalId: 'agent-a',
          readClosure: ['workspace/shared', 'workspace/shared'],
        },
        writableTargets: [],
      },
    ],
    ['unknown top-level field', { writer: validWriter, writableTargets: [], unexpected: true }],
    [
      'unknown writer field',
      {
        writer: { ...validWriter, unexpected: true },
        writableTargets: [],
      },
    ],
    [
      'unknown target field',
      {
        writer: validWriter,
        writableTargets: [
          {
            targetId: 'target',
            readerAudienceComplete: true,
            readers: [],
            unexpected: true,
          },
        ],
      },
    ],
    [
      'unknown reader field',
      {
        writer: validWriter,
        writableTargets: [
          {
            targetId: 'target',
            readerAudienceComplete: true,
            readers: [{ principalId: 'reader', readClosure: [], unexpected: true }],
          },
        ],
      },
    ],
    [
      'ambiguous duplicate target',
      {
        writer: { principalId: 'agent-a', readClosure: ['workspace/shared'] },
        writableTargets: [
          { targetId: 'shared-queue', readerAudienceComplete: true, readers: [] },
          { targetId: 'shared-queue', readerAudienceComplete: true, readers: [] },
        ],
      },
    ],
    [
      'ambiguous duplicate reader',
      {
        writer: { principalId: 'agent-a', readClosure: ['workspace/shared'] },
        writableTargets: [
          {
            targetId: 'shared-queue',
            readerAudienceComplete: true,
            readers: [
              { principalId: 'consumer', readClosure: ['workspace/shared'] },
              { principalId: 'consumer', readClosure: ['workspace/shared'] },
            ],
          },
        ],
      },
    ],
  ])('fails closed for %s input', (_case, input) => {
    expect(evaluateIssue2AuthorizedWriteContainment(input)).toEqual({
      allowed: false,
      reason: 'invalid-input',
      unsafeFlows: [],
    });
  });
});
