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

function expectUnsafeAuthorizedWriteDenied(control: ContainmentControl): void {
  expect(control(unsafeAuthorizedWrite)).toEqual({
    allowed: false,
    reason: 'unsafe-flow',
    unsafeFlows: [
      {
        targetId: 'shared-queue',
        readerPrincipalId: 'lower-trust-consumer',
        missingFromReaderClosure: ['workspace/secret'],
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

  it.each([
    ['malformed', { writer: { principalId: 'agent-a' }, writableTargets: [] }],
    [
      'ambiguous duplicate target',
      {
        writer: { principalId: 'agent-a', readClosure: ['workspace/shared'] },
        writableTargets: [
          { targetId: 'shared-queue', readers: [] },
          { targetId: 'shared-queue', readers: [] },
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
