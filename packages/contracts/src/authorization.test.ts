import { describe, expect, it } from 'vitest';

import {
  AccessMatrixSchema,
  AUTHORIZATION_STATES,
  AuthorizationAccessRowSchema,
  CAPABILITIES,
  CapabilitySchema,
  ClientStateSchema,
  DENIAL_REASON_CLASSES,
  DenialReasonClassSchema,
  ExpectedResultSchema,
  GrantStateSchema,
  IDENTITY_ELIGIBILITY_STATES,
  IdentityEligibilitySchema,
  MembershipStateSchema,
  PRINCIPAL_KINDS,
  PrincipalKindSchema,
} from './authorization.js';

const VALID_ROW = {
  principal: {
    id: 'principal-human-1',
    kind: 'human',
    identityEligibility: 'verified',
  },
  client: { id: 'client-cli-1', state: 'active' },
  workspace: { id: 'workspace-alpha', membershipState: 'active' },
  grantState: 'active',
  capability: 'memory:read',
  recordState: 'present',
  expectedResult: { decision: 'allow' },
} as const;

describe('authorization vocabulary', () => {
  it('freezes every exported vocabulary array at runtime', () => {
    const vocabularies = [
      PRINCIPAL_KINDS,
      IDENTITY_ELIGIBILITY_STATES,
      AUTHORIZATION_STATES,
      CAPABILITIES,
      DENIAL_REASON_CLASSES,
    ];

    for (const vocabulary of vocabularies) {
      expect(Object.isFrozen(vocabulary)).toBe(true);
    }
  });

  it('accepts exactly the frozen principal kinds', () => {
    const principalKinds = [
      'human',
      'delegated_agent',
      'service_agent',
      'reviewer',
      'system_worker',
    ] as const;

    for (const principalKind of principalKinds) {
      expect(PrincipalKindSchema.parse(principalKind)).toBe(principalKind);
    }

    expect(PrincipalKindSchema.safeParse('owner').success).toBe(false);
    expect(PrincipalKindSchema.safeParse('*').success).toBe(false);
  });

  it('accepts only explicit lifecycle states and memory read capabilities', () => {
    expect(IdentityEligibilitySchema.parse('verified')).toBe('verified');
    expect(IdentityEligibilitySchema.parse('denied')).toBe('denied');
    expect(IdentityEligibilitySchema.safeParse('active').success).toBe(false);

    for (const schema of [MembershipStateSchema, ClientStateSchema, GrantStateSchema]) {
      for (const state of ['active', 'expired', 'revoked']) {
        expect(schema.parse(state)).toBe(state);
      }
      expect(schema.safeParse('pending').success).toBe(false);
      expect(schema.safeParse('*').success).toBe(false);
    }

    expect(CapabilitySchema.parse('memory:search')).toBe('memory:search');
    expect(CapabilitySchema.parse('memory:read')).toBe('memory:read');
    expect(CapabilitySchema.safeParse('memory:*').success).toBe(false);
    expect(CapabilitySchema.safeParse('*').success).toBe(false);
  });

  it('requires unambiguous outcomes with stable non-enumerating denial classes', () => {
    const denialReasons = [
      'identity_denied',
      'client_denied',
      'membership_denied',
      'capability_denied',
      'record_unavailable',
    ] as const;

    for (const denialReason of denialReasons) {
      expect(DenialReasonClassSchema.parse(denialReason)).toBe(denialReason);
      expect(ExpectedResultSchema.parse({ decision: 'deny', denialReason })).toEqual({
        decision: 'deny',
        denialReason,
      });
    }

    expect(ExpectedResultSchema.parse({ decision: 'allow' })).toEqual({ decision: 'allow' });
    expect(ExpectedResultSchema.safeParse({ decision: 'deny' }).success).toBe(false);
    expect(
      ExpectedResultSchema.safeParse({ decision: 'allow', denialReason: 'record_unavailable' })
        .success,
    ).toBe(false);
    expect(
      ExpectedResultSchema.safeParse({
        decision: 'deny',
        denialReason: 'record_missing',
      }).success,
    ).toBe(false);
    expect(ExpectedResultSchema.safeParse({ decision: 'deny', result: 'allow' }).success).toBe(
      false,
    );
  });

  it.each([
    {
      boundary: 'identity',
      row: {
        ...VALID_ROW,
        principal: { ...VALID_ROW.principal, identityEligibility: 'denied' },
      },
    },
    {
      boundary: 'client',
      row: { ...VALID_ROW, client: { ...VALID_ROW.client, state: 'expired' } },
    },
    {
      boundary: 'membership',
      row: {
        ...VALID_ROW,
        workspace: { ...VALID_ROW.workspace, membershipState: 'revoked' },
      },
    },
    { boundary: 'grant', row: { ...VALID_ROW, grantState: 'revoked' } },
    { boundary: 'record', row: { ...VALID_ROW, recordState: 'absent' } },
  ] as const)('rejects an insecure allow when $boundary is ineligible', ({ row }) => {
    expect(AuthorizationAccessRowSchema.safeParse(row).success).toBe(false);
  });

  it.each([
    {
      fixture: 'cross-principal',
      row: {
        ...VALID_ROW,
        principal: {
          ...VALID_ROW.principal,
          id: 'principal-human-2',
          identityEligibility: 'denied',
        },
        expectedResult: { decision: 'deny', denialReason: 'identity_denied' },
      },
    },
    {
      fixture: 'cross-client',
      row: {
        ...VALID_ROW,
        client: { id: 'client-cli-2', state: 'revoked' },
        expectedResult: { decision: 'deny', denialReason: 'client_denied' },
      },
    },
    {
      fixture: 'cross-workspace',
      row: {
        ...VALID_ROW,
        workspace: { id: 'workspace-beta', membershipState: 'expired' },
        expectedResult: { decision: 'deny', denialReason: 'membership_denied' },
      },
    },
    {
      fixture: 'revoked-grant',
      row: {
        ...VALID_ROW,
        grantState: 'revoked',
        expectedResult: { decision: 'deny', denialReason: 'capability_denied' },
      },
    },
    {
      fixture: 'absent-record',
      row: {
        ...VALID_ROW,
        recordState: 'absent',
        expectedResult: { decision: 'deny', denialReason: 'record_unavailable' },
      },
    },
  ] as const)('accepts the denied-by-default $fixture fixture', ({ row }) => {
    expect(AuthorizationAccessRowSchema.parse(row)).toEqual(row);
  });

  it('enforces denial-reason coherence with deterministic boundary precedence', () => {
    const identityAndClientDenied = {
      ...VALID_ROW,
      principal: { ...VALID_ROW.principal, identityEligibility: 'denied' },
      client: { ...VALID_ROW.client, state: 'revoked' },
      expectedResult: { decision: 'deny', denialReason: 'identity_denied' },
    } as const;
    expect(AuthorizationAccessRowSchema.safeParse(identityAndClientDenied).success).toBe(true);
    expect(
      AuthorizationAccessRowSchema.safeParse({
        ...identityAndClientDenied,
        expectedResult: { decision: 'deny', denialReason: 'client_denied' },
      }).success,
    ).toBe(false);

    expect(
      AuthorizationAccessRowSchema.safeParse({
        ...VALID_ROW,
        expectedResult: { decision: 'deny', denialReason: 'capability_denied' },
      }).success,
    ).toBe(false);
  });

  it('validates complete access-matrix rows through a strict machine-readable seam', () => {
    const row = VALID_ROW;

    expect(AuthorizationAccessRowSchema.parse(row)).toEqual(row);
    expect(AccessMatrixSchema.parse([row])).toEqual([row]);

    const identityDeniedRow = {
      ...row,
      principal: { ...row.principal, identityEligibility: 'denied' },
      expectedResult: { decision: 'deny', denialReason: 'identity_denied' },
    } as const;
    expect(AuthorizationAccessRowSchema.parse(identityDeniedRow)).toEqual(identityDeniedRow);

    expect(AccessMatrixSchema.safeParse([]).success).toBe(false);
    expect(AuthorizationAccessRowSchema.safeParse({ ...row, recordState: 'unknown' }).success).toBe(
      false,
    );
    expect(
      AuthorizationAccessRowSchema.safeParse({
        ...row,
        principal: { id: row.principal.id, kind: row.principal.kind },
      }).success,
    ).toBe(false);
    expect(
      AuthorizationAccessRowSchema.safeParse({ ...row, ownerId: 'principal-human-1' }).success,
    ).toBe(false);
    expect(
      AuthorizationAccessRowSchema.safeParse({ ...row, tenantId: 'tenant-alpha' }).success,
    ).toBe(false);
    expect(
      AuthorizationAccessRowSchema.safeParse({
        ...row,
        principal: { ...row.principal, id: '*' },
      }).success,
    ).toBe(false);
    expect(
      AuthorizationAccessRowSchema.safeParse({
        ...row,
        client: { ...row.client, id: 'client-*' },
      }).success,
    ).toBe(false);
    expect(
      AuthorizationAccessRowSchema.safeParse({
        ...row,
        workspace: { ...row.workspace, id: '*' },
      }).success,
    ).toBe(false);
  });
});
