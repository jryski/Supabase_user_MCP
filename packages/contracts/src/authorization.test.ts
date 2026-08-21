import { describe, expect, it } from 'vitest';

import {
  AccessMatrixSchema,
  AuthorizationAccessRowSchema,
  CapabilitySchema,
  ClientStateSchema,
  DenialReasonClassSchema,
  ExpectedResultSchema,
  GrantStateSchema,
  MembershipStateSchema,
  PrincipalKindSchema,
} from './authorization.js';

describe('authorization vocabulary', () => {
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

  it('validates complete access-matrix rows through a strict machine-readable seam', () => {
    const row = {
      principal: { id: 'principal-human-1', kind: 'human' },
      client: { id: 'client-cli-1', state: 'active' },
      workspace: { id: 'workspace-alpha', membershipState: 'active' },
      grantState: 'active',
      capability: 'memory:read',
      recordState: 'present',
      expectedResult: { decision: 'allow' },
    } as const;

    expect(AuthorizationAccessRowSchema.parse(row)).toEqual(row);
    expect(AccessMatrixSchema.parse([row])).toEqual([row]);
    expect(AccessMatrixSchema.safeParse([]).success).toBe(false);
    expect(AuthorizationAccessRowSchema.safeParse({ ...row, recordState: 'unknown' }).success).toBe(
      false,
    );
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
