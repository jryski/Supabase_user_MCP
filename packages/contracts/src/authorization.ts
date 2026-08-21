import * as z from 'zod/v4';

export const PRINCIPAL_KINDS = [
  'human',
  'delegated_agent',
  'service_agent',
  'reviewer',
  'system_worker',
] as const;

export const PrincipalKindSchema = z.enum(PRINCIPAL_KINDS);
export type PrincipalKind = z.infer<typeof PrincipalKindSchema>;

export const AUTHORIZATION_STATES = ['active', 'expired', 'revoked'] as const;
export const MembershipStateSchema = z.enum(AUTHORIZATION_STATES);
export const ClientStateSchema = z.enum(AUTHORIZATION_STATES);
export const GrantStateSchema = z.enum(AUTHORIZATION_STATES);
export type MembershipState = z.infer<typeof MembershipStateSchema>;
export type ClientState = z.infer<typeof ClientStateSchema>;
export type GrantState = z.infer<typeof GrantStateSchema>;

export const CAPABILITIES = ['memory:search', 'memory:read'] as const;
export const CapabilitySchema = z.enum(CAPABILITIES);
export type Capability = z.infer<typeof CapabilitySchema>;

export const DENIAL_REASON_CLASSES = [
  'identity_denied',
  'client_denied',
  'membership_denied',
  'capability_denied',
  'record_unavailable',
] as const;
export const DenialReasonClassSchema = z.enum(DENIAL_REASON_CLASSES);
export type DenialReasonClass = z.infer<typeof DenialReasonClassSchema>;

export const ExpectedResultSchema = z.discriminatedUnion('decision', [
  z.object({ decision: z.literal('allow') }).strict(),
  z
    .object({
      decision: z.literal('deny'),
      denialReason: DenialReasonClassSchema,
    })
    .strict(),
]);
export type ExpectedResult = z.infer<typeof ExpectedResultSchema>;

export const RecordStateSchema = z.enum(['present', 'absent']);
export type RecordState = z.infer<typeof RecordStateSchema>;

export const AuthorizationIdentifierSchema = z
  .string()
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);

export const AuthorizationAccessRowSchema = z
  .object({
    principal: z
      .object({
        id: AuthorizationIdentifierSchema,
        kind: PrincipalKindSchema,
      })
      .strict(),
    client: z
      .object({
        id: AuthorizationIdentifierSchema,
        state: ClientStateSchema,
      })
      .strict(),
    workspace: z
      .object({
        id: AuthorizationIdentifierSchema,
        membershipState: MembershipStateSchema,
      })
      .strict(),
    grantState: GrantStateSchema,
    capability: CapabilitySchema,
    recordState: RecordStateSchema,
    expectedResult: ExpectedResultSchema,
  })
  .strict();
export type AuthorizationAccessRow = z.infer<typeof AuthorizationAccessRowSchema>;

export const AccessMatrixSchema = z.array(AuthorizationAccessRowSchema).min(1);
export type AccessMatrix = z.infer<typeof AccessMatrixSchema>;
