import { z } from 'zod';

export const MCP_PROTOCOL_POLICY = Object.freeze({
  supportedVersions: Object.freeze(['2026-07-28'] as const),
  negotiation: 'exact-match' as const,
  startup: 'validate-before-tool-registration' as const,
});

export const LOCAL_CREDENTIAL_POLICY = Object.freeze({
  allowedTransport: 'protected-local-file' as const,
  forbiddenTransports: Object.freeze(['cli-argument', 'query-parameter', 'tool-argument'] as const),
  requiredFileType: 'regular-file' as const,
  requireOwnerOnlyPermissions: true as const,
  refresh: 'replace-protected-file-and-restart' as const,
  startup: 'validate-before-tool-registration' as const,
  secretExposure: 'redacted' as const,
});

export type CredentialTransport =
  | 'protected-local-file'
  | 'cli-argument'
  | 'query-parameter'
  | 'tool-argument';

export type CredentialFileType = 'regular-file' | 'symbolic-link' | 'other';
export type CredentialTokenState =
  | 'valid'
  | 'malformed'
  | 'expired'
  | 'revoked'
  | 'refresh-required';

export class UnsupportedMcpProtocolVersionError extends Error {
  readonly code = 'mcp_protocol_version_unsupported';

  constructor() {
    super('MCP protocol version is unsupported.');
    this.name = 'UnsupportedMcpProtocolVersionError';
  }
}

export function assertSupportedMcpProtocolVersion(version: string): void {
  if (version !== MCP_PROTOCOL_POLICY.supportedVersions[0]) {
    throw new UnsupportedMcpProtocolVersionError();
  }
}

export abstract class LocalCredentialPolicyError extends Error {
  abstract readonly code: string;
}

export class InvalidLocalCredentialObservationError extends LocalCredentialPolicyError {
  readonly code = 'credential_observation_invalid';

  constructor() {
    super('Local credential observation is invalid.');
    this.name = 'InvalidLocalCredentialObservationError';
  }
}

export class UnsupportedCredentialTransportError extends LocalCredentialPolicyError {
  readonly code = 'credential_transport_forbidden';

  constructor() {
    super('Credential transport is forbidden; use the protected local file source.');
    this.name = 'UnsupportedCredentialTransportError';
  }
}

export class CredentialSourceAbsentError extends LocalCredentialPolicyError {
  readonly code = 'credential_source_absent';

  constructor() {
    super('Credential source is absent.');
    this.name = 'CredentialSourceAbsentError';
  }
}

export class CredentialSourceUnreadableError extends LocalCredentialPolicyError {
  readonly code = 'credential_source_unreadable';

  constructor() {
    super('Credential source is unreadable.');
    this.name = 'CredentialSourceUnreadableError';
  }
}

export class UnsafeCredentialSourceError extends LocalCredentialPolicyError {
  readonly code = 'credential_source_unsafe';

  constructor() {
    super('Credential source is not a protected regular file.');
    this.name = 'UnsafeCredentialSourceError';
  }
}

export class CredentialMalformedError extends LocalCredentialPolicyError {
  readonly code = 'credential_malformed';

  constructor() {
    super('Credential is malformed.');
    this.name = 'CredentialMalformedError';
  }
}

export class CredentialExpiredError extends LocalCredentialPolicyError {
  readonly code = 'credential_expired';

  constructor() {
    super('Credential has expired.');
    this.name = 'CredentialExpiredError';
  }
}

export class CredentialRevokedError extends LocalCredentialPolicyError {
  readonly code = 'credential_revoked';

  constructor() {
    super('Credential has been revoked.');
    this.name = 'CredentialRevokedError';
  }
}

export class CredentialRefreshRequiredError extends LocalCredentialPolicyError {
  readonly code = 'credential_refresh_required';

  constructor() {
    super('Credential replacement and restart are required.');
    this.name = 'CredentialRefreshRequiredError';
  }
}

export interface LocalCredentialObservation {
  readonly transport: CredentialTransport;
  readonly exists: boolean;
  readonly fileType: CredentialFileType;
  readonly ownerOnly: boolean;
  readonly ownedByCurrentUser: boolean;
  readonly readable: boolean;
  readonly tokenState: CredentialTokenState;
}

const localCredentialObservationSchema = z
  .object({
    transport: z.enum(['protected-local-file', 'cli-argument', 'query-parameter', 'tool-argument']),
    exists: z.boolean(),
    fileType: z.enum(['regular-file', 'symbolic-link', 'other']),
    ownerOnly: z.boolean(),
    ownedByCurrentUser: z.boolean(),
    readable: z.boolean(),
    tokenState: z.enum(['valid', 'malformed', 'expired', 'revoked', 'refresh-required']),
  })
  .strict();

export function assertLocalCredentialPolicy(observation: unknown): void {
  const result = (() => {
    try {
      return localCredentialObservationSchema.safeParse(observation);
    } catch {
      throw new InvalidLocalCredentialObservationError();
    }
  })();
  if (!result.success) {
    throw new InvalidLocalCredentialObservationError();
  }

  const validatedObservation: LocalCredentialObservation = result.data;
  if (validatedObservation.transport !== LOCAL_CREDENTIAL_POLICY.allowedTransport) {
    throw new UnsupportedCredentialTransportError();
  }
  if (!validatedObservation.exists) {
    throw new CredentialSourceAbsentError();
  }
  if (
    validatedObservation.fileType !== LOCAL_CREDENTIAL_POLICY.requiredFileType ||
    !validatedObservation.ownerOnly ||
    !validatedObservation.ownedByCurrentUser
  ) {
    throw new UnsafeCredentialSourceError();
  }
  if (!validatedObservation.readable) {
    throw new CredentialSourceUnreadableError();
  }

  switch (validatedObservation.tokenState) {
    case 'valid':
      return;
    case 'malformed':
      throw new CredentialMalformedError();
    case 'expired':
      throw new CredentialExpiredError();
    case 'revoked':
      throw new CredentialRevokedError();
    case 'refresh-required':
      throw new CredentialRefreshRequiredError();
    default:
      throw new InvalidLocalCredentialObservationError();
  }
}
