import { describe, expect, it } from 'vitest';

import {
  CredentialExpiredError,
  CredentialMalformedError,
  CredentialRefreshRequiredError,
  CredentialRevokedError,
  CredentialSourceAbsentError,
  CredentialSourceUnreadableError,
  LOCAL_CREDENTIAL_POLICY,
  MCP_PROTOCOL_POLICY,
  UnsupportedMcpProtocolVersionError,
  UnsafeCredentialSourceError,
  UnsupportedCredentialTransportError,
  assertLocalCredentialPolicy,
  assertSupportedMcpProtocolVersion,
} from './local-credential-protocol-policy.js';

describe('local credential policy', () => {
  const validObservation = {
    transport: 'protected-local-file',
    exists: true,
    fileType: 'regular-file',
    ownerOnly: true,
    ownedByCurrentUser: true,
    readable: true,
    tokenState: 'valid',
  } as const;
  const assertUnknownObservation = assertLocalCredentialPolicy as (observation: unknown) => void;

  it('allows only a protected regular local file carrying a valid user token', () => {
    expect(LOCAL_CREDENTIAL_POLICY.allowedTransport).toBe('protected-local-file');

    expect(() =>
      assertLocalCredentialPolicy({
        transport: 'protected-local-file',
        exists: true,
        fileType: 'regular-file',
        ownerOnly: true,
        ownedByCurrentUser: true,
        readable: true,
        tokenState: 'valid',
      }),
    ).not.toThrow();
  });

  it.each(['cli-argument', 'query-parameter', 'tool-argument'] as const)(
    'rejects credential transport through %s',
    (transport) => {
      expect(() =>
        assertLocalCredentialPolicy({
          transport,
          exists: true,
          fileType: 'regular-file',
          ownerOnly: true,
          ownedByCurrentUser: true,
          readable: true,
          tokenState: 'valid',
        }),
      ).toThrow(UnsupportedCredentialTransportError);
    },
  );

  it.each([
    ['absent source', { exists: false }, CredentialSourceAbsentError, 'credential_source_absent'],
    [
      'unreadable source',
      { readable: false },
      CredentialSourceUnreadableError,
      'credential_source_unreadable',
    ],
    [
      'symbolic link',
      { fileType: 'symbolic-link' as const },
      UnsafeCredentialSourceError,
      'credential_source_unsafe',
    ],
    [
      'non-regular file',
      { fileType: 'other' as const },
      UnsafeCredentialSourceError,
      'credential_source_unsafe',
    ],
    [
      'non-owner-only permissions',
      { ownerOnly: false },
      UnsafeCredentialSourceError,
      'credential_source_unsafe',
    ],
    [
      'different operating-system owner',
      { ownedByCurrentUser: false },
      UnsafeCredentialSourceError,
      'credential_source_unsafe',
    ],
  ])('classifies an %s without exposing credential bytes', (_name, override, ErrorClass, code) => {
    let caught: unknown;
    try {
      assertLocalCredentialPolicy({
        transport: 'protected-local-file',
        exists: true,
        fileType: 'regular-file',
        ownerOnly: true,
        ownedByCurrentUser: true,
        readable: true,
        tokenState: 'valid',
        ...override,
      });
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(ErrorClass);
    expect(caught).toMatchObject({ code });
    expect(String(caught)).not.toContain('token');
  });

  it.each([
    ['unknown string', 'unknown'],
    ['uppercase string', 'VALID'],
    ['null', null],
    ['undefined', undefined],
    ['number', 1],
  ])(
    'rejects an invalid %s token state with a stable non-secret observation error',
    (_name, tokenState) => {
      let caught: unknown;
      try {
        assertUnknownObservation({ ...validObservation, tokenState });
      } catch (error) {
        caught = error;
      }

      expect(caught).toMatchObject({
        name: 'InvalidLocalCredentialObservationError',
        code: 'credential_observation_invalid',
        message: 'Local credential observation is invalid.',
      });
      expect(String(caught)).not.toContain(String(tokenState));
    },
  );

  it.each(['exists', 'ownerOnly', 'ownedByCurrentUser', 'readable'] as const)(
    'rejects a non-boolean %s safety field',
    (field) => {
      expect(() => assertUnknownObservation({ ...validObservation, [field]: 'false' })).toThrow(
        expect.objectContaining({ code: 'credential_observation_invalid' }),
      );
    },
  );

  it.each([
    ['null', null],
    ['undefined', undefined],
    ['array', []],
    ['unknown property', { ...validObservation, unexpected: true }],
  ])('rejects an invalid %s observation', (_name, observation) => {
    expect(() => assertUnknownObservation(observation)).toThrow(
      expect.objectContaining({ code: 'credential_observation_invalid' }),
    );
  });

  it.each([
    ['malformed', CredentialMalformedError, 'credential_malformed'],
    ['expired', CredentialExpiredError, 'credential_expired'],
    ['revoked', CredentialRevokedError, 'credential_revoked'],
    ['refresh-required', CredentialRefreshRequiredError, 'credential_refresh_required'],
  ] as const)('classifies %s token state', (tokenState, ErrorClass, code) => {
    expect(() =>
      assertLocalCredentialPolicy({
        transport: 'protected-local-file',
        exists: true,
        fileType: 'regular-file',
        ownerOnly: true,
        ownedByCurrentUser: true,
        readable: true,
        tokenState,
      }),
    ).toThrow(expect.objectContaining({ code }));
    expect(() =>
      assertLocalCredentialPolicy({
        transport: 'protected-local-file',
        exists: true,
        fileType: 'regular-file',
        ownerOnly: true,
        ownedByCurrentUser: true,
        readable: true,
        tokenState,
      }),
    ).toThrow(ErrorClass);
  });
});

describe('MCP protocol policy', () => {
  it('pins the version proven by the M0 compatibility spike', () => {
    expect(MCP_PROTOCOL_POLICY).toEqual({
      supportedVersions: ['2026-07-28'],
      negotiation: 'exact-match',
      startup: 'validate-before-tool-registration',
    });
    expect(() => assertSupportedMcpProtocolVersion('2026-07-28')).not.toThrow();
  });

  it.each(['2025-06-18', '2024-11-05', '', 'not-a-version'])(
    'fails closed for unsupported protocol version %j',
    (version) => {
      expect(() => assertSupportedMcpProtocolVersion(version)).toThrow(
        UnsupportedMcpProtocolVersionError,
      );
    },
  );
});
