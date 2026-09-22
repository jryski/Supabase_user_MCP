import { describe, expect, it } from 'vitest';

import {
  ACCESS_TOKEN_REVOCATION_POLICY,
  audienceValues,
  canonicalizeResourceUri,
  DATA_API_AUDIENCE,
  DOWNSTREAM_CREDENTIAL_RECHECK_2026_09_22,
  DOWNSTREAM_CREDENTIAL_UNRESOLVED,
  extractServerControlledClientId,
  LOCAL_LAB_MCP_RESOURCE_URI,
  REMOTE_DOWNSTREAM_CREDENTIAL_POLICY,
  REMOTE_IDENTITY_CLAIM_POLICY,
  userMetadataAttemptsAuthorization,
} from './remote-oauth-http-policy.js';

describe('remote OAuth/HTTP policy contracts', () => {
  it('requires dual resource and Data API binding and never authorizes user_metadata', () => {
    expect(REMOTE_IDENTITY_CLAIM_POLICY.resourceBinding).toBe('mandatory');
    expect(REMOTE_IDENTITY_CLAIM_POLICY.defaultAudAuthenticatedInsufficient).toBe(true);
    expect(REMOTE_IDENTITY_CLAIM_POLICY.clientIdAloneInsufficient).toBe(true);
    expect(REMOTE_IDENTITY_CLAIM_POLICY.dataApiAudience).toBe(DATA_API_AUDIENCE);
    expect(REMOTE_IDENTITY_CLAIM_POLICY.oidcScopesAuthorizeData).toBe(false);
    expect(LOCAL_LAB_MCP_RESOURCE_URI).toBe('https://mcp.loopback.invalid/mcp');
    expect(REMOTE_IDENTITY_CLAIM_POLICY.forbiddenAuthorizationClaimPaths).toEqual([
      'user_metadata',
      'raw_user_meta_data',
    ]);
    expect(ACCESS_TOKEN_REVOCATION_POLICY.signatureValidityInsufficient).toBe(true);
    expect(ACCESS_TOKEN_REVOCATION_POLICY.distinctFromGrantRevocation).toBe(true);
    expect(ACCESS_TOKEN_REVOCATION_POLICY.distinctFromRefreshRevocation).toBe(true);
    expect(ACCESS_TOKEN_REVOCATION_POLICY.cache).toBe('none');
    expect(REMOTE_DOWNSTREAM_CREDENTIAL_POLICY.inboundMcpBearerForwardsToDataApi).toBe(false);
    expect(REMOTE_DOWNSTREAM_CREDENTIAL_POLICY.dualAudienceDoesNotAuthorizePassthrough).toBe(true);
    expect(REMOTE_DOWNSTREAM_CREDENTIAL_POLICY.separateDownstreamCredential).toBe('unresolved');
    expect(REMOTE_DOWNSTREAM_CREDENTIAL_POLICY.failClosedUntilResolved).toBe(true);
    expect(DOWNSTREAM_CREDENTIAL_RECHECK_2026_09_22).toEqual({
      checkedOn: '2026-09-22',
      nativeMcpToDataApiExchange: 'unsupported',
      oauthServerGrantTypes: ['authorization_code', 'refresh_token'],
      gotrueUserTokenExchangeOnMaster: 'absent',
      gotrueRfc8693ProviderLogin: 'not-a-data-api-credential',
      inboundBearerPassthrough: 'forbidden',
      privilegedMint: 'forbidden',
      customAccessTokenHookMintsSecondCredential: false,
      sameGrantRefreshIsSeparateUpstreamToken: false,
      dualGrantBroker: 'architecture-approval-required',
      remoteDataDispatch: 'fail-closed',
    });
    expect(DOWNSTREAM_CREDENTIAL_UNRESOLVED).toBe('downstream_credential_unresolved');
  });

  it('canonicalizes resource URIs without trailing slash unless the path is significant', () => {
    expect(canonicalizeResourceUri('https://MCP.Example.COM/mcp/')).toBe(
      'https://mcp.example.com/mcp',
    );
    expect(canonicalizeResourceUri('https://mcp.example.com:443')).toBe('https://mcp.example.com');
  });

  it('reads client_id from top-level or app_metadata and ignores user_metadata', () => {
    expect(
      extractServerControlledClientId({
        client_id: 'smp-lab-inspector',
        app_metadata: { client_id: 'ignored-app' },
        user_metadata: { client_id: 'forged-user' },
      }),
    ).toBe('smp-lab-inspector');
    expect(
      extractServerControlledClientId({
        app_metadata: { client_id: 'client-active' },
        user_metadata: { client_id: 'client-active' },
      }),
    ).toBe('client-active');
    expect(
      extractServerControlledClientId({
        user_metadata: { client_id: 'client-active', read_only: true },
      }),
    ).toBeUndefined();
    expect(
      userMetadataAttemptsAuthorization({
        user_metadata: { read_only: true },
      }),
    ).toBe(true);
    expect(audienceValues(['authenticated', 'https://mcp.example.com/mcp'])).toEqual([
      'authenticated',
      'https://mcp.example.com/mcp',
    ]);
  });
});
