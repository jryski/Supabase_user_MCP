import { getOAuthProtectedResourceMetadataUrl } from '@modelcontextprotocol/server';
import { LOCAL_LAB_MCP_RESOURCE_URI } from '@supabase-user-mcp/contracts';
import { describe, expect, it } from 'vitest';

import { createAuthorizationServerMetadata } from './authorization-server-metadata.js';
import { generateS256PkceChallenge } from './local-oauth-pkce-client.js';
import { createRemoteHttpProfile } from './remote-http-profile.js';
import {
  SYNTHETIC_OAUTH_HMAC_SECRET,
  SyntheticOAuthLab,
  SyntheticOAuthLabError,
} from './synthetic-oauth-lab.js';

const ISSUER = 'https://auth.loopback.invalid/auth/v1';
const RESOURCE = LOCAL_LAB_MCP_RESOURCE_URI;
const PRINCIPAL = '11111111-1111-4111-9111-111111111111';
const CLIENT = 'smp-lab-inspector';
const REDIRECT = 'http://127.0.0.1/oauth/callback';
const HMAC_SECRET_LITERAL = new TextDecoder().decode(SYNTHETIC_OAUTH_HMAC_SECRET);

function lab(): SyntheticOAuthLab {
  return new SyntheticOAuthLab({
    issuer: ISSUER,
    resourceUri: RESOURCE,
    client: { clientId: CLIENT, redirectUri: REDIRECT, tokenEndpointAuthMethod: 'none' },
  });
}

function profile(oauth: SyntheticOAuthLab) {
  return createRemoteHttpProfile({
    resourceUri: RESOURCE,
    issuer: ISSUER,
    expectedClientId: CLIENT,
    signingKey: { kind: 'hmac', secret: SYNTHETIC_OAUTH_HMAC_SECRET },
    revocationAuthority: oauth,
    authorizationServerMetadata: createAuthorizationServerMetadata(ISSUER),
  });
}

function authorizationRequest(pkce = generateS256PkceChallenge()) {
  return {
    responseType: 'code' as const,
    clientId: CLIENT,
    redirectUri: REDIRECT,
    codeChallenge: pkce.codeChallenge,
    codeChallengeMethod: 'S256' as const,
    resource: RESOURCE,
    principalId: PRINCIPAL,
  };
}

describe('issue63 discovery and PKCE gap closure', () => {
  describe('RFC 9728 protected-resource metadata', () => {
    it('serves metadata only on the path-aware well-known route', async () => {
      const handler = profile(lab());
      const intended = getOAuthProtectedResourceMetadataUrl(new URL(RESOURCE));
      const ok = await handler(new Request(intended));
      expect(ok.status).toBe(200);

      const wrongPath = await handler(
        new Request('https://mcp.loopback.invalid/.well-known/oauth-protected-resource/evil'),
      );
      expect(wrongPath.status).toBe(404);
      expect(await wrongPath.json()).toEqual({ error: 'not_found' });
    });

    it('does not expose signing secrets or internal lab material in discovery JSON', async () => {
      const handler = profile(lab());
      const protectedBody = await handler(
        new Request(getOAuthProtectedResourceMetadataUrl(new URL(RESOURCE))),
      ).then((response) => response.text());
      expect(protectedBody).not.toContain(HMAC_SECRET_LITERAL);
      expect(protectedBody).not.toContain('JWT_HMAC');
      expect(protectedBody).not.toContain('service_role');

      const authorizationBody = await handler(
        new Request('https://mcp.loopback.invalid/.well-known/oauth-authorization-server'),
      ).then((response) => response.text());
      expect(authorizationBody).not.toContain(HMAC_SECRET_LITERAL);
      const authorizationJson = JSON.parse(authorizationBody) as {
        issuer?: string;
        code_challenge_methods_supported?: string[];
        jwks_uri?: string;
      };
      expect(authorizationJson.issuer).toBe(ISSUER);
      expect(authorizationJson.code_challenge_methods_supported).toEqual(['S256']);
      expect(authorizationJson.jwks_uri).toBe(`${ISSUER}/.well-known/jwks.json`);
    });
  });

  describe('authorization-server metadata binding', () => {
    it('rejects profile construction when metadata issuer diverges from configured issuer', () => {
      const oauth = lab();
      expect(() =>
        createRemoteHttpProfile({
          resourceUri: RESOURCE,
          issuer: ISSUER,
          expectedClientId: CLIENT,
          signingKey: { kind: 'hmac', secret: SYNTHETIC_OAUTH_HMAC_SECRET },
          revocationAuthority: oauth,
          authorizationServerMetadata: createAuthorizationServerMetadata(
            'https://evil.loopback.invalid/auth/v1',
          ),
        }),
      ).toThrow(/issuer must match/i);
    });

    it('canonicalizes issuer and anchors OAuth endpoints on that issuer', () => {
      const metadata = createAuthorizationServerMetadata('https://AUTH.loopback.invalid/auth/v1/');
      expect(metadata.issuer).toBe('https://auth.loopback.invalid/auth/v1');
      expect(metadata.token_endpoint).toBe(`${metadata.issuer}/oauth/token`);
      expect(metadata.code_challenge_methods_supported).toEqual(['S256']);
    });
  });

  describe('MCP resource host and path boundary', () => {
    it('rejects a hostile Host header before bearer verification', async () => {
      const handler = profile(lab());
      for (const host of ['evil.loopback.invalid', 'sub.mcp.loopback.invalid']) {
        const response = await handler(
          new Request(RESOURCE, {
            method: 'POST',
            headers: { host, Accept: 'application/json' },
            body: '{}',
          }),
        );
        expect(response.status).toBe(400);
        expect(await response.json()).toEqual({ error: 'invalid_request' });
      }
    });

    it('rejects requests whose path leaves the registered MCP resource', async () => {
      const handler = profile(lab());
      for (const url of [
        'https://mcp.loopback.invalid/mcp/extra',
        'https://mcp.loopback.invalid/MCP',
        'https://mcp.loopback.invalid/',
      ]) {
        const response = await handler(
          new Request(url, {
            method: 'POST',
            headers: { Accept: 'application/json' },
            body: '{}',
          }),
        );
        expect(response.status).toBe(404);
        expect(await response.json()).toEqual({ error: 'not_found' });
      }
    });
  });

  describe('synthetic OAuth lab PKCE and consent', () => {
    it('rejects plain PKCE, missing challenges, and non-exact redirect URIs', () => {
      const oauth = lab();
      const pkce = generateS256PkceChallenge();

      expect(() =>
        oauth.startAuthorization({
          ...authorizationRequest(pkce),
          codeChallenge: pkce.codeVerifier,
          codeChallengeMethod: 'plain',
        }),
      ).toThrow(SyntheticOAuthLabError);

      expect(() =>
        oauth.startAuthorization({
          ...authorizationRequest(pkce),
          codeChallenge: 'short',
          codeChallengeMethod: 'S256',
        }),
      ).toThrow(SyntheticOAuthLabError);

      expect(() =>
        oauth.startAuthorization({
          ...authorizationRequest(pkce),
          codeChallenge: 'A'.repeat(42),
          codeChallengeMethod: 'S256',
        }),
      ).toThrow(SyntheticOAuthLabError);

      for (const redirectUri of [
        'http://127.0.0.1/OAuth/callback',
        'http://127.0.0.1/oauth/callback?extra=1',
        'http://127.0.0.1:80/oauth/callback',
      ]) {
        expect(() =>
          oauth.startAuthorization({
            ...authorizationRequest(pkce),
            redirectUri,
          }),
        ).toThrow(SyntheticOAuthLabError);
      }
    });

    it('denial returns access_denied without a code and blocks later approval', () => {
      const oauth = lab();
      const pkce = generateS256PkceChallenge();
      const authorizationId = oauth.startAuthorization(authorizationRequest(pkce));
      const denied = oauth.denyAuthorization(authorizationId);
      expect(denied.searchParams.get('error')).toBe('access_denied');
      expect(denied.searchParams.has('code')).toBe(false);
      expect(() => oauth.approveAuthorization(authorizationId)).toThrow(SyntheticOAuthLabError);
    });

    it('rejects malformed PKCE verifiers before consuming authorization codes', async () => {
      const oauth = lab();
      const pkce = generateS256PkceChallenge();
      const authorizationId = oauth.startAuthorization(authorizationRequest(pkce));
      const approved = oauth.approveAuthorization(authorizationId);
      const code = approved.searchParams.get('code');
      if (!code) throw new Error('missing code');

      const malformedVerifier = `${'a'.repeat(42)}!`;
      await expect(
        oauth.exchangeAuthorizationCode({
          grantType: 'authorization_code',
          code,
          clientId: CLIENT,
          redirectUri: REDIRECT,
          codeVerifier: malformedVerifier,
          resource: RESOURCE,
        }),
      ).rejects.toMatchObject({ code: 'invalid_pkce' });

      const recovered = await oauth.exchangeAuthorizationCode({
        grantType: 'authorization_code',
        code,
        clientId: CLIENT,
        redirectUri: REDIRECT,
        codeVerifier: pkce.codeVerifier,
        resource: RESOURCE,
      });
      expect(recovered.tokenType).toBe('Bearer');

      const wrongFormatPkce = generateS256PkceChallenge();
      const secondAuthorizationId = oauth.startAuthorization(authorizationRequest(wrongFormatPkce));
      const secondApproved = oauth.approveAuthorization(secondAuthorizationId);
      const secondCode = secondApproved.searchParams.get('code');
      if (!secondCode) throw new Error('missing code');

      await expect(
        oauth.exchangeAuthorizationCode({
          grantType: 'authorization_code',
          code: secondCode,
          clientId: CLIENT,
          redirectUri: REDIRECT,
          codeVerifier: generateS256PkceChallenge().codeVerifier,
          resource: RESOURCE,
        }),
      ).rejects.toMatchObject({ code: 'invalid_pkce' });

      await expect(
        oauth.exchangeAuthorizationCode({
          grantType: 'authorization_code',
          code: secondCode,
          clientId: CLIENT,
          redirectUri: REDIRECT,
          codeVerifier: wrongFormatPkce.codeVerifier,
          resource: RESOURCE,
        }),
      ).rejects.toMatchObject({ code: 'invalid_grant' });
    });
  });
});
