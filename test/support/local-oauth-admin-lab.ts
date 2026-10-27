import type { LocalOAuthClientRegistration } from '../../packages/server/src/local-oauth-pkce-client.js';

/**
 * Local lab only. Registers a public OAuth client on a disposable local Auth
 * server through the Auth admin endpoint. It needs the local stack's
 * privileged key, so it lives in test support and never in runtime source or
 * the built package. No runtime module may import this file.
 */
export async function registerLocalPublicOAuthClient(input: {
  readonly authOrigin: string;
  readonly serviceRoleKey: string;
  readonly clientName: string;
  readonly redirectUri: string;
}): Promise<LocalOAuthClientRegistration> {
  const response = await fetch(new URL('/auth/v1/admin/oauth/clients', input.authOrigin), {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${input.serviceRoleKey}`,
      apikey: input.serviceRoleKey,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      name: input.clientName,
      redirect_uris: [input.redirectUri],
      client_type: 'public',
      token_endpoint_auth_method: 'none',
    }),
  });
  if (!response.ok) {
    throw new Error(`oauth client registration failed: ${response.status}`);
  }
  const body = (await response.json()) as { client_id?: string; redirect_uris?: string[] };
  if (!body.client_id) {
    throw new Error('oauth client registration did not return client_id');
  }
  return {
    clientId: body.client_id,
    redirectUris: body.redirect_uris ?? [input.redirectUri],
  };
}
