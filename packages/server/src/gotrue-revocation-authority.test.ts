import { describe, expect, it } from 'vitest';

import { createGoTrueSessionRevocationAuthority } from './gotrue-revocation-authority.js';

describe('GoTrue session revocation authority', () => {
  it('treats 401 as revoked and 200 as active without caching', async () => {
    const calls: string[] = [];
    const authority = createGoTrueSessionRevocationAuthority({
      origin: 'https://m2-loopback.invalid',
      publishableKey: 'sb_publishable_lab_key',
      fetch: async (input) => {
        const url = typeof input === 'string' || input instanceof URL ? String(input) : input.url;
        calls.push(url);
        const status = calls.length === 1 ? 200 : 401;
        return new Response(
          status === 200 ? '{"id":"11111111-1111-4111-9111-111111111111"}' : '{}',
          {
            status,
          },
        );
      },
    });
    const inspect = {
      sessionId: '11111111-1111-4111-8111-111111111111',
      tokenFingerprint: 'abc',
      nowMs: Date.now(),
      accessToken: 'header.payload.signature',
    };
    await expect(authority.inspectAccessToken(inspect)).resolves.toBe('active');
    await expect(authority.inspectAccessToken(inspect)).resolves.toBe('revoked');
    expect(calls).toHaveLength(2);
  });
});
