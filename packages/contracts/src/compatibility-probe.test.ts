import { describe, expect, it } from 'vitest';

import {
  CompatibilityProbeInputSchema,
  CompatibilityProbeOutputSchema,
} from './compatibility-probe.js';

describe('compatibility probe contracts', () => {
  it('accepts only the exact M0 probe input', () => {
    expect(CompatibilityProbeInputSchema.parse({ probe: 'm0' })).toEqual({ probe: 'm0' });
    expect(CompatibilityProbeInputSchema.safeParse({ probe: 'm1' }).success).toBe(false);
    expect(CompatibilityProbeInputSchema.safeParse({ probe: 'm0', extra: true }).success).toBe(
      false,
    );
  });

  it('requires an explicitly non-authoritative result', () => {
    expect(
      CompatibilityProbeOutputSchema.parse({
        status: 'ok',
        milestone: 'M0',
        protocolTarget: '2026-07-28',
        dataAccess: false,
        networkAccess: false,
        writeAccess: false,
      }),
    ).toMatchObject({
      dataAccess: false,
      networkAccess: false,
      writeAccess: false,
    });
  });
});
