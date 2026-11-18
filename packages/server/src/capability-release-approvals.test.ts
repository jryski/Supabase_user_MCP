import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { createCapabilityRegistrationProfile } from './capability-mcp-registration.js';
import { COMPILED_CAPABILITY_APPROVALS } from './capability-release-approvals.js';

describe('installed release capability approvals', () => {
  it('ships no approved capabilities and emits its exact release digest', () => {
    const events: unknown[] = [];
    const profile = createCapabilityRegistrationProfile({
      composition: 'read-only',
      adopterSchemas: [],
      emitStartupEvent: (event) => events.push(event),
    });
    expect(COMPILED_CAPABILITY_APPROVALS.approvals).toEqual([]);
    expect(Object.isFrozen(COMPILED_CAPABILITY_APPROVALS.approvals)).toBe(true);
    expect(profile.status).toBe('ready');
    expect(profile.toolNames).toEqual([]);
    expect(events).toEqual([
      {
        event: 'capability_allowlist_loaded',
        sha256: createHash('sha256')
          .update(JSON.stringify(COMPILED_CAPABILITY_APPROVALS))
          .digest('hex'),
      },
    ]);
  });
});
