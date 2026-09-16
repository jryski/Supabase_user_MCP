import { expect, it, vi } from 'vitest';
import { createSessionCapabilitiesGet } from './session-capabilities-get.js';

it('returns a deadline error without discovering tools when already cancelled', async () => {
  const registeredToolNames = vi.fn(() => new Set(['session_capabilities_get']));
  const getCapabilities = createSessionCapabilitiesGet(registeredToolNames);

  await expect(getCapabilities(AbortSignal.abort())).resolves.toEqual({
    ok: false,
    error: {
      code: 'DEADLINE_EXCEEDED',
      message: 'Request deadline exceeded.',
      retryable: false,
    },
  });
  expect(registeredToolNames).not.toHaveBeenCalled();
});

it('returns a deadline error when cancelled while discovering tools', async () => {
  const controller = new AbortController();
  const getCapabilities = createSessionCapabilitiesGet(() => {
    controller.abort();
    return new Set(['session_capabilities_get']);
  });

  await expect(getCapabilities({ signal: controller.signal })).resolves.toMatchObject({
    ok: false,
    error: { code: 'DEADLINE_EXCEEDED' },
  });
});
