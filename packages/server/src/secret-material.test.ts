import { describe, expect, it } from 'vitest';

import { containsSecretMaterial } from './remote-http-profile.js';

const LAB_SECRET = 'lab_refresh_material_issue63';

describe('containsSecretMaterial', () => {
  it('detects non-empty secrets in nested model-visible result shapes', () => {
    const structured = {
      structuredContent: {
        ok: false,
        error: { code: 'denied', detail: `nested ${LAB_SECRET} tail` },
      },
    };
    expect(containsSecretMaterial(structured, [LAB_SECRET])).toBe(true);
  });

  it('detects secrets buried in nested arrays without matching unrelated siblings', () => {
    const payload = {
      content: [
        { type: 'text', text: 'safe surface' },
        { type: 'resource', parts: [{ uri: 'ok' }, { note: LAB_SECRET }] },
      ],
    };
    expect(containsSecretMaterial(payload, [LAB_SECRET])).toBe(true);
    expect(containsSecretMaterial(payload, ['unrelated-token-shape'])).toBe(false);
  });

  it('ignores empty secret strings when scanning serialized content', () => {
    const value = { message: 'visible-only', token: 'also-visible' };
    expect(containsSecretMaterial(value, [''])).toBe(false);
    expect(containsSecretMaterial(value, ['', LAB_SECRET])).toBe(false);
  });

  it('returns false for undefined and absent serializable content', () => {
    expect(containsSecretMaterial(undefined, [LAB_SECRET])).toBe(false);
    expect(containsSecretMaterial({ result: undefined }, [LAB_SECRET])).toBe(false);
  });

  it('does not false-positive on unrelated values that omit configured secrets', () => {
    const safe = {
      isError: true,
      error: { message: 'bounded denial', code: 'unauthorized' },
      structuredContent: { ok: false, items: [] },
    };
    expect(containsSecretMaterial(safe, [LAB_SECRET])).toBe(false);
    expect(containsSecretMaterial(safe, [])).toBe(false);
  });
});
