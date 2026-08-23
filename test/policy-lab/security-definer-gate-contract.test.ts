import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (path: string): string => readFileSync(path, 'utf8');

describe('SECURITY DEFINER pre-grant gate contract', () => {
  it('documents a fail-closed gate before API-role EXECUTE grants', () => {
    const securityModel = read('docs/SECURITY_MODEL.md');

    expect(securityModel).toMatch(/before[^\n]*EXECUTE[^\n]*(?:anon|authenticated)/i);
    expect(securityModel).toMatch(/verified request context/i);
    expect(securityModel).toMatch(/caller-supplied principal arguments must be removed/i);
    expect(securityModel).toMatch(/fixed(?:,| and)? safe `search_path`/i);
    expect(securityModel).toMatch(/REVOKE EXECUTE ON FUNCTION[^\n]*FROM PUBLIC/i);
    expect(securityModel).toMatch(/owning review/i);
    expect(securityModel).toMatch(/L08[^\n]*L09|L09[^\n]*L08/i);
    expect(securityModel).toMatch(/L09[\s\S]{0,120}(?:heuristic|human review)/i);
    expect(securityModel).toMatch(/no current API grant[^\n]*not[^\n]*safe[- ]to[- ]grant/i);
    expect(securityModel).toMatch(
      /service-role-only[\s\S]{0,80}remain inaccessible[\s\S]{0,80}reviewed/i,
    );
    expect(securityModel).toMatch(/existence or prior operation is not evidence of safety/i);
  });

  it('records bounded review evidence and rollback', () => {
    const evidence = read('docs/evidence/ISSUE_4_SECURITY_DEFINER_GATE.md');

    expect(evidence).toContain('# Issue 4: pre-grant SECURITY DEFINER gate');
    for (const heading of [
      '## Threat and invariant mapping',
      '## Review questions',
      '## Rollback',
      '## Scope limits',
    ]) {
      expect(evidence).toContain(heading);
    }
    expect(evidence).toMatch(/L08[^\n]*L09|L09[^\n]*L08/i);
    expect(evidence).toMatch(/verified request context/i);
    expect(evidence).toMatch(/caller-supplied principal/i);
    expect(evidence).toMatch(/REVOKE[^\n]*anon[^\n]*authenticated/i);
    expect(evidence).toMatch(/no SQL|does not change[^\n]*(?:SQL|database)/i);
  });
});
