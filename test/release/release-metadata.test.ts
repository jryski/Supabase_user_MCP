import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const RELEASE_VERSION = '0.1.0-alpha.1';
const normalize = (value: string): string => value.replace(/\s+/g, ' ').trim();
const readJson = (path: string): Record<string, unknown> =>
  JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;

describe('v0.1.0-alpha.1 release metadata contract', () => {
  it('keeps private workspace, package, dependency, and lock versions coherent', () => {
    const root = readJson('package.json');
    const contracts = readJson('packages/contracts/package.json');
    const server = readJson('packages/server/package.json');
    const lock = readJson('package-lock.json') as {
      version?: string;
      packages?: Record<string, { version?: string; dependencies?: Record<string, string> }>;
    };

    expect(root.version).toBe(RELEASE_VERSION);
    expect(root.private).toBe(true);
    expect(contracts.version).toBe(RELEASE_VERSION);
    expect(contracts.private).toBe(true);
    expect(server.version).toBe(RELEASE_VERSION);
    expect(server.private).toBe(true);
    expect((server.dependencies as Record<string, string>)['@supabase-user-mcp/contracts']).toBe(
      RELEASE_VERSION,
    );
    expect(lock.version).toBe(RELEASE_VERSION);
    expect(lock.packages?.['']?.version).toBe(RELEASE_VERSION);
    expect(lock.packages?.['packages/contracts']?.version).toBe(RELEASE_VERSION);
    expect(lock.packages?.['packages/server']?.version).toBe(RELEASE_VERSION);
    expect(lock.packages?.['packages/server']?.dependencies?.['@supabase-user-mcp/contracts']).toBe(
      RELEASE_VERSION,
    );
  });

  it('keeps the README opening explicit about category, authority, and alpha limits', () => {
    const opening = normalize(readFileSync('README.md', 'utf8').slice(0, 4_000));

    expect(opening).toContain('independent, security-first data-plane MCP server');
    expect(opening).toContain(
      'PostgreSQL Row Level Security (RLS) remains the final authorization',
    );
    expect(opening).toContain("Supabase's hosted MCP server is a developer control-plane tool");
    expect(opening).toContain('experimental local-stdio, read-only, synthetic-only');
    expect(opening).toContain('production deployment, remote OAuth');
    expect(opening).toContain('v0.1.0-alpha.1');
    expect(opening).toContain('release candidate');
  });

  it('records exercised capabilities and exclusions without claiming publication', () => {
    const changelog = normalize(readFileSync('CHANGELOG.md', 'utf8'));
    const notes = normalize(readFileSync('docs/releases/v0.1.0-alpha.1.md', 'utf8'));

    expect(changelog).toContain('## [0.1.0-alpha.1] - 2026-09-06');
    expect(notes).toContain('local principal-bound read path');
    expect(notes).toContain(
      'PostgreSQL Row Level Security as the final row-authorization boundary',
    );
    expect(notes).toContain('This alpha is not production-ready');
    expect(notes).toContain('no remote HTTP or OAuth profile');
    expect(notes).toContain('No tag, GitHub release, npm publication, or deployment');
    expect(notes).toContain('Jesse retains the publication decision');
  });
});
