import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

const ROOT = new URL('../', import.meta.url);

async function text(path: string): Promise<string> {
  return readFile(new URL(path, ROOT), 'utf8');
}

describe('issue #18 experimental operator contract', () => {
  it('keeps production and compatibility entrypoints distinct', async () => {
    const packageJson = JSON.parse(await text('package.json')) as {
      scripts?: Record<string, string>;
    };

    expect(packageJson.scripts?.start).toBe('node packages/server/dist/cli.js');
    expect(packageJson.scripts?.['start:compatibility']).toBe(
      'node packages/server/dist/compatibility-cli.js',
    );
  });

  it('publishes a credential-free environment-only client example', async () => {
    const example = JSON.parse(await text('examples/local-stdio-client.example.json')) as {
      mcpServers?: Record<string, { args?: string[]; env?: Record<string, string> }>;
    };
    const server = example.mcpServers?.['supabase-user-mcp'];

    expect(server?.args).toEqual([
      '/absolute/path/to/Supabase_user_MCP/packages/server/dist/cli.js',
    ]);
    expect(Object.keys(server?.env ?? {}).toSorted()).toEqual([
      'SUPABASE_USER_MCP_CREDENTIAL_FILE',
      'SUPABASE_USER_MCP_ORIGIN',
    ]);
    expect(server?.env?.SUPABASE_USER_MCP_ORIGIN).toBe('https://example.invalid');
    expect(server?.env?.SUPABASE_USER_MCP_CREDENTIAL_FILE).toBe(
      '/replace/with/absolute/path/to/protected-credentials.json',
    );
    expect(JSON.stringify(example)).not.toMatch(
      /userAccessToken|projectPublishableKey|service_role/iu,
    );
  });

  it('documents stop, revoke, rollback, and exact claim limits', async () => {
    const guide = (await text('docs/evidence/ISSUE_18_OPERATOR_RELEASE.md')).replace(/\s+/gu, ' ');

    for (const required of [
      'local stdio, read-only, synthetic acceptance',
      'Windows reports permission inspection as unsupported and therefore fails closed',
      'Supabase User MCP POSIX credential-permission profile is unavailable on Windows.',
      'Revoke and remove access',
      'Rollback',
      'Experimental release checklist',
      'does not prove remote OAuth',
    ]) {
      expect(guide).toContain(required);
    }
  });
});
