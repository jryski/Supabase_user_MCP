import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

const root = resolve(import.meta.dirname, '../..');
const lib = resolve(root, 'supabase/tests/lib/lifecycle.sh');

// Synthetic Docker and Supabase CLI shims backed by plain files, so the
// lifecycle contract can be exercised without a Docker daemon.
const dockerShim = `#!/usr/bin/env bash
set -euo pipefail
s="$SHIM_STATE"
echo "docker $*" >> "$s/calls"
case "$1 $2" in
  "container ls")
    if [[ "$*" == *--format* ]]; then cut -d' ' -f2- "$s/containers" 2>/dev/null || true
    else cut -d' ' -f1 "$s/containers" 2>/dev/null || true; fi ;;
  "volume ls") cat "$s/volumes" 2>/dev/null || true ;;
  "network inspect")
    name="\${!#}"; [[ -f "$s/net-$name" ]] || exit 1
    if [[ "$*" == *--format* ]]; then cat "$s/net-$name"; fi ;;
  "network create") echo 127.0.0.1 > "$s/net-\${!#}" ;;
  "network rm") [[ -n "\${SHIM_NETWORK_RM_FAIL:-}" ]] && exit 1; rm -f "$s/net-\${!#}" ;;
  *) echo "unexpected docker call: $*" >&2; exit 2 ;;
esac
`;
const supabaseShim = `#!/usr/bin/env bash
set -euo pipefail
echo "supabase $*" >> "$SHIM_STATE/calls"
[[ "$1" == stop ]] || exit 2
[[ -z "\${SHIM_STOP_FAIL:-}" ]] || exit 1
: > "$SHIM_STATE/containers"; : > "$SHIM_STATE/volumes"
`;
const driver = `set -euo pipefail
LC_TAG=selftest
source "$LC_LIB"
lc_require_tools docker supabase \${EXTRA_TOOL:-}
lc_read_project_id
TMP_DIR="$(mktemp -d "$SHIM_STATE/run.XXXXXX")"
echo "$TMP_DIR" > "$SHIM_STATE/tmpdir"
trap lc_cleanup EXIT
lc_guard_project_collision
lc_prepare_network
if [[ -n "\${SIMULATE_START:-}" ]]; then
  echo "c-new $PROJECT_ROOT" >> "$SHIM_STATE/containers"
  echo v-new >> "$SHIM_STATE/volumes"
fi
`;

let dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs) rmSync(dir, { force: true, recursive: true });
  dirs = [];
});

function setup(state: Record<string, string> = {}) {
  const base = mkdtempSync(join(tmpdir(), 'lifecycle-selftest-'));
  dirs.push(base);
  const bin = join(base, 'bin');
  const shimState = join(base, 'state');
  const project = join(base, 'project');
  mkdirSync(bin);
  mkdirSync(shimState);
  mkdirSync(join(project, 'supabase'), { recursive: true });
  writeFileSync(join(project, 'supabase/config.toml'), 'project_id = "selftest-project"\n');
  writeFileSync(join(bin, 'docker'), dockerShim);
  writeFileSync(join(bin, 'supabase'), supabaseShim);
  chmodSync(join(bin, 'docker'), 0o755);
  chmodSync(join(bin, 'supabase'), 0o755);
  for (const [name, content] of Object.entries(state)) {
    writeFileSync(join(shimState, name), content.replaceAll('$PROJECT', project));
  }
  return { bin, project, shimState };
}

function run(ctx: ReturnType<typeof setup>, env: Record<string, string> = {}) {
  const result = spawnSync('bash', ['-c', driver], {
    encoding: 'utf8',
    env: {
      LC_LIB: lib,
      NETWORK_NAME: 'selftest-net',
      PATH: `${ctx.bin}:${process.env.PATH ?? ''}`,
      PROJECT_ROOT: ctx.project,
      SHIM_STATE: ctx.shimState,
      ...env,
    },
  });
  const read = (name: string) => {
    const path = join(ctx.shimState, name);
    return existsSync(path) ? readFileSync(path, 'utf8') : '';
  };
  return { ...result, read };
}

describe('local Supabase harness lifecycle', () => {
  it('removes a network it created and verifies containers, volumes and temp are gone', () => {
    const ctx = setup();
    const result = run(ctx, { SIMULATE_START: '1' });
    expect(result.status).toBe(0);
    expect(result.stdout).toContain(
      'Cleanup verified: project=selftest-project containers=0 volumes=0 network=removed temp=removed',
    );
    expect(existsSync(join(ctx.shimState, 'net-selftest-net'))).toBe(false);
    expect(existsSync(result.read('tmpdir').trim())).toBe(false);
    expect(result.read('calls')).toContain('supabase stop --workdir');
  });

  it('reports a pre-existing loopback network as retained instead of silently keeping it', () => {
    const ctx = setup({ 'net-selftest-net': '127.0.0.1\n' });
    const result = run(ctx, { SIMULATE_START: '1' });
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('network=retained-preexisting');
    expect(existsSync(join(ctx.shimState, 'net-selftest-net'))).toBe(true);
    expect(result.read('calls')).not.toContain('network rm');
  });

  it('fails when the stack cannot be stopped instead of ignoring the stop failure', () => {
    const ctx = setup();
    const result = run(ctx, { SIMULATE_START: '1', SHIM_STOP_FAIL: '1' });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      'cleanup not verified: supabase stop failed;project containers remain',
    );
  });

  it('fails when a created network cannot be removed', () => {
    const ctx = setup();
    const result = run(ctx, { SHIM_NETWORK_RM_FAIL: '1' });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('created network selftest-net remains');
  });

  it('refuses to stop a stack with the same fixed project id from another checkout', () => {
    const ctx = setup({ containers: 'c-other /somewhere/else\n' });
    const result = run(ctx, { SIMULATE_START: '1' });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('already in use by another checkout or tool');
    expect(result.read('calls')).not.toContain('supabase stop');
    expect(result.read('containers')).toBe('c-other /somewhere/else\n');
    expect(result.read('calls')).not.toContain('network create');
    expect(result.stdout).toContain(
      'project=selftest-project not-owned-untouched network=not-used',
    );
  });

  it('stops a leftover stack from this same checkout and proceeds', () => {
    const ctx = setup({ containers: 'c-old $PROJECT\n' });
    const result = run(ctx);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('Stopping a leftover stack from this checkout.');
    expect(result.stdout).toContain('Cleanup verified');
  });

  it('fails before starting when a prerequisite command is missing', () => {
    const ctx = setup();
    const result = run(ctx, { EXTRA_TOOL: 'definitely-not-installed-tool' });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      'missing prerequisite command(s): definitely-not-installed-tool',
    );
    expect(result.read('calls')).toBe('');
  });

  it('wires both harnesses through the shared lifecycle and requires curl', () => {
    for (const script of ['supabase/tests/run-m2-memory-lab.sh', 'supabase/tests/run-s1-lab.sh']) {
      const text = readFileSync(resolve(root, script), 'utf8');
      expect(text).toContain('source "$PROJECT_ROOT/supabase/tests/lib/lifecycle.sh"');
      expect(text).toMatch(/lc_require_tools [^\n]*\bcurl\b/);
      expect(text).toContain('trap lc_cleanup EXIT');
      expect(text).not.toMatch(/supabase stop[^\n]*\|\| true/);
    }
  });
});
