#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright The Sovereign AI OS Authors
# Full LEAK-01 qualification: actionlint semantic validation of every leak
# workflow plus discovery of every tests/leak/test_*.py. Both native tools are
# mandatory; any missing tool, failure, error or skipped test exits non-zero.
set -euo pipefail
task_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "$task_root"

for var in LEAK_TEST_GITLEAKS LEAK_ACTIONLINT; do
  value="${!var:-}"
  if [[ -z "$value" || ! -x "$value" ]]; then
    echo "test_gate.sh: $var must name an executable installed by scripts/leak/install_*.py" >&2
    exit 2
  fi
done

workflows=(.github/workflows/leak-gate.yml)
[[ -f .github/workflows/leak-ci.yml ]] && workflows+=(.github/workflows/leak-ci.yml)
"$LEAK_ACTIONLINT" -no-color -shellcheck= -pyflakes= "${workflows[@]}"

python3 - <<'PY'
import sys, unittest
suite = unittest.defaultTestLoader.discover("tests/leak", pattern="test_*.py")
result = unittest.TextTestRunner(verbosity=2).run(suite)
skipped = len(result.skipped)
print(f"LEAK-01 suite: run={result.testsRun} failures={len(result.failures)} "
      f"errors={len(result.errors)} skipped={skipped}")
if not result.wasSuccessful() or skipped or result.testsRun == 0:
    sys.exit(1)
PY
