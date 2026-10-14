# SPDX-License-Identifier: Apache-2.0
"""Static guarantees for the unprivileged LEAK-01 regression CI and wrapper."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
CI = (ROOT / ".github/workflows/leak-ci.yml").read_text()
CODE = "\n".join(l for l in CI.splitlines() if not l.lstrip().startswith("#"))
WRAPPER = (ROOT / "tests/leak/test_gate.sh").read_text()


class LeakCiWorkflowTest(unittest.TestCase):
    def test_pull_request_only_never_target(self):
        self.assertIn("\n  pull_request:\n", CI)
        self.assertNotIn("pull_request_target", CI)
        self.assertNotIn("workflow_run", CI)

    def test_read_only_permissions(self):
        perms = re.findall(r"^\s*([a-z-]+): (read|write|none)\s*$", CI, re.M)
        self.assertTrue(perms)
        self.assertEqual({p for p in perms}, {("contents", "read")})

    def test_no_secrets_or_private_patterns(self):
        self.assertNotIn("secrets.", CODE)
        self.assertNotIn("LEAK_PRIVATE_PATTERNS", CODE)
        self.assertNotIn("GITHUB_TOKEN", CODE)
        self.assertNotIn("github.token", CODE)

    def test_checkout_pinned_without_credentials(self):
        uses = re.findall(r"uses: (\S+)", CI)
        self.assertTrue(uses)
        for ref in uses:
            self.assertRegex(ref, r"@[0-9a-f]{40}$")
        self.assertIn("persist-credentials: false", CI)

    def test_installs_pinned_tools_and_runs_full_wrapper(self):
        self.assertIn("install_gitleaks.py", CI)
        self.assertIn("install_actionlint.py", CI)
        self.assertIn("bash tests/leak/test_gate.sh", CI)

    def test_wrapper_runs_full_discovery_and_rejects_skips(self):
        self.assertIn('pattern="test_*.py"', WRAPPER)
        self.assertNotIn("-p 'test_gate.py'", WRAPPER)
        self.assertIn("or skipped", WRAPPER)
        for var in ("LEAK_TEST_GITLEAKS", "LEAK_ACTIONLINT"):
            self.assertIn(var, WRAPPER)


if __name__ == "__main__":
    unittest.main()
