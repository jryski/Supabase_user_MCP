# SPDX-License-Identifier: Apache-2.0
"""Full-workflow GitHub Actions semantic validation of the LEAK-01 workflow.

Uses checksum-verified actionlint (scripts/leak/actionlint-pin.json). An
unavailable validator is a failure, never a pass. Set LEAK_ACTIONLINT to a
binary already installed by install_actionlint.py to avoid re-downloading.
"""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ROOT / ".github/workflows/leak-gate.yml"
WORKFLOW = WORKFLOW_PATH.read_text()
PIN = ROOT / "scripts/leak/actionlint-pin.json"
sys.path.insert(0, str(ROOT / "scripts/leak"))
import install_actionlint  # noqa: E402


def actionlint_binary(directory):
    configured = os.environ.get("LEAK_ACTIONLINT")
    if configured:
        return Path(configured)
    return install_actionlint.install(PIN, Path(directory) / "actionlint")


class ActionsSemanticsTest(unittest.TestCase):
    def test_actionlint_reports_no_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = actionlint_binary(directory)
            result = subprocess.run([str(binary), "-no-color", "-shellcheck=", "-pyflakes=",
                                     str(WORKFLOW_PATH)], capture_output=True, text=True,
                                    timeout=120, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_no_status_function_in_env_values(self):
        for line in WORKFLOW.splitlines():
            if re.match(r"^\s+[A-Z_][A-Z0-9_]*: \$\{\{", line):
                self.assertIsNone(re.search(r"\b(cancelled|success|failure|always)\(\)", line), line)

    def test_pin_rejects_tampered_digest(self):
        pin = install_actionlint.load_pin(PIN)
        with self.assertRaises(install_actionlint.InstallError):
            install_actionlint.verify_archive(b"x" * pin["size_bytes"], pin)

    def test_pin_rejects_wrong_size(self):
        pin = install_actionlint.load_pin(PIN)
        with self.assertRaises(install_actionlint.InstallError):
            install_actionlint.verify_archive(b"x", pin)


if __name__ == "__main__":
    unittest.main()
