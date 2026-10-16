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


STATUS_FUNCTION = re.compile(r"\b(cancelled|success|failure|always)\s*\(", re.I)


def status_functions_in_env(text):
    """Return (line, text) for every status-function call inside any env mapping.

    Covers workflow-, job- and step-level block mappings, multi-line scalar
    values and flow mappings, with any spacing inside ${{ }}.
    """
    hits = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"^(\s*)(?:-\s+)?env:\s*(.*)$", line)
        if not match:
            index += 1
            continue
        indent = len(match.group(1))
        if match.group(2).strip():
            if STATUS_FUNCTION.search(match.group(2)):
                hits.append((index + 1, line.strip()))
            index += 1
            continue
        index += 1
        while index < len(lines):
            body = lines[index]
            if body.strip() and (len(body) - len(body.lstrip())) <= indent:
                break
            if not body.lstrip().startswith("#") and STATUS_FUNCTION.search(body):
                hits.append((index + 1, body.strip()))
            index += 1
    return hits


class ActionsSemanticsTest(unittest.TestCase):
    def test_actionlint_reports_no_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = actionlint_binary(directory)
            result = subprocess.run([str(binary), "-no-color", "-shellcheck=", "-pyflakes=",
                                     str(WORKFLOW_PATH)], capture_output=True, text=True,
                                    timeout=120, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_no_status_function_in_env_values(self):
        self.assertEqual(status_functions_in_env(WORKFLOW), [])
        ci = (ROOT / ".github/workflows/leak-ci.yml").read_text()
        self.assertEqual(status_functions_in_env(ci), [])

    def test_env_checker_detects_spacing_case_and_scope_variants(self):
        # Negative controls: each variant must be reported, so a pass above is meaningful.
        variants = [
            "    env:\n      RUN_CANCELLED: ${{ cancelled() }}\n",
            "    env:\n      RUN_CANCELLED: ${{cancelled()}}\n",
            "    env:\n      run_cancelled: ${{ always( ) }}\n",
            "    env:\n      X: ${{ failure() || 'x' }}\n",
            "    env:\n      X: >-\n        ${{ success() }}\n",
            "    env: { X: \"${{ cancelled() }}\" }\n",
            "env:\n  TOP: ${{ always() }}\n",
        ]
        for variant in variants:
            with self.subTest(variant=variant):
                self.assertTrue(status_functions_in_env(variant), variant)
        allowed = "    if: ${{ !cancelled() }}\n    env:\n      RUN_CANCELLED: \"false\"\n"
        self.assertEqual(status_functions_in_env(allowed), [])

    def test_actionlint_rejects_the_original_illegal_form(self):
        # Negative control for the validator itself: reintroducing the defect must fail.
        broken = WORKFLOW.replace('RUN_CANCELLED: "false"', "RUN_CANCELLED: ${{ cancelled() }}")
        self.assertNotEqual(broken, WORKFLOW)
        with tempfile.TemporaryDirectory() as directory:
            binary = actionlint_binary(directory)
            path = Path(directory) / "leak-gate.yml"
            path.write_text(broken)
            result = subprocess.run([str(binary), "-no-color", "-shellcheck=", "-pyflakes=", str(path)],
                                    capture_output=True, text=True, timeout=120, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cancelled", result.stdout + result.stderr)

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
