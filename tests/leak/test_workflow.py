# SPDX-License-Identifier: Apache-2.0
"""Execute the workflow's actual inline Python without GitHub or network writes."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest
import urllib.error
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / ".github/workflows/leak-gate.yml").read_text()


def inline_blocks():
    blocks = []
    for portion in WORKFLOW.split("python3 - <<'PY'\n")[1:]:
        lines = []
        for line in portion.splitlines():
            if line.strip() == "PY":
                break
            lines.append(line)
        blocks.append(textwrap.dedent("\n".join(lines)))
    return blocks


BLOCKS = inline_blocks()
PREFLIGHT = next(code for code in BLOCKS if "invalid or unsupported event revisions" in code)
PUBLISHERS = [code for code in BLOCKS if "LEAK-01_STATUS_PUBLISHER" in code]
FETCH = next(code for code in BLOCKS if "target Git object fetch" in code)


def execute(code, env):
    stdout, stderr = io.StringIO(), io.StringIO()
    result = 0
    with mock.patch.dict(os.environ, env, clear=True), redirect_stdout(stdout), redirect_stderr(stderr):
        try:
            exec(compile(code, "workflow-inline", "exec"), {})
        except SystemExit as exit:
            result = exit.code
    return result, stdout.getvalue(), stderr.getvalue()


class EventSelectionTests(unittest.TestCase):
    def setUp(self):
        self.base, self.head = "a" * 40, "b" * 40
        self.repo = {"full_name": "owner/repo", "default_branch": "main", "private": True}

    def check(self, event_name, event, ref="refs/heads/main", expected=0):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "event.json").write_text(json.dumps(event))
            env = {"EVENT_NAME": event_name, "CURRENT_SHA": self.head, "CURRENT_REF": ref,
                   "SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "owner/repo",
                   "GITHUB_EVENT_PATH": str(root / "event.json"), "GITHUB_OUTPUT": str(root / "outputs")}
            result, _, _ = execute(PREFLIGHT, env)
            self.assertEqual(result, expected)
            if expected:
                self.assertFalse((root / "outputs").exists())
                return None
            return dict(line.split("=", 1) for line in (root / "outputs").read_text().splitlines())

    def pr(self):
        return {"repository": self.repo, "number": 12,
                "pull_request": {"base": {"ref": "main", "repo": {"full_name": "owner/repo"}, "sha": self.base},
                                 "head": {"sha": self.head}}}

    def push(self):
        return {"repository": self.repo, "ref": "refs/heads/main", "before": self.base,
                "after": self.head, "deleted": False}

    def test_pr_uses_exact_base_policy_and_exact_head_data(self):
        outputs = self.check("pull_request_target", self.pr())
        self.assertEqual(outputs["trusted_sha"], self.base)
        self.assertEqual(outputs["base_sha"], self.base)
        self.assertEqual(outputs["head_sha"], self.head)
        self.assertEqual(outputs["pr_number"], "12")

    def test_push_uses_before_policy(self):
        outputs = self.check("push", self.push())
        self.assertEqual(outputs["trusted_sha"], self.base)

    def test_dispatch_uses_default_head_and_full_history(self):
        outputs = self.check("workflow_dispatch", {"repository": self.repo})
        self.assertEqual(outputs["trusted_sha"], self.head)
        self.assertEqual(outputs["mode"], "history")

    def test_dispatch_unreviewed_branch_rejected(self):
        self.check("workflow_dispatch", {"repository": self.repo}, ref="refs/heads/attack", expected=2)

    def test_push_bootstrap_delete_and_injected_sha_rejected(self):
        for changes in [{"before": "0" * 40}, {"deleted": True}, {"after": "$(fixture)"},
                        {"ref": "refs/heads/attack"}]:
            with self.subTest(changes=changes):
                self.check("push", dict(self.push(), **changes), expected=2)

    def test_wrong_base_and_event_rejected(self):
        event = self.pr()
        event["pull_request"]["base"]["ref"] = "attack"
        self.check("pull_request_target", event, expected=2)
        self.check("pull_request", self.pr(), expected=2)


class FakeResponse:
    status = 201

    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, maximum):
        return self.body[:maximum]


class StatusPublisherTests(unittest.TestCase):
    def setUp(self):
        self.env = {"STATUS_REPOSITORY": "owner/repo", "STATUS_HEAD": "b" * 40,
                    "GITHUB_RUN_ID": "1234", "STATUS_PHASE": "pending",
                    "STATUS_TOKEN": "fixture-private-token", "RUN_CANCELLED": "false"}

    def run_publisher(self, changes=None, receipt=None, error=None):
        requests = []
        def opened(request, timeout):
            requests.append(request)
            self.assertEqual(timeout, 30)
            if error:
                raise error
            payload = json.loads(request.data)
            body = json.dumps(payload if receipt is None else receipt).encode()
            return FakeResponse(body)
        opener = mock.Mock()
        opener.open.side_effect = opened
        with mock.patch("urllib.request.build_opener", return_value=opener):
            result, stdout, stderr = execute(PUBLISHERS[0], dict(self.env, **(changes or {})))
        return result, stdout, stderr, requests

    def test_pending_posts_fixed_context_to_exact_head_with_bounded_safe_body(self):
        result, stdout, stderr, requests = self.run_publisher()
        self.assertEqual(result, 0)
        request = requests[0]
        self.assertEqual(request.full_url, "https://api.github.com/repos/owner/repo/statuses/" + "b" * 40)
        self.assertEqual(request.method, "POST")
        self.assertEqual(json.loads(request.data), {"state": "pending", "context": "LEAK-01",
                         "description": "Leak scan pending", "target_url": "https://github.com/owner/repo/actions/runs/1234"})
        self.assertEqual(request.headers["X-github-api-version"], "2026-03-10")
        self.assertNotIn(self.env["STATUS_TOKEN"], stdout + stderr)

    def test_only_positive_job_and_scan_success_can_publish_success(self):
        outcomes = [("success", "success", "success"), ("success", "failure", "failure"),
                    ("failure", "success", "failure"), ("cancelled", "success", "failure"),
                    ("skipped", "skipped", "failure"), ("", "", "failure")]
        for job, scan, expected in outcomes:
            with self.subTest(job=job, scan=scan):
                result, _, _, requests = self.run_publisher({"STATUS_PHASE": "final", "SCAN_RESULT": job,
                                                           "SCAN_OUTCOME": scan})
                self.assertEqual(result, 0)
                self.assertEqual(json.loads(requests[0].data)["state"], expected)

    def test_cancellation_after_successful_scan_cannot_publish_success(self):
        result, _, _, requests = self.run_publisher({"STATUS_PHASE": "final", "SCAN_RESULT": "success",
                                                    "SCAN_OUTCOME": "success", "RUN_CANCELLED": "true"})
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(requests[0].data)["state"], "failure")

    def test_invalid_revision_phase_repository_or_run_id_never_calls_api(self):
        for changes in [{"STATUS_HEAD": "$(fixture)"}, {"STATUS_HEAD": "0" * 40},
                        {"STATUS_PHASE": "success"}, {"STATUS_REPOSITORY": "owner/repo/evil"},
                        {"GITHUB_RUN_ID": "1?private=fixture"}]:
            with self.subTest(changes=changes):
                result, _, _, requests = self.run_publisher(changes)
                self.assertEqual(result, 2)
                self.assertEqual(requests, [])

    def test_receipt_mismatch_and_http_errors_fail_without_dumping_private_data(self):
        result, stdout, stderr, _ = self.run_publisher(receipt={"state": "success", "private": "fixture-private-body"})
        self.assertEqual(result, 2)
        self.assertNotIn("fixture-private-body", stdout + stderr)
        error = urllib.error.HTTPError("https://api.github.com", 403, "fixture-private-error", {},
                                       io.BytesIO(b"fixture-private-body"))
        result, stdout, stderr, _ = self.run_publisher(error=error)
        self.assertEqual(result, 2)
        self.assertNotIn("fixture-private", stdout + stderr)


class WorkflowStructureTests(unittest.TestCase):
    def test_actual_inline_blocks_compile_and_both_publishers_match(self):
        self.assertEqual(len(BLOCKS), 5)
        for code in BLOCKS:
            compile(code, "workflow-inline", "exec")
        self.assertEqual(len(PUBLISHERS), 2)
        self.assertEqual(PUBLISHERS[0], PUBLISHERS[1])

    def test_status_write_isolated_from_scan_and_private_pattern_environment(self):
        prepare = WORKFLOW.split("  prepare:\n", 1)[1].split("  leak-gate:\n", 1)[0]
        scan = WORKFLOW.split("  leak-gate:\n", 1)[1].split("  publish-result:\n", 1)[0]
        final = WORKFLOW.split("  publish-result:\n", 1)[1]
        self.assertIn("permissions:\n      statuses: write", prepare)
        self.assertIn("permissions:\n      statuses: write", final)
        self.assertIn("permissions:\n      contents: read", scan)
        self.assertNotIn("statuses: write", scan)
        self.assertNotIn("LEAK_PRIVATE_PATTERNS", prepare)
        self.assertNotIn("LEAK_PRIVATE_PATTERNS", final)
        self.assertEqual(WORKFLOW.count("LEAK_PRIVATE_PATTERNS: ${{ secrets.LEAK_PRIVATE_PATTERNS }}"), 1)
        self.assertIn("if: ${{ always() && needs.prepare.outputs.head_sha != '' }}", final)
        self.assertIn("SCAN_OUTCOME: ${{ needs.leak-gate.outputs.scan_outcome }}", final)
        self.assertIn('RUN_CANCELLED: "false"', final)
        self.assertIn("if: ${{ !cancelled() }}", final)
        self.assertNotIn("${{ cancelled() }}", WORKFLOW)

    def test_trusted_only_checkout_pin_paths_and_cli(self):
        self.assertEqual(len(re.findall(r"^\s+uses:", WORKFLOW, flags=re.M)), 1)
        self.assertIn("uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", WORKFLOW)
        self.assertIn("ref: ${{ needs.prepare.outputs.trusted_sha }}", WORKFLOW)
        self.assertIn("persist-credentials: false", WORKFLOW)
        self.assertIn("allow-unsafe-pr-checkout: false", WORKFLOW)
        self.assertIn("scripts/leak/classify_literals.py", WORKFLOW)
        self.assertIn('--allowlist "$GITHUB_WORKSPACE/trusted-policy/.leak-allowlist"', WORKFLOW)
        self.assertNotIn(".leak-allowlist.json", WORKFLOW)
        self.assertNotIn("upload-artifact", WORKFLOW)
        self.assertNotIn("npm ", WORKFLOW)

    def test_fetch_is_bare_and_token_limited_to_fetch_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = {"RUNNER_TEMP": str(root), "GITHUB_OUTPUT": str(root / "outputs"),
                   "READ_TOKEN": "fixture-private-token", "REPOSITORY": "owner/repo",
                   "BASE_SHA": "a" * 40, "HEAD_SHA": "b" * 40, "SCAN_MODE": "diff", "PR_NUMBER": "12",
                   "GIT_SSH_COMMAND": "fixture-unsafe", "LEAK_PRIVATE_PATTERNS": "fixture-private-pattern"}
            calls = []
            def run(args, **kwargs):
                calls.append((args, kwargs))
                data = b""
                if "rev-parse" in args:
                    data = (("b" if "refs/leak/head^{commit}" in args else "a") * 40 + "\n").encode()
                return subprocess.CompletedProcess(args, 0, data, b"fixture-private-stderr")
            with mock.patch("subprocess.run", side_effect=run):
                result, stdout, stderr = execute(FETCH, env)
            self.assertEqual(result, 0)
            self.assertIn("--bare", calls[0][0])
            self.assertNotIn("checkout", repr(calls))
            for args, kwargs in calls:
                child_env = kwargs["env"]
                self.assertNotIn("GIT_SSH_COMMAND", child_env)
                self.assertNotIn("LEAK_PRIVATE_PATTERNS", child_env)
                self.assertEqual("GIT_CONFIG_VALUE_0" in child_env, "fetch" in args)
            self.assertNotIn("fixture-private", stdout + stderr)


if __name__ == "__main__":
    unittest.main()
