# SPDX-License-Identifier: Apache-2.0
# Copyright The Sovereign AI OS Authors
"""Synthetic Git repositories exercise the trusted gate, never live patterns."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import string
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "scripts/leak/gate.py"
PATTERN = "PRIVATE_" + "SENTINEL"
TOKEN = "gh" + "p_" + "".join(random.Random(92173).choices(string.ascii_letters + string.digits, k=36))


class GateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="leak01-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "target"
        self.repo.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.name", "Synthetic Test")
        self.git("config", "user.email", "test@example.invalid")
        self.policy = self.root / "policy.json"
        self.write_policy()
        self.config = self.root / "gitleaks.toml"
        self.config.write_text('[extend]\nuseDefault = true\n', encoding="utf-8")
        self.scanner = self.root / "scanner"
        self.scanner.write_text('''#!/usr/bin/env python3
import json, os, pathlib, re, sys
if sys.argv[1] == "version":
    print("8.30.1")
    sys.exit(0)
assert "LEAK_PRIVATE_PATTERNS" not in os.environ
assert not any(k.startswith("GITLEAKS_") for k in os.environ)
assert not any(k.startswith("GITHUB_") for k in os.environ)
assert "--ignore-gitleaks-allow" in sys.argv
assert sys.argv[sys.argv.index("--gitleaks-ignore-path") + 1] == os.devnull
findings = []
for path in pathlib.Path(sys.argv[2]).iterdir():
    text = path.read_text(encoding="utf-8")
    for match in re.finditer(r"ghp_[A-Za-z0-9]{36}", text):
        print(match.group(0))
        print(match.group(0), file=sys.stderr)
        findings.append({"File":str(path), "RuleID":"github-pat", "Match":match.group(0),
                         "Secret":match.group(0), "StartLine":text.count("\\n",0,match.start())+1})
pathlib.Path(sys.argv[sys.argv.index("--report-path")+1]).write_text(json.dumps(findings))
sys.exit(1 if findings else 0)
''', encoding="utf-8")
        self.scanner.chmod(0o700)
        self.write("readme.md", "Contact: test@example.invalid\n")
        self.base = self.commit()

    def git(self, *args):
        env = os.environ.copy()
        for key in list(env):
            if key.startswith("GIT_"):
                env.pop(key)
        result = subprocess.run(["git", "-C", str(self.repo), *args], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return result.stdout.decode().strip()

    def write(self, path, text):
        destination = self.repo / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")

    def commit(self):
        self.git("add", "--all")
        self.git("commit", "--quiet", "-m", "Synthetic case")
        return self.git("rev-parse", "HEAD")

    def write_policy(self, private=True, paths=None):
        self.policy.write_text(json.dumps({"private_repo": private, "literal_exempt_paths": paths or []}), encoding="utf-8")

    def run_gate(self, mode="diff", encoded=None, missing=False, scanner=None, extra=(), base=None):
        env = os.environ.copy()
        env["LEAK_PRIVATE_PATTERNS"] = encoded if encoded is not None else base64.b64encode(PATTERN.encode()).decode()
        if missing:
            env.pop("LEAK_PRIVATE_PATTERNS", None)
        # Poisoning inherited Gitleaks configuration must not override trusted policy.
        env["GITLEAKS_CONFIG_TOML"] = "this is invalid TOML"
        env["GITHUB_TOKEN"] = TOKEN
        command = [sys_executable(), str(GATE), "--repo", str(self.repo), "--mode", mode,
                   "--gitleaks", str(scanner or self.scanner), "--config", str(self.config),
                   "--policy", str(self.policy), *extra]
        if mode == "diff":
            command.extend(["--base", base or self.base])
        completed = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        self.assertEqual(completed.stderr, b"")
        self.assertNotIn(TOKEN.encode(), completed.stdout)
        self.assertNotIn(PATTERN.encode(), completed.stdout)
        return completed.returncode, json.loads(completed.stdout)

    def test_benign_example_is_clear(self):
        code, report = self.run_gate()
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "clear")

    def test_secret_detected_and_report_redacted(self):
        self.write("credential.txt", TOKEN + "\n")
        self.commit()
        report_path = self.root / "report.json"
        code, report = self.run_gate(extra=("--report", str(report_path)))
        self.assertEqual(code, 1)
        finding = next(x for x in report["findings"] if x["rule"] == "github-pat")
        self.assertEqual(finding["match_sha256"], hashlib.sha256(TOKEN.encode()).hexdigest())
        self.assertEqual(finding["file"], "sha256:" + hashlib.sha256(b"credential.txt").hexdigest())
        self.assertEqual(finding["line"], 1)
        self.assertEqual(json.loads(report_path.read_text()), report)
        self.assertNotIn(TOKEN, report_path.read_text())
        self.assertEqual(report_path.stat().st_mode & 0o777, 0o600)

    def test_private_literal_detected(self):
        self.write("note.md", "Hello " + PATTERN + "\n")
        self.commit()
        code, report = self.run_gate()
        self.assertEqual(code, 1)
        self.assertEqual(report["findings"][0]["rule"], "private-literal-001")

    def test_private_filename_is_hashed(self):
        self.write(PATTERN + ".md", "safe\n")
        self.commit()
        code, report = self.run_gate()
        self.assertEqual(code, 1)
        self.assertTrue(report["findings"][0]["file"].startswith("sha256:"))
        self.assertEqual(report["findings"][0]["line"], 0)

    def test_secret_filename_is_hashed(self):
        self.write(TOKEN + ".txt", TOKEN + "\n")
        self.commit()
        code, report = self.run_gate()
        self.assertEqual(code, 1)
        self.assertTrue(any(x["file"].startswith("sha256:") and x["line"] == 0 for x in report["findings"]))
        self.assertTrue(all(x["file"].startswith("sha256:") for x in report["findings"]))

    def test_raw_filename_cannot_be_exempted(self):
        self.write_policy(paths=["plans/"])
        self.write("plans/data.sql.gz", "synthetic text\n")
        self.commit()
        code, report = self.run_gate()
        self.assertEqual(code, 1)
        self.assertTrue(any(x["rule"] == "raw-artifact-filename" for x in report["findings"]))

    def test_raw_dump_body_detected(self):
        self.write("looks-like-doc.md", "-- PostgreSQL database " + "dump\n")
        self.commit()
        code, report = self.run_gate()
        self.assertEqual(code, 1)
        self.assertTrue(any(x["rule"] == "raw-artifact-content" for x in report["findings"]))

    def test_missing_patterns_fail_closed(self):
        code, report = self.run_gate(missing=True)
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "unable")

    def test_invalid_controls_fail_closed(self):
        cases = ["", "not base64", base64.b64encode(b"\xff").decode(),
                 base64.b64encode(b"first\n\nlast").decode(),
                 base64.b64encode(b"[").decode(), base64.b64encode(b".*").decode()]
        for encoded in cases:
            with self.subTest(control=hashlib.sha256(encoded.encode()).hexdigest()):
                code, report = self.run_gate(encoded=encoded)
                self.assertEqual(code, 2)
                self.assertEqual(report["status"], "unable")

    def test_pr_changed_config_and_code_cannot_bypass(self):
        marker = self.root / "target-was-executed"
        self.write(".gitleaks.toml", "[allowlist]\nregexes=['.*']\n")
        self.write(".gitleaksignore", "*\n")
        self.write("scripts/leak/gate.py", "raise SystemExit(0)\n")
        self.write("run.sh", "#!/bin/sh\ntouch " + str(marker) + "\n")
        self.write("credential.txt", TOKEN + " # gitleaks:allow\n")
        self.commit()
        code, report = self.run_gate()
        self.assertEqual(code, 1)
        self.assertTrue(any(x["rule"] == "github-pat" for x in report["findings"]))
        self.assertFalse(marker.exists())

    def test_removed_secret_is_still_detected_in_diff(self):
        self.write("temporary.txt", TOKEN + "\n")
        secret_commit = self.commit()
        (self.repo / "temporary.txt").unlink()
        self.commit()
        code, report = self.run_gate()
        self.assertEqual(code, 1)
        self.assertTrue(any(x["commit"] == secret_commit for x in report["findings"]))

    def test_history_scans_deleted_literal_on_other_branch(self):
        self.git("checkout", "-b", "old-branch", "--quiet")
        self.write("old.md", PATTERN + "\n")
        historic = self.commit()
        self.git("checkout", "--quiet", "-")
        code, report = self.run_gate(mode="history")
        self.assertEqual(code, 1)
        self.assertTrue(any(x["commit"] == historic for x in report["findings"]))

    def test_private_exemption_exact_prefix_and_secret_still_blocks(self):
        self.write_policy(paths=["plans/reviewed/"])
        self.write("plans/reviewed/note.md", PATTERN + "\n")
        self.commit()
        code, _report = self.run_gate()
        self.assertEqual(code, 0)
        self.write("plans/reviewed/credential.md", TOKEN + "\n")
        self.commit()
        code, report = self.run_gate()
        self.assertEqual(code, 1)
        self.assertTrue(any(x["rule"] == "github-pat" for x in report["findings"]))

    def test_prefix_does_not_exempt_neighbor(self):
        self.write_policy(paths=["plans/reviewed/"])
        self.write("plans/reviewed-other/note.md", PATTERN + "\n")
        self.commit()
        code, _report = self.run_gate()
        self.assertEqual(code, 1)

    def test_public_exemption_forbidden(self):
        self.write_policy(private=False, paths=["plans/"])
        code, report = self.run_gate()
        self.assertEqual(code, 2)
        self.assertEqual(report["error"], "public_repository_exemption_forbidden")

    def test_trusted_policy_must_be_outside_target(self):
        self.write("policy.json", self.policy.read_text())
        code, report = self.run_gate(extra=("--policy", str(self.repo / "policy.json")))
        self.assertEqual(code, 2)
        self.assertIn("trusted_path", report["error"])

    def test_report_must_not_write_target(self):
        destination = self.repo / "generated.json"
        code, _report = self.run_gate(extra=("--report", str(destination)))
        self.assertEqual(code, 2)
        self.assertFalse(destination.exists())

    def test_allowlist_requires_narrow_reviewed_unexpired_entry(self):
        allowlist = self.root / "allowlist.json"
        self.write("note.md", PATTERN + "\n")
        self.commit()
        item = {"rule":"private-literal-001", "path":"note.md", "reason":"Synthetic documented exception",
                "reviewer":"Synthetic reviewer", "expiry":"2999-01-01"}
        allowlist.write_text(json.dumps([item]))
        code, _report = self.run_gate(extra=("--allowlist", str(allowlist)))
        self.assertEqual(code, 0)
        for field, value in (("path", "*"), ("reason", ""), ("reviewer", ""), ("rule", "github-pat"),
                             ("expiry", "2000-01-01"), ("expiry", "bogus")):
            invalid = dict(item, **{field:value})
            allowlist.write_text(json.dumps([invalid]))
            code, _report = self.run_gate(extra=("--allowlist", str(allowlist)))
            self.assertEqual(code, 2)

    def test_symlink_lfs_and_nontext_fail_closed(self):
        for kind in ("symlink", "lfs", "binary"):
            with self.subTest(kind=kind):
                self.git("reset", "--hard", self.base)
                path = self.repo / "unsupported"
                if kind == "symlink":
                    path.symlink_to(self.root / "outside")
                elif kind == "lfs":
                    path.write_text("version https://git-lfs.github.com/spec/v1\noid sha256:" + "0"*64 + "\nsize 7\n")
                else:
                    path.write_bytes(b"\x00\xff\x00")
                self.commit()
                code, report = self.run_gate()
                self.assertEqual(code, 2)
                self.assertEqual(report["status"], "unable")
                self.assertIn(report["error"], ("unsupported_git_entry", "unsupported_binary_or_lfs"))

    def test_version_mismatch_fail_closed(self):
        self.scanner.write_text("#!/bin/sh\necho 0.0.0\n")
        self.scanner.chmod(0o700)
        code, report = self.run_gate()
        self.assertEqual(code, 2)
        self.assertEqual(report["error"], "scanner_version_mismatch")

    def test_oversized_blob_fails_closed(self):
        self.write("oversized.txt", "x" * (5 * 1024 * 1024 + 1))
        self.commit()
        code, report = self.run_gate()
        self.assertEqual(code, 2)
        self.assertEqual(report["error"], "blob_size_limit")

    def test_invalid_arguments_never_echo_input(self):
        code, report = self.run_gate(extra=("--unrecognized", TOKEN))
        self.assertEqual(code, 2)
        self.assertEqual(report["error"], "arguments_invalid")

    def test_scanner_path_inside_target_is_forbidden(self):
        target_scanner = self.repo / "scanner"
        shutil.copyfile(self.scanner, target_scanner)
        target_scanner.chmod(0o700)
        code, report = self.run_gate(scanner=target_scanner)
        self.assertEqual(code, 2)
        self.assertEqual(report["error"], "trusted_path_inside_target_or_not_regular")

    def test_public_allowlist_is_forbidden(self):
        self.write_policy(private=False)
        allowlist = self.root / "allowlist.json"
        allowlist.write_text(json.dumps([{"rule":"private-literal-001", "path":"note.md", "reason":"Synthetic exception",
                                         "reviewer":"Synthetic reviewer", "expiry":"2999-01-01"}]))
        code, report = self.run_gate(extra=("--allowlist", str(allowlist)))
        self.assertEqual(code, 2)
        self.assertEqual(report["error"], "public_repository_allowlist_forbidden")

    def test_partial_clone_controls_fail_closed(self):
        self.git("config", "remote.origin.promisor", "true")
        code, report = self.run_gate(mode="history")
        self.assertEqual(code, 2)
        self.assertEqual(report["error"], "partial_repository_forbidden")

    def test_shallow_history_cannot_hide_deleted_literal(self):
        self.write("historic.md", PATTERN + "\n")
        self.commit()
        (self.repo / "historic.md").unlink()
        self.commit()
        shallow = self.root / "shallow"
        subprocess.run(["git", "clone", "--quiet", "--depth", "1", self.repo.as_uri(), str(shallow)],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        self.repo = shallow
        code, report = self.run_gate(mode="history")
        self.assertEqual(code, 2)
        self.assertEqual(report["error"], "shallow_repository_forbidden")

    def test_invalid_scanner_report_fails_closed(self):
        self.scanner.write_text('''#!/usr/bin/env python3
import pathlib, sys
if sys.argv[1] == "version":
    print("8.30.1")
else:
    pathlib.Path(sys.argv[sys.argv.index("--report-path")+1]).write_text("not JSON")
''')
        self.scanner.chmod(0o700)
        code, report = self.run_gate()
        self.assertEqual(code, 2)
        self.assertEqual(report["error"], "scanner_report_invalid")

    def test_scanner_failure_never_echoes_stderr(self):
        self.scanner.write_text("#!/usr/bin/env python3\nimport sys\nif sys.argv[1]=='version': print('8.30.1')\nelse:\n print(" + repr(TOKEN) + ",file=sys.stderr)\n sys.exit(7)\n")
        self.scanner.chmod(0o700)
        code, report = self.run_gate()
        self.assertEqual(code, 2)
        self.assertEqual(report["error"], "subprocess_failed")

    @unittest.skipUnless(os.environ.get("LEAK_TEST_GITLEAKS"), "real pinned Gitleaks not supplied")
    def test_real_pinned_gitleaks_acceptance_and_bypass(self):
        scanner = Path(os.environ["LEAK_TEST_GITLEAKS"]).resolve()
        code, report = self.run_gate(scanner=scanner)
        self.assertEqual(code, 0, report)
        self.write("credential.md", TOKEN + " # gitleaks:allow\n")
        self.write(".gitleaks.toml", "[allowlist]\nregexes=['.*']\n")
        self.write(".gitleaksignore", "*\n")
        leak_commit = self.commit()
        (self.repo / "credential.md").unlink()
        self.commit()
        code, report = self.run_gate(scanner=scanner)
        self.assertEqual(code, 1, report)
        self.assertTrue(any(x["commit"] == leak_commit for x in report["findings"]))
        self.assertTrue(any(x["match_sha256"] == hashlib.sha256((TOKEN + " # gitleaks:allow").encode()).hexdigest()
                            or x["match_sha256"] == hashlib.sha256(TOKEN.encode()).hexdigest() for x in report["findings"]))

    @unittest.skipUnless(os.environ.get("LEAK_TEST_GITLEAKS"), "real pinned Gitleaks not supplied")
    def test_real_secret_filename_raw_artifact_is_never_serialized(self):
        self.write(TOKEN + ".db", "safe text\n")
        self.commit()
        code, report = self.run_gate(scanner=Path(os.environ["LEAK_TEST_GITLEAKS"]).resolve())
        self.assertEqual(code, 1)
        self.assertTrue(any(x["rule"] == "raw-artifact-filename" for x in report["findings"]))
        self.assertTrue(all(x["file"].startswith("sha256:") for x in report["findings"]))

    @unittest.skipUnless(os.environ.get("LEAK_TEST_GITLEAKS"), "real pinned Gitleaks not supplied")
    def test_real_secret_filename_binary_is_never_serialized(self):
        (self.repo / (TOKEN + ".txt")).write_bytes(b"\x00\xff")
        self.commit()
        code, report = self.run_gate(scanner=Path(os.environ["LEAK_TEST_GITLEAKS"]).resolve())
        self.assertEqual(code, 2)
        self.assertEqual(report["error"], "unsupported_binary_or_lfs")

    @unittest.skipUnless(os.environ.get("LEAK_TEST_GITLEAKS"), "real pinned Gitleaks not supplied")
    def test_real_secret_filename_and_body_are_never_serialized(self):
        self.write(TOKEN + ".txt", TOKEN + "\n")
        self.commit()
        code, report = self.run_gate(scanner=Path(os.environ["LEAK_TEST_GITLEAKS"]).resolve())
        self.assertEqual(code, 1)
        self.assertTrue(any(x["rule"] == "github-pat" for x in report["findings"]))
        self.assertTrue(all(x["file"].startswith("sha256:") for x in report["findings"]))

    def test_commit_message_secret_is_detected(self):
        self.write("changed.md", "safe\n")
        self.git("add", "--all")
        self.git("commit", "--quiet", "-m", TOKEN)
        commit = self.git("rev-parse", "HEAD")
        code, report = self.run_gate()
        self.assertEqual(code, 1)
        self.assertTrue(any(x["rule"] == "github-pat" and x["commit"] == commit for x in report["findings"]))

    def test_annotated_tag_message_secret_is_detected(self):
        self.git("tag", "-a", "safe-tag", "-m", TOKEN)
        tag = self.git("rev-parse", "safe-tag")
        code, report = self.run_gate(mode="history")
        self.assertEqual(code, 1)
        self.assertTrue(any(x["rule"] == "github-pat" and x["commit"] == tag for x in report["findings"]))

    def test_history_refname_literal_is_detected(self):
        self.git("branch", "synthetic-" + PATTERN)
        code, report = self.run_gate(mode="history")
        self.assertEqual(code, 1)
        self.assertTrue(any(x["rule"] == "private-literal-001" for x in report["findings"]))

    def test_noncommit_ref_target_cannot_receive_clear_certificate(self):
        blob = subprocess.run(["git", "-C", str(self.repo), "hash-object", "-w", "--stdin"],
                              input=TOKEN.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout.decode().strip()
        self.git("update-ref", "refs/tags/synthetic-blob", blob)
        code, report = self.run_gate(mode="history")
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "unable")

    @unittest.skipUnless(os.environ.get("LEAK_TEST_GITLEAKS"), "real pinned Gitleaks not supplied")
    def test_real_commit_and_annotated_tag_messages(self):
        self.write("changed.md", "safe\n")
        self.git("add", "--all")
        self.git("commit", "--quiet", "-m", TOKEN)
        commit = self.git("rev-parse", "HEAD")
        self.git("tag", "-a", "safe-tag", "-m", TOKEN)
        tag = self.git("rev-parse", "safe-tag")
        code, report = self.run_gate(mode="history", scanner=Path(os.environ["LEAK_TEST_GITLEAKS"]).resolve())
        self.assertEqual(code, 1)
        self.assertTrue(any(x["rule"] == "github-pat" and x["commit"] == commit for x in report["findings"]))
        self.assertTrue(any(x["rule"] == "github-pat" and x["commit"] == tag for x in report["findings"]))


def sys_executable():
    import sys
    return sys.executable


if __name__ == "__main__":
    unittest.main()
