# SPDX-License-Identifier: Apache-2.0
# Copyright The Sovereign AI OS Authors
"""Exact-head LEAK-01 controls for unprivileged pull-request CI.

Runs the real trusted gate (scripts/leak/gate.py) with the real pinned
Gitleaks binary three times:

1. clean fixture: a synthetic repository with only benign commits -> must be
   "clear" with exit 0;
2. leak sentinel: the same fixture plus a commit containing a deliberately
   planted synthetic private literal -> must be "findings" with exit 1 and the
   private-literal rule;
3. exact head: the complete tree and metadata of the checked-out
   pull-request HEAD commit (scanned as HEAD^..HEAD, with policy and config
   taken from the PR base) -> must be "clear" with exit 0. Intermediate PR
   commits are not covered here; the trusted LEAK-01 workflow scans every
   commit in base..head, so a PR that removes a finding must be squash-merged.

The private pattern is generated randomly at run time and never committed,
so no real or reusable pattern exists in source or logs. The real
LEAK_PRIVATE_PATTERNS secret is never read here; that check belongs to the
trusted LEAK-01 workflow. Only fixed summary lines are printed: no gate
report, finding hash, file name, scanner output or pattern value reaches the
public log. Any unexpected result exits non-zero with a fixed message.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "scripts/leak/gate.py"


def fail(message: str) -> None:
    print("LEAK-01 exact-head controls: FAIL: " + message)
    raise SystemExit(1)


def clean_git_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0")
    return env


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], env=clean_git_env(),
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    if result.returncode:
        fail("git step failed")
    return result.stdout.decode("ascii", "replace").strip()


def git_show(revision: str, name: str) -> str:
    result = subprocess.run(["git", "-C", str(ROOT), "show", revision + ":" + name], env=clean_git_env(),
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    if result.returncode:
        fail("base policy file unavailable")
    return result.stdout.decode("utf-8")


def run_gate(repo: Path, base: str, head: str, scanner: Path, policy: Path,
             pattern: str, config: Path) -> tuple[int, dict, bytes]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GITLEAKS_", "GITHUB_", "GIT_"))}
    env["LEAK_PRIVATE_PATTERNS"] = base64.b64encode(pattern.encode()).decode()
    command = [sys.executable, str(GATE), "--repo", str(repo), "--mode", "diff", "--base", base,
               "--head", head, "--gitleaks", str(scanner), "--config", str(config), "--policy", str(policy)]
    completed = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=300, check=False)
    output = completed.stdout + completed.stderr
    try:
        report = json.loads(completed.stdout)
    except ValueError:
        fail("gate output was not a sanitized JSON report")
    return completed.returncode, report, output


def make_fixture(root: Path) -> tuple[Path, str, str]:
    repo = root / "fixture"
    repo.mkdir()
    git(repo, "init", "--quiet")
    git(repo, "config", "user.name", "Synthetic Fixture")
    git(repo, "config", "user.email", "fixture@example.invalid")
    (repo / "readme.md").write_text("Synthetic fixture. Contact: fixture@example.invalid\n", encoding="utf-8")
    git(repo, "add", "--all")
    git(repo, "commit", "--quiet", "-m", "Synthetic base")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "notes.md").write_text("A benign synthetic change.\n", encoding="utf-8")
    git(repo, "add", "--all")
    git(repo, "commit", "--quiet", "-m", "Synthetic clean change")
    return repo, base, git(repo, "rev-parse", "HEAD")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gitleaks", required=True, type=Path)
    parser.add_argument("--base", required=True, help="exact pull-request base SHA")
    parser.add_argument("--head", required=True, help="exact pull-request head SHA")
    args = parser.parse_args()
    scanner = args.gitleaks.resolve()
    if not os.access(scanner, os.X_OK):
        fail("pinned scanner is not executable")
    actual_head = git(ROOT, "rev-parse", "HEAD")
    if actual_head != args.head:
        fail("checked-out HEAD is not the exact pull-request head")
    pattern = "SYNTHETIC_SENTINEL_" + secrets.token_hex(16)
    leaked: list[bytes] = [pattern.encode()]

    with tempfile.TemporaryDirectory(prefix="leak01-controls-") as temporary:
        root = Path(temporary)
        policy = root / "policy.json"
        policy.write_text(json.dumps({"private_repo": True, "literal_exempt_paths": []}), encoding="utf-8")
        config = root / "gitleaks.toml"
        config.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
        fixture, base, clean_head = make_fixture(root)

        code, report, output = run_gate(fixture, base, clean_head, scanner, policy, pattern, config)
        if code != 0 or report.get("status") != "clear" or report.get("findings"):
            fail("clean fixture was not clear")
        print("control 1 clean fixture: clear (exit 0)")

        (fixture / "planted.md").write_text("Planted value " + pattern + "\n", encoding="utf-8")
        git(fixture, "add", "--all")
        git(fixture, "commit", "--quiet", "-m", "Synthetic sentinel")
        sentinel_head = git(fixture, "rev-parse", "HEAD")
        code, report, output = run_gate(fixture, base, sentinel_head, scanner, policy, pattern, config)
        rules = sorted({f.get("rule", "") for f in report.get("findings", [])})
        if code != 1 or report.get("status") != "findings" or not any(r.startswith("private-literal-") for r in rules):
            fail("deliberate sentinel was not blocked")
        if any(value in output for value in leaked) or b"planted.md" in output:
            fail("gate output exposed the sentinel or its file name")
        print("control 2 deliberate sentinel: blocked (exit 1, rule family private-literal)")

        # As in the trusted workflow, policy and config come from the PR base,
        # copied outside the scanned repository.
        trusted = root / "trusted"
        trusted.mkdir()
        for name in (".gitleaks.toml", ".leak-policy.json"):
            (trusted / name).write_text(git_show(args.base, name), encoding="utf-8")
        parent = git(ROOT, "rev-parse", args.head + "^")
        code, report, output = run_gate(ROOT, parent, args.head, scanner, trusted / ".leak-policy.json",
                                        pattern, config=trusted / ".gitleaks.toml")
        if any(value in output for value in leaked):
            fail("gate output exposed the synthetic pattern")
        if code != 0 or report.get("status") != "clear":
            fail("exact head tree is not clear under default rules (exit %d, status %s)"
                 % (code, report.get("status") if report.get("status") in {"findings", "unable"} else "invalid"))
        print("control 3 exact head tree %s (PR base %s policy): clear (exit 0, %d paths)"
              % (args.head, args.base, int(report.get("paths_scanned", 0))))
    print("LEAK-01 exact-head controls: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
