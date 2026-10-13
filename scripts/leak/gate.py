#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright The Sovereign AI OS Authors
"""Fail-closed leakage gate. All target repository files remain untrusted data.

The caller supplies trusted policy, configuration and scanner paths. No target
checkout, hook, target executable, target ignore file or target configuration is
used. Exit codes: 0 clear; 1 findings; 2 unable to establish a valid result.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
import tempfile

from classify_literals import ControlError, digest, find_matches, load_patterns, safe_path

PINNED_VERSION = "8.30.1"
MAX_COMMITS = 2500
MAX_TREE_ENTRIES = 500000
MAX_FILES = 30000
MAX_BLOB_BYTES = 5 * 1024 * 1024
MAX_TOTAL_BYTES = 200 * 1024 * 1024
MAX_COMMAND_BYTES = 32 * 1024 * 1024
MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_FINDINGS = 10000
RAW_NAME = re.compile(r"(?i)(?:\.(?:dump|pgdump|backup|sqlite3?|db)$|\.sql\.(?:gz|bz2|xz|zip)$|(?:^|/)(?:raw[-_]|pg_dump|supabase[-_]export|database[-_]export))")
RAW_BODY = re.compile(r"(?im)^-- PostgreSQL database dump\b|^COPY\s+[^\n]+\s+FROM stdin;\s*$")
OID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


def deadline_handler(_signum, _frame):
    raise ControlError("resource_timeout")


def git_env():
    # Subprocesses receive only runtime essentials, never CI credentials,
    # private patterns, poisoned scanner controls or inherited Git controls.
    env = {key: os.environ[key] for key in ("PATH", "LANG", "TZ") if key in os.environ}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_SYSTEM=os.devnull,
               GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0",
               GIT_PAGER="cat", LC_ALL="C", GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1")
    return env


def run_bounded(command, temporary, *, allowed=(0,), timeout=60):
    def subprocess_limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_COMMAND_BYTES, MAX_COMMAND_BYTES))

    with tempfile.TemporaryFile(dir=temporary) as out, tempfile.TemporaryFile(dir=temporary) as err:
        try:
            completed = subprocess.run(command, stdin=subprocess.DEVNULL,
                                       stdout=out, stderr=err, env=git_env(),
                                       timeout=timeout, check=False, preexec_fn=subprocess_limits)
        except (OSError, subprocess.TimeoutExpired):
            raise ControlError("subprocess_unavailable_or_timeout") from None
        if out.tell() > MAX_COMMAND_BYTES or err.tell() > MAX_COMMAND_BYTES:
            raise ControlError("subprocess_output_limit")
        if completed.returncode not in allowed:
            raise ControlError("subprocess_failed")
        out.seek(0)
        return completed.returncode, out.read()


def inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def trusted_file(name: str, target: Path, *, executable=False) -> Path:
    path = Path(name)
    if not path.is_absolute() or path.is_symlink():
        raise ControlError("trusted_path_invalid")
    try:
        resolved = path.resolve(strict=True)
        mode = resolved.stat().st_mode
    except OSError:
        raise ControlError("trusted_file_unavailable") from None
    if inside(resolved, target) or not stat.S_ISREG(mode):
        raise ControlError("trusted_path_inside_target_or_not_regular")
    if executable and not os.access(resolved, os.X_OK):
        raise ControlError("scanner_not_executable")
    return resolved


def read_json(path: Path):
    try:
        if path.stat().st_size > 1024 * 1024:
            raise ValueError()
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError, UnicodeError):
        raise ControlError("trusted_json_invalid") from None


def validate_policy(value):
    if not isinstance(value, dict) or set(value) != {"private_repo", "literal_exempt_paths"}:
        raise ControlError("policy_schema_invalid")
    private = value["private_repo"]
    paths = value["literal_exempt_paths"]
    if type(private) is not bool or not isinstance(paths, list) or len(paths) > 32:
        raise ControlError("policy_schema_invalid")
    for path in paths:
        if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path:
            raise ControlError("policy_exemption_invalid")
        if any(c in path for c in "*?[]") or any(p in ("", ".", "..") for p in path.rstrip("/").split("/")):
            raise ControlError("policy_exemption_invalid")
    if paths and not private:
        raise ControlError("public_repository_exemption_forbidden")
    return tuple(paths)


def validate_allowlist(value):
    if not isinstance(value, list) or len(value) > 100:
        raise ControlError("allowlist_schema_invalid")
    today = dt.datetime.now(dt.timezone.utc).date()
    validated = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"rule", "path", "reason", "reviewer", "expiry"}:
            raise ControlError("allowlist_schema_invalid")
        if any(not isinstance(v, str) or not v.strip() or len(v) > 1024 for v in item.values()):
            raise ControlError("allowlist_entry_invalid")
        # An allowlist can only suppress a private literal at an exact path.
        if not re.fullmatch(r"private-literal-[0-9]{3}", item["rule"]):
            raise ControlError("allowlist_secret_or_raw_rule_forbidden")
        path = item["path"]
        if path.startswith("/") or "\\" in path or any(c in path for c in "*?[]") or any(p in ("", ".", "..") for p in path.split("/")):
            raise ControlError("allowlist_path_invalid")
        try:
            expiry = dt.date.fromisoformat(item["expiry"])
        except ValueError:
            raise ControlError("allowlist_expiry_invalid") from None
        if expiry < today:
            raise ControlError("allowlist_expired")
        validated.append((item["rule"], path))
    return frozenset(validated)


class Gate:
    def __init__(self, args, temporary):
        self.args = args
        self.temp = Path(temporary)
        self.repo = Path(args.repo).resolve(strict=True)
        self.patterns = load_patterns(os.environ.get("LEAK_PRIVATE_PATTERNS"))
        self.config = trusted_file(args.config, self.repo)
        self.scanner = trusted_file(args.gitleaks, self.repo, executable=True)
        self.policy_path = trusted_file(args.policy, self.repo)
        policy = read_json(self.policy_path)
        self.exemptions = validate_policy(policy)
        self.allowlist = validate_allowlist(read_json(trusted_file(args.allowlist, self.repo))) if args.allowlist else frozenset()
        if self.allowlist and not policy["private_repo"]:
            raise ControlError("public_repository_allowlist_forbidden")
        self.findings = []
        self.finding_keys = set()
        self.blobs = {}
        self.total_bytes = 0
        self.tree_entries = 0
        self.paths = set()
        self.staged = self.temp / "objects"
        self.staged.mkdir(mode=0o700)
        self.materialized = {}
        self.metadata_count = 0

    def git(self, *arguments):
        return run_bounded(["git", "-c", f"safe.directory={self.repo}", "-c", "core.fsmonitor=false",
                            "-c", "core.hooksPath=/dev/null", "-c", "core.attributesFile=/dev/null",
                            "-c", "core.pager=cat", "-C", str(self.repo), *arguments], self.temp)[1]

    def commit(self, revision):
        if not revision or revision.startswith("-") or len(revision) > 256:
            raise ControlError("revision_invalid")
        try:
            result = self.git("rev-parse", "--verify", revision + "^{commit}").decode("ascii").strip()
        except UnicodeError:
            raise ControlError("git_object_invalid") from None
        if not OID.fullmatch(result):
            raise ControlError("git_object_invalid")
        return result

    def add_finding(self, rule, path, line, match_hash, commit, *, sensitive_path=False):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", rule):
            raise ControlError("scanner_rule_invalid")
        safe = safe_path(path, self.patterns, sensitive=sensitive_path)
        key = (rule, safe, line, match_hash, commit)
        if key in self.finding_keys:
            return
        if len(self.findings) >= MAX_FINDINGS:
            raise ControlError("finding_limit")
        self.finding_keys.add(key)
        self.findings.append({"file": safe, "line": line, "rule": rule,
                              "match_sha256": match_hash, "commit": commit})

    def exempt(self, rule, path):
        return (rule, path) in self.allowlist or any(path == p or (p.endswith("/") and path.startswith(p)) for p in self.exemptions)

    def scan_literals(self, path, text, commit, *, filename=False):
        for rule, line, hashed in find_matches(text, self.patterns):
            if not self.exempt(rule, path):
                self.add_finding(rule, path, 0 if filename else line, hashed, commit, sensitive_path=filename)

    def scan_tree(self, commit):
        records = self.git("ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0")
        for record in records:
            if not record:
                continue
            self.tree_entries += 1
            if self.tree_entries > MAX_TREE_ENTRIES:
                raise ControlError("tree_entry_limit")
            try:
                metadata, path_bytes = record.split(b"\t", 1)
                mode, kind, object_id = metadata.decode("ascii").split(" ")
                path = path_bytes.decode("utf-8", errors="strict")
            except (ValueError, UnicodeError):
                raise ControlError("git_tree_encoding_invalid") from None
            if not path or len(path_bytes) > 4096 or not OID.fullmatch(object_id):
                raise ControlError("git_tree_entry_invalid")
            self.paths.add(path)
            if len(self.paths) > MAX_FILES:
                raise ControlError("file_count_limit")
            self.scan_literals(path, path, commit, filename=True)
            if RAW_NAME.search(path):
                self.add_finding("raw-artifact-filename", path, 0, digest(path), commit)
            if kind != "blob" or mode not in ("100644", "100755"):
                raise ControlError("unsupported_git_entry")
            if object_id not in self.blobs:
                try:
                    size = int(self.git("cat-file", "-s", object_id))
                except ValueError:
                    raise ControlError("git_blob_size_invalid") from None
                if size > MAX_BLOB_BYTES:
                    raise ControlError("blob_size_limit")
                self.total_bytes += size
                if self.total_bytes > MAX_TOTAL_BYTES:
                    raise ControlError("total_blob_size_limit")
                data = self.git("cat-file", "blob", object_id)
                if len(data) != size:
                    raise ControlError("git_blob_size_mismatch")
                if data.startswith(b"version https://git-lfs.github.com/spec/v1\n"):
                    self.blobs[object_id] = None
                else:
                    try:
                        text = data.decode("utf-8", errors="strict")
                        if any(ord(c) < 32 and c not in "\t\n\r\f" for c in text):
                            raise UnicodeError()
                    except UnicodeError:
                        self.blobs[object_id] = None
                    else:
                        self.blobs[object_id] = text
                        # Hash-only stage names defeat repository-controlled ignore/config files.
                        stage_name = "blob-" + object_id
                        fd = os.open(self.staged / stage_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        with os.fdopen(fd, "wb") as stream:
                            stream.write(data)
                        self.materialized[stage_name] = []
            text = self.blobs[object_id]
            if text is None:
                raise ControlError("unsupported_binary_or_lfs")
            self.scan_literals(path, text, commit)
            for match in RAW_BODY.finditer(text):
                self.add_finding("raw-artifact-content", path, text.count("\n", 0, match.start()) + 1, digest(match.group()), commit)
            self.materialized["blob-" + object_id].append((path, commit))
            # Filenames themselves can carry credentials. They use an isolated blob too.
            path_key = "path-" + digest(path)
            if path_key not in self.materialized:
                fd = os.open(self.staged / path_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(path.encode("utf-8"))
                self.materialized[path_key] = []
            self.materialized[path_key].append((path, commit))

    def scan_metadata(self, data, source, object_id):
        if len(data) > MAX_BLOB_BYTES:
            raise ControlError("metadata_size_limit")
        self.total_bytes += len(data)
        if self.total_bytes > MAX_TOTAL_BYTES:
            raise ControlError("total_blob_size_limit")
        try:
            text = data.decode("utf-8", errors="strict")
            if any(ord(c) < 32 and c not in "\t\n\r\f" for c in text):
                raise UnicodeError()
        except UnicodeError:
            raise ControlError("unsupported_metadata_encoding") from None
        self.scan_literals(source, text, object_id)
        for match in RAW_BODY.finditer(text):
            self.add_finding("raw-artifact-content", source, text.count("\n", 0, match.start()) + 1,
                             digest(match.group()), object_id)
        stage_name = "metadata-" + digest(source + "\0" + object_id)
        fd = os.open(self.staged / stage_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        self.materialized[stage_name] = [(source, object_id)]
        self.metadata_count += 1

    def scan_ref_metadata(self):
        refs = self.git("for-each-ref", "--format=%(refname)%09%(objecttype)%09%(objectname)").splitlines()
        if len(refs) > MAX_FILES:
            raise ControlError("ref_count_limit")
        tags = set()
        for record in refs:
            try:
                name, kind, object_id_bytes = record.split(b"\t")
                object_id = object_id_bytes.decode("ascii")
                name.decode("utf-8", errors="strict")
            except (ValueError, UnicodeError):
                raise ControlError("ref_encoding_invalid") from None
            if not OID.fullmatch(object_id):
                raise ControlError("ref_object_invalid")
            if kind not in (b"commit", b"tag"):
                raise ControlError("unsupported_ref_target")
            self.scan_metadata(name, "history/ref-metadata/" + digest(name), object_id)
            while kind == b"tag" and object_id not in tags:
                tags.add(object_id)
                if len(tags) > MAX_COMMITS:
                    raise ControlError("tag_count_limit")
                data = self.git("cat-file", "tag", object_id)
                self.scan_metadata(data, "history/tag-metadata/" + object_id, object_id)
                try:
                    object_line, type_line = data.split(b"\n", 2)[:2]
                    if not object_line.startswith(b"object ") or not type_line.startswith(b"type "):
                        raise ValueError()
                    object_id = object_line[7:].decode("ascii")
                    kind = type_line[5:]
                    if not OID.fullmatch(object_id):
                        raise ValueError()
                except (ValueError, UnicodeError):
                    raise ControlError("tag_object_invalid") from None
                if kind not in (b"commit", b"tag"):
                    raise ControlError("unsupported_ref_target")

    def scan_secrets(self):
        _code, version = run_bounded([str(self.scanner), "version"], self.temp)
        if version.decode("ascii", errors="replace").strip() not in (PINNED_VERSION, "v" + PINNED_VERSION):
            raise ControlError("scanner_version_mismatch")
        report = self.temp / "gitleaks.json"
        fd = os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        code, _ignored = run_bounded([str(self.scanner), "dir", str(self.staged), "--config", str(self.config),
                                    "--no-banner", "--report-format", "json", "--report-path", str(report),
                                    "--ignore-gitleaks-allow", "--gitleaks-ignore-path", os.devnull,
                                    "--max-target-megabytes", "6", "--max-decode-depth", "5",
                                    "--redact=0", "--exit-code", "1"], self.temp, allowed=(0, 1), timeout=180)
        if report.stat().st_size > MAX_REPORT_BYTES:
            raise ControlError("scanner_report_limit")
        try:
            records = json.loads(report.read_text(encoding="utf-8"))
        except (ValueError, UnicodeError, OSError):
            raise ControlError("scanner_report_invalid") from None
        if not isinstance(records, list) or len(records) > MAX_FINDINGS:
            raise ControlError("scanner_report_invalid")
        if bool(records) != bool(code):
            raise ControlError("scanner_exit_report_mismatch")
        for record in records:
            if not isinstance(record, dict):
                raise ControlError("scanner_finding_invalid")
            name = Path(str(record.get("File", ""))).name
            associations = self.materialized.get(name)
            rule, match, line = record.get("RuleID"), record.get("Match"), record.get("StartLine")
            if not associations or not isinstance(rule, str) or not isinstance(match, str) or type(line) is not int or line < 1:
                raise ControlError("scanner_finding_invalid")
            if not match or match in ("REDACTED", "***"):
                raise ControlError("scanner_match_unavailable")
            for path, commit in associations:
                self.add_finding(rule, path, 0 if name.startswith("path-") else line, digest(match), commit,
                                 sensitive_path=name.startswith("path-"))

    def run(self):
        if self.git("rev-parse", "--is-shallow-repository").strip() != b"false":
            raise ControlError("shallow_repository_forbidden")
        config_names = self.git("config", "--local", "--name-only", "--list").decode("utf-8", errors="strict").splitlines()
        if any(name.lower() == "extensions.partialclone" or re.fullmatch(r"remote\..*\.(?:promisor|partialclonefilter)", name.lower())
               for name in config_names):
            raise ControlError("partial_repository_forbidden")
        head = self.commit(self.args.head)
        if self.args.mode == "diff":
            if not self.args.base:
                raise ControlError("diff_base_required")
            base = self.commit(self.args.base)
            commits = self.git("rev-list", "--reverse", f"{base}..{head}").decode("ascii").splitlines()
        else:
            if self.args.base:
                raise ControlError("history_base_forbidden")
            commits = self.git("rev-list", "--all", head).decode("ascii").splitlines()
        commits = list(dict.fromkeys([head, *commits]))
        if len(commits) > MAX_COMMITS or any(not OID.fullmatch(c) for c in commits):
            raise ControlError("commit_count_or_encoding_invalid")
        for commit in commits:
            self.scan_tree(commit)
            self.scan_metadata(self.git("cat-file", "commit", commit), "history/commit-metadata/" + commit, commit)
        if self.args.mode == "history":
            self.scan_ref_metadata()
        self.scan_secrets()
        return {"status": "findings" if self.findings else "clear", "mode": self.args.mode,
                "head": head, "commits_scanned": len(commits), "paths_scanned": len(self.paths),
                "unique_blobs_scanned": len(self.blobs), "metadata_objects_scanned": self.metadata_count,
                "findings": self.findings}


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise ControlError("arguments_invalid")


def main(argv=None):
    parser = SafeParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--mode", choices=("diff", "history"), required=True)
    parser.add_argument("--base")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--gitleaks", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--allowlist")
    parser.add_argument("--report")
    report_path = None
    try:
        args = parser.parse_args(argv)
        target = Path(args.repo).resolve(strict=True)
        if args.report:
            candidate_report = Path(args.report)
            if not candidate_report.is_absolute() or inside(candidate_report.resolve(), target) or candidate_report.is_symlink():
                raise ControlError("report_path_invalid")
            report_path = candidate_report
        signal.signal(signal.SIGALRM, deadline_handler)
        signal.alarm(300)
        with tempfile.TemporaryDirectory(prefix="leak01-") as temporary:
            os.chmod(temporary, 0o700)
            gate = Gate(args, temporary)
            result = gate.run()
        exit_code = 1 if result["findings"] else 0
    except ControlError as exc:
        # Only our fixed, literal codes are emitted. No upstream output or traceback.
        result = {"status": "unable", "error": str(exc), "findings": []}
        exit_code = 2
    except (Exception, KeyboardInterrupt):
        result = {"status": "unable", "error": "unexpected_failure", "findings": []}
        exit_code = 2
    finally:
        signal.alarm(0)
    rendered = json.dumps(result, sort_keys=True, ensure_ascii=True) + "\n"
    if report_path:
        try:
            if report_path.is_symlink():
                raise OSError()
            fd = os.open(report_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(rendered)
        except OSError:
            result = {"status": "unable", "error": "sanitized_report_unavailable", "findings": []}
            rendered = json.dumps(result, sort_keys=True) + "\n"
            exit_code = 2
    sys.stdout.write(rendered)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
