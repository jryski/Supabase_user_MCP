# SPDX-License-Identifier: Apache-2.0
"""Installer trust-boundary tests; no network or executable downloads required."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("install_gitleaks", ROOT / "scripts/leak/install_gitleaks.py")
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)
PIN = json.loads((ROOT / "scripts/leak/scanner-pin.json").read_text())


def elf(machine=62):
    data = bytearray(64)
    data[:6] = b"\x7fELF\x02\x01"
    data[18:20] = machine.to_bytes(2, "little")
    return bytes(data)


def archive(executable=None, extra=None, executable_type=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tar:
        for name, data in [("LICENSE", b"fixture license"), ("README.md", b"fixture readme"),
                           ("gitleaks", elf() if executable is None else executable)]:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            if name == "gitleaks" and executable_type is not None:
                member.type = executable_type
                member.linkname = "outside"
                member.size = 0
                tar.addfile(member)
            else:
                tar.addfile(member, io.BytesIO(data))
        if extra is not None:
            member = tarfile.TarInfo(extra)
            member.size = 1
            tar.addfile(member, io.BytesIO(b"x"))
    return stream.getvalue()


class PinTests(unittest.TestCase):
    def write_pin(self, directory, **changes):
        pin = dict(PIN, **changes)
        path = Path(directory) / "pin.json"
        path.write_text(json.dumps(pin))
        return path

    def test_committed_pin_valid(self):
        self.assertEqual(installer.load_pin(ROOT / "scripts/leak/scanner-pin.json"), PIN)

    def test_bad_pin_contracts(self):
        cases = [
            {"version": "8.30.2"}, {"platform": "darwin_arm64"},
            {"url": "https://example.invalid/scanner"}, {"size_bytes": True},
            {"size_bytes": 0}, {"size_bytes": installer.MAX_ARCHIVE_BYTES + 1},
            {"sha256": "x" * 64}, {"archive_members": ["gitleaks", "../evil"]},
            {"archive_members": ["gitleaks", None]}, {"executable_member": "README.md"},
            {"extra": "unexpected"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            for changes in cases:
                with self.subTest(changes=changes), self.assertRaises(installer.InstallError):
                    installer.load_pin(self.write_pin(directory, **changes))

    def test_corrupt_and_large_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pin.json"
            for data in [b"not JSON", b"\xff", b" " * 4097, b"[]"]:
                path.write_bytes(data)
                with self.subTest(length=len(data)), self.assertRaises(installer.InstallError):
                    installer.load_pin(path)

    def test_host_must_be_linux_x64(self):
        for system, machine in [("darwin", "arm64"), ("linux", "aarch64"), ("win32", "AMD64")]:
            with mock.patch.object(installer.sys, "platform", system), \
                    mock.patch.object(installer.platform, "machine", return_value=machine), \
                    self.assertRaises(installer.InstallError):
                installer.validate_host()


class ArchiveTests(unittest.TestCase):
    def test_size_and_hash_verified_before_extraction(self):
        data = archive()
        pin = dict(PIN, size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        installer.verify_archive(data, pin)
        for malformed in [data[:-1], data + b"x", b"x" + data[1:]]:
            with self.subTest(size=len(malformed)), self.assertRaises(installer.InstallError):
                installer.verify_archive(malformed, pin)

    def test_only_executable_materialized(self):
        data = archive()
        self.assertEqual(installer.executable_bytes(data, PIN), elf())

    def test_unexpected_and_traversal_names_rejected(self):
        for name in ["../outside", "/absolute", "subdir/file", "gitleaks", "extra", "C:\\evil"]:
            with self.subTest(name=name), self.assertRaises(installer.InstallError):
                installer.executable_bytes(archive(extra=name), PIN)

    def test_links_and_special_members_rejected(self):
        for kind in [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE,
                     tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE]:
            with self.subTest(kind=kind), self.assertRaises(installer.InstallError):
                installer.executable_bytes(archive(executable_type=kind), PIN)

    def test_non_elf_or_wrong_architecture_rejected(self):
        for binary in [b"#!/bin/sh\necho fixture", b"", elf(machine=183), elf()[:19]]:
            with self.subTest(binary_size=len(binary)), self.assertRaises(installer.InstallError):
                installer.executable_bytes(archive(executable=binary), PIN)

    def test_invalid_archive_rejected(self):
        with self.assertRaises(installer.InstallError):
            installer.executable_bytes(b"not an archive", PIN)

    def test_bounded_read_rejects_overflow_and_truncation(self):
        self.assertEqual(installer.read_bounded(io.BytesIO(b"abc"), 3), b"abc")
        for data in [b"ab", b"abcd"]:
            with self.assertRaises(installer.InstallError):
                installer.read_bounded(io.BytesIO(data), 3)


class InstallTests(unittest.TestCase):
    def test_exact_version_is_required_and_binary_output_not_reported(self):
        for result in [subprocess.CompletedProcess([], 0, b"8.30.2\n", b""),
                       subprocess.CompletedProcess([], 1, b"private failure", b"private stderr")]:
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "gitleaks"
                with mock.patch.object(installer.subprocess, "run", return_value=result), \
                        self.assertRaisesRegex(installer.InstallError, "version mismatch"):
                    installer.write_and_check(elf(), output)
                self.assertFalse(output.exists())
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_valid_install_private_mode_and_no_overwrite(self):
        result = subprocess.CompletedProcess([], 0, b"8.30.1\n", b"")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "gitleaks"
            with mock.patch.object(installer.subprocess, "run", return_value=result) as run:
                installer.write_and_check(elf(), output)
                self.assertEqual(run.call_args.args[0][1], "version")
                self.assertNotIn("LEAK_PRIVATE_PATTERNS", run.call_args.kwargs["env"])
            self.assertEqual(output.read_bytes(), elf())
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            with self.assertRaises(installer.InstallError):
                installer.write_and_check(elf(), output)

    def test_existing_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "gitleaks"
            output.symlink_to(Path(directory) / "missing")
            with self.assertRaises(installer.InstallError):
                installer.write_and_check(elf(), output)

    def test_install_verifies_before_materializing(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "archive.tar.gz"
            source.write_bytes(b"invalid")
            with mock.patch.object(installer, "validate_host"), \
                    mock.patch.object(installer, "write_and_check") as writer, \
                    self.assertRaises(installer.InstallError):
                installer.install(ROOT / "scripts/leak/scanner-pin.json", Path(directory) / "gitleaks", source)
            writer.assert_not_called()

    def test_redirects_must_remain_on_approved_https_hosts(self):
        for url in ["https://release-assets.githubusercontent.com/path?token=fixture",
                    "https://github.com/gitleaks/gitleaks/releases"]:
            installer._validate_download_url(url)
        for url in ["http://github.com/file", "https://evil.invalid/file",
                    "https://github.com.evil.invalid/file", "https://user@github.com/file",
                    "https://github.com:444/file", "https://github.com:bad/file"]:
            with self.subTest(url=url), self.assertRaises(installer.InstallError):
                installer._validate_download_url(url)


if __name__ == "__main__":
    unittest.main()
