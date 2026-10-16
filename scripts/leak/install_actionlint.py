#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Install one checksum-verified actionlint binary (validation tooling only).

actionlint never receives secrets and never runs in the privileged scan job.
Fails closed on any size, digest, member or version mismatch.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import urllib.request

VERSION = "1.7.12"
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
EXPECTED_URL = (f"https://github.com/rhysd/actionlint/releases/download/v{VERSION}/"
                f"actionlint_{VERSION}_linux_amd64.tar.gz")


class InstallError(Exception):
    pass


def load_pin(path: Path) -> dict:
    try:
        pin = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise InstallError("cannot read actionlint pin") from None
    required = {"version", "platform", "url", "size_bytes", "sha256", "executable_member"}
    if not isinstance(pin, dict) or set(pin) != required:
        raise InstallError("invalid actionlint pin fields")
    if (pin["version"] != VERSION or pin["platform"] != "linux_amd64" or pin["url"] != EXPECTED_URL
            or pin["executable_member"] != "actionlint" or type(pin["size_bytes"]) is not int
            or not isinstance(pin["sha256"], str) or len(pin["sha256"]) != 64):
        raise InstallError("unsupported actionlint pin")
    return pin


def verify_archive(data: bytes, pin: dict) -> bytes:
    if len(data) != pin["size_bytes"]:
        raise InstallError("actionlint archive size mismatch")
    if hashlib.sha256(data).hexdigest() != pin["sha256"]:
        raise InstallError("actionlint archive digest mismatch")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = [m for m in archive.getmembers() if m.name == pin["executable_member"]]
        if len(members) != 1 or not members[0].isreg():
            raise InstallError("actionlint executable member missing or unsafe")
        handle = archive.extractfile(members[0])
        if handle is None:
            raise InstallError("actionlint executable unreadable")
        return handle.read()


def install(pin_path: Path, output: Path, archive: Path | None = None) -> Path:
    if sys.platform != "linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise InstallError("unsupported host; Linux x86_64 is required")
    pin = load_pin(pin_path)
    if archive is not None:
        data = archive.read_bytes()
    else:
        with urllib.request.urlopen(pin["url"], timeout=60) as response:
            data = response.read(MAX_ARCHIVE_BYTES + 1)
    if len(data) > MAX_ARCHIVE_BYTES:
        raise InstallError("actionlint archive too large")
    binary = verify_archive(data, pin)
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    output.write_bytes(binary)
    os.chmod(output, 0o700)
    version = subprocess.run([str(output), "-version"], capture_output=True, text=True,
                             timeout=30, check=False).stdout.splitlines()
    if not version or version[0].strip() != VERSION:
        output.unlink(missing_ok=True)
        raise InstallError("actionlint version mismatch")
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pin", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    try:
        install(args.pin, args.output, args.archive)
    except (InstallError, OSError, tarfile.TarError, subprocess.SubprocessError) as error:
        print("actionlint install failed: " + str(error), file=sys.stderr)
        return 2
    print("actionlint " + VERSION + " verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
