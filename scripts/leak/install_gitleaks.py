#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Install one verified, pinned Gitleaks Linux x64 binary using only stdlib.

No archive path is extracted to the filesystem. All members are inspected;
only the regular, ELF x86_64 `gitleaks` member is materialized privately.
Diagnostics contain neither remote response bodies nor binary output.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "8.30.1"
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 32 * 1024 * 1024
APPROVED_REDIRECT_HOSTS = frozenset({
    "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"
})


class InstallError(Exception):
    """A safe, fixed diagnostic suitable for a CI log."""


def validate_host() -> None:
    if sys.platform != "linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise InstallError("unsupported scanner host; Linux x86_64 is required")


def load_pin(path: Path) -> dict:
    try:
        if path.stat().st_size > 4096:
            raise InstallError("scanner pin is too large")
        pin = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise InstallError("cannot read scanner pin") from None
    required = {"version", "platform", "url", "size_bytes", "sha256",
                "archive_members", "executable_member"}
    if not isinstance(pin, dict) or set(pin) != required:
        raise InstallError("invalid scanner pin fields")
    expected_url = (f"https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/"
                    f"gitleaks_{VERSION}_linux_x64.tar.gz")
    if (pin["version"] != VERSION or pin["platform"] != "linux_x64"
            or pin["url"] != expected_url or pin["executable_member"] != "gitleaks"):
        raise InstallError("unsupported scanner pin")
    if (type(pin["size_bytes"]) is not int
            or not 0 < pin["size_bytes"] <= MAX_ARCHIVE_BYTES
            or not isinstance(pin["sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", pin["sha256"])):
        raise InstallError("invalid scanner checksum or size")
    if (not isinstance(pin["archive_members"], list)
            or not all(isinstance(name, str) for name in pin["archive_members"])
            or sorted(pin["archive_members"]) != ["LICENSE", "README.md", "gitleaks"]):
        raise InstallError("invalid scanner archive layout")
    return pin


def _validate_download_url(url: str) -> None:
    try:
        parts = urllib.parse.urlsplit(url)
        invalid = (parts.scheme != "https" or parts.hostname not in APPROVED_REDIRECT_HOSTS
                   or parts.username is not None or parts.password is not None
                   or parts.port not in {None, 443})
    except ValueError:
        invalid = True
    if invalid:
        raise InstallError("unapproved scanner download redirect")


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validate_download_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def read_bounded(stream, size: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    deadline = time.monotonic() + 90
    while total <= size:
        if time.monotonic() > deadline:
            raise InstallError("scanner download exceeded time budget")
        chunk = stream.read(min(64 * 1024, size + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    if total != size:
        raise InstallError("scanner archive size mismatch")
    return b"".join(chunks)


def download_archive(pin: dict) -> bytes:
    _validate_download_url(pin["url"])
    request = urllib.request.Request(pin["url"], headers={
        "Accept": "application/octet-stream", "User-Agent": "LEAK-01-pinned-installer"
    })
    # Disable environment proxy discovery; CI fetches the official HTTPS origin.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), SafeRedirect())
    try:
        with opener.open(request, timeout=30) as response:
            _validate_download_url(response.geturl())
            length = response.headers.get("Content-Length")
            if length is not None and length != str(pin["size_bytes"]):
                raise InstallError("scanner archive size header mismatch")
            return read_bounded(response, pin["size_bytes"])
    except InstallError:
        raise
    except (OSError, ValueError, urllib.error.URLError):
        raise InstallError("scanner download failed") from None


def verify_archive(data: bytes, pin: dict) -> None:
    if len(data) != pin["size_bytes"]:
        raise InstallError("scanner archive size mismatch")
    if hashlib.sha256(data).hexdigest() != pin["sha256"]:
        raise InstallError("scanner archive checksum mismatch")


def executable_bytes(data: bytes, pin: dict) -> bytes:
    """Inspect all members without extract()/extractall(), then read one member."""
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            if sorted(names) != sorted(pin["archive_members"]):
                raise InstallError("unexpected scanner archive member")
            for member in members:
                if (not member.isreg() or member.name not in pin["archive_members"]
                        or "/" in member.name or "\\" in member.name
                        or member.size < 0 or member.size > MAX_EXECUTABLE_BYTES):
                    raise InstallError("unsafe scanner archive member")
            member = archive.getmember(pin["executable_member"])
            stream = archive.extractfile(member)
            if stream is None:
                raise InstallError("scanner executable missing")
            executable = stream.read(MAX_EXECUTABLE_BYTES + 1)
            if len(executable) != member.size or len(executable) > MAX_EXECUTABLE_BYTES:
                raise InstallError("scanner executable size mismatch")
    except InstallError:
        raise
    except (OSError, EOFError, KeyError, tarfile.TarError):
        raise InstallError("invalid scanner archive") from None
    if (len(executable) < 20 or executable[:6] != b"\x7fELF\x02\x01"
            or int.from_bytes(executable[18:20], "little") != 62):
        raise InstallError("scanner executable is not Linux x86_64 ELF")
    return executable


def write_and_check(executable: bytes, output: Path) -> None:
    output = output.absolute()
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if output.exists() or output.is_symlink():
        raise InstallError("scanner output already exists")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".gitleaks-", dir=output.parent, delete=False) as f:
            temporary = Path(f.name)
            f.write(executable)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temporary, 0o700)
        result = subprocess.run([str(temporary), "version"], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=10, check=False, env={"PATH": "/usr/bin:/bin", "LANG": "C"})
        if result.returncode != 0 or result.stdout.strip() != VERSION.encode("ascii"):
            raise InstallError("scanner executable version mismatch")
        # link() fails atomically if the destination already exists; never overwrite it.
        os.link(temporary, output)
    except InstallError:
        raise
    except (OSError, subprocess.SubprocessError):
        raise InstallError("scanner installation failed") from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def install(pin_path: Path, output: Path, archive_path: Path | None = None) -> None:
    validate_host()
    pin = load_pin(pin_path)
    if archive_path is None:
        data = download_archive(pin)
    else:
        try:
            with archive_path.open("rb") as f:
                data = read_bounded(f, pin["size_bytes"])
        except OSError:
            raise InstallError("cannot read scanner archive") from None
    verify_archive(data, pin)
    write_and_check(executable_bytes(data, pin), output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pin", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive", type=Path, help="verify a previously downloaded archive")
    args = parser.parse_args()
    try:
        install(args.pin, args.output, args.archive)
    except InstallError as error:
        print(f"LEAK-01 unable: {error}", file=sys.stderr)
        return 2
    print(f"LEAK-01 scanner installed: version={VERSION}, platform=linux_x64")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
