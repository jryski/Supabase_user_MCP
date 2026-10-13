# SPDX-License-Identifier: Apache-2.0
# Copyright The Sovereign AI OS Authors
"""Private literal matching without exposing expressions or matched values."""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass


class ControlError(Exception):
    """A fixed, non-sensitive control error code."""


@dataclass(frozen=True)
class LiteralPattern:
    rule: str
    expression: re.Pattern[str]


def digest(value: str | bytes) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def load_patterns(encoded: str | None) -> tuple[LiteralPattern, ...]:
    if not encoded or len(encoded) > 131072:
        raise ControlError("private_patterns_missing_or_oversized")
    try:
        raw = base64.b64decode(encoded, validate=True)
        # Noncanonical encodings and transport whitespace are not accepted.
        if base64.b64encode(raw).decode("ascii") != encoded:
            raise ValueError()
        decoded = raw.decode("utf-8", errors="strict")
    except (ValueError, UnicodeError, binascii.Error):
        raise ControlError("private_patterns_invalid_encoding") from None
    lines = decoded.splitlines()
    if not lines or len(lines) > 128 or any(not x.strip() or len(x) > 2048 for x in lines):
        raise ControlError("private_patterns_invalid_lines")
    result = []
    for index, line in enumerate(lines, 1):
        try:
            expression = re.compile(line)
            if expression.search("") is not None:
                raise ValueError()
        except (re.error, ValueError, OverflowError):
            raise ControlError("private_patterns_invalid_regex") from None
        result.append(LiteralPattern(f"private-literal-{index:03}", expression))
    return tuple(result)


def find_matches(text: str, patterns: tuple[LiteralPattern, ...]):
    """Yield rule, line, and irreversible match hash, never match text."""
    for pattern in patterns:
        for match in pattern.expression.finditer(text):
            if match.start() == match.end():
                raise ControlError("private_patterns_zero_width_match")
            yield pattern.rule, text.count("\n", 0, match.start()) + 1, digest(match.group(0))


def safe_path(path: str, patterns: tuple[LiteralPattern, ...], sensitive=False) -> str:
    # The filename itself may contain a secret that another rule rejects before
    # text scanning, including unsupported binary files. Opaque identifiers for
    # every path guarantee that no original filename is serialized.
    return "sha256:" + digest(path)
