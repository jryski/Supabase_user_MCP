#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright The Sovereign AI OS Authors
set -euo pipefail
task_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
python3 -m unittest discover -s "${task_root}/tests/leak" -p 'test_gate.py' -v
