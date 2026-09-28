#!/usr/bin/env bash
# Lab-only r2 dual-grant broker. In-process synthetic upstream plus a 127.0.0.1
# callback. Does not start Supabase, does not use service_role, and does not
# complete issue #62. The ordinary M4 script remains fail-closed.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"
npm run test:lab-dual-grant
