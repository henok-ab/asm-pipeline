#!/usr/bin/env bash
# Offline regression test: real scanner scripts (stub tools) + real workflow Code-node logic
# (in-memory MongoDB). Requires: bash, python3, node >= 18. No network, no Docker.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ASM_TEST_HOME="$(mktemp -d)"
trap 'rm -rf "$ASM_TEST_HOME"' EXIT
bash "$HERE/make_stubs.sh" "$ASM_TEST_HOME"
python3 "$HERE/../scripts/validate_workflows.py"
node "$HERE/harness.js" "$HERE/../workflows"
