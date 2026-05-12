#!/usr/bin/env bash
set -euo pipefail
WORKSPACE="/home/kavia/workspace/code-generation/career-navigator-23819-23866/CareerNavigatorBackendAPI"
cd "$WORKSPACE"
. "$WORKSPACE"/.venv/bin/activate
# Run pytest if present; return non-zero if tests fail. Quiet output for automation.
if [ -f pytest.ini ] || [ -d tests ] || ls test_*.py 1>/dev/null 2>&1; then
  "$WORKSPACE"/.venv/bin/pytest -q
else
  # No tests to run; exit success to avoid breaking pipelines
  exit 0
fi
