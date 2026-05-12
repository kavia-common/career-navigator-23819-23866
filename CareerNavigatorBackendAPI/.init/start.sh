#!/usr/bin/env bash
set -euo pipefail
WORKSPACE="/home/kavia/workspace/code-generation/career-navigator-23819-23866/CareerNavigatorBackendAPI"
cd "$WORKSPACE"
. "$WORKSPACE"/.venv/bin/activate
PORT=${PORT:-8000}
# Launch uvicorn in background and record PID to venv for later stop
# Use --proxy-headers to match provided script; run without --reload for headless container
"$WORKSPACE"/.venv/bin/uvicorn main:app --host 0.0.0.0 --port "$PORT" --proxy-headers >/dev/null 2>&1 &
UV_PID=$!
# write PID atomically
mkdir -p "$WORKSPACE"/.venv
echo "$UV_PID" > "$WORKSPACE"/.venv/uvicorn.pid
# give server a moment to start
sleep 1
# simple sanity: ensure process exists
if ! ps -p "$UV_PID" >/dev/null 2>&1; then
  echo "start failed: uvicorn did not remain running (pid $UV_PID)" >&2
  exit 3
fi
exit 0
