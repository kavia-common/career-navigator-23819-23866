#!/usr/bin/env bash
set -euo pipefail
WORKSPACE="/home/kavia/workspace/code-generation/career-navigator-23819-23866/CareerNavigatorBackendAPI"
cd "$WORKSPACE"
. "$WORKSPACE"/.venv/bin/activate
PORT=${PORT:-8000}
# Start server via start script
bash .init/start.sh
# Read PID
if [ -f "$WORKSPACE"/.venv/uvicorn.pid ]; then
  UV_PID=$(cat "$WORKSPACE"/.venv/uvicorn.pid)
else
  echo "validation failed: pid file not found" >&2
  exit 5
fi
# Give a brief moment for server to accept connections
sleep 1
# Try health endpoint
if ! curl -sSf "http://127.0.0.1:$PORT/health" | grep -q 'ok'; then
  echo "validation failed: /health not responding" >&2
  # attempt to stop server
  kill "$UV_PID" >/dev/null 2>&1 || true
  exit 4
fi
# Stop server cleanly
kill "$UV_PID" >/dev/null 2>&1 || true
sleep 1
# ensure process is gone, otherwise force kill
if ps -p "$UV_PID" >/dev/null 2>&1; then
  kill -9 "$UV_PID" >/dev/null 2>&1 || true
fi
# remove pid file
rm -f "$WORKSPACE"/.venv/uvicorn.pid
echo "validation ok"
exit 0
