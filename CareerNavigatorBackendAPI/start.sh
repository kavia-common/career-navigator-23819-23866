#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="/home/kavia/workspace/code-generation/career-navigator-23819-23866/CareerNavigatorBackendAPI"
cd "$WORKSPACE"

. "$WORKSPACE/.venv/bin/activate"

PORT="${PORT:-3001}"

exec "$WORKSPACE/.venv/bin/uvicorn" main:app --host "${HOST:-0.0.0.0}" --port "$PORT" --proxy-headers
