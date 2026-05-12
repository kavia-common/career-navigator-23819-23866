#!/usr/bin/env bash
set -euo pipefail
WORKSPACE="/home/kavia/workspace/code-generation/career-navigator-23819-23866/CareerNavigatorBackendAPI"
cd "$WORKSPACE"
# create venv if missing
python3 -m venv .venv || true
# ensure PATH export for future shells (idempotent)
PROFILE_FILE="/etc/profile.d/venv_workspace.sh"
if [ ! -f "$PROFILE_FILE" ]; then
  sudo bash -c "cat > $PROFILE_FILE <<'EOF'
# add workspace venv to PATH
export PATH=\"$WORKSPACE/.venv/bin:\$PATH\"
EOF"
fi
# activate venv and install minimal deps non-interactively
. "$WORKSPACE"/.venv/bin/activate
python -m pip install --quiet --upgrade pip
python -m pip install --quiet fastapi uvicorn sqlalchemy pytest pylint
# verify installations
python -c "import fastapi, uvicorn, sqlalchemy, pytest, pylint" >/dev/null 2>&1 || { echo "python deps failed" >&2; exit 3; }
