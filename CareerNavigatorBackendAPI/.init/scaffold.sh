#!/usr/bin/env bash
set -euo pipefail
WORKSPACE="/home/kavia/workspace/code-generation/career-navigator-23819-23866/CareerNavigatorBackendAPI"
mkdir -p "$WORKSPACE"
cd "$WORKSPACE"
cat > "$WORKSPACE"/main.py <<'PY'
from fastapi import FastAPI
from sqlalchemy import create_engine, text
import os
app = FastAPI()
DB_URL = os.getenv('DATABASE_URL','sqlite:///./career_nav.db')
engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
@app.get("/health")
def health():
    return {"status": "ok"}
@app.get("/count")
def count():
    with engine.connect() as conn:
        r = conn.execute(text('select 1 as v'))
        return {"value": r.first()[0]}
PY
cat > "$WORKSPACE"/requirements.txt <<'REQ'
fastapi
uvicorn
sqlalchemy
pytest
pylint
REQ
cat > "$WORKSPACE"/start.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail
WORKSPACE="/home/kavia/workspace/code-generation/career-navigator-23819-23866/CareerNavigatorBackendAPI"
cd "$WORKSPACE"
exec "$WORKSPACE"/.venv/bin/uvicorn main:app --host 0.0.0.0 --port "${PORT:-8000}" --proxy-headers
SH
chmod +x "$WORKSPACE"/start.sh
