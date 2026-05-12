"""
Career Navigator Backend API (MVP).

This service exposes REST endpoints consumed by the React frontend:
- Auth: register/login (JWT bearer)
- Dashboard aggregation
- Profile persona + document ingestion
- Skill assessment questionnaire + responses
- Career path recommendations + selection
- Roadmap generation + task completion tracking
- Marketplace browsing/filtering

Configuration is via environment variables (see .env.example).
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from dotenv import load_dotenv
from fastapi import (
    Depends,
    FastAPI,
    File,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

load_dotenv()

# =========================
# App & OpenAPI metadata
# =========================

openapi_tags = [
    {"name": "Health", "description": "Service health and diagnostics."},
    {"name": "Auth", "description": "User registration and login (JWT bearer)."},
    {"name": "Dashboard", "description": "Dashboard aggregation for phase progress."},
    {"name": "Profile", "description": "Persona ingestion and editing; document upload."},
    {"name": "Assessment", "description": "Questionnaire and assessment response submission."},
    {"name": "Career Paths", "description": "Recommendations and selecting a target career path."},
    {"name": "Roadmap", "description": "Roadmap generation and progress tracking."},
    {"name": "Marketplace", "description": "Browse/filter marketplace items."},
]


app = FastAPI(
    title="Career Navigator Backend API",
    description=(
        "MVP REST API for Career Navigator. Uses JWT bearer auth. "
        "Endpoints are designed to match the frontend API client in "
        "`CareerNavigatorWebFrontend/src/api/backend.ts`."
    ),
    version="0.1.0",
    openapi_tags=openapi_tags,
)

# =========================
# CORS
# =========================

def _csv_env(name: str, default: str) -> List[str]:
    val = os.getenv(name, default)
    return [x.strip() for x in val.split(",") if x.strip()]


allowed_origins = _csv_env("ALLOWED_ORIGINS", "http://localhost:3000")
allowed_headers = _csv_env("ALLOWED_HEADERS", "Content-Type,Authorization")
allowed_methods = _csv_env("ALLOWED_METHODS", "GET,POST,PUT,DELETE,PATCH,OPTIONS")
cors_max_age = int(os.getenv("CORS_MAX_AGE", "3600"))

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=allowed_methods,
    allow_headers=allowed_headers,
    max_age=cors_max_age,
)

# =========================
# Database
# =========================

def _get_engine() -> Engine:
    """
    Create SQLAlchemy engine for PostgreSQL.

    Expects DATABASE_URL to be set to a PostgreSQL DSN, for example:
    postgresql://user:pass@host:port/dbname
    """
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        # IMPORTANT: request orchestrator to set this for DB connectivity.
        raise RuntimeError("DATABASE_URL is not set; backend cannot connect to PostgreSQL.")
    return create_engine(db_url, pool_pre_ping=True)


_engine: Optional[Engine] = None


def get_db() -> Engine:
    """Get (and lazily initialize) the SQLAlchemy engine."""
    global _engine
    if _engine is None:
        _engine = _get_engine()
    return _engine


# =========================
# Auth helpers
# =========================

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_ALG = os.getenv("JWT_ALG", "HS256")
JWT_EXPIRES_MIN = int(os.getenv("JWT_EXPIRES_MIN", "10080"))  # 7 days default

if not JWT_SECRET:
    # IMPORTANT: request orchestrator to set this in .env for production.
    # Local dev may still set it; without it, app should not start safely.
    raise RuntimeError("JWT_SECRET is not set; refusing to start without a signing key.")


def _hash_password(password: str) -> str:
    return pwd_context.hash(password)


def _verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def _create_access_token(*, user_id: UUID, email: str) -> str:
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": str(user_id),
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXPIRES_MIN)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


class AuthUser(BaseModel):
    id: UUID
    email: str


def _get_bearer_token(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    return auth.removeprefix("Bearer ").strip()


def get_current_user(request: Request, db: Engine = Depends(get_db)) -> AuthUser:
    """Dependency that authenticates the request using the Bearer JWT."""
    token = _get_bearer_token(request)
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = UUID(payload.get("sub", ""))
        email = str(payload.get("email", ""))
    except (JWTError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token")

    with db.connect() as conn:
        row = conn.execute(
            text("SELECT id, email FROM app_user WHERE id = :id"),
            {"id": str(user_id)},
        ).mappings().first()

    if not row:
        raise HTTPException(status_code=401, detail="User not found")

    return AuthUser(id=UUID(row["id"]), email=row["email"])


# =========================
# Request/Response models (aligned with frontend)
# =========================

class RegisterRequest(BaseModel):
    email: str = Field(..., description="User email (unique).")
    password: str = Field(..., min_length=6, description="User password (min 6 chars).")


class AuthResponse(BaseModel):
    token: str = Field(..., description="JWT bearer token to use in Authorization header.")
    user: Dict[str, str] = Field(..., description="Minimal user info.")


class LoginRequest(BaseModel):
    email: str = Field(..., description="User email.")
    password: str = Field(..., description="User password.")


class PersonaModel(BaseModel):
    headline: Optional[str] = Field(None, description="Persona headline/title.")
    summary: Optional[str] = Field(None, description="Persona summary/bio.")
    location: Optional[str] = Field(None, description="Location (free text).")
    yearsExperience: Optional[float] = Field(None, ge=0, le=80, description="Years of experience.")
    skills: Optional[List[str]] = Field(None, description="List of canonical skill names.")


class QuestionnaireOption(BaseModel):
    value: str = Field(..., description="Stable option value.")
    label: str = Field(..., description="Human-friendly label.")


class QuestionnaireQuestion(BaseModel):
    id: str = Field(..., description="Stable question ID (code).")
    prompt: str = Field(..., description="Question prompt text.")
    options: List[QuestionnaireOption] = Field(..., description="Available answer options.")


class QuestionnaireResponseModel(BaseModel):
    questions: List[QuestionnaireQuestion] = Field(..., description="Questionnaire questions.")


class CareerPathRec(BaseModel):
    id: str = Field(..., description="Career path id.")
    title: str = Field(..., description="Career path title.")
    fitScore: float = Field(..., ge=0, le=1, description="Fit score between 0 and 1.")
    why: List[str] = Field(..., description="Explainability bullet points.")
    keySkills: List[str] = Field(..., description="Key skills for this path.")


class CareerPathRecsResponse(BaseModel):
    recommendations: List[CareerPathRec] = Field(..., description="Ranked recommendations.")


class SelectCareerPathRequest(BaseModel):
    pathId: str = Field(..., description="Career path id to select.")


class RoadmapTaskModel(BaseModel):
    id: str
    title: str
    done: bool


class RoadmapMilestoneModel(BaseModel):
    id: str
    title: str
    targetMonth: int = Field(..., ge=1, description="1..N relative month marker for UI.")
    tasks: List[RoadmapTaskModel]


class RoadmapResponseModel(BaseModel):
    selectedPathTitle: Optional[str]
    milestones: List[RoadmapMilestoneModel]


class ToggleTaskRequest(BaseModel):
    milestoneId: str
    taskId: str
    done: bool


class MarketplaceItemModel(BaseModel):
    id: str
    title: str
    provider: str
    type: str = Field(..., description="COURSE | CERT | BOOTCAMP | BOOK | PROJECT")
    skillTags: List[str]


class MarketplaceResponseModel(BaseModel):
    items: List[MarketplaceItemModel]


class DashboardPhaseModel(BaseModel):
    key: str = Field(..., description="PROFILE|ASSESSMENT|PATHS|ROADMAP|MARKETPLACE")
    title: str
    description: str
    status: str = Field(..., description="NOT_STARTED|IN_PROGRESS|COMPLETED|LOCKED")
    progressPct: int = Field(..., ge=0, le=100)
    ctaPath: str


class DashboardResponseModel(BaseModel):
    user: Dict[str, str]
    overallProgressPct: int = Field(..., ge=0, le=100)
    phases: List[DashboardPhaseModel]


# =========================
# Utilities: phase computation
# =========================

_PHASE_META: Dict[str, Dict[str, str]] = {
    "PROFILE": {
        "title": "Build Profile",
        "description": "Upload documents and review your extracted persona.",
        "ctaPath": "/app/profile",
    },
    "ASSESSMENT": {
        "title": "Skill Assessment",
        "description": "Answer a short questionnaire and self-rate your skills.",
        "ctaPath": "/app/assessment",
    },
    "PATHS": {
        "title": "Career Paths",
        "description": "Review recommendations, compare and select a target path.",
        "ctaPath": "/app/paths",
    },
    "ROADMAP": {
        "title": "Roadmap",
        "description": "Track milestones and next best actions.",
        "ctaPath": "/app/roadmap",
    },
    "MARKETPLACE": {
        "title": "Marketplace",
        "description": "Browse learning and project items aligned to your roadmap.",
        "ctaPath": "/app/marketplace",
    },
}


def _phase_locked_statuses(profile_done: bool, assessment_done: bool, path_selected: bool, has_roadmap: bool) -> Dict[str, str]:
    """
    Compute phase status fields (frontend expects LOCKED gating).
    """
    profile_status = "COMPLETED" if profile_done else "NOT_STARTED"
    assessment_status = "COMPLETED" if assessment_done else ("LOCKED" if not profile_done else "NOT_STARTED")
    paths_status = "COMPLETED" if path_selected else ("LOCKED" if not assessment_done else "NOT_STARTED")
    roadmap_status = "IN_PROGRESS" if has_roadmap else ("LOCKED" if not path_selected else "NOT_STARTED")
    marketplace_status = "LOCKED" if not has_roadmap else "NOT_STARTED"
    return {
        "PROFILE": profile_status,
        "ASSESSMENT": assessment_status,
        "PATHS": paths_status,
        "ROADMAP": roadmap_status,
        "MARKETPLACE": marketplace_status,
    }


def _safe_int_pct(numer: int, denom: int) -> int:
    if denom <= 0:
        return 0
    return max(0, min(100, int(round((numer / denom) * 100))))


# =========================
# Health
# =========================

# PUBLIC_INTERFACE
@app.get(
    "/health",
    tags=["Health"],
    summary="Health check",
    description="Returns service health status. Used for container liveness checks.",
    operation_id="health_check",
)
def health_check() -> Dict[str, str]:
    """Simple health check endpoint."""
    return {"status": "ok"}


# =========================
# Auth
# =========================

# PUBLIC_INTERFACE
@app.post(
    "/auth/register",
    tags=["Auth"],
    summary="Register a new user",
    description="Creates a new user with email/password, returns a JWT token.",
    response_model=AuthResponse,
    operation_id="auth_register",
)
def register(payload: RegisterRequest, db: Engine = Depends(get_db)) -> AuthResponse:
    """Register a new user. Returns a bearer token."""
    email = payload.email.strip().lower()
    password_hash = _hash_password(payload.password)

    try:
        with db.begin() as conn:
            row = conn.execute(
                text(
                    """
                    INSERT INTO app_user (email, password_hash)
                    VALUES (:email, :password_hash)
                    RETURNING id, email
                    """
                ),
                {"email": email, "password_hash": password_hash},
            ).mappings().first()
    except IntegrityError:
        raise HTTPException(status_code=409, detail="Email already registered")

    user_id = UUID(row["id"])
    token = _create_access_token(user_id=user_id, email=row["email"])
    return AuthResponse(token=token, user={"email": row["email"]})


# PUBLIC_INTERFACE
@app.post(
    "/auth/login",
    tags=["Auth"],
    summary="Login",
    description="Authenticates with email/password and returns a JWT token.",
    response_model=AuthResponse,
    operation_id="auth_login",
)
def login(payload: LoginRequest, db: Engine = Depends(get_db)) -> AuthResponse:
    """Login endpoint returning JWT bearer token."""
    email = payload.email.strip().lower()

    with db.connect() as conn:
        row = conn.execute(
            text("SELECT id, email, password_hash FROM app_user WHERE email = :email"),
            {"email": email},
        ).mappings().first()

    if not row or not _verify_password(payload.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user_id = UUID(row["id"])
    token = _create_access_token(user_id=user_id, email=row["email"])
    return AuthResponse(token=token, user={"email": row["email"]})


# =========================
# Dashboard
# =========================

# PUBLIC_INTERFACE
@app.get(
    "/dashboard",
    tags=["Dashboard"],
    summary="Dashboard aggregate",
    description="Returns overall progress and phase cards for the authenticated user.",
    response_model=DashboardResponseModel,
    operation_id="get_dashboard",
)
def get_dashboard(current_user: AuthUser = Depends(get_current_user), db: Engine = Depends(get_db)) -> DashboardResponseModel:
    """Aggregate dashboard data from DB views and workflow state."""
    user_id = str(current_user.id)

    with db.connect() as conn:
        persona_row = conn.execute(
            text("SELECT user_id FROM persona_profile WHERE user_id = :uid"),
            {"uid": user_id},
        ).first()

        assessment_row = conn.execute(
            text(
                """
                SELECT a.id
                FROM assessment a
                WHERE a.user_id = :uid AND a.status = 'completed'
                ORDER BY a.completed_at DESC NULLS LAST
                LIMIT 1
                """
            ),
            {"uid": user_id},
        ).first()

        selected_path_row = conn.execute(
            text(
                """
                SELECT cp.title
                FROM user_career_path ucp
                JOIN career_path cp ON cp.id = ucp.career_path_id
                WHERE ucp.user_id = :uid AND ucp.is_selected = TRUE
                LIMIT 1
                """
            ),
            {"uid": user_id},
        ).mappings().first()

        roadmap_row = conn.execute(
            text("SELECT id FROM roadmap WHERE user_id = :uid AND status = 'active' ORDER BY created_at DESC LIMIT 1"),
            {"uid": user_id},
        ).first()

        task_stats = conn.execute(
            text("SELECT * FROM v_user_task_stats WHERE user_id = :uid"),
            {"uid": user_id},
        ).mappings().first()

    profile_done = persona_row is not None
    assessment_done = assessment_row is not None
    path_selected = selected_path_row is not None
    has_roadmap = roadmap_row is not None

    statuses = _phase_locked_statuses(profile_done, assessment_done, path_selected, has_roadmap)

    # Progress heuristics:
    # - Profile: 100 if persona exists else 0
    # - Assessment: 100 if any completed assessment else 0
    # - Paths: 100 if selected path else 0
    # - Roadmap: task completion ratio if roadmap exists, else 0
    # - Marketplace: 0 (browse does not contribute to progress in MVP)
    profile_pct = 100 if profile_done else 0
    assessment_pct = 100 if assessment_done else 0
    paths_pct = 100 if path_selected else 0

    if task_stats and task_stats.get("total_tasks", 0) > 0:
        roadmap_pct = _safe_int_pct(int(task_stats["completed_tasks"]), int(task_stats["total_tasks"]))
    else:
        roadmap_pct = 0

    marketplace_pct = 0

    phases = []
    for key, pct in [
        ("PROFILE", profile_pct),
        ("ASSESSMENT", assessment_pct),
        ("PATHS", paths_pct),
        ("ROADMAP", roadmap_pct),
        ("MARKETPLACE", marketplace_pct),
    ]:
        meta = _PHASE_META[key]
        phases.append(
            DashboardPhaseModel(
                key=key,
                title=meta["title"],
                description=meta["description"],
                status=statuses[key],
                progressPct=pct,
                ctaPath=meta["ctaPath"],
            )
        )

    overall = int(round((profile_pct + assessment_pct + paths_pct + roadmap_pct + marketplace_pct) / 5))

    return DashboardResponseModel(
        user={"email": current_user.email},
        overallProgressPct=overall,
        phases=phases,
    )


# =========================
# Profile: documents + persona
# =========================

def _extract_skills_from_text(text_blob: str) -> List[str]:
    """
    Very lightweight MVP extraction:
    - Looks for known skills by canonical_name in `skill` table later, but here just tokenize.
    - Also recognizes common tech tokens.
    """
    # Normalize
    cleaned = re.sub(r"[^a-zA-Z0-9\+\#\.\s]", " ", text_blob)
    tokens = {t.strip() for t in re.split(r"\s+", cleaned) if 2 <= len(t.strip()) <= 32}

    # Common normalizations
    normalized: List[str] = []
    for t in tokens:
        tl = t.lower()
        if tl in ("js", "javascript"):
            normalized.append("JavaScript")
        elif tl in ("ts", "typescript"):
            normalized.append("TypeScript")
        elif tl in ("react", "reactjs"):
            normalized.append("React")
        elif tl in ("node", "nodejs", "node.js"):
            normalized.append("Node.js")
        elif tl in ("postgres", "postgresql"):
            normalized.append("PostgreSQL")
        elif tl == "aws":
            normalized.append("AWS")
        elif tl in ("system", "design") and "System Design" not in normalized:
            # crude; often appears as separate tokens
            pass

    if "system" in {t.lower() for t in tokens} and "design" in {t.lower() for t in tokens}:
        normalized.append("System Design")

    # De-dupe preserving order
    out: List[str] = []
    seen = set()
    for s in normalized:
        if s not in seen:
            out.append(s)
            seen.add(s)
    return out


def _upsert_user_skill(conn, user_id: str, canonical_name: str, source: str = "persona") -> None:
    # Ensure skill exists, then upsert into user_skill
    skill_row = conn.execute(
        text("SELECT id FROM skill WHERE canonical_name = :name"),
        {"name": canonical_name},
    ).mappings().first()
    if not skill_row:
        skill_row = conn.execute(
            text("INSERT INTO skill (canonical_name) VALUES (:name) RETURNING id"),
            {"name": canonical_name},
        ).mappings().first()

    conn.execute(
        text(
            """
            INSERT INTO user_skill (user_id, skill_id, source, updated_at)
            VALUES (:uid, :sid, :source, now())
            ON CONFLICT (user_id, skill_id)
            DO UPDATE SET source = EXCLUDED.source, updated_at = now()
            """
        ),
        {"uid": user_id, "sid": skill_row["id"], "source": source},
    )


# PUBLIC_INTERFACE
@app.post(
    "/profile/documents",
    tags=["Profile"],
    summary="Upload profile documents",
    description="Accepts one or more files, stores extracted text into persona_document, and updates skills/persona heuristically.",
    operation_id="upload_profile_documents",
)
async def upload_profile_documents(
    files: List[UploadFile] = File(..., description="One or more documents."),
    current_user: AuthUser = Depends(get_current_user),
    db: Engine = Depends(get_db),
) -> Dict[str, List[str]]:
    """
    Uploads documents. MVP stores file name and extracted text (best-effort, treating as text).
    For binary PDFs/DOCX, this MVP will store placeholder text indicating unsupported extraction.
    """
    user_id = str(current_user.id)
    doc_ids: List[str] = []

    with db.begin() as conn:
        for f in files:
            raw = await f.read()
            # best-effort decode
            try:
                content_text = raw.decode("utf-8", errors="ignore")
            except Exception:
                content_text = ""

            if not content_text.strip():
                content_text = f"[MVP] Text extraction not available for file '{f.filename}'."

            row = conn.execute(
                text(
                    """
                    INSERT INTO persona_document (user_id, doc_type, file_name, content_text, metadata)
                    VALUES (:uid, :doc_type, :file_name, :content_text, '{}'::jsonb)
                    RETURNING id
                    """
                ),
                {
                    "uid": user_id,
                    "doc_type": "upload",
                    "file_name": f.filename,
                    "content_text": content_text,
                },
            ).mappings().first()
            doc_id = row["id"]
            doc_ids.append(str(doc_id))

            # Extract skills and upsert
            for skill_name in _extract_skills_from_text(content_text):
                _upsert_user_skill(conn, user_id, skill_name, source="persona")

        # Ensure persona_profile exists (MVP: create empty profile if missing)
        conn.execute(
            text(
                """
                INSERT INTO persona_profile (user_id, updated_at)
                VALUES (:uid, now())
                ON CONFLICT (user_id) DO UPDATE SET updated_at = now()
                """
            ),
            {"uid": user_id},
        )

        # Update phase state: build_profile in_progress/completed
        conn.execute(
            text(
                """
                INSERT INTO dashboard_phase_state (user_id, phase, state, updated_at)
                VALUES (:uid, 'build_profile', 'completed', now())
                ON CONFLICT (user_id, phase)
                DO UPDATE SET state = 'completed', updated_at = now()
                """
            ),
            {"uid": user_id},
        )

        # Unlock next phase
        conn.execute(
            text(
                """
                INSERT INTO dashboard_phase_state (user_id, phase, state, updated_at)
                VALUES (:uid, 'skill_assessment', 'not_started', now())
                ON CONFLICT (user_id, phase) DO NOTHING
                """
            ),
            {"uid": user_id},
        )

    return {"documentIds": doc_ids}


# PUBLIC_INTERFACE
@app.get(
    "/profile/persona",
    tags=["Profile"],
    summary="Get persona",
    description="Returns the user's persona profile and a list of skills derived for MVP.",
    response_model=PersonaModel,
    operation_id="get_persona",
)
def get_persona(
    current_user: AuthUser = Depends(get_current_user),
    db: Engine = Depends(get_db),
) -> PersonaModel:
    """Fetch persona_profile and skills."""
    user_id = str(current_user.id)
    with db.connect() as conn:
        profile = conn.execute(
            text(
                """
                SELECT headline, summary, location, years_experience
                FROM persona_profile
                WHERE user_id = :uid
                """
            ),
            {"uid": user_id},
        ).mappings().first()

        skills = conn.execute(
            text(
                """
                SELECT s.canonical_name
                FROM user_skill us
                JOIN skill s ON s.id = us.skill_id
                WHERE us.user_id = :uid
                ORDER BY s.canonical_name
                """
            ),
            {"uid": user_id},
        ).mappings().all()

    if not profile:
        return PersonaModel(skills=[r["canonical_name"] for r in skills])

    return PersonaModel(
        headline=profile["headline"],
        summary=profile["summary"],
        location=profile["location"],
        yearsExperience=float(profile["years_experience"]) if profile["years_experience"] is not None else None,
        skills=[r["canonical_name"] for r in skills],
    )


# PUBLIC_INTERFACE
@app.put(
    "/profile/persona",
    tags=["Profile"],
    summary="Update persona",
    description="Updates persona profile fields and optional skill list (upsert).",
    response_model=PersonaModel,
    operation_id="update_persona",
)
def update_persona(
    payload: PersonaModel,
    current_user: AuthUser = Depends(get_current_user),
    db: Engine = Depends(get_db),
) -> PersonaModel:
    """Update persona profile and upsert any provided skills."""
    user_id = str(current_user.id)

    with db.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO persona_profile (user_id, headline, summary, location, years_experience, updated_at)
                VALUES (:uid, :headline, :summary, :location, :years_experience, now())
                ON CONFLICT (user_id)
                DO UPDATE SET
                    headline = EXCLUDED.headline,
                    summary = EXCLUDED.summary,
                    location = EXCLUDED.location,
                    years_experience = EXCLUDED.years_experience,
                    updated_at = now()
                """
            ),
            {
                "uid": user_id,
                "headline": payload.headline,
                "summary": payload.summary,
                "location": payload.location,
                "years_experience": payload.yearsExperience,
            },
        )

        if payload.skills:
            for s in payload.skills:
                if s and s.strip():
                    _upsert_user_skill(conn, user_id, s.strip(), source="manual")

        # Mark profile completed
        conn.execute(
            text(
                """
                INSERT INTO dashboard_phase_state (user_id, phase, state, updated_at)
                VALUES (:uid, 'build_profile', 'completed', now())
                ON CONFLICT (user_id, phase)
                DO UPDATE SET state = 'completed', updated_at = now()
                """
            ),
            {"uid": user_id},
        )

    return get_persona(current_user=current_user, db=db)


# =========================
# Assessment
# =========================

_LIKERT_OPTIONS = [
    {"value": "1", "label": "Not at all"},
    {"value": "2", "label": "A little"},
    {"value": "3", "label": "Somewhat"},
    {"value": "4", "label": "Comfortable"},
    {"value": "5", "label": "Very comfortable"},
]


# PUBLIC_INTERFACE
@app.get(
    "/assessment/questionnaire",
    tags=["Assessment"],
    summary="Get questionnaire",
    description="Returns the static MVP questionnaire seeded in the DB.",
    response_model=QuestionnaireResponseModel,
    operation_id="get_questionnaire",
)
def get_questionnaire(
    current_user: AuthUser = Depends(get_current_user),
    db: Engine = Depends(get_db),
) -> QuestionnaireResponseModel:
    """Load questionnaire questions from DB and return in frontend expected shape."""
    user_id = str(current_user.id)  # only to ensure auth
    _ = user_id

    with db.connect() as conn:
        rows = conn.execute(
            text(
                """
                SELECT code, prompt
                FROM questionnaire_question
                WHERE active = TRUE
                ORDER BY sort_order ASC, code ASC
                """
            )
        ).mappings().all()

    questions = [
        QuestionnaireQuestion(
            id=r["code"],
            prompt=r["prompt"],
            options=[QuestionnaireOption(**o) for o in _LIKERT_OPTIONS],
        )
        for r in rows
    ]
    return QuestionnaireResponseModel(questions=questions)


def _ensure_open_assessment(conn, user_id: str) -> str:
    row = conn.execute(
        text(
            """
            SELECT id
            FROM assessment
            WHERE user_id = :uid AND status = 'in_progress'
            ORDER BY started_at DESC
            LIMIT 1
            """
        ),
        {"uid": user_id},
    ).mappings().first()
    if row:
        return str(row["id"])

    row = conn.execute(
        text("INSERT INTO assessment (user_id, assessment_type, status) VALUES (:uid, 'questionnaire', 'in_progress') RETURNING id"),
        {"uid": user_id},
    ).mappings().first()
    return str(row["id"])


# PUBLIC_INTERFACE
@app.post(
    "/assessment/responses",
    tags=["Assessment"],
    summary="Submit assessment responses",
    description="Accepts a map of questionId -> selected value. Persists responses and computes basic skill self-ratings.",
    operation_id="submit_assessment",
)
def submit_assessment(
    payload: Dict[str, str],
    current_user: AuthUser = Depends(get_current_user),
    db: Engine = Depends(get_db),
) -> Dict[str, bool]:
    """Persist questionnaire responses and mark assessment completed."""
    user_id = str(current_user.id)

    with db.begin() as conn:
        assessment_id = _ensure_open_assessment(conn, user_id)

        # Load questions keyed by code
        questions = conn.execute(
            text("SELECT id, code, skill_hint FROM questionnaire_question WHERE active = TRUE"),
        ).mappings().all()
        q_by_code = {q["code"]: q for q in questions}

        for code, value in payload.items():
            if code not in q_by_code:
                continue
            q = q_by_code[code]
            conn.execute(
                text(
                    """
                    INSERT INTO questionnaire_response (assessment_id, question_id, response_value)
                    VALUES (:aid, :qid, :val::jsonb)
                    ON CONFLICT (assessment_id, question_id)
                    DO UPDATE SET response_value = EXCLUDED.response_value, created_at = now()
                    """
                ),
                {"aid": assessment_id, "qid": q["id"], "val": f"\"{value}\""},
            )

            # Use skill_hint to create/update user_skill self_rating
            if q["skill_hint"] and value.isdigit():
                canonical = str(q["skill_hint"])
                _upsert_user_skill(conn, user_id, canonical, source="assessment")
                conn.execute(
                    text(
                        """
                        UPDATE user_skill us
                        SET self_rating = :rating, updated_at = now()
                        FROM skill s
                        WHERE us.user_id = :uid AND us.skill_id = s.id AND s.canonical_name = :name
                        """
                    ),
                    {"uid": user_id, "name": canonical, "rating": int(value)},
                )

        conn.execute(
            text(
                """
                UPDATE assessment
                SET status = 'completed', completed_at = now()
                WHERE id = :aid
                """
            ),
            {"aid": assessment_id},
        )

        # Phase state updates
        conn.execute(
            text(
                """
                INSERT INTO dashboard_phase_state (user_id, phase, state, updated_at)
                VALUES (:uid, 'skill_assessment', 'completed', now())
                ON CONFLICT (user_id, phase)
                DO UPDATE SET state = 'completed', updated_at = now()
                """
            ),
            {"uid": user_id},
        )
        conn.execute(
            text(
                """
                INSERT INTO dashboard_phase_state (user_id, phase, state, updated_at)
                VALUES (:uid, 'career_paths', 'not_started', now())
                ON CONFLICT (user_id, phase) DO NOTHING
                """
            ),
            {"uid": user_id},
        )

    return {"ok": True}


# =========================
# Career paths
# =========================

def _compute_fit_for_path(conn, user_id: str, path_id: str) -> Tuple[float, List[str], List[str]]:
    """
    Compute fit score and explainability:
    - Fit is weighted average of min(user_level/target_level, 1).
    - user_level uses self_rating first, else computed_level, else 0.
    """
    targets = conn.execute(
        text(
            """
            SELECT s.canonical_name, t.target_level, t.weight,
                   us.self_rating, us.computed_level
            FROM career_path_skill_target t
            JOIN skill s ON s.id = t.skill_id
            LEFT JOIN user_skill us
              ON us.user_id = :uid AND us.skill_id = t.skill_id
            WHERE t.career_path_id = :pid
            """
        ),
        {"uid": user_id, "pid": path_id},
    ).mappings().all()

    if not targets:
        return (0.0, ["No target skills defined for this path in seed data."], [])

    numer = 0.0
    denom = 0.0
    why: List[str] = []
    key_skills: List[str] = []

    for t in targets:
        target_level = int(t["target_level"])
        weight = float(t["weight"])
        user_level = t["self_rating"] if t["self_rating"] is not None else (t["computed_level"] if t["computed_level"] is not None else 0)
        user_level = int(user_level)

        ratio = min(user_level / target_level, 1.0) if target_level > 0 else 1.0
        numer += ratio * weight
        denom += weight

        key_skills.append(t["canonical_name"])
        if user_level >= target_level:
            why.append(f"Strong on {t['canonical_name']} (you rated {user_level}/{target_level}).")
        elif user_level > 0:
            why.append(f"Some experience in {t['canonical_name']} (you rated {user_level}/{target_level}).")
        else:
            why.append(f"Gap in {t['canonical_name']} (target {target_level}).")

    fit = float(numer / denom) if denom > 0 else 0.0
    fit = max(0.0, min(1.0, fit))
    return fit, why[:5], sorted(set(key_skills))


# PUBLIC_INTERFACE
@app.get(
    "/paths/recommendations",
    tags=["Career Paths"],
    summary="Get career path recommendations",
    description="Generates recommendations based on user skills/assessment (MVP heuristic).",
    response_model=CareerPathRecsResponse,
    operation_id="get_career_path_recommendations",
)
def get_career_path_recommendations(
    current_user: AuthUser = Depends(get_current_user),
    db: Engine = Depends(get_db),
) -> CareerPathRecsResponse:
    """Return ranked path recommendations and persist them in user_career_path."""
    user_id = str(current_user.id)

    with db.begin() as conn:
        paths = conn.execute(text("SELECT id, title FROM career_path ORDER BY title ASC")).mappings().all()

        recs: List[CareerPathRec] = []
        for p in paths:
            fit, why, key_skills = _compute_fit_for_path(conn, user_id, str(p["id"]))
            conn.execute(
                text(
                    """
                    INSERT INTO user_career_path (user_id, career_path_id, fit_score, explanation, is_selected)
                    VALUES (:uid, :pid, :fit, :exp::jsonb, FALSE)
                    ON CONFLICT (user_id, career_path_id)
                    DO UPDATE SET fit_score = EXCLUDED.fit_score, explanation = EXCLUDED.explanation
                    """
                ),
                {"uid": user_id, "pid": str(p["id"]), "fit": round(fit * 100, 2), "exp": '{"why": []}'},
            )
            recs.append(
                CareerPathRec(
                    id=str(p["id"]),
                    title=p["title"],
                    fitScore=fit,
                    why=why,
                    keySkills=key_skills,
                )
            )

        recs.sort(key=lambda r: r.fitScore, reverse=True)

    return CareerPathRecsResponse(recommendations=recs[:6])


# PUBLIC_INTERFACE
@app.post(
    "/paths/select",
    tags=["Career Paths"],
    summary="Select a career path",
    description="Marks the specified career path as selected for the user and generates/activates a roadmap.",
    operation_id="select_career_path",
)
def select_career_path(
    payload: SelectCareerPathRequest,
    current_user: AuthUser = Depends(get_current_user),
    db: Engine = Depends(get_db),
) -> Dict[str, bool]:
    """Select a path; ensures a roadmap exists."""
    user_id = str(current_user.id)

    with db.begin() as conn:
        # Unselect all
        conn.execute(
            text("UPDATE user_career_path SET is_selected = FALSE WHERE user_id = :uid"),
            {"uid": user_id},
        )
        # Select one
        conn.execute(
            text(
                """
                INSERT INTO user_career_path (user_id, career_path_id, is_selected, created_at)
                VALUES (:uid, :pid, TRUE, now())
                ON CONFLICT (user_id, career_path_id)
                DO UPDATE SET is_selected = TRUE
                """
            ),
            {"uid": user_id, "pid": payload.pathId},
        )

        # Phase state updates
        conn.execute(
            text(
                """
                INSERT INTO dashboard_phase_state (user_id, phase, state, updated_at)
                VALUES (:uid, 'career_paths', 'completed', now())
                ON CONFLICT (user_id, phase)
                DO UPDATE SET state = 'completed', updated_at = now()
                """
            ),
            {"uid": user_id},
        )
        conn.execute(
            text(
                """
                INSERT INTO dashboard_phase_state (user_id, phase, state, updated_at)
                VALUES (:uid, 'roadmap', 'not_started', now())
                ON CONFLICT (user_id, phase) DO NOTHING
                """
            ),
            {"uid": user_id},
        )

        # Ensure an active roadmap exists
        existing = conn.execute(
            text("SELECT id FROM roadmap WHERE user_id = :uid AND status = 'active' ORDER BY created_at DESC LIMIT 1"),
            {"uid": user_id},
        ).mappings().first()

        if not existing:
            # Title from career path
            cp = conn.execute(
                text("SELECT title FROM career_path WHERE id = :pid"),
                {"pid": payload.pathId},
            ).mappings().first()
            title = f"Roadmap: {cp['title']}" if cp else "Roadmap"

            r = conn.execute(
                text(
                    """
                    INSERT INTO roadmap (user_id, career_path_id, title, status, start_date)
                    VALUES (:uid, :pid, :title, 'active', CURRENT_DATE)
                    RETURNING id
                    """
                ),
                {"uid": user_id, "pid": payload.pathId, "title": title},
            ).mappings().first()
            roadmap_id = str(r["id"])

            # Generate 3 simple milestones with tasks
            milestones = [
                ("Foundation", 1, ["Review fundamentals", "Complete one small project"]),
                ("Build Portfolio", 2, ["Create a portfolio project", "Write case study / README"]),
                ("Interview Prep", 3, ["Practice system/role interviews", "Update CV & LinkedIn"]),
            ]
            for idx, (m_title, month, tasks) in enumerate(milestones, start=1):
                mrow = conn.execute(
                    text(
                        """
                        INSERT INTO roadmap_milestone (roadmap_id, title, sort_order)
                        VALUES (:rid, :title, :order)
                        RETURNING id
                        """
                    ),
                    {"rid": roadmap_id, "title": m_title, "order": idx},
                ).mappings().first()
                milestone_id = str(mrow["id"])
                for t_idx, t_title in enumerate(tasks, start=1):
                    conn.execute(
                        text(
                            """
                            INSERT INTO roadmap_task (milestone_id, title, status, sort_order)
                            VALUES (:mid, :title, 'not_started', :order)
                            """
                        ),
                        {"mid": milestone_id, "title": t_title, "order": t_idx},
                    )

    return {"ok": True}


# =========================
# Roadmap
# =========================

# PUBLIC_INTERFACE
@app.get(
    "/roadmap",
    tags=["Roadmap"],
    summary="Get roadmap",
    description="Returns the active roadmap milestones and tasks for the user.",
    response_model=RoadmapResponseModel,
    operation_id="get_roadmap",
)
def get_roadmap(
    current_user: AuthUser = Depends(get_current_user),
    db: Engine = Depends(get_db),
) -> RoadmapResponseModel:
    """Return active roadmap. If none exists, returns empty milestones and null selectedPathTitle."""
    user_id = str(current_user.id)

    with db.connect() as conn:
        sel = conn.execute(
            text(
                """
                SELECT cp.title
                FROM user_career_path ucp
                JOIN career_path cp ON cp.id = ucp.career_path_id
                WHERE ucp.user_id = :uid AND ucp.is_selected = TRUE
                LIMIT 1
                """
            ),
            {"uid": user_id},
        ).mappings().first()
        selected_title = sel["title"] if sel else None

        roadmap = conn.execute(
            text("SELECT id FROM roadmap WHERE user_id = :uid AND status = 'active' ORDER BY created_at DESC LIMIT 1"),
            {"uid": user_id},
        ).mappings().first()

        if not roadmap:
            return RoadmapResponseModel(selectedPathTitle=selected_title, milestones=[])

        milestones = conn.execute(
            text(
                """
                SELECT id, title, sort_order
                FROM roadmap_milestone
                WHERE roadmap_id = :rid
                ORDER BY sort_order ASC
                """
            ),
            {"rid": str(roadmap["id"])},
        ).mappings().all()

        out: List[RoadmapMilestoneModel] = []
        for m in milestones:
            tasks = conn.execute(
                text(
                    """
                    SELECT id, title, status
                    FROM roadmap_task
                    WHERE milestone_id = :mid
                    ORDER BY sort_order ASC
                    """
                ),
                {"mid": str(m["id"])},
            ).mappings().all()

            out.append(
                RoadmapMilestoneModel(
                    id=str(m["id"]),
                    title=m["title"],
                    targetMonth=int(m["sort_order"]),
                    tasks=[
                        RoadmapTaskModel(
                            id=str(t["id"]),
                            title=t["title"],
                            done=(t["status"] == "completed"),
                        )
                        for t in tasks
                    ],
                )
            )

    return RoadmapResponseModel(selectedPathTitle=selected_title, milestones=out)


# PUBLIC_INTERFACE
@app.post(
    "/roadmap/task",
    tags=["Roadmap"],
    summary="Toggle a roadmap task",
    description="Marks a roadmap task as completed/not completed. Used by the UI checkbox.",
    operation_id="toggle_roadmap_task",
)
def toggle_roadmap_task(
    payload: ToggleTaskRequest,
    current_user: AuthUser = Depends(get_current_user),
    db: Engine = Depends(get_db),
) -> Dict[str, bool]:
    """Toggle task completion and update roadmap phase state if needed."""
    user_id = str(current_user.id)

    with db.begin() as conn:
        # Ensure task belongs to the current user (join through milestone->roadmap)
        row = conn.execute(
            text(
                """
                SELECT t.id
                FROM roadmap_task t
                JOIN roadmap_milestone m ON m.id = t.milestone_id
                JOIN roadmap r ON r.id = m.roadmap_id
                WHERE t.id = :tid AND m.id = :mid AND r.user_id = :uid AND r.status = 'active'
                """
            ),
            {"tid": payload.taskId, "mid": payload.milestoneId, "uid": user_id},
        ).first()
        if not row:
            raise HTTPException(status_code=404, detail="Task not found")

        if payload.done:
            conn.execute(
                text(
                    """
                    UPDATE roadmap_task
                    SET status = 'completed', completed_at = now()
                    WHERE id = :tid
                    """
                ),
                {"tid": payload.taskId},
            )
        else:
            conn.execute(
                text(
                    """
                    UPDATE roadmap_task
                    SET status = 'not_started', completed_at = NULL
                    WHERE id = :tid
                    """
                ),
                {"tid": payload.taskId},
            )

        # Mark roadmap phase as in_progress once user interacts
        conn.execute(
            text(
                """
                INSERT INTO dashboard_phase_state (user_id, phase, state, updated_at)
                VALUES (:uid, 'roadmap', 'in_progress', now())
                ON CONFLICT (user_id, phase)
                DO UPDATE SET state = 'in_progress', updated_at = now()
                """
            ),
            {"uid": user_id},
        )

    return {"ok": True}


# =========================
# Marketplace
# =========================

def _map_item_type(item_type: str) -> str:
    t = item_type.lower()
    if t == "course":
        return "COURSE"
    if t in ("cert", "certification"):
        return "CERT"
    if t == "bootcamp":
        return "BOOTCAMP"
    if t == "book":
        return "BOOK"
    if t == "project":
        return "PROJECT"
    return "COURSE"


# PUBLIC_INTERFACE
@app.get(
    "/marketplace",
    tags=["Marketplace"],
    summary="Browse marketplace",
    description="Browse/filter marketplace items by query string and type.",
    response_model=MarketplaceResponseModel,
    operation_id="get_marketplace",
)
def get_marketplace(
    q: Optional[str] = Query(None, description="Search query (matches title/provider/tags)."),
    type: Optional[str] = Query(None, description="Filter by type: COURSE|CERT|BOOTCAMP|BOOK|PROJECT"),
    current_user: AuthUser = Depends(get_current_user),
    db: Engine = Depends(get_db),
) -> MarketplaceResponseModel:
    """Marketplace browse endpoint aligned to frontend /marketplace?q=&type=."""
    user_id = str(current_user.id)
    _ = user_id

    sql = """
        SELECT id, title, provider, item_type, tags, skills
        FROM marketplace_item
        WHERE 1=1
    """
    params: Dict[str, Any] = {}

    if type:
        # Map to DB values
        t = type.strip().lower()
        if t == "cert":
            t = "certification"
        sql += " AND item_type = :type"
        params["type"] = t

    if q and q.strip():
        sql += " AND (title ILIKE :q OR provider ILIKE :q OR array_to_string(tags, ',') ILIKE :q)"
        params["q"] = f"%{q.strip()}%"

    sql += " ORDER BY created_at DESC LIMIT 50"

    with db.connect() as conn:
        rows = conn.execute(text(sql), params).mappings().all()

    items: List[MarketplaceItemModel] = []
    for r in rows:
        skill_tags: List[str] = []
        try:
            # `skills` column is JSONB array of canonical skill names
            skill_tags = list(r["skills"]) if r["skills"] is not None else []
        except Exception:
            skill_tags = []

        items.append(
            MarketplaceItemModel(
                id=str(r["id"]),
                title=r["title"],
                provider=r["provider"] or "Unknown",
                type=_map_item_type(r["item_type"]),
                skillTags=skill_tags,
            )
        )

    return MarketplaceResponseModel(items=items)
