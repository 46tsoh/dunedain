from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import Base, SessionLocal, SQLALCHEMY_DATABASE_URL, engine
from .models import AutomationRule, Policy
from .routers import policies, reports, registries, sbom, scans, settings, teams, vulns, integrations, webhooks, automation


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create all tables on startup (handles fresh installs)
    Base.metadata.create_all(bind=engine)
    _run_alembic_upgrade()
    _seed_default_policies()
    _seed_default_automation_rules()
    yield


def _run_alembic_upgrade() -> None:
    """Apply pending Alembic migrations to bring the schema up to head.

    Runs after Base.metadata.create_all() so both fresh installs (tables created
    by create_all) and existing databases (tables already present) are covered.
    All migrations MUST guard column operations with existence checks to remain
    idempotent — create_all may have already added the column on fresh databases.

    Skips silently when alembic.ini is absent (e.g. test environments that rely
    solely on Base.metadata.create_all() for schema setup).
    """
    from alembic.config import Config
    from alembic import command

    ini_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "alembic.ini"))
    if not os.path.exists(ini_path):
        return
    alembic_cfg = Config(ini_path)
    alembic_cfg.set_main_option("sqlalchemy.url", SQLALCHEMY_DATABASE_URL)
    command.upgrade(alembic_cfg, "head")


def _seed_default_policies() -> None:
    db = SessionLocal()
    try:
        if db.query(Policy).count() > 0:
            return

        defaults = [
            Policy(
                id=str(uuid4()),
                name="Block Critical Vulnerabilities",
                description="Block pipeline if any CRITICAL severity findings are detected.",
                enabled=True,
                rules=[{"type": "severity_threshold", "min_severity": "CRITICAL", "action": "block"}],
                action="block",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            ),
            Policy(
                id=str(uuid4()),
                name="Warn on High Vulnerabilities",
                description="Emit a warning when HIGH severity findings are present.",
                enabled=True,
                rules=[{"type": "severity_threshold", "min_severity": "HIGH", "action": "warn"}],
                action="warn",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            ),
            Policy(
                id=str(uuid4()),
                name="Require Fix Available",
                description="Warn when vulnerable packages have no fix version available.",
                enabled=True,
                rules=[{"type": "fix_available", "require_fix": True, "action": "warn"}],
                action="warn",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            ),
            Policy(
                id=str(uuid4()),
                name="CVE Score Threshold",
                description="Block if any finding has a CVSS base score >= 9.0.",
                enabled=True,
                rules=[{"type": "cvss_threshold", "min_score": 9.0, "action": "block"}],
                action="block",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            ),
        ]
        db.add_all(defaults)
        db.commit()
    finally:
        db.close()


def _seed_default_automation_rules() -> None:
    """Seed default automation rules if the table is empty.

    Disabled by default — users must explicitly enable them.
    """
    db = SessionLocal()
    try:
        if db.query(AutomationRule).count() > 0:
            return

        defaults = [
            AutomationRule(
                id=str(uuid4()),
                name="Rescan on ticket closure",
                description=(
                    "When a Jira ticket is moved to Done/Closed/Resolved, "
                    "automatically re-run the associated scan to verify the fix."
                ),
                enabled=False,
                trigger="jira_status_changed",
                conditions=[
                    {"type": "ticket_status_in", "values": ["done", "closed", "resolved"]},
                ],
                actions=[
                    {"type": "rerun_scan"},
                ],
                integration_id=None,
                team_id=None,
                execution_count=0,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            ),
            AutomationRule(
                id=str(uuid4()),
                name="Rescan on GitHub issue closure",
                description=(
                    "When a GitHub issue is closed, automatically re-run the "
                    "associated scan to verify the fix."
                ),
                enabled=False,
                trigger="ticket_status_changed",
                conditions=[
                    {"type": "ticket_status_in", "values": ["closed"]},
                ],
                actions=[
                    {"type": "rerun_scan"},
                ],
                integration_id=None,
                team_id=None,
                execution_count=0,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            ),
        ]
        db.add_all(defaults)
        db.commit()
    finally:
        db.close()


app = FastAPI(
    title="Dunedain",
    description="Open-source software supply chain security platform powered by OSV.dev",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

_raw_origins = os.environ.get("ALLOWED_ORIGINS", "*")
_allowed_origins: list[str] = (
    ["*"] if _raw_origins.strip() == "*" else [o.strip() for o in _raw_origins.split(",") if o.strip()]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=_raw_origins.strip() != "*",  # credentials require explicit origins
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router, prefix="/api")
app.include_router(policies.router, prefix="/api")
app.include_router(sbom.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(vulns.router, prefix="/api")
app.include_router(settings.router, prefix="/api")
app.include_router(registries.router, prefix="/api")
app.include_router(teams.router, prefix="/api")
app.include_router(integrations.router, prefix="/api")
app.include_router(webhooks.router, prefix="/api")
app.include_router(automation.router, prefix="/api")


@app.get("/health", tags=["health"])
def health_check():
    return {"status": "ok", "version": "1.0.0"}
