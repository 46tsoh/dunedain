from __future__ import annotations

import fnmatch
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuditLog, OwnershipRule, Team
from ..repositories import (
    AuditLogRepository,
    FindingRepository,
    OwnershipRuleRepository,
    ScanRepository,
    SettingRepository,
    TeamRepository,
)
from ..schemas import (
    OwnershipRuleCreate,
    OwnershipRuleRead,
    TeamCreate,
    TeamDashboardReport,
    TeamFindingSummary,
    TeamRead,
    TeamUpdate,
)

router = APIRouter(prefix="/teams", tags=["teams"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _team_to_read(team: Team) -> TeamRead:
    """Build a TeamRead from the ORM model, including scan count."""
    return TeamRead(
        id=team.id,
        name=team.name,
        description=team.description,
        contact_email=team.contact_email,
        created_at=team.created_at,
        updated_at=team.updated_at,
        ownership_rules=[OwnershipRuleRead.model_validate(r) for r in (team.ownership_rules or [])],
        scan_count=len(team.scans) if team.scans else 0,
    )


def resolve_team_for_target(db: Session, target: str, scan_type: str) -> str | None:
    """Find the best-matching team for a scan target using ownership rules.

    Rules are checked in descending priority order.  The first match wins.
    Returns the team_id or None.
    """
    rules = OwnershipRuleRepository(db).list_all()  # ordered by priority desc
    for rule in rules:
        # If the rule is scoped to a scan type, skip non-matching types
        if rule.scan_type and rule.scan_type != scan_type:
            continue
        if fnmatch.fnmatch(target, rule.pattern):
            return rule.team_id
    return None


# ---------------------------------------------------------------------------
# Team CRUD
# ---------------------------------------------------------------------------

@router.get("", response_model=list[TeamRead])
def list_teams(db: Session = Depends(get_db)):
    teams = TeamRepository(db).list_all()
    return [_team_to_read(t) for t in teams]


@router.post("", response_model=TeamRead, status_code=201)
def create_team(payload: TeamCreate, db: Session = Depends(get_db)):
    team_repo = TeamRepository(db)
    audit_repo = AuditLogRepository(db)

    if team_repo.get_by_name(payload.name):
        raise HTTPException(status_code=409, detail=f"Team '{payload.name}' already exists")

    now = datetime.now(timezone.utc)
    team = team_repo.save(Team(
        id=str(uuid4()),
        name=payload.name,
        description=payload.description,
        contact_email=payload.contact_email,
        created_at=now,
        updated_at=now,
    ))

    audit_repo.add(AuditLog(
        id=str(uuid4()),
        action="team_created",
        resource_type="team",
        resource_id=team.id,
        details={"name": team.name},
    ))
    audit_repo.commit()
    return _team_to_read(team)


@router.get("/{team_id}", response_model=TeamRead)
def get_team(team_id: str, db: Session = Depends(get_db)):
    team = TeamRepository(db).get_or_404(team_id, detail="Team not found")
    return _team_to_read(team)


@router.put("/{team_id}", response_model=TeamRead)
def update_team(team_id: str, payload: TeamUpdate, db: Session = Depends(get_db)):
    repo = TeamRepository(db)
    team = repo.get_or_404(team_id, detail="Team not found")

    if payload.name is not None:
        team.name = payload.name
    if payload.description is not None:
        team.description = payload.description
    if payload.contact_email is not None:
        team.contact_email = payload.contact_email
    team.updated_at = datetime.now(timezone.utc)

    repo.commit()
    repo.refresh(team)
    return _team_to_read(team)


@router.delete("/{team_id}", status_code=204)
def delete_team(team_id: str, db: Session = Depends(get_db)):
    repo = TeamRepository(db)
    team = repo.get_or_404(team_id, detail="Team not found")
    repo.delete(team)


# ---------------------------------------------------------------------------
# Ownership Rules
# ---------------------------------------------------------------------------

@router.get("/{team_id}/rules", response_model=list[OwnershipRuleRead])
def list_ownership_rules(team_id: str, db: Session = Depends(get_db)):
    TeamRepository(db).get_or_404(team_id, detail="Team not found")
    return OwnershipRuleRepository(db).for_team(team_id)


@router.post("/{team_id}/rules", response_model=OwnershipRuleRead, status_code=201)
def create_ownership_rule(
    team_id: str,
    payload: OwnershipRuleCreate,
    db: Session = Depends(get_db),
):
    TeamRepository(db).get_or_404(team_id, detail="Team not found")
    rule_repo = OwnershipRuleRepository(db)

    rule = rule_repo.save(OwnershipRule(
        id=str(uuid4()),
        team_id=team_id,
        pattern=payload.pattern,
        scan_type=payload.scan_type,
        priority=payload.priority,
        description=payload.description,
        created_at=datetime.now(timezone.utc),
    ))
    return rule


@router.delete("/{team_id}/rules/{rule_id}", status_code=204)
def delete_ownership_rule(team_id: str, rule_id: str, db: Session = Depends(get_db)):
    TeamRepository(db).get_or_404(team_id, detail="Team not found")
    rule_repo = OwnershipRuleRepository(db)
    rule = rule_repo.get_or_404(rule_id, detail="Ownership rule not found")
    if rule.team_id != team_id:
        raise HTTPException(status_code=404, detail="Ownership rule not found for this team")
    rule_repo.delete(rule)


# ---------------------------------------------------------------------------
# Team Dashboard
# ---------------------------------------------------------------------------

def _resolve_sla_hours(
    severity: str, cvss_score: float | None, db: Session,
) -> int | None:
    """Return the SLA deadline (hours) for a finding based on global settings.

    Reads the ``sla_mode`` setting:
    - ``"severity"`` (default): maps the finding severity to the corresponding
      ``sla_<severity>_hours`` global setting.
    - ``"cvss"``: classifies the finding by its CVSS score using the
      configurable tier thresholds.  Falls back to severity-based lookup
      when the finding has no CVSS score.
    """
    settings = SettingRepository(db)
    mode = settings.get_value("sla_mode", default="severity")

    if mode == "cvss" and cvss_score is not None:
        critical_min = float(settings.get_value("sla_cvss_critical_min", default="9.0"))
        high_min = float(settings.get_value("sla_cvss_high_min", default="7.0"))
        medium_min = float(settings.get_value("sla_cvss_medium_min", default="4.0"))

        if cvss_score >= critical_min:
            key = "sla_critical_hours"
        elif cvss_score >= high_min:
            key = "sla_high_hours"
        elif cvss_score >= medium_min:
            key = "sla_medium_hours"
        else:
            key = "sla_low_hours"
    else:
        # Severity mode, or CVSS mode with null score (fallback)
        key_map = {
            "CRITICAL": "sla_critical_hours",
            "HIGH": "sla_high_hours",
            "MEDIUM": "sla_medium_hours",
            "LOW": "sla_low_hours",
        }
        key = key_map.get(severity.upper())  # type: ignore[arg-type]
        if key is None:
            return None

    raw = settings.get_value(key, default="")
    try:
        return int(raw) if raw else None
    except (ValueError, TypeError):
        return None


@router.get("/{team_id}/dashboard", response_model=TeamDashboardReport)
def team_dashboard(
    team_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    sla_status: Optional[str] = Query(None, description="'violated' or 'ok'"),
    is_fixed: Optional[bool] = Query(None, description="Filter by fix status"),
    db: Session = Depends(get_db),
):
    """Per-team vulnerability dashboard with SLA tracking.

    Returns all findings across all scans owned by the team, enriched with
    SLA deadline info and violation flags.
    """
    team_repo = TeamRepository(db)
    team = team_repo.get_or_404(team_id, detail="Team not found")
    team_read = _team_to_read(team)

    # Gather all scans for this team
    scans = team_repo.scans_for_team(team_id)
    if not scans:
        return TeamDashboardReport(team=team_read)

    now = datetime.utcnow()
    finding_repo = FindingRepository(db)

    findings_out: list[TeamFindingSummary] = []
    total = 0
    critical = 0
    high = 0
    medium = 0
    low = 0
    violations = 0

    for scan in scans:
        # Only look at completed scans
        if scan.status != "completed":
            continue

        scan_findings = finding_repo.for_scan(
            scan.id,
            severity=severity,
            is_fixed=is_fixed,
        )

        for f in scan_findings:
            discovered_at = scan.created_at
            sla_hours = _resolve_sla_hours(f.severity, f.cvss_score, db)
            hours_elapsed = (now - discovered_at).total_seconds() / 3600.0
            sla_violated = False
            if sla_hours is not None:
                sla_violated = hours_elapsed > sla_hours

            # Apply sla_status filter
            if sla_status == "violated" and not sla_violated:
                continue
            if sla_status == "ok" and sla_violated:
                continue

            total += 1
            sev = f.severity.upper()
            if sev == "CRITICAL":
                critical += 1
            elif sev == "HIGH":
                high += 1
            elif sev == "MEDIUM":
                medium += 1
            elif sev == "LOW":
                low += 1

            if sla_violated:
                violations += 1

            findings_out.append(TeamFindingSummary(
                finding_id=f.id,
                vulnerability_id=f.vulnerability_id,
                package_name=f.package_name,
                package_version=f.package_version,
                severity=f.severity,
                cvss_score=f.cvss_score,
                risk_score=f.risk_score,
                is_fixed=f.is_fixed,
                fix_version=f.fix_version,
                discovered_at=discovered_at,
                scan_id=scan.id,
                scan_name=scan.name,
                sla_hours=sla_hours,
                hours_elapsed=round(hours_elapsed, 1),
                sla_violated=sla_violated,
            ))

    return TeamDashboardReport(
        team=team_read,
        total_findings=total,
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        sla_violations=violations,
        findings=findings_out,
    )
