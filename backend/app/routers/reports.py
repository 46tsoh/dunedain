from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..repositories import AuditLogRepository, ScanRepository, VulnerabilityInstanceRepository
from ..schemas import (
    AuditLogRead,
    DashboardReport,
    ScanSummary,
    SeverityTrendPoint,
    TopVulnerability,
)

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/dashboard", response_model=DashboardReport)
def dashboard(db: Session = Depends(get_db)):
    scan_repo = ScanRepository(db)
    vuln_repo = VulnerabilityInstanceRepository(db)

    total_scans = scan_repo.count()

    # ── Deduped counts from VulnerabilityInstance table ────────────────
    total_findings = vuln_repo.total_count()
    sev_counts = vuln_repo.severity_counts()
    critical_count = sev_counts.get("CRITICAL", 0)
    high_count = sev_counts.get("HIGH", 0)
    medium_count = sev_counts.get("MEDIUM", 0)
    low_count = sev_counts.get("LOW", 0)
    negligible_count = sev_counts.get("NEGLIGIBLE", 0)
    unknown_count = sev_counts.get("UNKNOWN", 0)

    # Recent scans (last 10)
    from ..models import Scan
    recent = scan_repo.list(limit=10, order_by=Scan.created_at.desc())
    recent_scans = []
    for s in recent:
        findings = s.findings
        registry_name = s.registry.name if s.registry else None
        team_name = s.team.name if s.team else None
        recent_scans.append(ScanSummary(
            id=s.id,
            name=s.name,
            scan_type=s.scan_type,
            target=s.target,
            status=s.status,
            error_message=s.error_message,
            created_at=s.created_at,
            completed_at=s.completed_at,
            scanner_engine=s.scanner_engine,
            scanner_override=s.scanner_override,
            base_image=s.base_image,
            base_image_chain=s.base_image_chain,
            registry_id=s.registry_id,
            registry_name=registry_name,
            team_id=s.team_id,
            team_name=team_name,
            finding_count=len(findings),
            critical_count=sum(1 for f in findings if f.severity == "CRITICAL"),
            high_count=sum(1 for f in findings if f.severity == "HIGH"),
            medium_count=sum(1 for f in findings if f.severity == "MEDIUM"),
            low_count=sum(1 for f in findings if f.severity == "LOW"),
            negligible_count=sum(1 for f in findings if f.severity == "NEGLIGIBLE"),
            unknown_count=sum(1 for f in findings if f.severity == "UNKNOWN"),
        ))

    # Top vulnerabilities (deduped — counts how many targets are affected)
    top_vulnerabilities = [
        TopVulnerability(
            vulnerability_id=row.vulnerability_id,
            count=row.cnt,
            severity=row.severity,
            max_cvss=row.max_cvss,
        )
        for row in vuln_repo.top_vulnerabilities(limit=10)
    ]

    # Severity trend: last 30 days (based on first_seen_at of unique vulns)
    trend_instances = vuln_repo.trend_since(days=30)

    day_buckets: dict[str, dict[str, int]] = defaultdict(
        lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0, "unknown": 0}
    )
    for vi in trend_instances:
        day_key = vi.first_seen_at.strftime("%Y-%m-%d")
        sev = vi.severity.lower()
        if sev in day_buckets[day_key]:
            day_buckets[day_key][sev] += 1

    severity_trend = [
        SeverityTrendPoint(
            date=day,
            critical=counts["critical"],
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
            negligible=counts["negligible"],
            unknown=counts["unknown"],
        )
        for day, counts in sorted(day_buckets.items())
    ]

    return DashboardReport(
        total_scans=total_scans,
        total_findings=total_findings,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        negligible_count=negligible_count,
        unknown_count=unknown_count,
        recent_scans=recent_scans,
        top_vulnerabilities=top_vulnerabilities,
        severity_trend=severity_trend,
    )


@router.get("/audit-log", response_model=list[AuditLogRead])
def audit_log(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    action: Optional[str] = Query(None, description="Filter by action (e.g. scan_completed)"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type (e.g. scan, policy)"),
    db: Session = Depends(get_db),
):
    return AuditLogRepository(db).list_with_filters(
        skip=skip, limit=limit, action=action, resource_type=resource_type
    )
