from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..repositories import AuditLogRepository, FindingRepository, ScanRepository
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
    finding_repo = FindingRepository(db)

    total_scans = scan_repo.count()
    total_findings = finding_repo.count()

    from ..models import Finding
    critical_count = finding_repo.count(filters=[Finding.severity == "CRITICAL"])
    high_count = finding_repo.count(filters=[Finding.severity == "HIGH"])
    medium_count = finding_repo.count(filters=[Finding.severity == "MEDIUM"])
    low_count = finding_repo.count(filters=[Finding.severity == "LOW"])
    negligible_count = finding_repo.count(filters=[Finding.severity == "NEGLIGIBLE"])
    unknown_count = finding_repo.count(filters=[Finding.severity == "UNKNOWN"])

    # Recent scans (last 10)
    from ..models import Scan
    recent = scan_repo.list(limit=10, order_by=Scan.created_at.desc())
    recent_scans = [
        ScanSummary(
            id=s.id,
            name=s.name,
            scan_type=s.scan_type,
            target=s.target,
            status=s.status,
            created_at=s.created_at,
            completed_at=s.completed_at,
            finding_count=len(s.findings),
        )
        for s in recent
    ]

    # Top vulnerabilities
    top_vulnerabilities = [
        TopVulnerability(
            vulnerability_id=row.vulnerability_id,
            count=row.cnt,
            severity=row.severity,
            max_cvss=row.max_cvss,
        )
        for row in finding_repo.top_vulnerabilities(limit=10)
    ]

    # Severity trend: last 30 days
    trend_findings = finding_repo.trend_since(days=30)

    day_buckets: dict[str, dict[str, int]] = defaultdict(
        lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0, "unknown": 0}
    )
    for f in trend_findings:
        scan = scan_repo.get(f.scan_id)
        if scan and scan.created_at:
            day_key = scan.created_at.strftime("%Y-%m-%d")
            sev = f.severity.lower()
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
