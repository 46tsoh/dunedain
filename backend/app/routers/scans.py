from __future__ import annotations

from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Scan
from ..repositories import (
    FindingRepository,
    PolicyResultRepository,
    SBOMRepository,
    ScanRepository,
)
from ..schemas import (
    FindingRead,
    PolicyResultRead,
    SBOMRead,
    ScanCreate,
    ScanRead,
    ScanSummary,
    _compute_policy_status,
)
from ..tasks.scan import run_scan
from ..services.scanner import _get_scanner_preference
from ..celery_app import celery_app

router = APIRouter(prefix="/scans", tags=["scans"])

_VALID_SCAN_TYPES = {"container", "dependency", "source"}
_VALID_STATUSES = {"pending", "running", "completed", "failed", "unsupported"}


@router.post("", response_model=ScanRead, status_code=202)
def create_scan(payload: ScanCreate, db: Session = Depends(get_db)):
    scan_repo = ScanRepository(db)
    if payload.scanner_override:
        scanner_override = payload.scanner_override
    elif payload.scan_type == "container":
        scanner_override = _get_scanner_preference()
    else:
        scanner_override = None
    scan = scan_repo.save(
        Scan(
            id=str(uuid4()),
            name=payload.name or payload.target,
            scan_type=payload.scan_type,
            target=payload.target,
            status="pending",
            packages=payload.packages,
            registry_id=payload.registry_id,
            scanner_override=scanner_override,
        )
    )

    # Dispatch to Celery worker — non-blocking
    run_scan.delay(scan.id, payload.packages)

    return scan


@router.get("", response_model=list[ScanSummary])
def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    scan_type: str | None = Query(None),
    status: str | None = Query(None),
    db: Session = Depends(get_db),
):
    if scan_type and scan_type not in _VALID_SCAN_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scan_type '{scan_type}'. Valid values: {', '.join(sorted(_VALID_SCAN_TYPES))}",
        )
    if status and status not in _VALID_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{status}'. Valid values: {', '.join(sorted(_VALID_STATUSES))}",
        )

    scans = ScanRepository(db).list_with_filters(
        skip=skip, limit=limit, scan_type=scan_type, status=status
    )

    result = []
    for s in scans:
        findings = s.findings
        registry_name = s.registry.name if s.registry else None
        result.append(ScanSummary(
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
            finding_count=len(findings),
            critical_count=sum(1 for f in findings if f.severity == "CRITICAL"),
            high_count=sum(1 for f in findings if f.severity == "HIGH"),
            medium_count=sum(1 for f in findings if f.severity == "MEDIUM"),
            low_count=sum(1 for f in findings if f.severity == "LOW"),
            negligible_count=sum(1 for f in findings if f.severity == "NEGLIGIBLE"),
            unknown_count=sum(1 for f in findings if f.severity == "UNKNOWN"),
        ))
    return result


@router.get("/{scan_id}", response_model=ScanRead)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = ScanRepository(db).get_or_404(scan_id, detail="Scan not found")
    findings = scan.findings
    count = len(findings)
    registry_name = scan.registry.name if scan.registry else None
    return ScanRead(
        id=scan.id,
        name=scan.name,
        scan_type=scan.scan_type,
        target=scan.target,
        status=scan.status,
        error_message=scan.error_message,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        scanner_engine=scan.scanner_engine,
        scanner_override=scan.scanner_override,
        base_image=scan.base_image,
        base_image_chain=scan.base_image_chain,
        registry_id=scan.registry_id,
        registry_name=registry_name,
        findings=[FindingRead.model_validate(f) for f in findings],
        finding_count=count,
        findings_count=count,
        critical_count=sum(1 for f in findings if f.severity == "CRITICAL"),
        high_count=sum(1 for f in findings if f.severity == "HIGH"),
        medium_count=sum(1 for f in findings if f.severity == "MEDIUM"),
        low_count=sum(1 for f in findings if f.severity == "LOW"),
        negligible_count=sum(1 for f in findings if f.severity == "NEGLIGIBLE"),
        unknown_count=sum(1 for f in findings if f.severity == "UNKNOWN"),
    )


@router.get("/{scan_id}/findings", response_model=list[FindingRead])
def get_findings(
    scan_id: str,
    severity: str | None = Query(None),
    is_fixed: bool | None = Query(None),
    db: Session = Depends(get_db),
):
    ScanRepository(db).get_or_404(scan_id, detail="Scan not found")
    return FindingRepository(db).for_scan(scan_id, severity=severity, is_fixed=is_fixed)


@router.get("/{scan_id}/sbom", response_model=SBOMRead)
def get_sbom(scan_id: str, db: Session = Depends(get_db)):
    sbom = SBOMRepository(db).for_scan(scan_id)
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found for this scan")
    return sbom


@router.get("/{scan_id}/policy-results", response_model=list[PolicyResultRead])
def get_policy_results(scan_id: str, db: Session = Depends(get_db)):
    ScanRepository(db).get_or_404(scan_id, detail="Scan not found")
    results = PolicyResultRepository(db).for_scan(scan_id)
    output = []
    for pr in results:
        policy = pr.policy
        policy_name = policy.name if policy else ""
        policy_action = policy.action if policy else "warn"
        status = _compute_policy_status(pr.passed, policy_action)
        output.append(PolicyResultRead(
            id=pr.id,
            scan_id=pr.scan_id,
            policy_id=pr.policy_id,
            policy_name=policy_name,
            passed=pr.passed,
            status=status,
            violations=pr.violations or [],
            evaluated_at=pr.evaluated_at,
        ))
    return output


@router.post("/{scan_id}/rerun", response_model=ScanRead, status_code=202)
def rerun_scan(scan_id: str, db: Session = Depends(get_db)):
    """Create a new scan that repeats the same target/type/packages as an existing scan.

    A brand-new Scan row is created (the original is untouched) and the Celery
    task is dispatched immediately to execute a fresh scan.
    """
    original = ScanRepository(db).get_or_404(scan_id, detail="Scan not found")
    if original.scan_type == "container":
        scanner_override = _get_scanner_preference()
    else:
        scanner_override = None

    new_scan = ScanRepository(db).save(
        Scan(
            id=str(uuid4()),
            name=original.target,
            scan_type=original.scan_type,
            target=original.target,
            status="pending",
            packages=original.packages,
            registry_id=original.registry_id,
            scanner_override=scanner_override,
        )
    )

    run_scan.delay(new_scan.id, original.packages)

    return new_scan


@router.post("/queue/flush", status_code=200)
def flush_queue():
    """Purge all pending tasks from the Celery scans queue."""
    purged = celery_app.control.purge()
    return {"purged": purged}


@router.delete("", status_code=200)
def delete_all_scans(db: Session = Depends(get_db)):
    """Delete every scan and all associated data (findings, SBOMs, policy results)."""
    deleted = ScanRepository(db).delete_all()
    return {"deleted": deleted}


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    """Delete a scan and all associated data (findings, SBOM, policy results)."""
    repo = ScanRepository(db)
    scan = repo.get_or_404(scan_id, detail="Scan not found")
    repo.delete(scan)
