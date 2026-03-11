from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuditLog, Finding, Scan, SBOM
from ..repositories import AuditLogRepository, FindingRepository, SBOMRepository, ScanRepository
from ..schemas import SBOMIngestRequest, SBOMRead
from ..services import scanner as scanner_svc
from ..services import sbom as sbom_svc

router = APIRouter(prefix="/sbom", tags=["sbom"])


@router.post("/ingest", response_model=SBOMRead)
def ingest_sbom(payload: SBOMIngestRequest, db: Session = Depends(get_db)):
    """Ingest an existing SBOM, extract packages, scan them with OSV, and persist."""
    packages = sbom_svc.parse_sbom(payload.content)
    if not packages:
        raise HTTPException(status_code=400, detail="No packages found in SBOM")

    now = datetime.now(timezone.utc)
    scan_repo = ScanRepository(db)
    scan = scan_repo.save(Scan(
        id=str(uuid4()),
        name=payload.name,
        scan_type="dependency",
        target=f"sbom-ingest:{payload.name}",
        status="running",
        created_at=now,
    ))

    raw_findings = scanner_svc.scan_dependencies(packages)

    finding_repo = FindingRepository(db)
    for fd in raw_findings:
        finding_repo.add(Finding(
            id=fd.get("id", str(uuid4())),
            scan_id=scan.id,
            package_name=fd["package_name"],
            package_version=fd["package_version"],
            package_ecosystem=fd["package_ecosystem"],
            vulnerability_id=fd["vulnerability_id"],
            severity=fd.get("severity", "UNKNOWN"),
            cvss_score=fd.get("cvss_score"),
            description=fd.get("description", ""),
            fix_version=fd.get("fix_version"),
            is_fixed=fd.get("is_fixed", False),
            reachable=fd.get("reachable", False),
            exploitable=fd.get("exploitable", False),
            risk_score=fd.get("risk_score", 0.0),
            aliases=fd.get("aliases", []),
            references=fd.get("references", []),
        ))
    finding_repo.flush()

    sbom_repo = SBOMRepository(db)
    sbom_content = sbom_svc.generate_sbom(scan, scan.findings)
    sbom = sbom_repo.save(SBOM(
        id=str(uuid4()),
        scan_id=scan.id,
        format=payload.format,
        spec_version="1.4",
        content=payload.content,
        components_count=len(packages),
        generated_at=now,
    ))

    scan.status = "completed"
    scan.completed_at = now
    scan_repo.commit()

    audit_repo = AuditLogRepository(db)
    audit_repo.add(AuditLog(
        id=str(uuid4()),
        action="sbom_ingested",
        resource_type="sbom",
        resource_id=sbom.id,
        details={"scan_id": scan.id, "components": len(packages), "findings": len(raw_findings)},
    ))
    audit_repo.commit()

    return sbom


@router.get("/{sbom_id}", response_model=SBOMRead)
def get_sbom(sbom_id: str, db: Session = Depends(get_db)):
    return SBOMRepository(db).get_or_404(sbom_id, detail="SBOM not found")
