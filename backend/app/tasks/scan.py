from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)

from ..celery_app import celery_app
from ..database import SessionLocal
from ..models import AuditLog, Finding, PolicyResult, Scan, SBOM
from ..repositories import (
    AuditLogRepository,
    FindingRepository,
    PolicyRepository,
    PolicyResultRepository,
    RegistryRepository,
    SBOMRepository,
    ScanRepository,
)
from ..services import scanner as scanner_svc
from ..services import sbom as sbom_svc
from ..services.scanner import WindowsImageUnsupportedError
from ..services.policy import evaluate_policy
from ..services.risk import prioritize_findings


@celery_app.task(
    name="app.tasks.scan.run_scan",
    bind=True,
    max_retries=0,
    queue="scans",
)
def run_scan(self, scan_id: str, packages: list[dict] | None = None) -> None:
    """Execute the full scan pipeline for a given scan_id.

    Runs inside a Celery worker. Opens its own DB session and closes it on
    completion or error. The scan row must already exist in the DB with
    status='pending' before this task is dispatched.

    Args:
        scan_id: Primary key of the Scan row to execute.
        packages: Optional explicit package list (dependency scans).
    """
    db = SessionLocal()
    try:
        scan_repo = ScanRepository(db)
        finding_repo = FindingRepository(db)
        policy_repo = PolicyRepository(db)
        policy_result_repo = PolicyResultRepository(db)
        sbom_repo = SBOMRepository(db)
        audit_repo = AuditLogRepository(db)

        scan = scan_repo.get(scan_id)
        if not scan:
            return

        scan.status = "running"
        scan_repo.commit()

        comp_backend = scanner_svc._get_comparison_backend()
        if scan.scan_type == "container" and scan.scanner_override != comp_backend and comp_backend != "none":
            try:
                _maybe_dispatch_comparison(scan_id)
            except Exception:
                pass

        engine: str = "unknown"
        base_image: str | None = None
        base_image_chain: list[str] = []

        # Resolve registry credentials when this scan is linked to a registry.
        reg_username: str | None = None
        reg_password: str | None = None
        if scan.registry_id:
            reg = RegistryRepository(db).get(scan.registry_id)
            if reg and reg.auth_method == "username_password":
                reg_username = reg.username
                reg_password = reg.password

        try:
            if scan.scan_type == "container":
                raw_findings, engine, base_image, base_image_chain = scanner_svc.scan_container(
                    scan.target,
                    username=reg_username,
                    password=reg_password,
                    scanner_override=scan.scanner_override,
                )
            elif scan.scan_type == "source":
                raw_findings, engine = scanner_svc.scan_source(scan.target)
            else:
                raw_findings = []
        except WindowsImageUnsupportedError as exc:
            scan.status = "unsupported"
            scan.error_message = str(exc)
            scan.completed_at = datetime.now(timezone.utc)
            scan_repo.commit()
            return
        except Exception as exc:
            import traceback
            logger.error("Scan %s failed: %s\n%s", scan.id, exc, traceback.format_exc())
            scan.status = "failed"
            scan.error_message = str(exc)[:1000]
            scan.completed_at = datetime.now(timezone.utc)
            scan_repo.commit()
            return

        # ── Deduplicate findings ──────────────────────────────────────────
        # Scanners can emit the same (vuln_id, package_name, package_version)
        # tuple more than once (e.g. grype via relatedVulnerabilities or
        # repeated match entries). Keep the entry with the highest CVSS score;
        # on a tie prefer the one with a fix version or more references.
        dedup: dict[tuple[str, str, str], dict] = {}
        for fd in raw_findings:
            key = (
                fd["vulnerability_id"],
                fd["package_name"],
                fd["package_version"],
            )
            existing = dedup.get(key)
            if existing is None:
                dedup[key] = fd
            else:
                # Prefer higher CVSS score
                new_score = fd.get("cvss_score") or 0.0
                old_score = existing.get("cvss_score") or 0.0
                if new_score > old_score:
                    dedup[key] = fd
                elif new_score == old_score:
                    # Prefer entry with a fix version
                    if fd.get("fix_version") and not existing.get("fix_version"):
                        dedup[key] = fd
                    # Otherwise prefer more references
                    elif len(fd.get("references") or []) > len(existing.get("references") or []):
                        dedup[key] = fd

        # ── Persist findings ──────────────────────────────────────────────
        db_findings: list[Finding] = []
        for fd in dedup.values():
            finding = Finding(
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
            )
            finding_repo.add(finding)
            db_findings.append(finding)

        finding_repo.flush()
        db_findings = prioritize_findings(db_findings)

        # ── Policy evaluation ─────────────────────────────────────────────
        policies = policy_repo.list_enabled()
        for policy in policies:
            result = evaluate_policy(policy, db_findings)
            policy_result_repo.add(PolicyResult(
                id=result.id,
                scan_id=scan.id,
                policy_id=policy.id,
                passed=result.passed,
                violations=result.violations,
                evaluated_at=result.evaluated_at,
            ))

        # ── SBOM ──────────────────────────────────────────────────────────
        sbom_content = sbom_svc.generate_sbom(scan, db_findings)
        sbom_repo.add(SBOM(
            id=str(uuid4()),
            scan_id=scan.id,
            format="cyclonedx",
            spec_version="1.4",
            content=sbom_content,
            components_count=len(sbom_content.get("components", [])),
        ))

        # ── Finalise ──────────────────────────────────────────────────────
        scan.status = "completed"
        scan.scanner_engine = engine
        scan.completed_at = datetime.now(timezone.utc)
        if base_image is not None:
            scan.base_image = base_image
        if base_image_chain:
            scan.base_image_chain = base_image_chain
        scan_repo.commit()

        audit_repo.add(AuditLog(
            id=str(uuid4()),
            action="scan_completed",
            resource_type="scan",
            resource_id=scan.id,
            details={
                "findings_count": len(db_findings),
                "scanner_engine": engine,
                "base_image": base_image,
            },
        ))
        audit_repo.commit()

    except Exception:
        try:
            db.rollback()  # clear any dirty session state before re-fetching
            scan = ScanRepository(db).get(scan_id)
            if scan and scan.status not in ("completed", "failed", "unsupported"):
                scan.status = "failed"
                scan.completed_at = datetime.now(timezone.utc)
                scan_repo.commit()
        except Exception:
            pass
        raise
    finally:
        db.close()


def _maybe_dispatch_comparison(primary_scan_id: str) -> None:
    """Create and enqueue a comparison scan if the comparison_backend setting is active.

    Opens its own DB session so it is fully decoupled from the primary scan's
    session (which is already closed by the time this is called).  The
    comparison task is dispatched via run_scan.delay() and executes on
    whichever worker picks it up — never blocking the primary worker.

    Guards:
    - Does nothing when ``comparison_backend`` is ``"none"`` (default).
    - Does nothing when the primary scan is not a container scan.
    - Does nothing when the primary scan itself has ``scanner_override`` set
      (i.e. it is already a comparison scan — prevents infinite chaining).
    - Does nothing when ``comparison_backend`` resolves to the same engine
      label as the primary, to avoid duplicate identical scans.
    """
    comp_backend = scanner_svc._get_comparison_backend()
    if comp_backend == "none":
        return

    db = SessionLocal()
    try:
        primary_scan = ScanRepository(db).get(primary_scan_id)
        if not primary_scan:
            return
        if primary_scan.scan_type != "container":
            return
        if primary_scan.scanner_override == comp_backend:
            # Already running the same engine as the comparison — do not chain further.
            return

        # Map the comparison setting to the engine label it would produce so
        # we can skip if it's the same as what was just run.
        _BACKEND_TO_ENGINE = {
            "trivy": "trivy",
            "grype": "grype",
            "syft_grype": "syft+grype",
            "osv_scanner": "osv_scanner",
            "auto": None,  # auto can vary — always run it
        }
        comp_engine_label = _BACKEND_TO_ENGINE.get(comp_backend)
        if comp_engine_label and comp_engine_label == primary_scan.scanner_engine:
            # Would produce identical results — skip.
            return

        comp_scan = ScanRepository(db).save(Scan(
            id=str(uuid4()),
            name=primary_scan.name,
            scan_type="container",
            target=primary_scan.target,
            status="pending",
            packages=primary_scan.packages,
            registry_id=primary_scan.registry_id,
            scanner_override=comp_backend,
        ))

        run_scan.delay(comp_scan.id)
    finally:
        db.close()
