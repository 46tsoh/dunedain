from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuditLog, Finding, Policy, PolicyResult
from ..repositories import AuditLogRepository, FindingRepository, PolicyRepository, PolicyResultRepository, ScanRepository
from ..schemas import PolicyCreate, PolicyRead, PolicyResultRead, PolicyUpdate, _compute_policy_status
from ..services.policy import evaluate_policy

router = APIRouter(prefix="/policies", tags=["policies"])


@router.get("", response_model=list[PolicyRead])
def list_policies(db: Session = Depends(get_db)):
    return PolicyRepository(db).list_all()


@router.post("", response_model=PolicyRead)
def create_policy(payload: PolicyCreate, db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    policy_repo = PolicyRepository(db)
    audit_repo = AuditLogRepository(db)

    policy = policy_repo.save(Policy(
        id=str(uuid4()),
        name=payload.name,
        description=payload.description,
        enabled=payload.enabled,
        rules=payload.rules,
        action=payload.action,
        created_at=now,
        updated_at=now,
    ))

    audit_repo.add(AuditLog(
        id=str(uuid4()),
        action="policy_created",
        resource_type="policy",
        resource_id=policy.id,
        details={"name": policy.name},
    ))
    audit_repo.commit()
    return policy


@router.get("/{policy_id}", response_model=PolicyRead)
def get_policy(policy_id: str, db: Session = Depends(get_db)):
    return PolicyRepository(db).get_or_404(policy_id, detail="Policy not found")


@router.put("/{policy_id}", response_model=PolicyRead)
def update_policy(policy_id: str, payload: PolicyUpdate, db: Session = Depends(get_db)):
    repo = PolicyRepository(db)
    policy = repo.get_or_404(policy_id, detail="Policy not found")

    policy.name = payload.name
    policy.description = payload.description
    policy.enabled = payload.enabled
    policy.rules = payload.rules
    policy.action = payload.action
    policy.updated_at = datetime.now(timezone.utc)

    repo.commit()
    repo.refresh(policy)
    return policy


@router.delete("/{policy_id}", status_code=204)
def delete_policy(policy_id: str, db: Session = Depends(get_db)):
    repo = PolicyRepository(db)
    policy = repo.get_or_404(policy_id, detail="Policy not found")
    repo.delete(policy)


@router.post("/{policy_id}/evaluate/{scan_id}", response_model=PolicyResultRead)
def evaluate_policy_against_scan(
    policy_id: str,
    scan_id: str,
    db: Session = Depends(get_db),
):
    policy = PolicyRepository(db).get_or_404(policy_id, detail="Policy not found")

    scan = ScanRepository(db).get_or_404(scan_id, detail="Scan not found")

    findings = FindingRepository(db).for_scan(scan_id)
    result = evaluate_policy(policy, findings)
    result.scan_id = scan_id

    pr_repo = PolicyResultRepository(db)
    pr = pr_repo.save(PolicyResult(
        id=result.id,
        scan_id=scan_id,
        policy_id=policy_id,
        passed=result.passed,
        violations=result.violations,
        evaluated_at=result.evaluated_at,
    ))

    status = _compute_policy_status(result.passed, policy.action)
    return PolicyResultRead(
        id=pr.id,
        scan_id=pr.scan_id,
        policy_id=pr.policy_id,
        policy_name=policy.name,
        passed=pr.passed,
        status=status,
        violations=pr.violations or [],
        evaluated_at=pr.evaluated_at,
    )
