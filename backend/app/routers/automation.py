"""Automation rules CRUD and execution history endpoints."""
from __future__ import annotations

import logging
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuditLog, AutomationRule
from ..repositories.repos import (
    AuditLogRepository,
    AutomationRuleExecutionRepository,
    AutomationRuleRepository,
)
from ..schemas import (
    AutomationRuleCreate,
    AutomationRuleExecutionRead,
    AutomationRuleRead,
    AutomationRuleUpdate,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/automation", tags=["automation"])

# Valid trigger names for frontend display
VALID_TRIGGERS = [
    "jira_status_changed",
    "jira_priority_changed",
    "jira_comment_added",
    "jira_assignee_changed",
    "jira_issue_deleted",
    # Provider-agnostic triggers (used by GitHub Issues and future providers)
    "ticket_status_changed",
    "ticket_comment_added",
    "ticket_assignee_changed",
    "ticket_deleted",
    "ticket_label_changed",
    "scan_completed",
    "finding_fixed",
    "finding_regressed",
    "policy_violated",
]


@router.get("/triggers")
def list_triggers():
    """Return the list of valid automation trigger names."""
    return {"triggers": VALID_TRIGGERS}


@router.get("/rules", response_model=list[AutomationRuleRead])
def list_rules(
    trigger: str | None = None,
    enabled: bool | None = None,
    integration_id: str | None = None,
    db: Session = Depends(get_db),
):
    """List automation rules with optional filters."""
    rule_repo = AutomationRuleRepository(db)
    
    if trigger and enabled is True:
        return rule_repo.list_enabled(trigger=trigger)
    if trigger:
        rules = rule_repo.list_all()
        return [r for r in rules if r.trigger == trigger]
    if enabled is not None:
        if enabled:
            return rule_repo.list_enabled()
        else:
            rules = rule_repo.list_all()
            return [r for r in rules if not r.enabled]
    if integration_id:
        return rule_repo.for_integration(integration_id)
    return rule_repo.list_all()


@router.post("/rules", response_model=AutomationRuleRead, status_code=201)
def create_rule(payload: AutomationRuleCreate, db: Session = Depends(get_db)):
    """Create a new automation rule."""
    if payload.trigger not in VALID_TRIGGERS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid trigger '{payload.trigger}'. Valid triggers: {VALID_TRIGGERS}",
        )

    rule = AutomationRule(
        name=payload.name,
        description=payload.description,
        enabled=payload.enabled,
        trigger=payload.trigger,
        conditions=payload.conditions,
        actions=payload.actions,
        integration_id=payload.integration_id,
        team_id=payload.team_id,
    )
    rule_repo = AutomationRuleRepository(db)
    rule_repo.save(rule)

    AuditLogRepository(db).save(AuditLog(
        id=str(uuid4()),
        action="automation_rule_created",
        resource_type="automation_rule",
        resource_id=rule.id,
        details={"name": rule.name, "trigger": rule.trigger},
    ))
    return rule


@router.get("/rules/{rule_id}", response_model=AutomationRuleRead)
def get_rule(rule_id: str, db: Session = Depends(get_db)):
    """Get an automation rule by ID."""
    rule_repo = AutomationRuleRepository(db)
    return rule_repo.get_or_404(rule_id, detail="Automation rule not found")


@router.put("/rules/{rule_id}", response_model=AutomationRuleRead)
def update_rule(rule_id: str, payload: AutomationRuleUpdate, db: Session = Depends(get_db)):
    """Update an automation rule."""
    rule_repo = AutomationRuleRepository(db)
    rule = rule_repo.get_or_404(rule_id, detail="Automation rule not found")

    if payload.trigger is not None and payload.trigger not in VALID_TRIGGERS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid trigger '{payload.trigger}'. Valid triggers: {VALID_TRIGGERS}",
        )

    if payload.name is not None:
        rule.name = payload.name
    if payload.description is not None:
        rule.description = payload.description
    if payload.enabled is not None:
        rule.enabled = payload.enabled
    if payload.trigger is not None:
        rule.trigger = payload.trigger
    if payload.conditions is not None:
        rule.conditions = payload.conditions
    if payload.actions is not None:
        rule.actions = payload.actions
    if payload.integration_id is not None:
        rule.integration_id = payload.integration_id if payload.integration_id else None
    if payload.team_id is not None:
        rule.team_id = payload.team_id if payload.team_id else None

    rule_repo.commit()
    rule_repo.refresh(rule)
    return rule


@router.delete("/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: str, db: Session = Depends(get_db)):
    """Delete an automation rule and all its execution history."""
    rule_repo = AutomationRuleRepository(db)
    rule = rule_repo.get_or_404(rule_id, detail="Automation rule not found")
    rule_repo.delete(rule)


@router.get(
    "/rules/{rule_id}/executions",
    response_model=list[AutomationRuleExecutionRead],
)
def list_rule_executions(
    rule_id: str,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    """List execution history for an automation rule."""
    AutomationRuleRepository(db).get_or_404(rule_id, detail="Automation rule not found")
    exec_repo = AutomationRuleExecutionRepository(db)
    return exec_repo.for_rule(rule_id, limit=limit)


@router.get("/executions/recent", response_model=list[AutomationRuleExecutionRead])
def list_recent_executions(limit: int = 50, db: Session = Depends(get_db)):
    """List most recent automation rule executions across all rules."""
    exec_repo = AutomationRuleExecutionRepository(db)
    return exec_repo.recent(limit=limit)


@router.post("/rules/{rule_id}/toggle", response_model=AutomationRuleRead)
def toggle_rule(rule_id: str, db: Session = Depends(get_db)):
    """Toggle an automation rule's enabled state."""
    rule_repo = AutomationRuleRepository(db)
    rule = rule_repo.get_or_404(rule_id, detail="Automation rule not found")
    rule.enabled = not rule.enabled
    rule_repo.commit()
    rule_repo.refresh(rule)
    return rule
