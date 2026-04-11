"""Celery tasks for webhook event processing and automation rule firing.

Two main tasks:
- process_webhook_event: Processes a single inbound webhook event
- fire_internal_event: Fires automation rules for internal platform events
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import uuid4

from ..celery_app import celery_app
from ..database import SessionLocal
from ..models import AuditLog, WebhookEvent
from ..repositories.repos import (
    AuditLogRepository,
    WebhookEventRepository,
)

logger = logging.getLogger(__name__)


@celery_app.task(
    name="app.tasks.automation.process_webhook_event",
    bind=True,
    max_retries=3,
    default_retry_delay=10,
    queue="scans",
)
def process_webhook_event(self, event_id: str) -> None:
    """Process a single webhook event.
    
    Steps:
    1. Load the WebhookEvent from DB
    2. Set status to "processing"
    3. Run the webhook processor (parse payload, update tickets)
    4. Classify which automation triggers apply
    5. Fire automation rules for each trigger
    6. Set status to "processed" (or "failed"/"ignored")
    7. Write audit log
    """
    db = SessionLocal()
    try:
        event_repo = WebhookEventRepository(db)
        audit_repo = AuditLogRepository(db)

        event = event_repo.get(event_id)
        if not event:
            logger.warning("WebhookEvent %s not found", event_id)
            return

        if event.status not in ("received", "failed"):
            logger.info("WebhookEvent %s already %s, skipping", event_id, event.status)
            return

        event.status = "processing"
        event_repo.commit()

        try:
            # Step 1: Process the webhook (update local ticket state)
            from ..repositories.repos import IntegrationRepository as _IntRepo
            _integration = _IntRepo(db).get(event.integration_id)

            if _integration and _integration.provider == "github_issues":
                from ..services.ticketing.github_webhook_processor import (
                    classify_github_triggers as _classify,
                    parse_github_event as _parse,
                    process_github_webhook_event as _process,
                )
                process_result = _process(db, event)
            else:
                from ..services.ticketing.webhook_processor import (
                    classify_event_triggers as _classify,
                    parse_jira_event as _parse,
                    process_webhook_event as _process,
                )
                process_result = _process(db, event)

            if process_result.error:
                event.status = "failed"
                event.error_message = process_result.error[:1000]
                event.processed_at = datetime.now(timezone.utc)
                event_repo.commit()
                return

            # Step 2: Classify triggers from the parsed event
            if _integration and _integration.provider == "github_issues":
                event_type = event.payload.get("_github_event_type", "unknown")
                parsed = _parse(event.payload, event_type)
            else:
                parsed = _parse(event.payload)
            triggers = _classify(parsed)

            if not triggers and not process_result.matched_ticket:
                event.status = "ignored"
                event.processed_at = datetime.now(timezone.utc)
                event_repo.commit()
                return

            # Step 3: Fire automation rules for each trigger
            from ..services.automation.engine import evaluate_automation_rules

            # Build context for automation rules
            context = {
                "integration_id": event.integration_id,
                "event_type": process_result.event_type,
                "external_issue_key": process_result.external_issue_key,
            }

            # Add ticket context if we matched a ticket
            if process_result.matched_ticket:
                from ..repositories.repos import TicketRepository
                ticket_repo = TicketRepository(db)
                t = None
                external_id = parsed.get("issue_id") or parsed.get("issue_number") or ""
                if external_id:
                    t = ticket_repo.find_by_external_id(event.integration_id, str(external_id))
                if t is None and process_result.external_issue_key:
                    t = ticket_repo.find_by_external_key(event.integration_id, process_result.external_issue_key)
                if t is not None:
                    context["ticket_id"] = t.id
                    context["finding_id"] = t.finding_id
                    context["jira_status"] = t.external_status
                    context["ticket_status"] = t.external_status

            # Add change details to context
            context.update(process_result.changes)

            # Add finding details to context if available
            if context.get("finding_id"):
                from ..repositories.repos import FindingRepository
                finding = FindingRepository(db).get(context["finding_id"])
                if finding:
                    context["severity"] = finding.severity
                    context["cvss_score"] = finding.cvss_score
                    context["package_name"] = finding.package_name
                    context["has_fix"] = finding.is_fixed
                    context["fix_version"] = finding.fix_version
                    context["scan_id"] = finding.scan_id
                    # Get scan context
                    from ..repositories.repos import ScanRepository
                    scan = ScanRepository(db).get(finding.scan_id)
                    if scan:
                        context["scan_type"] = scan.scan_type
                        if scan.team_id:
                            context["team_id"] = scan.team_id

            all_evaluations = []
            for trigger in triggers:
                evals = evaluate_automation_rules(db, trigger, context)
                all_evaluations.extend(evals)

            db.commit()

            # Mark event as processed
            event.status = "processed"
            event.processed_at = datetime.now(timezone.utc)
            event_repo.commit()

            # Audit log
            rules_fired = sum(1 for e in all_evaluations if e.conditions_matched)
            audit_repo.save(AuditLog(
                id=str(uuid4()),
                action="webhook_processed",
                resource_type="webhook_event",
                resource_id=event.id,
                details={
                    "event_type": process_result.event_type,
                    "triggers": triggers,
                    "rules_evaluated": len(all_evaluations),
                    "rules_fired": rules_fired,
                    "matched_ticket": process_result.matched_ticket,
                    "changes": process_result.changes,
                },
            ))

        except Exception as exc:
            db.rollback()
            event = event_repo.get(event_id)
            if event:
                event.status = "failed"
                event.error_message = str(exc)[:1000]
                event.processed_at = datetime.now(timezone.utc)
                event_repo.commit()

            logger.exception("Failed to process webhook event %s", event_id)
            raise self.retry(exc=exc)

    finally:
        db.close()


@celery_app.task(
    name="app.tasks.automation.fire_internal_event",
    bind=True,
    max_retries=2,
    default_retry_delay=5,
    queue="scans",
)
def fire_internal_event(self, trigger: str, context: dict) -> None:
    """Fire automation rules for an internal platform event.
    
    Called by the scan pipeline, policy evaluator, etc. when an internal
    event occurs that should trigger automation rules.
    
    Supported triggers:
    - scan_completed: A scan finished successfully
    - finding_fixed: A previously-open finding is now fixed
    - finding_regressed: A previously-fixed finding has reappeared
    - policy_violated: A policy evaluation found violations
    """
    db = SessionLocal()
    try:
        from ..services.automation.engine import evaluate_automation_rules

        evaluations = evaluate_automation_rules(db, trigger, context)
        db.commit()

        rules_fired = sum(1 for e in evaluations if e.conditions_matched)
        if rules_fired > 0:
            logger.info(
                "Internal event '%s': evaluated %d rules, %d fired",
                trigger, len(evaluations), rules_fired,
            )

    except Exception as exc:
        db.rollback()
        logger.exception("Failed to fire internal event '%s'", trigger)
        raise self.retry(exc=exc)
    finally:
        db.close()
