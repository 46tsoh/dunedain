"""Webhook receiver and event log endpoints.

The /api/webhooks/jira/{integration_id} endpoint receives inbound Jira
webhook calls, persists them as WebhookEvent rows, and dispatches a
Celery task for async processing.
"""
from __future__ import annotations

import logging
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuditLog, WebhookEvent
from ..repositories.repos import (
    AuditLogRepository,
    IntegrationRepository,
    WebhookEventRepository,
)
from ..schemas import WebhookEventDetail, WebhookEventRead

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.post("/jira/{integration_id}", status_code=202)
async def receive_jira_webhook(
    integration_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Receive an inbound Jira webhook.
    
    Validates that the integration exists and is enabled, persists
    the raw payload as a WebhookEvent, and dispatches an async
    Celery task for processing.
    
    Returns 202 Accepted immediately — processing happens asynchronously.
    """
    int_repo = IntegrationRepository(db)
    integration = int_repo.get(integration_id)
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")
    if not integration.enabled:
        raise HTTPException(status_code=403, detail="Integration is disabled")
    if integration.provider != "jira":
        raise HTTPException(status_code=400, detail="Integration is not a Jira integration")

    # Read the raw body for HMAC verification
    body = await request.body()
    
    # Verify HMAC signature if webhook_secret is configured
    if integration.webhook_secret:
        from ..services.ticketing.webhook_processor import verify_hmac_signature
        signature = (
            request.headers.get("X-Atlassian-Webhook-Signature")
            or request.headers.get("X-Hub-Signature")
            or ""
        )
        if not verify_hmac_signature(body, integration.webhook_secret, signature):
            raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # Parse the JSON payload
    try:
        import json
        payload = json.loads(body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Extract basic event info for the DB record
    event_type = payload.get("webhookEvent", payload.get("issue_event_type_name", "unknown"))
    issue = payload.get("issue", {})
    external_issue_id = issue.get("id")
    external_issue_key = issue.get("key")

    # Persist the webhook event
    event_repo = WebhookEventRepository(db)
    event = WebhookEvent(
        id=str(uuid4()),
        integration_id=integration.id,
        event_type=event_type,
        external_issue_id=external_issue_id,
        external_issue_key=external_issue_key,
        payload=payload,
        status="received",
    )
    event_repo.save(event)

    # Dispatch async processing
    try:
        from ..tasks.automation import process_webhook_event
        process_webhook_event.delay(event.id)
    except Exception as exc:
        logger.warning("Failed to dispatch webhook task for event %s: %s", event.id, exc)

    return {"event_id": event.id, "status": "accepted"}


@router.post("/github/{integration_id}", status_code=202)
async def receive_github_webhook(
    integration_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Receive an inbound GitHub webhook.

    Validates that the integration exists and is enabled, persists
    the raw payload as a WebhookEvent, and dispatches an async
    Celery task for processing.

    Returns 202 Accepted immediately — processing happens asynchronously.
    """
    int_repo = IntegrationRepository(db)
    integration = int_repo.get(integration_id)
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")
    if not integration.enabled:
        raise HTTPException(status_code=403, detail="Integration is disabled")
    if integration.provider != "github_issues":
        raise HTTPException(status_code=400, detail="Integration is not a GitHub Issues integration")

    # Read the raw body for HMAC verification
    body = await request.body()

    # Verify HMAC signature if webhook_secret is configured
    if integration.webhook_secret:
        from ..services.ticketing.github_webhook_processor import verify_github_signature
        signature = request.headers.get("X-Hub-Signature-256", "")
        if not verify_github_signature(body, integration.webhook_secret, signature):
            raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # Parse the JSON payload
    try:
        import json
        payload = json.loads(body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Store the GitHub event type header in the payload for downstream processing
    github_event = request.headers.get("X-GitHub-Event", "unknown")
    payload["_github_event_type"] = github_event

    # Extract basic event info for the DB record
    action = payload.get("action", "")
    event_type = f"{github_event}:{action}" if action else github_event
    issue = payload.get("issue", {})
    repo_data = payload.get("repository", {})
    full_name = repo_data.get("full_name", "")
    number = issue.get("number")
    external_issue_id = str(number) if number is not None else None
    external_issue_key = f"{full_name}#{number}" if full_name and number else None

    # Persist the webhook event
    event_repo = WebhookEventRepository(db)
    event = WebhookEvent(
        id=str(uuid4()),
        integration_id=integration.id,
        event_type=event_type,
        external_issue_id=external_issue_id,
        external_issue_key=external_issue_key,
        payload=payload,
        status="received",
    )
    event_repo.save(event)

    # Dispatch async processing
    try:
        from ..tasks.automation import process_webhook_event
        process_webhook_event.delay(event.id)
    except Exception as exc:
        logger.warning("Failed to dispatch webhook task for event %s: %s", event.id, exc)

    return {"event_id": event.id, "status": "accepted"}


@router.get("/events", response_model=list[WebhookEventRead])
def list_webhook_events(
    integration_id: str | None = None,
    status: str | None = None,
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    """List webhook events, optionally filtered by integration and status."""
    event_repo = WebhookEventRepository(db)
    
    if integration_id:
        return event_repo.list_for_integration(
            integration_id,
            skip=skip,
            limit=limit,
            status=status,
        )
    
    filters = []
    if status:
        filters.append(WebhookEvent.status == status)
    return event_repo.list(
        skip=skip,
        limit=limit,
        order_by=WebhookEvent.received_at.desc(),
        filters=filters or None,
    )


@router.get("/events/{event_id}", response_model=WebhookEventDetail)
def get_webhook_event(event_id: str, db: Session = Depends(get_db)):
    """Get a webhook event with full payload."""
    event_repo = WebhookEventRepository(db)
    event = event_repo.get_or_404(event_id, detail="Webhook event not found")
    return event


@router.post("/events/{event_id}/retry", status_code=202)
def retry_webhook_event(event_id: str, db: Session = Depends(get_db)):
    """Retry processing a failed webhook event."""
    event_repo = WebhookEventRepository(db)
    event = event_repo.get_or_404(event_id, detail="Webhook event not found")

    if event.status not in ("failed", "ignored"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot retry event with status '{event.status}'",
        )

    event.status = "received"
    event.error_message = None
    event.processed_at = None
    event_repo.commit()

    try:
        from ..tasks.automation import process_webhook_event
        process_webhook_event.delay(event.id)
    except Exception as exc:
        logger.warning("Failed to dispatch retry for event %s: %s", event.id, exc)

    return {"event_id": event.id, "status": "retry_queued"}
