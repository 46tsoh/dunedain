from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuditLog, Finding as FindingModel, Integration, IntegrationFieldMapping, Scan as ScanModel, Ticket, TicketComment, WebhookRegistration
from ..repositories.repos import (
    AuditLogRepository,
    FindingRepository,
    IntegrationFieldMappingRepository,
    IntegrationRepository,
    ScanRepository,
    TicketCommentRepository,
    TicketRepository,
    WebhookRegistrationRepository,
)
from ..schemas import (
    BulkCreateTicketsRequest,
    BulkCreateTicketsResponse,
    CreateTicketRequest,
    IntegrationCreate,
    IntegrationRead,
    IntegrationUpdate,
    TicketCommentCreate,
    TicketCommentRead,
    TestIntegrationResponse,
    TicketRead,
    WebhookRegistrationCreate,
    WebhookRegistrationRead,
)
from ..services.ticketing import get_provider
from ..services.ticketing.field_mapper import build_ticket_fields

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/integrations", tags=["integrations"])


def _to_read(integration: Integration) -> IntegrationRead:
    data = IntegrationRead.model_validate(integration)
    data.has_secret = bool(integration.auth_secret)
    data.has_webhook_secret = bool(integration.webhook_secret)
    return data


@router.get("", response_model=list[IntegrationRead])
def list_integrations(db: Session = Depends(get_db)):
    repo = IntegrationRepository(db)
    return [_to_read(i) for i in repo.list_all()]


@router.post("", response_model=IntegrationRead, status_code=201)
def create_integration(payload: IntegrationCreate, db: Session = Depends(get_db)):
    integration = Integration(
        name=payload.name,
        provider=payload.provider,
        enabled=payload.enabled,
        base_url=payload.base_url,
        auth_method=payload.auth_method,
        auth_username=payload.auth_username,
        auth_secret=payload.auth_secret,
        webhook_secret=payload.webhook_secret,
        provider_config=payload.provider_config,
    )
    for m in payload.field_mappings:
        integration.field_mappings.append(IntegrationFieldMapping(
            source=m.source,
            target_field=m.target_field,
            transform=m.transform,
            template_value=m.template_value,
            priority=m.priority,
        ))
    repo = IntegrationRepository(db)
    repo.save(integration)

    AuditLogRepository(db).save(AuditLog(
        action="integration_created",
        resource_type="integration",
        resource_id=integration.id,
        details={"name": integration.name, "provider": integration.provider},
    ))
    return _to_read(integration)


@router.get("/{integration_id}", response_model=IntegrationRead)
def get_integration(integration_id: str, db: Session = Depends(get_db)):
    repo = IntegrationRepository(db)
    integration = repo.get_or_404(integration_id, detail="Integration not found")
    return _to_read(integration)


@router.put("/{integration_id}", response_model=IntegrationRead)
def update_integration(integration_id: str, payload: IntegrationUpdate, db: Session = Depends(get_db)):
    repo = IntegrationRepository(db)
    integration = repo.get_or_404(integration_id, detail="Integration not found")

    if payload.name is not None:
        integration.name = payload.name
    if payload.enabled is not None:
        integration.enabled = payload.enabled
    if payload.base_url is not None:
        integration.base_url = payload.base_url
    if payload.auth_method is not None:
        integration.auth_method = payload.auth_method
    if payload.auth_username is not None:
        integration.auth_username = payload.auth_username
    if payload.auth_secret is not None:
        integration.auth_secret = payload.auth_secret if payload.auth_secret else None
    if payload.webhook_secret is not None:
        integration.webhook_secret = payload.webhook_secret if payload.webhook_secret else None
    if payload.provider_config is not None:
        integration.provider_config = payload.provider_config

    if payload.field_mappings is not None:
        mapping_repo = IntegrationFieldMappingRepository(db)
        new_mappings = [
            IntegrationFieldMapping(
                integration_id=integration.id,
                source=m.source,
                target_field=m.target_field,
                transform=m.transform,
                template_value=m.template_value,
                priority=m.priority,
            )
            for m in payload.field_mappings
        ]
        mapping_repo.replace_for_integration(integration.id, new_mappings)

    repo.commit()
    repo.refresh(integration)
    return _to_read(integration)


@router.delete("/{integration_id}", status_code=204)
def delete_integration(integration_id: str, db: Session = Depends(get_db)):
    repo = IntegrationRepository(db)
    integration = repo.get_or_404(integration_id, detail="Integration not found")
    repo.delete(integration)


@router.post("/{integration_id}/test", response_model=TestIntegrationResponse)
def test_integration(integration_id: str, db: Session = Depends(get_db)):
    repo = IntegrationRepository(db)
    integration = repo.get_or_404(integration_id, detail="Integration not found")
    provider = get_provider(
        provider=integration.provider,
        base_url=integration.base_url,
        auth_method=integration.auth_method,
        username=integration.auth_username,
        secret=integration.auth_secret,
        provider_config=integration.provider_config or {},
    )
    result = provider.test_connection()
    return TestIntegrationResponse(
        success=result.success,
        message=result.message,
        projects=result.projects,
    )


@router.get("/{integration_id}/tickets", response_model=list[TicketRead])
def list_integration_tickets(integration_id: str, db: Session = Depends(get_db)):
    IntegrationRepository(db).get_or_404(integration_id, detail="Integration not found")
    return TicketRepository(db).for_integration(integration_id)


@router.post("/tickets", response_model=TicketRead, status_code=201)
def create_ticket(payload: CreateTicketRequest, db: Session = Depends(get_db)):
    int_repo = IntegrationRepository(db)
    integration = int_repo.get_or_404(payload.integration_id, detail="Integration not found")

    finding_repo = FindingRepository(db)
    finding = finding_repo.get_or_404(payload.finding_id, detail="Finding not found")

    ticket_repo = TicketRepository(db)
    if ticket_repo.exists_for_integration_and_finding(integration.id, finding.id):
        raise HTTPException(status_code=409, detail="Ticket already exists for this finding and integration")

    scan_repo = ScanRepository(db)
    scan = scan_repo.get_or_404(finding.scan_id, detail="Scan not found")

    mapping_repo = IntegrationFieldMappingRepository(db)
    mappings = mapping_repo.for_integration(integration.id)

    fields = build_ticket_fields(integration, mappings, finding, scan, payload.field_overrides or None)

    provider = get_provider(
        provider=integration.provider,
        base_url=integration.base_url,
        auth_method=integration.auth_method,
        username=integration.auth_username,
        secret=integration.auth_secret,
        provider_config=integration.provider_config or {},
    )

    try:
        result = provider.create_ticket(fields)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to create ticket: {exc}")

    ticket = Ticket(
        integration_id=integration.id,
        finding_id=finding.id,
        external_id=result.external_id,
        external_key=result.external_key,
        external_url=result.external_url,
        summary=result.summary,
    )
    ticket_repo.save(ticket)

    AuditLogRepository(db).save(AuditLog(
        action="ticket_created",
        resource_type="ticket",
        resource_id=ticket.id,
        details={
            "integration": integration.name,
            "external_key": result.external_key,
            "finding_id": finding.id,
        },
    ))
    return ticket


@router.post("/tickets/bulk", response_model=BulkCreateTicketsResponse)
def bulk_create_tickets(payload: BulkCreateTicketsRequest, db: Session = Depends(get_db)):
    int_repo = IntegrationRepository(db)
    integration = int_repo.get_or_404(payload.integration_id, detail="Integration not found")

    ticket_repo = TicketRepository(db)
    finding_repo = FindingRepository(db)
    mapping_repo = IntegrationFieldMappingRepository(db)
    audit_repo = AuditLogRepository(db)

    mappings = mapping_repo.for_integration(integration.id)

    existing = ticket_repo.bulk_check_existing(integration.id, payload.finding_ids)
    skipped = [fid for fid in payload.finding_ids if fid in existing] if payload.skip_existing else []
    to_create = [fid for fid in payload.finding_ids if fid not in existing] if payload.skip_existing else payload.finding_ids

    if not to_create:
        return BulkCreateTicketsResponse(created=[], skipped=skipped, errors=[])

    # Batch-load all findings and scans upfront to avoid N+1 queries
    findings_by_id: dict[str, FindingModel] = {
        f.id: f
        for f in finding_repo.list(
            filters=[FindingModel.id.in_(to_create)],
            limit=len(to_create),
        )
    }
    scan_ids = {f.scan_id for f in findings_by_id.values()}
    scans_by_id: dict[str, ScanModel] = {
        s.id: s
        for s in db.query(ScanModel).filter(ScanModel.id.in_(scan_ids)).all()
    } if scan_ids else {}

    provider = get_provider(
        provider=integration.provider,
        base_url=integration.base_url,
        auth_method=integration.auth_method,
        username=integration.auth_username,
        secret=integration.auth_secret,
        provider_config=integration.provider_config or {},
    )

    created: list[Ticket] = []
    errors: list[dict[str, str]] = []

    for finding_id in to_create:
        finding = findings_by_id.get(finding_id)
        if not finding:
            errors.append({"finding_id": finding_id, "error": "Finding not found"})
            continue
        scan = scans_by_id.get(finding.scan_id)
        if not scan:
            errors.append({"finding_id": finding_id, "error": "Scan not found"})
            continue

        fields = build_ticket_fields(integration, mappings, finding, scan, payload.field_overrides or None)
        try:
            result = provider.create_ticket(fields)
        except Exception as exc:
            errors.append({"finding_id": finding_id, "error": str(exc)})
            continue

        ticket = Ticket(
            integration_id=integration.id,
            finding_id=finding.id,
            external_id=result.external_id,
            external_key=result.external_key,
            external_url=result.external_url,
            summary=result.summary,
        )
        ticket_repo.add(ticket)
        created.append(ticket)

        audit_repo.add(AuditLog(
            action="ticket_created",
            resource_type="ticket",
            resource_id=ticket.id,
            details={
                "integration": integration.name,
                "external_key": result.external_key,
                "finding_id": finding.id,
            },
        ))

    # Single commit for all tickets and audit logs
    if created:
        db.commit()
        for t in created:
            db.refresh(t)

    return BulkCreateTicketsResponse(
        created=[TicketRead.model_validate(t) for t in created],
        skipped=skipped,
        errors=errors,
    )


@router.get("/findings/{finding_id}/tickets", response_model=list[TicketRead])
def list_finding_tickets(finding_id: str, db: Session = Depends(get_db)):
    FindingRepository(db).get_or_404(finding_id, detail="Finding not found")
    return TicketRepository(db).for_finding(finding_id)


@router.post("/{integration_id}/sync-status")
def sync_ticket_statuses(integration_id: str, db: Session = Depends(get_db)):
    int_repo = IntegrationRepository(db)
    integration = int_repo.get_or_404(integration_id, detail="Integration not found")

    provider = get_provider(
        provider=integration.provider,
        base_url=integration.base_url,
        auth_method=integration.auth_method,
        username=integration.auth_username,
        secret=integration.auth_secret,
        provider_config=integration.provider_config or {},
    )

    ticket_repo = TicketRepository(db)
    tickets = ticket_repo.for_integration(integration_id)
    synced = 0
    for ticket in tickets:
        status = provider.get_ticket_status(ticket.external_id)
        if status is not None:
            ticket.external_status = status
            ticket.synced_at = datetime.now(timezone.utc)
            synced += 1
    db.commit()
    return {"synced": synced}


# ---------------------------------------------------------------------------
# Webhook Registration
# ---------------------------------------------------------------------------

@router.post("/{integration_id}/webhooks", response_model=WebhookRegistrationRead, status_code=201)
def register_webhook(
    integration_id: str,
    payload: WebhookRegistrationCreate,
    db: Session = Depends(get_db),
):
    """Register a webhook for an integration.

    For Jira integrations, uses register_with_jira / jira_events.
    For other providers, uses register_with_provider / events.
    The registration is persisted locally regardless of whether
    auto-registration succeeds.
    """
    int_repo = IntegrationRepository(db)
    integration = int_repo.get_or_404(integration_id, detail="Integration not found")

    wh_repo = WebhookRegistrationRepository(db)
    existing = wh_repo.for_integration(integration_id)
    if existing:
        raise HTTPException(status_code=409, detail="Webhook already registered for this integration")

    external_webhook_id = None

    # Determine whether to auto-register and which events to use
    should_register = False

    if integration.provider == "jira":
        should_register = payload.register_with_jira
        webhook_events = payload.jira_events
    elif integration.provider == "github_issues":
        should_register = payload.register_with_provider
        webhook_events = payload.events if payload.events else ["issues", "issue_comment"]
    else:
        should_register = payload.register_with_provider
        webhook_events = payload.events if payload.events else []

    if should_register:
        provider = get_provider(
            provider=integration.provider,
            base_url=integration.base_url,
            auth_method=integration.auth_method,
            username=integration.auth_username,
            secret=integration.auth_secret,
            provider_config=integration.provider_config or {},
        )
        try:
            result = provider.register_webhook(
                payload.callback_url,
                webhook_events,
                secret=integration.webhook_secret,
            )
            if result.get("success"):
                external_webhook_id = result.get("external_webhook_id")
            else:
                logger.warning(
                    "Webhook auto-registration failed for integration %s (%s): %s",
                    integration_id, integration.provider, result.get("message"),
                )
        except Exception:
            logger.warning(
                "Webhook auto-registration not supported for provider %s",
                integration.provider,
            )

    registration = WebhookRegistration(
        integration_id=integration.id,
        external_webhook_id=external_webhook_id,
        callback_url=payload.callback_url,
        jira_events=webhook_events,
        secret=integration.webhook_secret,
        is_cloud=True,
    )
    wh_repo.save(registration)

    AuditLogRepository(db).save(AuditLog(
        action="webhook_registered",
        resource_type="integration",
        resource_id=integration.id,
        details={
            "callback_url": payload.callback_url,
            "auto_registered": external_webhook_id is not None,
            "provider": integration.provider,
        },
    ))
    return registration


@router.get("/{integration_id}/webhooks", response_model=Optional[WebhookRegistrationRead])
def get_webhook_registration(integration_id: str, db: Session = Depends(get_db)):
    """Get the webhook registration for an integration (if any)."""
    IntegrationRepository(db).get_or_404(integration_id, detail="Integration not found")
    return WebhookRegistrationRepository(db).for_integration(integration_id)


@router.delete("/{integration_id}/webhooks", status_code=204)
def deregister_webhook(integration_id: str, db: Session = Depends(get_db)):
    """Delete a webhook registration. Optionally deregisters from the provider."""
    int_repo = IntegrationRepository(db)
    integration = int_repo.get_or_404(integration_id, detail="Integration not found")

    wh_repo = WebhookRegistrationRepository(db)
    registration = wh_repo.for_integration(integration_id)
    if not registration:
        raise HTTPException(status_code=404, detail="No webhook registration found")

    # Try to deregister from the external provider
    if registration.external_webhook_id:
        try:
            provider = get_provider(
                provider=integration.provider,
                base_url=integration.base_url,
                auth_method=integration.auth_method,
                username=integration.auth_username,
                secret=integration.auth_secret,
                provider_config=integration.provider_config or {},
            )
            provider.deregister_webhook(registration.external_webhook_id)
        except Exception:
            logger.warning(
                "Failed to deregister webhook from %s for integration %s",
                integration.provider, integration_id,
            )

    wh_repo.delete(registration)


# ---------------------------------------------------------------------------
# Ticket Comments
# ---------------------------------------------------------------------------

@router.get("/tickets/{ticket_id}/comments", response_model=list[TicketCommentRead])
def list_ticket_comments(ticket_id: str, db: Session = Depends(get_db)):
    """List comments for a ticket."""
    TicketRepository(db).get_or_404(ticket_id, detail="Ticket not found")
    return TicketCommentRepository(db).for_ticket(ticket_id)


@router.post("/tickets/{ticket_id}/comments", response_model=TicketCommentRead, status_code=201)
def add_ticket_comment(
    ticket_id: str,
    payload: TicketCommentCreate,
    db: Session = Depends(get_db),
):
    """Add an outbound comment to a ticket (syncs to external provider)."""
    ticket_repo = TicketRepository(db)
    ticket = ticket_repo.get_or_404(ticket_id, detail="Ticket not found")

    int_repo = IntegrationRepository(db)
    integration = int_repo.get_or_404(ticket.integration_id, detail="Integration not found")

    # Send comment to Jira
    provider = get_provider(
        provider=integration.provider,
        base_url=integration.base_url,
        auth_method=integration.auth_method,
        username=integration.auth_username,
        secret=integration.auth_secret,
        provider_config=integration.provider_config or {},
    )
    external_comment_id = provider.add_comment(ticket.external_id, payload.body)
    if external_comment_id is None:
        raise HTTPException(status_code=502, detail="Failed to add comment to external provider")

    comment = TicketComment(
        ticket_id=ticket.id,
        external_comment_id=external_comment_id,
        author="Dunedain",
        body=payload.body,
        direction="outbound",
    )
    TicketCommentRepository(db).save(comment)
    return comment
