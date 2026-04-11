"""Automatic ticket creation for scan findings based on team configuration."""
from __future__ import annotations

import logging
from uuid import uuid4

from sqlalchemy.orm import Session

from ...models import AuditLog, Finding, Scan, Ticket
from ...repositories.repos import (
    AuditLogRepository,
    IntegrationFieldMappingRepository,
    IntegrationRepository,
    TeamRepository,
    TicketRepository,
)
from .field_mapper import build_ticket_fields
from .registry import get_provider

logger = logging.getLogger(__name__)

_SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "NEGLIGIBLE": 0,
    "UNKNOWN": -1,
}


def create_tickets_for_scan(
    db: Session,
    scan: Scan,
    findings: list[Finding],
) -> int:
    """Create tickets for qualifying findings if the scan's team has auto-ticketing enabled.

    Returns the number of tickets created.
    """
    if not scan.team_id:
        return 0

    team_repo = TeamRepository(db)
    team = team_repo.get(scan.team_id)
    if not team or not team.auto_create_tickets or not team.integration_id:
        return 0

    int_repo = IntegrationRepository(db)
    integration = int_repo.get(team.integration_id)
    if not integration or not integration.enabled:
        return 0

    threshold_level = _SEVERITY_ORDER.get(team.ticket_severity_threshold, 3)
    qualifying = [
        f for f in findings
        if _SEVERITY_ORDER.get(f.severity, -1) >= threshold_level
    ]
    if not qualifying:
        return 0

    ticket_repo = TicketRepository(db)
    finding_ids = [f.id for f in qualifying]
    existing = ticket_repo.bulk_check_existing(integration.id, finding_ids)
    to_create = [f for f in qualifying if f.id not in existing]
    if not to_create:
        return 0

    mapping_repo = IntegrationFieldMappingRepository(db)
    mappings = mapping_repo.for_integration(integration.id)

    try:
        provider = get_provider(
            provider=integration.provider,
            base_url=integration.base_url,
            auth_method=integration.auth_method,
            username=integration.auth_username,
            secret=integration.auth_secret,
            provider_config=integration.provider_config or {},
        )
    except ValueError:
        logger.warning(
            "Unsupported provider '%s' for integration %s",
            integration.provider, integration.id,
        )
        return 0

    audit_repo = AuditLogRepository(db)
    created_count = 0

    for finding in to_create:
        fields = build_ticket_fields(integration, mappings, finding, scan)
        try:
            result = provider.create_ticket(fields)
        except Exception:
            logger.exception(
                "Failed to auto-create ticket for finding %s via integration %s",
                finding.id, integration.id,
            )
            continue

        ticket = Ticket(
            id=str(uuid4()),
            integration_id=integration.id,
            finding_id=finding.id,
            external_id=result.external_id,
            external_key=result.external_key,
            external_url=result.external_url,
            summary=result.summary,
        )
        ticket_repo.add(ticket)
        created_count += 1

    if created_count > 0:
        db.flush()
        audit_repo.add(AuditLog(
            id=str(uuid4()),
            action="auto_tickets_created",
            resource_type="scan",
            resource_id=scan.id,
            details={
                "team_id": team.id,
                "team_name": team.name,
                "integration_id": integration.id,
                "integration_name": integration.name,
                "tickets_created": created_count,
                "severity_threshold": team.ticket_severity_threshold,
            },
        ))
        db.commit()

    return created_count
