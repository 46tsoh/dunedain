"""Webhook event processor for inbound Jira events.

Parses raw webhook payloads, verifies HMAC signatures, and applies
state changes to local Ticket / TicketComment records.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from ...models import Integration, Ticket, TicketComment, WebhookEvent
from ...repositories.repos import (
    IntegrationRepository,
    TicketCommentRepository,
    TicketRepository,
)

logger = logging.getLogger(__name__)


@dataclass
class WebhookProcessResult:
    """Outcome of processing a single webhook event."""
    event_type: str = ""
    external_issue_key: str = ""
    matched_ticket: bool = False
    changes: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


def verify_hmac_signature(
    payload_bytes: bytes,
    secret: str,
    signature: str,
) -> bool:
    """Verify HMAC-SHA256 signature from Jira webhook.
    
    Jira Cloud sends the signature in the X-Hub-Signature header as
    ``sha256=<hex_digest>``.
    """
    if not secret or not signature:
        return False
    expected = hmac.new(
        secret.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()
    # Accept both "sha256=abc..." and plain "abc..." formats
    actual = signature.removeprefix("sha256=")
    return hmac.compare_digest(expected, actual)


def parse_jira_event(payload: dict[str, Any]) -> dict[str, Any]:
    """Extract structured fields from a raw Jira webhook payload.
    
    Returns a dict with normalized keys regardless of the Jira event type:
    - event_type: str (e.g. "jira:issue_updated", "comment_created")
    - issue_id: str | None
    - issue_key: str | None
    - status: str | None (current status name)
    - previous_status: str | None
    - assignee: str | None (display name)
    - priority: str | None (priority name)
    - comment_id: str | None
    - comment_body: str | None
    - comment_author: str | None
    - changelog_items: list[dict] (raw changelog items)
    """
    event_type = payload.get("webhookEvent", payload.get("issue_event_type_name", "unknown"))
    issue = payload.get("issue", {})
    fields = issue.get("fields", {})
    changelog = payload.get("changelog", {})
    changelog_items = changelog.get("items", [])
    comment_data = payload.get("comment", {})

    # Extract status change from changelog
    status = fields.get("status", {}).get("name") if fields.get("status") else None
    previous_status = None
    for item in changelog_items:
        if item.get("field") == "status":
            previous_status = item.get("fromString")
            status = item.get("toString") or status

    # Extract assignee
    assignee_data = fields.get("assignee")
    assignee = assignee_data.get("displayName") if assignee_data else None

    # Extract priority
    priority_data = fields.get("priority")
    priority = priority_data.get("name") if priority_data else None

    return {
        "event_type": event_type,
        "issue_id": issue.get("id"),
        "issue_key": issue.get("key"),
        "status": status,
        "previous_status": previous_status,
        "assignee": assignee,
        "priority": priority,
        "comment_id": comment_data.get("id"),
        "comment_body": comment_data.get("body"),
        "comment_author": (
            comment_data.get("author", {}).get("displayName")
            if comment_data.get("author")
            else None
        ),
        "changelog_items": changelog_items,
    }


def process_webhook_event(
    db: Session,
    event: WebhookEvent,
) -> WebhookProcessResult:
    """Process a single webhook event, updating local state.
    
    Steps:
    1. Look up the integration
    2. Parse the payload
    3. Find the matching local Ticket by external_id or external_key
    4. Apply changes (status, assignee, priority, comments)
    5. Return a result describing what happened
    """
    result = WebhookProcessResult()

    integration = IntegrationRepository(db).get(event.integration_id)
    if not integration:
        result.error = f"Integration {event.integration_id} not found"
        return result

    parsed = parse_jira_event(event.payload)
    result.event_type = parsed["event_type"]
    result.external_issue_key = parsed.get("issue_key") or ""

    # Update the event record with extracted metadata
    if parsed.get("issue_id"):
        event.external_issue_id = parsed["issue_id"]
    if parsed.get("issue_key"):
        event.external_issue_key = parsed["issue_key"]

    # Find matching ticket
    ticket_repo = TicketRepository(db)
    ticket: Ticket | None = None

    if parsed.get("issue_id"):
        ticket = ticket_repo.find_by_external_id(event.integration_id, parsed["issue_id"])

    if ticket is None and parsed.get("issue_key"):
        ticket = ticket_repo.find_by_external_key(event.integration_id, parsed["issue_key"])

    if ticket is None:
        # No matching ticket — event is valid but not tracked
        result.matched_ticket = False
        return result

    result.matched_ticket = True

    # Apply status change
    if parsed.get("status") and parsed["status"] != ticket.external_status:
        old_status = ticket.external_status
        ticket.external_status = parsed["status"]
        ticket.synced_at = datetime.now(timezone.utc)
        result.changes["status"] = {
            "old": old_status,
            "new": parsed["status"],
        }

    # Apply assignee change
    if parsed.get("assignee") is not None:
        if parsed["assignee"] != ticket.external_assignee:
            old_assignee = ticket.external_assignee
            ticket.external_assignee = parsed["assignee"]
            ticket.synced_at = datetime.now(timezone.utc)
            result.changes["assignee"] = {
                "old": old_assignee,
                "new": parsed["assignee"],
            }

    # Apply priority change
    if parsed.get("priority") is not None:
        if parsed["priority"] != ticket.external_priority:
            old_priority = ticket.external_priority
            ticket.external_priority = parsed["priority"]
            ticket.synced_at = datetime.now(timezone.utc)
            result.changes["priority"] = {
                "old": old_priority,
                "new": parsed["priority"],
            }

    # Sync inbound comment
    if parsed.get("comment_id") and parsed.get("comment_body"):
        comment_repo = TicketCommentRepository(db)
        if not comment_repo.exists_by_external_id(ticket.id, str(parsed["comment_id"])):
            comment = TicketComment(
                ticket_id=ticket.id,
                external_comment_id=str(parsed["comment_id"]),
                author=parsed.get("comment_author"),
                body=parsed["comment_body"],
                direction="inbound",
            )
            try:
                nested = db.begin_nested()
                comment_repo.add(comment)
                db.flush()
            except Exception:
                # TOCTOU race: another worker already inserted this comment.
                # Savepoint rollback only undoes the comment insert, preserving
                # status/assignee/priority changes made earlier in this session.
                nested.rollback()
                logger.debug("Duplicate comment %s skipped (concurrent insert)", parsed["comment_id"])
            else:
                result.changes["comment_added"] = {
                    "author": parsed.get("comment_author"),
                    "comment_id": parsed["comment_id"],
                }

    return result


def classify_event_triggers(parsed: dict[str, Any]) -> list[str]:
    """Determine which automation triggers this webhook event should fire.
    
    Returns a list of trigger names suitable for matching against AutomationRule.trigger.
    """
    triggers: list[str] = []
    event_type = parsed.get("event_type", "")

    # Status change
    if parsed.get("previous_status") and parsed.get("status"):
        triggers.append("jira_status_changed")

    # Assignee change (check changelog)
    for item in parsed.get("changelog_items", []):
        if item.get("field") == "assignee":
            triggers.append("jira_assignee_changed")
            break

    # Priority change (check changelog)
    for item in parsed.get("changelog_items", []):
        if item.get("field") == "priority":
            triggers.append("jira_priority_changed")
            break

    # Comment — only fire for newly created comments, not updates/deletes
    if "comment_created" in event_type.lower() or (
        parsed.get("comment_id")
        and "comment" not in event_type.lower()
    ):
        triggers.append("jira_comment_added")

    # Issue deleted
    if "deleted" in event_type.lower():
        triggers.append("jira_issue_deleted")

    return triggers
