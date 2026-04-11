"""Webhook event processor for inbound GitHub events.

Parses raw GitHub webhook payloads and applies state changes to local
Ticket / TicketComment records.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from ...models import TicketComment, WebhookEvent
from ...repositories.repos import (
    IntegrationRepository,
    TicketCommentRepository,
    TicketRepository,
)
from .webhook_processor import WebhookProcessResult

logger = logging.getLogger(__name__)


def verify_github_signature(
    payload_bytes: bytes,
    secret: str,
    signature: str,
) -> bool:
    """Verify HMAC-SHA256 signature from GitHub webhook.

    GitHub sends the signature in the X-Hub-Signature-256 header as
    ``sha256=<hex_digest>``.
    """
    if not secret or not signature:
        return False
    expected = hmac.new(
        secret.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()
    actual = signature.removeprefix("sha256=")
    return hmac.compare_digest(expected, actual)


def parse_github_event(
    payload: dict[str, Any],
    event_type: str = "",
) -> dict[str, Any]:
    """Extract structured fields from a raw GitHub webhook payload.

    ``event_type`` is the value of the ``X-GitHub-Event`` header, stored
    in the payload as ``_github_event_type`` by the webhook receiver.

    Returns a dict with normalized keys:
    - event_type: str (e.g. "issues", "issue_comment")
    - action: str (e.g. "opened", "closed", "created")
    - issue_number: str (issue number as string)
    - issue_key: str (e.g. "owner/repo#42")
    - status: str (current issue state: "open" or "closed")
    - previous_status: str | None (from changes.old_state or inferred)
    - assignee: str | None (login)
    - labels: list[str] (label names)
    - comment_id: str | None
    - comment_body: str | None
    - comment_author: str | None
    """
    if not event_type:
        event_type = payload.get("_github_event_type", "unknown")

    action = payload.get("action", "")
    issue = payload.get("issue", {})
    repo_data = payload.get("repository", {})
    full_name = repo_data.get("full_name", "")
    number = issue.get("number")
    state = issue.get("state", "")

    # Determine previous status from action semantics
    previous_status = None
    if action == "closed":
        previous_status = "open"
    elif action == "reopened":
        previous_status = "closed"

    # Assignee
    assignee_data = issue.get("assignee")
    assignee = assignee_data.get("login") if assignee_data else None

    # Labels
    labels = [lbl.get("name", "") for lbl in issue.get("labels", [])]

    # Comment data
    comment = payload.get("comment", {})
    comment_id = str(comment["id"]) if comment.get("id") else None
    comment_body = comment.get("body")
    comment_author_data = comment.get("user", {})
    comment_author = comment_author_data.get("login") if comment_author_data else None

    return {
        "event_type": event_type,
        "action": action,
        "issue_number": str(number) if number is not None else None,
        "issue_key": f"{full_name}#{number}" if full_name and number else None,
        "status": state,
        "previous_status": previous_status,
        "assignee": assignee,
        "labels": labels,
        "comment_id": comment_id,
        "comment_body": comment_body,
        "comment_author": comment_author,
    }


def classify_github_triggers(parsed: dict[str, Any]) -> list[str]:
    """Determine which automation triggers this GitHub event should fire.

    Returns generic trigger names (provider-agnostic) for matching against
    AutomationRule.trigger.
    """
    triggers: list[str] = []
    event_type = parsed.get("event_type", "")
    action = parsed.get("action", "")

    if event_type == "issues":
        if action in ("closed", "reopened"):
            triggers.append("ticket_status_changed")
        if action == "assigned" or action == "unassigned":
            triggers.append("ticket_assignee_changed")
        if action == "labeled" or action == "unlabeled":
            triggers.append("ticket_label_changed")
        if action == "deleted":
            triggers.append("ticket_deleted")
    elif event_type == "issue_comment":
        if action == "created":
            triggers.append("ticket_comment_added")

    return triggers


def process_github_webhook_event(
    db: Session,
    event: WebhookEvent,
) -> WebhookProcessResult:
    """Process a single GitHub webhook event, updating local state.

    Same pattern as the Jira processor — finds matching ticket, applies
    status/assignee/comment changes, returns result.
    """
    result = WebhookProcessResult()

    integration = IntegrationRepository(db).get(event.integration_id)
    if not integration:
        result.error = f"Integration {event.integration_id} not found"
        return result

    event_type = event.payload.get("_github_event_type", "unknown")
    parsed = parse_github_event(event.payload, event_type)
    result.event_type = f"github:{event_type}:{parsed.get('action', '')}"
    result.external_issue_key = parsed.get("issue_key") or ""

    # Update the event record with extracted metadata
    if parsed.get("issue_number"):
        event.external_issue_id = parsed["issue_number"]
    if parsed.get("issue_key"):
        event.external_issue_key = parsed["issue_key"]

    # Find matching ticket by external_id (issue number) or external_key
    ticket_repo = TicketRepository(db)
    ticket = None

    if parsed.get("issue_number"):
        ticket = ticket_repo.find_by_external_id(event.integration_id, parsed["issue_number"])

    if ticket is None and parsed.get("issue_key"):
        ticket = ticket_repo.find_by_external_key(event.integration_id, parsed["issue_key"])

    if ticket is None:
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
                # status/assignee/label changes made earlier in this session.
                nested.rollback()
                logger.debug("Duplicate comment %s skipped (concurrent insert)", parsed["comment_id"])
            else:
                result.changes["comment_added"] = {
                    "author": parsed.get("comment_author"),
                    "comment_id": parsed["comment_id"],
                }

    return result
