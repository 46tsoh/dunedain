"""Automation rules engine.

Evaluates triggered rules against conditions and dispatches actions.
Used by the Celery automation tasks after a webhook event or internal event.
"""
from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from ...models import (
    AuditLog,
    AutomationRule,
    AutomationRuleExecution,
    Finding,
    Ticket,
)
from ...repositories.repos import (
    AuditLogRepository,
    AutomationRuleExecutionRepository,
    AutomationRuleRepository,
    FindingRepository,
    IntegrationRepository,
    RegistryRepository,
    ScanRepository,
    TicketRepository,
)

logger = logging.getLogger(__name__)

# Severity ordering for comparison
_SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "NEGLIGIBLE": 0,
    "UNKNOWN": -1,
}


@dataclass
class ActionResult:
    action_type: str
    success: bool
    detail: str = ""


@dataclass
class RuleEvaluation:
    rule_id: str
    rule_name: str
    conditions_matched: bool
    actions: list[ActionResult] = field(default_factory=list)
    status: str = "skipped"  # success, partial_failure, failed, skipped


def evaluate_conditions(
    conditions: list[dict[str, Any]],
    context: dict[str, Any],
) -> bool:
    """Evaluate all conditions (AND logic) against event context.

    Supported condition types:
    - severity_in: context["severity"] must be in condition["values"]
    - severity_gte: context["severity"] must be >= condition["severity"] or condition["min_severity"]
    - team_id: context["team_id"] must equal condition["value"]
    - integration_id: context["integration_id"] must equal condition["value"]
    - jira_status_in: context["jira_status"] must be in condition["values"]
    - ticket_status_in: context["ticket_status"] must be in condition["values"]
    - cvss_min: context["cvss_score"] must be >= condition["value"]
    - cvss_max: context["cvss_score"] must be <= condition["value"]
    - package_name_matches: context["package_name"] must match condition["pattern"] (glob)
    - scan_type: context["scan_type"] must equal condition["value"]
    - has_fix: context finding has/lacks a fix version (condition["value"] bool)
    """
    if not conditions:
        return True  # No conditions = always match

    for cond in conditions:
        cond_type = cond.get("type", "")

        if cond_type == "severity_in":
            values = [v.upper() for v in cond.get("values", [])]
            if context.get("severity", "").upper() not in values:
                return False

        elif cond_type == "team_id":
            if context.get("team_id") != cond.get("value"):
                return False

        elif cond_type == "integration_id":
            if context.get("integration_id") != cond.get("value"):
                return False

        elif cond_type == "jira_status_in":
            values = [v.lower() for v in cond.get("values", [])]
            if (context.get("jira_status") or "").lower() not in values:
                return False

        elif cond_type == "ticket_status_in":
            values = [v.lower() for v in cond.get("values", [])]
            if (context.get("ticket_status") or "").lower() not in values:
                return False

        elif cond_type == "cvss_min":
            score = context.get("cvss_score")
            if score is None or score < cond.get("value", 0):
                return False

        elif cond_type == "cvss_max":
            score = context.get("cvss_score")
            if score is None or score > cond.get("value", 10):
                return False

        elif cond_type == "package_name_matches":
            pattern = cond.get("pattern", "")
            pkg_name = context.get("package_name", "")
            if not fnmatch.fnmatch(pkg_name.lower(), pattern.lower()):
                return False

        elif cond_type == "severity_gte":
            min_sev = cond.get("severity", cond.get("min_severity", "HIGH")).upper()
            ctx_sev = (context.get("severity") or "UNKNOWN").upper()
            if _SEVERITY_ORDER.get(ctx_sev, -1) < _SEVERITY_ORDER.get(min_sev, 0):
                return False

        elif cond_type == "has_fix":
            expected = cond.get("value", True)
            actual = bool(context.get("has_fix") or context.get("fix_version"))
            if actual != expected:
                return False

        elif cond_type == "scan_type":
            if context.get("scan_type") != cond.get("value"):
                return False

        # -- Frontend-emitted aliases (map to canonical backend conditions) --

        elif cond_type == "cvss_gte":
            # Frontend sends {"type":"cvss_gte","score":7.0}; canonical is cvss_min
            score = context.get("cvss_score")
            if score is None or score < cond.get("score", cond.get("value", 0)):
                return False

        elif cond_type == "team_equals":
            # Frontend sends {"type":"team_equals","team_id":"..."}; canonical is team_id
            if context.get("team_id") != cond.get("team_id", cond.get("value")):
                return False

        elif cond_type == "package_matches":
            # Frontend sends {"type":"package_matches","pattern":"..."}; canonical is package_name_matches
            pattern = cond.get("pattern", "")
            pkg_name = context.get("package_name", "")
            if not fnmatch.fnmatch(pkg_name.lower(), pattern.lower()):
                return False

        elif cond_type == "status_equals":
            # Compare ticket/Jira status against the condition's status value
            ctx_status = (
                context.get("jira_status")
                or context.get("ticket_status")
                or ""
            ).lower()
            if ctx_status != (cond.get("status", "")).lower():
                return False

        elif cond_type == "priority_equals":
            # Compare ticket/external priority against the condition's priority value
            ctx_priority = (
                context.get("external_priority")
                or context.get("new_priority")
                or ""
            ).lower()
            if ctx_priority != (cond.get("priority", "")).lower():
                return False

        elif cond_type == "ecosystem_equals":
            # Compare package ecosystem
            ctx_eco = (context.get("ecosystem") or context.get("package_ecosystem") or "").lower()
            if ctx_eco != (cond.get("ecosystem", "")).lower():
                return False

        else:
            logger.warning("Unknown condition type: %s — treating as non-match", cond_type)
            return False

    return True


def execute_actions(
    actions: list[dict[str, Any]],
    context: dict[str, Any],
    db: Session,
) -> list[ActionResult]:
    """Execute a list of actions in order. Returns results for each action.

    Supported action types:
    - transition_jira_ticket / transition_ticket: Transition a ticket to a new status
    - add_jira_comment / add_comment / add_ticket_comment: Add a comment to a ticket
    - update_jira_fields / update_ticket_fields: Update fields on a ticket
    - mark_finding_accepted: Mark a finding as risk-accepted
    - log_audit_event: Write an audit log entry
    - rerun_scan: Re-trigger a scan
    """
    results: list[ActionResult] = []

    for action in actions:
        action_type = action.get("type", "")
        try:
            if action_type == "transition_jira_ticket":
                result = _action_transition_ticket(action, context, db)
            elif action_type == "add_jira_comment":
                result = _action_add_comment(action, context, db)
            elif action_type == "update_jira_fields":
                result = _action_update_fields(action, context, db)
            # Provider-agnostic aliases (map to same implementations)
            elif action_type == "transition_ticket":
                result = _action_transition_ticket(action, context, db)
            elif action_type in ("add_comment", "add_ticket_comment"):
                result = _action_add_comment(action, context, db)
            elif action_type == "update_ticket_fields":
                result = _action_update_fields(action, context, db)
            elif action_type == "mark_finding_accepted":
                result = _action_mark_finding_accepted(action, context, db)
            elif action_type == "log_audit_event":
                result = _action_log_audit(action, context, db)
            elif action_type == "rerun_scan":
                result = _action_rerun_scan(action, context, db)
            else:
                result = ActionResult(
                    action_type=action_type,
                    success=False,
                    detail=f"Unknown action type: {action_type}",
                )
        except Exception as exc:
            logger.exception("Action %s failed: %s", action_type, exc)
            result = ActionResult(
                action_type=action_type,
                success=False,
                detail=str(exc)[:500],
            )
        results.append(result)

    return results


def _action_transition_ticket(
    action: dict[str, Any], context: dict[str, Any], db: Session,
) -> ActionResult:
    """Transition a ticket to a target status."""
    from ..ticketing import get_provider

    ticket_id = context.get("ticket_id")
    if not ticket_id:
        return ActionResult("transition_ticket", False, "No ticket_id in context")

    ticket = TicketRepository(db).get(ticket_id)
    if not ticket:
        return ActionResult("transition_ticket", False, f"Ticket {ticket_id} not found")

    integration = IntegrationRepository(db).get(ticket.integration_id)
    if not integration:
        return ActionResult("transition_ticket", False, "Integration not found")

    provider = get_provider(
        provider=integration.provider,
        base_url=integration.base_url,
        auth_method=integration.auth_method,
        username=integration.auth_username,
        secret=integration.auth_secret,
        provider_config=integration.provider_config or {},
    )
    target_status = action.get("target_status", "")
    canonical_status = provider.transition_ticket(ticket.external_id, target_status)
    success = canonical_status is not None
    if canonical_status:
        ticket.external_status = canonical_status
        ticket.synced_at = datetime.now(timezone.utc)

    return ActionResult(
        "transition_ticket",
        success,
        f"Transitioned to '{canonical_status}'" if canonical_status else f"Failed to transition to '{target_status}'",
    )


def _action_add_comment(
    action: dict[str, Any], context: dict[str, Any], db: Session,
) -> ActionResult:
    """Add a comment to a ticket."""
    from ..ticketing import get_provider

    ticket_id = context.get("ticket_id")
    if not ticket_id:
        return ActionResult("add_comment", False, "No ticket_id in context")

    ticket = TicketRepository(db).get(ticket_id)
    if not ticket:
        return ActionResult("add_comment", False, f"Ticket {ticket_id} not found")

    integration = IntegrationRepository(db).get(ticket.integration_id)
    if not integration:
        return ActionResult("add_comment", False, "Integration not found")

    provider = get_provider(
        provider=integration.provider,
        base_url=integration.base_url,
        auth_method=integration.auth_method,
        username=integration.auth_username,
        secret=integration.auth_secret,
        provider_config=integration.provider_config or {},
    )

    body = action.get("body", "")
    # Template substitution — simple {key} replacement from context
    for key, value in context.items():
        if isinstance(value, str):
            body = body.replace(f"{{{key}}}", value)

    comment_id = provider.add_comment(ticket.external_id, body)
    if comment_id:
        from ...models import TicketComment
        from ...repositories.repos import TicketCommentRepository
        TicketCommentRepository(db).add(TicketComment(
            ticket_id=ticket.id,
            external_comment_id=comment_id,
            author="Dunedain Automation",
            body=body,
            direction="outbound",
        ))

    return ActionResult(
        "add_comment",
        comment_id is not None,
        f"Comment added (id={comment_id})" if comment_id else "Failed to add comment",
    )


def _action_update_fields(
    action: dict[str, Any], context: dict[str, Any], db: Session,
) -> ActionResult:
    """Update fields on a ticket."""
    from ..ticketing import get_provider

    ticket_id = context.get("ticket_id")
    if not ticket_id:
        return ActionResult("update_ticket_fields", False, "No ticket_id in context")

    ticket = TicketRepository(db).get(ticket_id)
    if not ticket:
        return ActionResult("update_ticket_fields", False, f"Ticket {ticket_id} not found")

    integration = IntegrationRepository(db).get(ticket.integration_id)
    if not integration:
        return ActionResult("update_ticket_fields", False, "Integration not found")

    provider = get_provider(
        provider=integration.provider,
        base_url=integration.base_url,
        auth_method=integration.auth_method,
        username=integration.auth_username,
        secret=integration.auth_secret,
        provider_config=integration.provider_config or {},
    )

    fields = action.get("fields", {})
    success = provider.update_fields(ticket.external_id, fields)
    return ActionResult(
        "update_ticket_fields",
        success,
        f"Updated fields: {list(fields.keys())}" if success else "Failed to update fields",
    )


def _action_mark_finding_accepted(
    action: dict[str, Any], context: dict[str, Any], db: Session,
) -> ActionResult:
    """Mark a finding as risk-accepted."""
    finding_id = context.get("finding_id")
    if not finding_id:
        return ActionResult("mark_finding_accepted", False, "No finding_id in context")

    finding = FindingRepository(db).get(finding_id)
    if not finding:
        return ActionResult("mark_finding_accepted", False, f"Finding {finding_id} not found")

    finding.risk_accepted = True
    finding.risk_accepted_at = datetime.now(timezone.utc)
    return ActionResult(
        "mark_finding_accepted",
        True,
        f"Finding {finding_id} marked as risk-accepted",
    )


def _action_log_audit(
    action: dict[str, Any], context: dict[str, Any], db: Session,
) -> ActionResult:
    """Write an audit log entry."""
    audit_action = action.get("action", "automation_action")
    resource_type = action.get("resource_type", "automation")
    resource_id = context.get("finding_id") or context.get("ticket_id") or context.get("scan_id")

    AuditLogRepository(db).add(AuditLog(
        id=str(uuid4()),
        action=audit_action,
        resource_type=resource_type,
        resource_id=resource_id,
        details={
            "trigger": context.get("trigger", ""),
            "rule_name": context.get("rule_name", ""),
            **{k: v for k, v in action.get("extra_details", {}).items()},
        },
    ))
    return ActionResult("log_audit_event", True, f"Logged: {audit_action}")


def _split_image_ref(target: str) -> tuple[str, str | None, str | None]:
    """Parse a container image reference into (name, tag, digest).

    Handles:
    - ``registry.example.com:5000/repo:tag``  → ``("registry.example.com:5000/repo", "tag", None)``
    - ``registry.example.com:5000/repo``       → ``("registry.example.com:5000/repo", None, None)``
    - ``repo@sha256:abc123``                   → ``("repo", None, "sha256:abc123")``
    - ``myacr.azurecr.io/app:v2.0.0``         → ``("myacr.azurecr.io/app", "v2.0.0", None)``

    The ``:`` is treated as a tag separator **only** when it appears after the
    last ``/`` (or in the entire string if there is no ``/``).  A ``@`` always
    indicates a digest.
    """
    # Digest form: name@sha256:...
    if "@" in target:
        name, digest = target.split("@", 1)
        return name, None, digest

    # Find the last '/' to isolate the name-component that may contain a tag
    last_slash = target.rfind("/")
    if last_slash == -1:
        # Simple reference like "myimage:tag"
        if ":" in target:
            name, tag = target.rsplit(":", 1)
            return name, tag, None
        return target, None, None

    # Everything after the last '/' is the final name component (possibly with :tag)
    after_slash = target[last_slash + 1:]
    if ":" in after_slash:
        colon_pos = after_slash.index(":")
        name = target[: last_slash + 1 + colon_pos]
        tag = after_slash[colon_pos + 1:]
        return name, tag, None

    return target, None, None


def _resolve_newest_tag(tags: list[str]) -> str | None:
    """Return the highest semver tag from a list, or None if none are parseable.

    Strips a leading 'v' prefix for parsing (e.g. 'v2.1.0' → '2.1.0')
    but returns the *original* tag string.  Non-semver tags (e.g. 'latest',
    'sha-abc123') are silently skipped.
    """
    from packaging.version import Version, InvalidVersion

    best_tag: str | None = None
    best_ver: Version | None = None

    for tag in tags:
        raw = tag.lstrip("v") if tag.lower().startswith("v") else tag
        try:
            ver = Version(raw)
        except InvalidVersion:
            continue
        if best_ver is None or ver > best_ver:
            best_ver = ver
            best_tag = tag

    return best_tag


def _resolve_container_target(
    action: dict[str, Any],
    scan: Any,
    db: Session,
) -> str:
    """Resolve the best container image target for a rescan.

    Priority:
      1. Explicit ``fix_version`` override from the action config
      2. Live ``list_tags()`` call → pick highest semver tag
      3. Fall back to original ``scan.target``

    Falls back gracefully on any failure (registry not found, API errors,
    no semver-parseable tags).
    """
    original_target: str = scan.target

    # 1. Explicit fix_version override
    fix_version = action.get("fix_version")
    if fix_version:
        # Replace tag (or append if no tag present); skip digest-form refs
        name, _tag, digest = _split_image_ref(original_target)
        if digest:
            logger.warning("Cannot apply fix_version to digest ref %s", original_target)
            return original_target
        return f"{name}:{fix_version}"

    # 2. Live registry tag resolution
    if not scan.registry_id:
        return original_target

    try:
        registry = RegistryRepository(db).get(scan.registry_id)
        if not registry:
            logger.warning("Registry %s not found for scan %s", scan.registry_id, scan.id)
            return original_target

        # Extract repository name from target:  "{registry.url}/{repo}:{tag}"
        url_prefix = registry.url.rstrip("/") + "/"
        name, _tag, _digest = _split_image_ref(original_target)
        without_prefix = name
        if name.startswith(url_prefix):
            without_prefix = name[len(url_prefix):]
        repo_name = without_prefix

        from ..registry import list_tags
        live_tags = list_tags(
            registry_url=registry.url,
            auth_method=registry.auth_method,
            repository=repo_name,
            username=registry.username,
            password=registry.password,
        )

        newest = _resolve_newest_tag(live_tags)
        if newest:
            return f"{registry.url.rstrip('/')}/{repo_name}:{newest}"

        logger.info("No semver tags found for %s; using original target", repo_name)
    except Exception:
        logger.exception("Failed to resolve newest tag for scan %s; using original target", scan.id)

    return original_target


def _action_rerun_scan(
    action: dict[str, Any], context: dict[str, Any], db: Session,
) -> ActionResult:
    """Re-trigger a scan by creating a new scan and dispatching a Celery task.

    Mirrors the HTTP /api/scans/{id}/rerun endpoint:
    - Copies scan_type, target, packages, registry_id, team_id
    - For registry container scans, resolves the newest image tag via live API
    - Resolves scanner_override for container scans via _get_scanner_preference
    - Passes packages to run_scan.delay for dependency reruns
    - Cleans up orphan scan row if Celery dispatch fails
    """
    scan_id = context.get("scan_id")
    if not scan_id:
        return ActionResult("rerun_scan", False, "No scan_id in context")

    scan = ScanRepository(db).get(scan_id)
    if not scan:
        return ActionResult("rerun_scan", False, f"Scan {scan_id} not found")

    # Resolve target — for registry container scans, pick the newest tag
    target = scan.target
    if scan.scan_type == "container" and scan.registry_id:
        target = _resolve_container_target(action, scan, db)

    # Resolve scanner preference for container scans (matches HTTP /rerun endpoint)
    scanner_override = None
    if scan.scan_type == "container":
        try:
            from ...services.scanner import _get_scanner_preference
            scanner_override = _get_scanner_preference()
        except Exception:
            pass  # Fall back to app setting at scan time

    from ...models import Scan
    new_scan = Scan(
        id=str(uuid4()),
        name=scan.name,
        scan_type=scan.scan_type,
        target=target,
        status="pending",
        packages=scan.packages,
        registry_id=scan.registry_id,
        scanner_override=scanner_override,
        team_id=scan.team_id,
    )
    ScanRepository(db).save(new_scan)

    # Dispatch Celery task — pass packages for dependency reruns
    try:
        from ...tasks.scan import run_scan
        run_scan.delay(new_scan.id, scan.packages)
    except Exception as exc:
        # Remove orphan scan row to avoid "stuck pending" state
        try:
            ScanRepository(db).delete(new_scan)
        except Exception:
            logger.exception("Failed to clean up orphan scan %s after dispatch failure", new_scan.id)
        return ActionResult("rerun_scan", False, f"Scan dispatch failed: {exc}")

    return ActionResult(
        "rerun_scan",
        True,
        f"Scan {new_scan.id} dispatched (target={target})",
    )


def evaluate_automation_rules(
    db: Session,
    trigger: str,
    context: dict[str, Any],
) -> list[RuleEvaluation]:
    """Find and evaluate all enabled rules matching the trigger.

    For each matching rule:
    1. Evaluate conditions against context
    2. If conditions match, execute actions
    3. Record execution in AutomationRuleExecution
    4. Update rule execution_count and last_executed_at

    Returns list of RuleEvaluation results.
    """
    rule_repo = AutomationRuleRepository(db)
    exec_repo = AutomationRuleExecutionRepository(db)

    rules = rule_repo.list_enabled(trigger=trigger)
    evaluations: list[RuleEvaluation] = []

    for rule in rules:
        eval_result = RuleEvaluation(
            rule_id=rule.id,
            rule_name=rule.name,
            conditions_matched=False,
        )

        # Check additional filters on rule (integration_id, team_id)
        if rule.integration_id and context.get("integration_id") != rule.integration_id:
            eval_result.status = "skipped"
            evaluations.append(eval_result)
            continue
        if rule.team_id and context.get("team_id") != rule.team_id:
            eval_result.status = "skipped"
            evaluations.append(eval_result)
            continue

        # Evaluate conditions
        conditions_matched = evaluate_conditions(rule.conditions, context)
        eval_result.conditions_matched = conditions_matched

        if not conditions_matched:
            eval_result.status = "skipped"
            # Record skipped execution
            exec_repo.add(AutomationRuleExecution(
                id=str(uuid4()),
                rule_id=rule.id,
                trigger_event=trigger,
                trigger_context=context,
                conditions_matched=False,
                actions_executed=[],
                status="skipped",
            ))
            evaluations.append(eval_result)
            continue

        # Execute actions
        action_context = {**context, "rule_name": rule.name, "trigger": trigger}
        action_results = execute_actions(rule.actions, action_context, db)
        eval_result.actions = action_results

        # Determine overall status
        successes = sum(1 for a in action_results if a.success)
        if successes == len(action_results):
            eval_result.status = "success"
        elif successes == 0:
            eval_result.status = "failed"
        else:
            eval_result.status = "partial_failure"

        # Record execution
        exec_repo.add(AutomationRuleExecution(
            id=str(uuid4()),
            rule_id=rule.id,
            trigger_event=trigger,
            trigger_context=context,
            conditions_matched=True,
            actions_executed=[
                {"action_type": a.action_type, "success": a.success, "detail": a.detail}
                for a in action_results
            ],
            status=eval_result.status,
        ))

        # Update rule stats
        rule_repo.increment_execution(rule.id)

        evaluations.append(eval_result)

    return evaluations


def fire_event(
    db: Session,
    trigger: str,
    context: dict[str, Any],
) -> list[RuleEvaluation]:
    """Convenience wrapper: evaluate rules and commit.

    Used by internal event sources (scan completion, etc.)
    """
    results = evaluate_automation_rules(db, trigger, context)
    db.commit()
    return results
