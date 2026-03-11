from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from ..models import Finding, Policy, PolicyResult


def evaluate_policy(policy: Policy, findings: list[Finding]) -> PolicyResult:
    """Evaluate a policy against a list of findings and return a PolicyResult."""
    violations: list[dict[str, Any]] = []

    for rule in policy.rules or []:
        rule_type = rule.get("type", "")

        if rule_type == "severity_threshold":
            min_sev = rule.get("min_severity", "CRITICAL")
            _sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
            threshold = _sev_order.get(min_sev.upper(), 4)
            matched = [
                f for f in findings
                if _sev_order.get(f.severity.upper(), 0) >= threshold
            ]
            if matched:
                violations.append(
                    {
                        "rule": rule_type,
                        "message": f"Found {len(matched)} findings with severity >= {min_sev}",
                        "affected_findings": [f.vulnerability_id for f in matched],
                    }
                )

        elif rule_type == "cvss_threshold":
            min_score = float(rule.get("min_score", 7.0))
            matched = [f for f in findings if f.cvss_score is not None and f.cvss_score >= min_score]
            if matched:
                violations.append(
                    {
                        "rule": rule_type,
                        "message": f"Found {len(matched)} findings with CVSS >= {min_score}",
                        "affected_findings": [f.vulnerability_id for f in matched],
                    }
                )

        elif rule_type == "fix_available":
            require_fix = rule.get("require_fix", True)
            if require_fix:
                matched = [f for f in findings if not f.is_fixed]
                if matched:
                    violations.append(
                        {
                            "rule": rule_type,
                            "message": f"{len(matched)} findings have no fix available",
                            "affected_findings": [f.vulnerability_id for f in matched],
                        }
                    )

        elif rule_type == "package_blocklist":
            blocked: list[str] = [p.lower() for p in rule.get("packages", [])]
            matched = [f for f in findings if f.package_name.lower() in blocked]
            if matched:
                violations.append(
                    {
                        "rule": rule_type,
                        "message": f"Blocked packages found: {[f.package_name for f in matched]}",
                        "affected_findings": [f.vulnerability_id for f in matched],
                    }
                )

    return PolicyResult(
        id=str(uuid4()),
        scan_id="",  # caller must set this
        policy_id=str(policy.id),
        passed=len(violations) == 0,
        violations=violations,
        evaluated_at=datetime.now(timezone.utc),
    )
